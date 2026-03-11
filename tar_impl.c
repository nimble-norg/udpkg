#define _XOPEN_SOURCE 700
#include "tar_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <dirent.h>
#include <utime.h>
#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#define BLOCK_SIZE      512
#define RECORDS_PER_BLK 20
#define IOBUF_SIZE      65536

#define TMAGIC_USTAR "ustar"
#define TVERSION_USTAR "00"
#define TMAGIC_GNU   "ustar  "

typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
} ustar_header;

#define TF_REG  '0'
#define TF_LNKH '1'
#define TF_SYM  '2'
#define TF_CHR  '3'
#define TF_BLK  '4'
#define TF_DIR  '5'
#define TF_FIFO '6'
#define TF_CONT '7'
#define TF_PAX_GLOBAL 'g'
#define TF_PAX_LOCAL  'x'
#define TF_GNU_LONGNAME 'L'
#define TF_GNU_LONGLINK 'K'

static unsigned int calc_checksum(const ustar_header *h) {
    const unsigned char *p = (const unsigned char *)h;
    unsigned int sum = 0;
    size_t i;
    for (i = 0; i < BLOCK_SIZE; i++)
        sum += (i >= 148 && i < 156) ? (unsigned int)' ' : (unsigned int)p[i];
    return sum;
}

static void set_octal(char *field, size_t sz, unsigned long long val) {
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%0*llo",
                     (int)(sz - 1), (unsigned long long)val);
    if (n < 0 || (size_t)n >= sz) {
        memset(field, '7', sz - 1);
        field[sz - 1] = '\0';
    } else {
        strncpy(field, tmp, sz);
    }
}

static unsigned long long get_octal(const char *field, size_t sz) {
    char tmp[32];
    unsigned long long v = 0;
    size_t i = 0;
    while (i < sz && field[i] == ' ') i++;
    while (i < sz && field[i] == '0') i++;
    if (i < sz && (field[i] >= '1' && field[i] <= '7'))
        sscanf(field, "%llo", &v);
    else if (i < sz && field[i] == '0')
        v = 0;
    else
        sscanf(field, "%llo", &v);
    (void)tmp;
    sscanf(field, "%llo", &v);
    return v;
}

static void write_checksum(ustar_header *h) {
    unsigned int sum;
    memset(h->checksum, ' ', sizeof(h->checksum));
    sum = calc_checksum(h);
    snprintf(h->checksum, sizeof(h->checksum), "%06o", sum);
    h->checksum[6] = '\0';
    h->checksum[7] = ' ';
}

static int check_checksum(const ustar_header *h) {
    unsigned int stored, calc;
    unsigned int calc_s;
    char tmp[8];
    memcpy(tmp, h->checksum, 8);
    calc = calc_checksum(h);
    if (sscanf(tmp, "%o", &stored) != 1) {
        const unsigned char *p = (const unsigned char *)h;
        unsigned int s2 = 0;
        size_t i;
        for (i = 0; i < BLOCK_SIZE; i++)
            s2 += (i >= 148 && i < 156) ? (unsigned int)' ' : p[i];
        calc_s = s2;
        stored = calc_s;
    }
    (void)calc_s;
    return (calc == stored) ? 0 : -1;
}

static int is_zero_block(const char *buf) {
    size_t i;
    for (i = 0; i < BLOCK_SIZE; i++)
        if (buf[i] != '\0') return 0;
    return 1;
}

typedef struct {
    int fd;
    pid_t decomp_pid;
    char buf[IOBUF_SIZE];
    size_t buf_pos;
    size_t buf_filled;
    long long total_read;
} rstream;

static int rs_open(rstream *rs, const char *path) {
    unsigned char magic[6];
    int raw_fd;
    int pipefd[2];
    const char *decomp = NULL;
    char *dargv[4];
    rs->decomp_pid = -1;
    raw_fd = open(path, O_RDONLY);
    if (raw_fd < 0) return -1;
    if (read(raw_fd, magic, sizeof(magic)) == (ssize_t)sizeof(magic)) {
        if (magic[0] == 0x1f && magic[1] == 0x8b)
            decomp = "gzip";
        else if (magic[0] == 0xfd && magic[1] == '7' && magic[2] == 'z' &&
                 magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0x00)
            decomp = "xz";
        else if (magic[0] == 0x28 && magic[1] == 0xb5 &&
                 magic[2] == 0x2f && magic[3] == 0xfd)
            decomp = "zstd";
        else if (magic[0] == 0x42 && magic[1] == 0x5a && magic[2] == 0x68)
            decomp = "bzip2";
    }
    lseek(raw_fd, 0, SEEK_SET);
    if (!decomp) {
        rs->fd = raw_fd;
    } else {
        if (pipe(pipefd) != 0) { close(raw_fd); return -1; }
        rs->decomp_pid = fork();
        if (rs->decomp_pid < 0) {
            close(raw_fd); close(pipefd[0]); close(pipefd[1]);
            return -1;
        }
        if (rs->decomp_pid == 0) {
            dup2(raw_fd, STDIN_FILENO);
            dup2(pipefd[1], STDOUT_FILENO);
            close(raw_fd); close(pipefd[0]); close(pipefd[1]);
            dargv[0] = (char *)decomp;
            dargv[1] = "-d";
            dargv[2] = "-c";
            dargv[3] = NULL;
            execvp(dargv[0], dargv);
            _exit(127);
        }
        close(raw_fd);
        close(pipefd[1]);
        rs->fd = pipefd[0];
    }
    rs->buf_pos    = 0;
    rs->buf_filled = 0;
    rs->total_read = 0;
    return 0;
}

static int rs_read_block(rstream *rs, char *out) {
    size_t got = 0;
    while (got < BLOCK_SIZE) {
        if (rs->buf_pos >= rs->buf_filled) {
            ssize_t n = read(rs->fd, rs->buf, IOBUF_SIZE);
            if (n <= 0) {
                if (got == 0) return -1;
                memset(out + got, 0, BLOCK_SIZE - got);
                return 0;
            }
            rs->buf_pos = 0;
            rs->buf_filled = (size_t)n;
        }
        size_t avail = rs->buf_filled - rs->buf_pos;
        size_t need  = BLOCK_SIZE - got;
        size_t take  = avail < need ? avail : need;
        memcpy(out + got, rs->buf + rs->buf_pos, take);
        rs->buf_pos += take;
        got += take;
    }
    rs->total_read += BLOCK_SIZE;
    return 0;
}

static void rs_close(rstream *rs) {
    close(rs->fd);
    if (rs->decomp_pid > 0) {
        int st;
        waitpid(rs->decomp_pid, &st, 0);
        rs->decomp_pid = -1;
    }
}

typedef struct {
    int fd;
    char buf[IOBUF_SIZE];
    size_t buf_pos;
} wstream;

static int ws_open(wstream *ws, const char *path) {
    ws->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (ws->fd < 0) return -1;
    ws->buf_pos = 0;
    return 0;
}

static int ws_flush(wstream *ws) {
    size_t written = 0;
    while (written < ws->buf_pos) {
        ssize_t n = write(ws->fd, ws->buf + written, ws->buf_pos - written);
        if (n <= 0) return -1;
        written += (size_t)n;
    }
    ws->buf_pos = 0;
    return 0;
}

static int ws_write_block(wstream *ws, const char *data) {
    if (ws->buf_pos + BLOCK_SIZE > IOBUF_SIZE)
        if (ws_flush(ws) != 0) return -1;
    memcpy(ws->buf + ws->buf_pos, data, BLOCK_SIZE);
    ws->buf_pos += BLOCK_SIZE;
    return 0;
}

static int ws_close(wstream *ws) {
    int rc = 0;
    if (ws->buf_pos > 0)
        rc = ws_flush(ws);
    close(ws->fd);
    return rc;
}

static void build_ustar_header(ustar_header *h, const char *path,
                                const char *link, const struct stat *st,
                                char typeflag, int fmt) {
    char name_buf[256];
    const char *prefix_part = "";
    const char *name_part   = path;
    size_t plen;
    memset(h, 0, sizeof(*h));
    plen = strlen(path);
    if (plen > 99 && fmt != TARFMT_V7) {
        const char *slash = NULL;
        const char *p = path + plen - 1;
        while (p > path && (size_t)(p - path) > plen - 155) {
            if (*p == '/' && (size_t)(p - path) <= 154 &&
                (size_t)(plen - (size_t)(p - path) - 1) <= 99) {
                slash = p;
                break;
            }
            p--;
        }
        if (slash) {
            strncpy(name_buf, slash + 1, 100);
            name_buf[99] = '\0';
            name_part   = name_buf;
            prefix_part = path;
        }
    }
    strncpy(h->name, name_part, 99);
    h->name[99] = '\0';
    if (fmt != TARFMT_V7) {
        strncpy(h->prefix, prefix_part, 154);
        h->prefix[154] = '\0';
        if (prefix_part == path)
            h->prefix[(size_t)(name_part - path - 1)] = '\0';
    }
    set_octal(h->mode, sizeof(h->mode), (unsigned long long)(st->st_mode & 07777));
    set_octal(h->uid, sizeof(h->uid), (unsigned long long)st->st_uid);
    set_octal(h->gid, sizeof(h->gid), (unsigned long long)st->st_gid);
    set_octal(h->mtime, sizeof(h->mtime), (unsigned long long)st->st_mtime);
    h->typeflag = typeflag;
    if (link)
        strncpy(h->linkname, link, 99);
    if (typeflag == TF_REG || typeflag == TF_CONT ||
        typeflag == TF_PAX_LOCAL || typeflag == TF_PAX_GLOBAL ||
        typeflag == TF_GNU_LONGNAME || typeflag == TF_GNU_LONGLINK)
        set_octal(h->size, sizeof(h->size), (unsigned long long)st->st_size);
    if (fmt != TARFMT_V7) {
        memcpy(h->magic, TMAGIC_USTAR, 5);
        h->magic[5] = '\0';
        h->version[0] = '0';
        h->version[1] = '0';
        struct passwd *pw = getpwuid(st->st_uid);
        struct group  *gr = getgrgid(st->st_gid);
        if (pw) strncpy(h->uname, pw->pw_name, 31);
        if (gr) strncpy(h->gname, gr->gr_name, 31);
    }
    write_checksum(h);
}

static int pax_record(char *out, size_t outsz, const char *kv) {
    size_t kvlen = strlen(kv);
    int digits = 1;
    size_t total;
    for (;;) {
        /* total = len(str(total)) + SP + kv + NL */
        total = (size_t)digits + 2 + kvlen;
        size_t t = total;
        int d = 0;
        while (t > 0) { d++; t /= 10; }
        if (d == digits) break;
        digits = d;
    }
    return snprintf(out, outsz, "%zu %s\n", total, kv);
}

static int write_pax_ext(wstream *ws, const char *longpath,
                          const char *longlink, char typeflag) {
    char pax_data[8192];
    int plen = 0;
    ustar_header ph;
    struct stat fake;
    char kv[PATH_MAX + 16];
    (void)typeflag;
    if (longpath) {
        snprintf(kv, sizeof(kv), "path=%s", longpath);
        plen += pax_record(pax_data + plen, (int)sizeof(pax_data) - plen, kv);
    }
    if (longlink) {
        snprintf(kv, sizeof(kv), "linkpath=%s", longlink);
        plen += pax_record(pax_data + plen, (int)sizeof(pax_data) - plen, kv);
    }
    if (plen == 0) return 0;
    memset(&fake, 0, sizeof(fake));
    fake.st_size  = (off_t)plen;
    fake.st_mode  = 0600;
    fake.st_mtime = time(NULL);
    build_ustar_header(&ph, "././@PaxHeader", NULL, &fake,
                       TF_PAX_LOCAL, TARFMT_PAX);
    if (ws_write_block(ws, (char *)&ph) != 0) return -1;
    {
        char block[BLOCK_SIZE];
        int off = 0;
        while (off < plen) {
            int take = plen - off < BLOCK_SIZE ? plen - off : BLOCK_SIZE;
            memset(block, 0, BLOCK_SIZE);
            memcpy(block, pax_data + off, (size_t)take);
            if (ws_write_block(ws, block) != 0) return -1;
            off += take;
        }
    }
    return 0;
}

static int write_gnu_longname(wstream *ws, const char *longpath, char tflag) {
    ustar_header gh;
    struct stat fake;
    size_t plen = strlen(longpath) + 1;
    memset(&fake, 0, sizeof(fake));
    fake.st_size  = (off_t)plen;
    fake.st_mode  = 0600;
    fake.st_mtime = time(NULL);
    build_ustar_header(&gh, "././@LongLink", NULL, &fake,
                       tflag == TF_SYM ? TF_GNU_LONGLINK : TF_GNU_LONGNAME,
                       TARFMT_POSIX);
    memcpy(gh.magic, TMAGIC_GNU, 7);
    write_checksum(&gh);
    if (ws_write_block(ws, (char *)&gh) != 0) return -1;
    {
        char block[BLOCK_SIZE];
        size_t off = 0;
        while (off < plen) {
            size_t take = plen - off < BLOCK_SIZE ? plen - off : BLOCK_SIZE;
            memset(block, 0, BLOCK_SIZE);
            memcpy(block, longpath + off, take);
            if (ws_write_block(ws, block) != 0) return -1;
            off += take;
        }
    }
    return 0;
}

typedef struct hardlink_map {
    struct hardlink_map *next;
    ino_t ino;
    dev_t dev;
    char path[1024];
} hardlink_map;

static hardlink_map *hl_find(hardlink_map *head, ino_t ino, dev_t dev) {
    hardlink_map *e = head;
    while (e) {
        if (e->ino == ino && e->dev == dev) return e;
        e = e->next;
    }
    return NULL;
}

static hardlink_map *hl_add(hardlink_map **head, ino_t ino, dev_t dev,
                             const char *path) {
    hardlink_map *e = (hardlink_map *)malloc(sizeof(hardlink_map));
    if (!e) return NULL;
    e->ino  = ino;
    e->dev  = dev;
    e->next = *head;
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->path[sizeof(e->path) - 1] = '\0';
    *head = e;
    return e;
}

static void hl_free(hardlink_map *head) {
    while (head) {
        hardlink_map *n = head->next;
        free(head);
        head = n;
    }
}

static int do_write_entry(wstream *ws, const char *arcpath,
                           const char *fspath, const struct stat *st,
                           hardlink_map **hlmap, int fmt, int verbose) {
    char typeflag;
    char linkbuf[PATH_MAX];
    const char *linkptr = NULL;
    ustar_header h;
    int need_long_name = (strlen(arcpath) > 99);
    int need_long_link = 0;
    ssize_t llen = 0;
    hardlink_map *existing = NULL;
    if (S_ISREG(st->st_mode)) {
        if (st->st_nlink > 1) {
            existing = hl_find(*hlmap, st->st_ino, st->st_dev);
            if (existing) {
                typeflag = TF_LNKH;
                linkptr  = existing->path;
                need_long_link = (strlen(existing->path) > 99);
            } else {
                hl_add(hlmap, st->st_ino, st->st_dev, arcpath);
                typeflag = TF_REG;
            }
        } else {
            typeflag = TF_REG;
        }
    } else if (S_ISDIR(st->st_mode)) {
        typeflag = TF_DIR;
    } else if (S_ISLNK(st->st_mode)) {
        typeflag = TF_SYM;
        llen = readlink(fspath, linkbuf, sizeof(linkbuf) - 1);
        if (llen < 0) return -1;
        linkbuf[llen] = '\0';
        linkptr = linkbuf;
        need_long_link = (llen > 99);
    } else if (S_ISCHR(st->st_mode)) {
        typeflag = TF_CHR;
    } else if (S_ISBLK(st->st_mode)) {
        typeflag = TF_BLK;
    } else if (S_ISFIFO(st->st_mode)) {
        typeflag = TF_FIFO;
    } else {
        typeflag = TF_REG;
    }
    if (fmt == TARFMT_PAX) {
        if (need_long_name || need_long_link) {
            if (write_pax_ext(ws,
                              need_long_name ? arcpath : NULL,
                              need_long_link ? linkptr : NULL,
                              typeflag) != 0)
                return -1;
        }
    } else if (fmt == TARFMT_POSIX || fmt == TARFMT_AUTO) {
        if (need_long_name) {
            if (write_gnu_longname(ws, arcpath, TF_REG) != 0) return -1;
        }
        if (need_long_link && linkptr) {
            if (write_gnu_longname(ws, linkptr, TF_SYM) != 0) return -1;
        }
    }
    build_ustar_header(&h, arcpath, linkptr, st, typeflag, fmt);
    if (fmt == TARFMT_PAX) {
        memcpy(h.magic, TMAGIC_USTAR, 5);
        h.magic[5] = '\0';
        h.version[0] = '0';
        h.version[1] = '0';
        write_checksum(&h);
    }
    if (verbose) {
        if (typeflag == TF_SYM)
            fprintf(stderr, "%s -> %s\n", arcpath, linkptr ? linkptr : "");
        else if (typeflag == TF_LNKH)
            fprintf(stderr, "%s link to %s\n", arcpath, linkptr ? linkptr : "");
        else
            fprintf(stderr, "%s\n", arcpath);
    }
    if (ws_write_block(ws, (char *)&h) != 0) return -1;
    if (typeflag == TF_REG) {
        int fd;
        char buf[IOBUF_SIZE];
        off_t written = 0;
        fd = open(fspath, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "tar: cannot open %s: %s\n",
                    fspath, strerror(errno));
            return -1;
        }
        while (written < st->st_size) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            {
                off_t off = 0;
                while (off < n) {
                    char block[BLOCK_SIZE];
                    size_t take = (size_t)(n - off) < BLOCK_SIZE
                                  ? (size_t)(n - off) : BLOCK_SIZE;
                    memset(block, 0, BLOCK_SIZE);
                    memcpy(block, buf + off, take);
                    if (ws_write_block(ws, block) != 0) {
                        close(fd); return -1;
                    }
                    off += (off_t)BLOCK_SIZE;
                }
            }
            written += n;
        }
        close(fd);
    }
    return 0;
}

static int collect_and_write(wstream *ws, const char *srcdir,
                              const char *exclude, int fmt, int verbose,
                              hardlink_map **hlmap,
                              char *path_buf, size_t path_len,
                              const char *arc_prefix) {
    DIR *d;
    struct dirent *de;
    struct stat st;
    char fspath[PATH_MAX];
    char arcpath[PATH_MAX];
    d = opendir(srcdir);
    if (!d) return -1;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        snprintf(fspath, sizeof(fspath), "%s/%s", srcdir, de->d_name);
        if (arc_prefix && arc_prefix[0])
            snprintf(arcpath, sizeof(arcpath), "%s/%s", arc_prefix, de->d_name);
        else
            snprintf(arcpath, sizeof(arcpath), "%s", de->d_name);
        if (exclude) {
            const char *bn = de->d_name;
            if (strcmp(bn, exclude) == 0) continue;
            {
                size_t elen = strlen(exclude);
                if (elen > 2 && exclude[0] == '.' && exclude[1] == '/') {
                    const char *exc_rest = exclude + 2;
                    if (strcmp(arcpath, exc_rest) == 0) continue;
                }
                if (strcmp(arcpath, exclude) == 0) continue;
                if (exclude[0] == '.' && exclude[1] == '/' &&
                    strcmp(arcpath, exclude + 2) == 0) continue;
            }
        }
        if (lstat(fspath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            char dir_arcpath[PATH_MAX + 2];
            size_t aplen = strlen(arcpath);
            if (aplen < sizeof(dir_arcpath) - 2) {
                memcpy(dir_arcpath, arcpath, aplen);
                dir_arcpath[aplen]   = '/';
                dir_arcpath[aplen+1] = '\0';
            } else {
                memcpy(dir_arcpath, arcpath, sizeof(dir_arcpath) - 2);
                dir_arcpath[sizeof(dir_arcpath) - 2] = '/';
                dir_arcpath[sizeof(dir_arcpath) - 1] = '\0';
            }
            if (do_write_entry(ws, dir_arcpath, fspath, &st,
                               hlmap, fmt, verbose) != 0) {
                closedir(d);
                return -1;
            }
            if (collect_and_write(ws, fspath, exclude, fmt, verbose,
                                  hlmap, path_buf, path_len,
                                  arcpath) != 0) {
                closedir(d);
                return -1;
            }
        } else {
            if (do_write_entry(ws, arcpath, fspath, &st,
                               hlmap, fmt, verbose) != 0) {
                closedir(d);
                return -1;
            }
        }
    }
    closedir(d);
    return 0;
}

int tar_create(const char *archive, const char *srcdir,
               const char *exclude, int fmt, int verbose) {
    wstream ws;
    hardlink_map *hlmap = NULL;
    char end[BLOCK_SIZE * 2];
    char path_buf[PATH_MAX];
    int actual_fmt = fmt;
    if (actual_fmt == TARFMT_AUTO) actual_fmt = TARFMT_PAX;
    if (ws_open(&ws, archive) != 0) {
        fprintf(stderr, "tar: cannot create '%s': %s\n",
                archive, strerror(errno));
        return -1;
    }
    if (collect_and_write(&ws, srcdir, exclude, actual_fmt, verbose,
                          &hlmap, path_buf, sizeof(path_buf), NULL) != 0) {
        ws_close(&ws);
        hl_free(hlmap);
        return -1;
    }
    hl_free(hlmap);
    memset(end, 0, sizeof(end));
    {
        int n;
        for (n = 0; n < 2 * RECORDS_PER_BLK; n++)
            ws_write_block(&ws, end);
    }
    if (ws_close(&ws) != 0) return -1;
    return 0;
}

static int mkdir_p(const char *path, mode_t mode) {
    char buf[PATH_MAX];
    char *p;
    struct stat st;
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    p = buf + 1;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            if (stat(buf, &st) != 0)
                if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
        p++;
    }
    if (stat(buf, &st) != 0)
        if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

typedef struct {
    char  path[PATH_MAX];
    char  linkname[PATH_MAX];
    char  uname[32];
    char  gname[32];
    off_t size;
    mode_t mode;
    time_t mtime;
    uid_t uid;
    gid_t gid;
    char typeflag;
    int   has_pax_path;
    int   has_pax_link;
} entry_meta;

static void parse_pax_data(const char *data, size_t len,
                            char *path_out, size_t path_sz,
                            char *link_out, size_t link_sz) {
    size_t pos = 0;
    while (pos < len) {
        size_t rec_len = 0;
        const char *p = data + pos;
        size_t rem = len - pos;
        size_t i;
        for (i = 0; i < rem && p[i] != ' '; i++)
            rec_len = rec_len * 10 + (size_t)(p[i] - '0');
        if (rec_len == 0 || rec_len > rem) break;
        i++;
        {
            const char *kv = p + i;
            size_t kv_len = rec_len - i - 1;
            const char *eq = NULL;
            size_t ki;
            for (ki = 0; ki < kv_len; ki++) {
                if (kv[ki] == '=') { eq = kv + ki; break; }
            }
            if (eq) {
                const char *key = kv;
                size_t klen = (size_t)(eq - kv);
                const char *val = eq + 1;
                size_t vlen = kv_len - klen - 1;
                if (klen == 4 && strncmp(key, "path", 4) == 0 && path_out) {
                    size_t cp = vlen < path_sz - 1 ? vlen : path_sz - 1;
                    memcpy(path_out, val, cp);
                    path_out[cp] = '\0';
                }
                if (klen == 8 && strncmp(key, "linkpath", 8) == 0 && link_out) {
                    size_t cp = vlen < link_sz - 1 ? vlen : link_sz - 1;
                    memcpy(link_out, val, cp);
                    link_out[cp] = '\0';
                }
            }
        }
        pos += rec_len;
    }
}

static int detect_format(const ustar_header *h) {
    if (h->typeflag == TF_GNU_LONGNAME || h->typeflag == TF_GNU_LONGLINK)
        return TARFMT_POSIX;
    if (h->typeflag == TF_PAX_GLOBAL || h->typeflag == TF_PAX_LOCAL)
        return TARFMT_PAX;
    if (strncmp(h->magic, TMAGIC_USTAR, 5) == 0) {
        if (h->version[0] == '0' && h->version[1] == '0')
            return TARFMT_USTAR;
        return TARFMT_USTAR;
    }
    if (strncmp(h->magic, TMAGIC_GNU, 6) == 0)
        return TARFMT_POSIX;
    return TARFMT_V7;
}

static int extract_entry(const entry_meta *m, const char *destdir,
                          rstream *rs, int verbose) {
    char fullpath[PATH_MAX * 2];
    size_t blocks, i;
    struct stat dst_st;
    if (m->path[0] == '/' || strstr(m->path, "..")) {
        off_t skip_blocks = (m->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
        char block[BLOCK_SIZE];
        for (i = 0; i < (size_t)skip_blocks; i++)
            rs_read_block(rs, block);
        return 0;
    }
    if (m->path[0] == '\0') return 0;
    snprintf(fullpath, sizeof(fullpath), "%s/%s", destdir, m->path);
    {
        size_t flen = strlen(fullpath);
        if (flen > 0 && fullpath[flen - 1] == '/')
            fullpath[flen - 1] = '\0';
    }
    if (verbose)
        fprintf(stderr, "%s\n", m->path);
    if (m->typeflag == TF_DIR) {
        if (mkdir_p(fullpath, m->mode & 0777) != 0 && errno != EEXIST) {
            fprintf(stderr, "tar: mkdir '%s': %s\n", fullpath, strerror(errno));
        }
        return 0;
    }
    {
        char parent[PATH_MAX];
        strncpy(parent, fullpath, sizeof(parent) - 1);
        parent[sizeof(parent) - 1] = '\0';
        {
            char *sl = strrchr(parent, '/');
            if (sl && sl != parent) {
                *sl = '\0';
                mkdir_p(parent, 0755);
            }
        }
    }
    if (m->typeflag == TF_SYM) {
        unlink(fullpath);
        if (symlink(m->linkname, fullpath) != 0)
            fprintf(stderr, "tar: symlink '%s' -> '%s': %s\n",
                    fullpath, m->linkname, strerror(errno));
        return 0;
    }
    if (m->typeflag == TF_LNKH) {
        char linksrc[PATH_MAX * 2];
        unlink(fullpath);
        snprintf(linksrc, sizeof(linksrc), "%s/%s", destdir, m->linkname);
        if (link(linksrc, fullpath) != 0) {
            fprintf(stderr, "tar: hard link '%s' -> '%s': %s\n",
                    fullpath, linksrc, strerror(errno));
        }
        return 0;
    }
    if (m->typeflag == TF_CHR || m->typeflag == TF_BLK ||
        m->typeflag == TF_FIFO) {
        blocks = (size_t)((m->size + BLOCK_SIZE - 1) / BLOCK_SIZE);
        {
            char block[BLOCK_SIZE];
            for (i = 0; i < blocks; i++) rs_read_block(rs, block);
        }
        return 0;
    }
    {
        int fd;
        off_t written = 0;
        char block[BLOCK_SIZE];
        int already_exists = (lstat(fullpath, &dst_st) == 0);
        (void)already_exists;
        fd = open(fullpath, O_WRONLY | O_CREAT | O_TRUNC, m->mode & 0777);
        if (fd < 0) {
            fprintf(stderr, "tar: cannot create '%s': %s\n",
                    fullpath, strerror(errno));
            blocks = (size_t)((m->size + BLOCK_SIZE - 1) / BLOCK_SIZE);
            for (i = 0; i < blocks; i++) rs_read_block(rs, block);
            return -1;
        }
        blocks = (size_t)((m->size + BLOCK_SIZE - 1) / BLOCK_SIZE);
        for (i = 0; i < blocks; i++) {
            size_t take;
            if (rs_read_block(rs, block) != 0) { close(fd); return -1; }
            take = (size_t)(m->size - written);
            if (take > BLOCK_SIZE) take = BLOCK_SIZE;
            if (write(fd, block, take) != (ssize_t)take) {
                close(fd);
                return -1;
            }
            written += (off_t)take;
        }
        close(fd);
        if (m->mode & 07000)
            chmod(fullpath, m->mode & 07777);
    }
    {
        struct utimbuf ut;
        ut.actime  = m->mtime;
        ut.modtime = m->mtime;
        utime(fullpath, &ut);
    }
    return 0;
}

static void list_entry(const entry_meta *m, int verbose) {
    if (!verbose) {
        printf("%s\n", m->path);
        return;
    }
    {
        char typechar;
        char modestr[11];
        struct tm *tm;
        char timebuf[32];
        time_t mt = m->mtime;
        switch (m->typeflag) {
            case TF_DIR:  typechar = 'd'; break;
            case TF_SYM:  typechar = 'l'; break;
            case TF_LNKH: typechar = 'h'; break;
            case TF_CHR:  typechar = 'c'; break;
            case TF_BLK:  typechar = 'b'; break;
            case TF_FIFO: typechar = 'p'; break;
            default:      typechar = '-'; break;
        }
        snprintf(modestr, sizeof(modestr), "%c%c%c%c%c%c%c%c%c%c",
                 typechar,
                 (m->mode & 0400) ? 'r' : '-',
                 (m->mode & 0200) ? 'w' : '-',
                 (m->mode & 0100) ? 'x' : '-',
                 (m->mode & 0040) ? 'r' : '-',
                 (m->mode & 0020) ? 'w' : '-',
                 (m->mode & 0010) ? 'x' : '-',
                 (m->mode & 0004) ? 'r' : '-',
                 (m->mode & 0002) ? 'w' : '-',
                 (m->mode & 0001) ? 'x' : '-');
        tm = gmtime(&mt);
        if (tm)
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", tm);
        else
            strncpy(timebuf, "0000-00-00 00:00", sizeof(timebuf) - 1);
        if (m->typeflag == TF_SYM)
            printf("%s %s/%s %8lld %s %s -> %s\n",
                   modestr,
                   m->uname[0] ? m->uname : "root",
                   m->gname[0] ? m->gname : "root",
                   (long long)m->size, timebuf, m->path, m->linkname);
        else
            printf("%s %s/%s %8lld %s %s\n",
                   modestr,
                   m->uname[0] ? m->uname : "root",
                   m->gname[0] ? m->gname : "root",
                   (long long)m->size, timebuf, m->path);
    }
}

static int tar_read_archive(const char *archive, int fmt_hint,
                             const char *destdir, int verbose,
                             int do_extract, char *outfile) {
    rstream rs;
    char block[BLOCK_SIZE];
    entry_meta cur;
    char gnu_longname[PATH_MAX];
    char gnu_longlink[PATH_MAX];
    int gnu_longname_set = 0;
    int gnu_longlink_set = 0;
    int zero_count = 0;
    int detected_fmt = TARFMT_AUTO;
    FILE *listfp = NULL;
    int is_first = 1;
    (void)fmt_hint;
    gnu_longname[0] = '\0';
    gnu_longlink[0] = '\0';
    if (rs_open(&rs, archive) != 0) {
        fprintf(stderr, "tar: cannot open '%s': %s\n",
                archive, strerror(errno));
        return -1;
    }
    if (outfile) {
        listfp = fopen(outfile, "w");
        if (!listfp) { rs_close(&rs); return -1; }
    }
    while (1) {
        ustar_header *h = (ustar_header *)block;
        if (rs_read_block(&rs, block) != 0) break;
        if (is_zero_block(block)) {
            zero_count++;
            if (zero_count >= 2) break;
            continue;
        }
        zero_count = 0;
        if (check_checksum(h) != 0) {
            fprintf(stderr, "tar: invalid checksum, skipping block\n");
            continue;
        }
        if (is_first) {
            detected_fmt = detect_format(h);
            is_first = 0;
        }
        if (h->typeflag == TF_GNU_LONGNAME) {
            off_t sz = (off_t)get_octal(h->size, sizeof(h->size));
            size_t blocks2 = (size_t)((sz + BLOCK_SIZE - 1) / BLOCK_SIZE);
            size_t i, off2 = 0;
            gnu_longname[0] = '\0';
            for (i = 0; i < blocks2; i++) {
                char b2[BLOCK_SIZE];
                if (rs_read_block(&rs, b2) != 0) break;
                size_t take = (size_t)(sz - (off_t)off2);
                if (take > BLOCK_SIZE) take = BLOCK_SIZE;
                if (off2 + take < sizeof(gnu_longname)) {
                    memcpy(gnu_longname + off2, b2, take);
                    gnu_longname[off2 + take] = '\0';
                }
                off2 += BLOCK_SIZE;
            }
            gnu_longname_set = 1;
            continue;
        }
        if (h->typeflag == TF_GNU_LONGLINK) {
            off_t sz = (off_t)get_octal(h->size, sizeof(h->size));
            size_t blocks2 = (size_t)((sz + BLOCK_SIZE - 1) / BLOCK_SIZE);
            size_t i, off2 = 0;
            gnu_longlink[0] = '\0';
            for (i = 0; i < blocks2; i++) {
                char b2[BLOCK_SIZE];
                if (rs_read_block(&rs, b2) != 0) break;
                size_t take = (size_t)(sz - (off_t)off2);
                if (take > BLOCK_SIZE) take = BLOCK_SIZE;
                if (off2 + take < sizeof(gnu_longlink)) {
                    memcpy(gnu_longlink + off2, b2, take);
                    gnu_longlink[off2 + take] = '\0';
                }
                off2 += BLOCK_SIZE;
            }
            gnu_longlink_set = 1;
            continue;
        }
        if (h->typeflag == TF_PAX_LOCAL || h->typeflag == TF_PAX_GLOBAL) {
            off_t sz = (off_t)get_octal(h->size, sizeof(h->size));
            size_t blocks2 = (size_t)((sz + BLOCK_SIZE - 1) / BLOCK_SIZE);
            char *pax_buf = NULL;
            size_t i, off2 = 0;
            pax_buf = (char *)malloc((size_t)sz + 1);
            if (pax_buf) {
                for (i = 0; i < blocks2; i++) {
                    char b2[BLOCK_SIZE];
                    if (rs_read_block(&rs, b2) != 0) break;
                    size_t take = (size_t)(sz - (off_t)off2);
                    if (take > BLOCK_SIZE) take = BLOCK_SIZE;
                    memcpy(pax_buf + off2, b2, take);
                    off2 += BLOCK_SIZE;
                }
                pax_buf[sz] = '\0';
                parse_pax_data(pax_buf, (size_t)sz,
                               gnu_longname, sizeof(gnu_longname),
                               gnu_longlink, sizeof(gnu_longlink));
                if (gnu_longname[0]) gnu_longname_set = 1;
                if (gnu_longlink[0]) gnu_longlink_set = 1;
                free(pax_buf);
            } else {
                char b2[BLOCK_SIZE];
                for (i = 0; i < blocks2; i++) rs_read_block(&rs, b2);
            }
            continue;
        }
        memset(&cur, 0, sizeof(cur));
        if (gnu_longname_set) {
            strncpy(cur.path, gnu_longname, sizeof(cur.path) - 1);
            gnu_longname_set = 0;
        } else {
            if (h->prefix[0]) {
                snprintf(cur.path, sizeof(cur.path), "%s/%s",
                         h->prefix, h->name);
            } else {
                strncpy(cur.path, h->name, sizeof(cur.path) - 1);
            }
        }
        if (gnu_longlink_set) {
            strncpy(cur.linkname, gnu_longlink, sizeof(cur.linkname) - 1);
            gnu_longlink_set = 0;
        } else {
            strncpy(cur.linkname, h->linkname, sizeof(cur.linkname) - 1);
        }
        cur.size    = (off_t)get_octal(h->size,  sizeof(h->size));
        cur.mode    = (mode_t)get_octal(h->mode,  sizeof(h->mode));
        cur.uid     = (uid_t)get_octal(h->uid,   sizeof(h->uid));
        cur.gid     = (gid_t)get_octal(h->gid,   sizeof(h->gid));
        cur.mtime   = (time_t)get_octal(h->mtime, sizeof(h->mtime));
        cur.typeflag= h->typeflag;
        strncpy(cur.uname, h->uname, sizeof(cur.uname) - 1);
        strncpy(cur.gname, h->gname, sizeof(cur.gname) - 1);
        if (cur.typeflag == '\0' || cur.typeflag == TF_REG ||
            cur.typeflag == TF_CONT)
            cur.typeflag = TF_REG;
        if (outfile && listfp) {
            {
                size_t plen = strlen(cur.path);
                if (plen > 0 && cur.path[plen - 1] == '/') {
                    cur.path[plen - 1] = '\0';
                    plen--;
                }
            }
            if (cur.path[0])
                fprintf(listfp, "%s\n", cur.path);
            {
                off_t skip = (cur.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
                size_t i;
                char b2[BLOCK_SIZE];
                for (i = 0; i < (size_t)skip; i++) rs_read_block(&rs, b2);
            }
        } else if (do_extract && destdir) {
            if (extract_entry(&cur, destdir, &rs, verbose) != 0) {
                if (listfp) fclose(listfp);
                rs_close(&rs);
                return -1;
            }
        } else {
            list_entry(&cur, verbose);
            {
                off_t skip = (cur.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
                size_t i;
                char b2[BLOCK_SIZE];
                for (i = 0; i < (size_t)skip; i++) rs_read_block(&rs, b2);
            }
        }
    }
    if (listfp) fclose(listfp);
    rs_close(&rs);
    (void)detected_fmt;
    return 0;
}

int tar_extract(const char *archive, const char *destdir,
                int fmt, int verbose) {
    return tar_read_archive(archive, fmt, destdir, verbose, 1, NULL);
}

int tar_list(const char *archive, int fmt, int verbose, char *outfile) {
    return tar_read_archive(archive, fmt, NULL, verbose, 0, outfile);
}
