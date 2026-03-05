#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <fnmatch.h>
#include <errno.h>
#include <dirent.h>
#include "db.h"
#include "ctrl.h"

#define BLOCK_MAX 16384

static char g_root[4096]    = "";
static char g_admindir[4096] = "";

static const char *admindir(void) {
    static char buf[8192];
    if (g_admindir[0])
        return g_admindir;
    if (g_root[0]) {
        snprintf(buf, sizeof(buf), "%s/var/lib/udpkg", g_root);
        return buf;
    }
    return "/var/lib/udpkg";
}

static void apath(char *buf, size_t sz, const char *suffix) {
    snprintf(buf, sz, "%s%s", admindir(), suffix);
}

void db_set_root(const char *root) {
    size_t len;
    if (!root || root[0] == '\0' || strcmp(root, "/") == 0) {
        g_root[0] = '\0';
        return;
    }
    strncpy(g_root, root, sizeof(g_root) - 1);
    g_root[sizeof(g_root) - 1] = '\0';
    len = strlen(g_root);
    while (len > 0 && g_root[len - 1] == '/')
        g_root[--len] = '\0';
}

void db_set_admindir(const char *dir) {
    size_t len;
    if (!dir || dir[0] == '\0') {
        g_admindir[0] = '\0';
        return;
    }
    strncpy(g_admindir, dir, sizeof(g_admindir) - 1);
    g_admindir[sizeof(g_admindir) - 1] = '\0';
    len = strlen(g_admindir);
    while (len > 1 && g_admindir[len - 1] == '/')
        g_admindir[--len] = '\0';
}

const char *db_tmpci(void) {
    static char buf[4096];
    apath(buf, sizeof(buf), "/tmp.ci");
    return buf;
}

const char *db_tmpci_ctrl(void) {
    static char buf[4096];
    apath(buf, sizeof(buf), "/tmp.ci/ctrl");
    return buf;
}

static int mkdirp(const char *path, mode_t mode) {
    char buf[4096];
    char *p;
    size_t len;
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    len = strlen(buf);
    while (len > 0 && buf[len - 1] == '/')
        buf[--len] = '\0';
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

typedef struct block_node {
    char               name[256];
    char               text[BLOCK_MAX];
    struct block_node *next;
} block_node_t;

static void extract_name(block_node_t *node) {
    const char *p = node->text;
    while (*p) {
        if (strncasecmp(p, "package:", 8) == 0) {
            const char *v = p + 8;
            const char *e;
            size_t nlen;
            while (*v == ' ')
                v++;
            e = v;
            while (*e && *e != '\n')
                e++;
            nlen = (size_t)(e - v);
            if (nlen >= sizeof(node->name))
                nlen = sizeof(node->name) - 1;
            memcpy(node->name, v, nlen);
            node->name[nlen] = '\0';
            return;
        }
        while (*p && *p != '\n')
            p++;
        if (*p)
            p++;
    }
}

static block_node_t *status_read(void) {
    char path[4096];
    FILE *fp;
    char line[4096];
    char buf[BLOCK_MAX];
    size_t blen = 0;
    block_node_t *head = NULL;
    block_node_t **tail = &head;
    apath(path, sizeof(path), "/status");
    fp = fopen(path, "r");
    if (!fp)
        return NULL;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '\n' || (line[0] == '\r' && line[1] == '\n')) {
            if (blen > 0) {
                block_node_t *node = calloc(1, sizeof(*node));
                if (!node)
                    break;
                while (blen > 0 && (buf[blen-1] == '\n' || buf[blen-1] == '\r'))
                    blen--;
                if (blen >= sizeof(node->text))
                    blen = sizeof(node->text) - 1;
                memcpy(node->text, buf, blen);
                node->text[blen] = '\0';
                extract_name(node);
                *tail = node;
                tail = &node->next;
                blen = 0;
            }
        } else {
            size_t llen = strlen(line);
            if (blen + llen < sizeof(buf) - 1) {
                memcpy(buf + blen, line, llen);
                blen += llen;
            }
        }
    }
    if (blen > 0) {
        block_node_t *node = calloc(1, sizeof(*node));
        if (node) {
            while (blen > 0 && (buf[blen-1] == '\n' || buf[blen-1] == '\r'))
                blen--;
            if (blen >= sizeof(node->text))
                blen = sizeof(node->text) - 1;
            memcpy(node->text, buf, blen);
            node->text[blen] = '\0';
            extract_name(node);
            *tail = node;
        }
    }
    fclose(fp);
    return head;
}

static void status_free(block_node_t *head) {
    block_node_t *n;
    while (head) {
        n = head->next;
        free(head);
        head = n;
    }
}

static int status_write(block_node_t *head) {
    char path[4096];
    char tmp[8192];
    FILE *fp;
    block_node_t *n;
    apath(path, sizeof(path), "/status");
    snprintf(tmp, sizeof(tmp)-4, "%s", path);
    strcat(tmp, ".tmp");
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    for (n = head; n; n = n->next)
        fprintf(fp, "%s\n\n", n->text);
    fclose(fp);
    return rename(tmp, path);
}

int db_init(void) {
    char db_dir[4096];
    char info_dir[4096];
    char status_f[4096];
    struct stat st;
    int fd;
    snprintf(db_dir,   sizeof(db_dir),   "%s", admindir());
    apath(info_dir, sizeof(info_dir), "/info");
    apath(status_f, sizeof(status_f), "/status");
    if (mkdirp(db_dir, 0755) != 0)
        return -1;
    if (mkdirp(info_dir, 0755) != 0)
        return -1;
    if (stat(status_f, &st) != 0) {
        fd = open(status_f, O_WRONLY | O_CREAT, 0644);
        if (fd < 0)
            return -1;
        close(fd);
    }
    return 0;
}

int db_install(const ctrl_t *c, const char *listfile) {
    char entry[BLOCK_MAX];
    char info_dir[4096];
    size_t elen = 0;
    int i;
    const char *name;
    block_node_t *list;
    block_node_t *node;
    char dst[8192];
    char buf[8192];
    size_t nr;
    FILE *src_fp, *dst_fp;
    apath(info_dir, sizeof(info_dir), "/info");
    name = ctrl_get(c, "Package");
    if (!name)
        return -1;
    db_remove(name);
    elen += (size_t)snprintf(entry + elen, sizeof(entry) - elen,
        "Package: %s\n", name);
    elen += (size_t)snprintf(entry + elen, sizeof(entry) - elen,
        "Status: install ok installed\n");
    for (i = 0; i < c->nfields; i++) {
        if (strcasecmp(c->fields[i].key, "Package") == 0)
            continue;
        elen += (size_t)snprintf(entry + elen, sizeof(entry) - elen,
            "%s: %s\n", c->fields[i].key, c->fields[i].val);
        if (elen >= sizeof(entry) - 2)
            break;
    }
    while (elen > 0 && entry[elen-1] == '\n')
        elen--;
    entry[elen] = '\0';
    list = status_read();
    node = calloc(1, sizeof(*node));
    if (!node) {
        status_free(list);
        return -1;
    }
    strncpy(node->name, name, sizeof(node->name) - 1);
    strncpy(node->text, entry, sizeof(node->text) - 1);
    node->next = list;
    if (status_write(node) != 0) {
        node->next = NULL;
        free(node);
        status_free(list);
        return -1;
    }
    node->next = NULL;
    free(node);
    status_free(list);
    if (listfile) {
        snprintf(dst, sizeof(dst), "%s/%s.list", info_dir, name);
        src_fp = fopen(listfile, "r");
        if (!src_fp)
            return 0;
        dst_fp = fopen(dst, "w");
        if (!dst_fp) {
            fclose(src_fp);
            return -1;
        }
        while ((nr = fread(buf, 1, sizeof(buf), src_fp)) > 0)
            fwrite(buf, 1, nr, dst_fp);
        fclose(src_fp);
        fclose(dst_fp);
    }
    return 0;
}

int db_remove(const char *name) {
    char info_dir[4096];
    block_node_t *list = status_read();
    block_node_t *prev = NULL, *cur = list, *next;
    char path[8192];
    int found = 0;
    apath(info_dir, sizeof(info_dir), "/info");
    while (cur) {
        next = cur->next;
        if (strcmp(cur->name, name) == 0) {
            if (prev)
                prev->next = next;
            else
                list = next;
            free(cur);
            found = 1;
        } else {
            prev = cur;
        }
        cur = next;
    }
    if (found)
        status_write(list);
    status_free(list);
    snprintf(path, sizeof(path), "%s/%s.list", info_dir, name);
    unlink(path);
    return found ? 0 : -1;
}

int db_is_installed(const char *name) {
    block_node_t *list = status_read();
    block_node_t *n;
    int found = 0;
    for (n = list; n; n = n->next) {
        if (strcmp(n->name, name) == 0) {
            found = 1;
            break;
        }
    }
    status_free(list);
    return found;
}

int db_get(const char *name, ctrl_t *c) {
    block_node_t *list = status_read();
    block_node_t *n;
    int ret = -1;
    for (n = list; n; n = n->next) {
        if (strcmp(n->name, name) == 0) {
            ret = ctrl_parse_str(n->text, c);
            break;
        }
    }
    status_free(list);
    return ret;
}

int db_get_version(const char *name, char *buf, size_t bufsz) {
    ctrl_t c;
    const char *ver;
    if (db_get(name, &c) != 0)
        return -1;
    ver = ctrl_get(&c, "Version");
    if (!ver)
        return -1;
    strncpy(buf, ver, bufsz - 1);
    buf[bufsz - 1] = '\0';
    return 0;
}

int db_list(const char *pattern) {
    block_node_t *list = status_read();
    block_node_t *n;
    ctrl_t c;
    const char *ver, *arch, *desc;
    char descbuf[80];
    int any = 0;
    for (n = list; n; n = n->next) {
        if (pattern && fnmatch(pattern, n->name, 0) != 0)
            continue;
        any = 1;
        break;
    }
    if (any || !pattern) {
        printf("Desired=Unknown/Install/Remove/Purge/Hold\n");
        printf("| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/"
               "trig-aWait/Trig-pend\n");
        printf("|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n");
        printf("||/ %-28s %-20s %-12s %s\n",
            "Name", "Version", "Architecture", "Description");
        printf("+++-%-28s-%-20s-%-12s-%s\n",
            "============================",
            "====================",
            "============",
            "================================");
    }
    for (n = list; n; n = n->next) {
        if (pattern && fnmatch(pattern, n->name, 0) != 0)
            continue;
        if (ctrl_parse_str(n->text, &c) != 0)
            continue;
        ver  = ctrl_get(&c, "Version");
        arch = ctrl_get(&c, "Architecture");
        desc = ctrl_get(&c, "Description");
        descbuf[0] = '\0';
        if (desc) {
            strncpy(descbuf, desc, sizeof(descbuf) - 1);
            descbuf[sizeof(descbuf) - 1] = '\0';
            {
                char *nl = strchr(descbuf, '\n');
                if (nl)
                    *nl = '\0';
            }
        }
        printf("ii  %-28s %-20s %-12s %s\n",
            n->name,
            ver  ? ver  : "(unknown)",
            arch ? arch : "?",
            descbuf);
    }
    status_free(list);
    return 0;
}

int db_list_files(const char *name) {
    char path[8192];
    char line[4096];
    FILE *fp;
    {
        char info_dir[4096];
        apath(info_dir, sizeof(info_dir), "/info");
        snprintf(path, sizeof(path), "%s/%s.list", info_dir, name);
    }
    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "udpkg: %s: package not installed or no file list\n",
                name);
        return -1;
    }
    while (fgets(line, sizeof(line), fp))
        fputs(line, stdout);
    fclose(fp);
    return 0;
}

int db_get_listpath(const char *name, char *buf, size_t bufsz) {
    char info_dir[4096];
    apath(info_dir, sizeof(info_dir), "/info");
    snprintf(buf, bufsz, "%s/%s.list", info_dir, name);
    return 0;
}

int db_get_scriptpath(const char *name, const char *script,
                      char *buf, size_t bufsz) {
    char info_dir[4096];
    apath(info_dir, sizeof(info_dir), "/info");
    if (bufsz > 8192) bufsz = 8192;
    snprintf(buf, bufsz, "%s/%s.%s", info_dir, name, script);
    return 0;
}

int db_install_script(const char *name, const char *script,
                      const char *srcpath) {
    char info_dir[4096];
    char dst[8192];
    char buf[8192];
    size_t nr;
    FILE *src_fp, *dst_fp;
    apath(info_dir, sizeof(info_dir), "/info");
    snprintf(dst, sizeof(dst), "%s/%s.%s", info_dir, name, script);
    src_fp = fopen(srcpath, "r");
    if (!src_fp)
        return -1;
    dst_fp = fopen(dst, "w");
    if (!dst_fp) {
        fclose(src_fp);
        return -1;
    }
    while ((nr = fread(buf, 1, sizeof(buf), src_fp)) > 0)
        fwrite(buf, 1, nr, dst_fp);
    fclose(src_fp);
    fclose(dst_fp);
    chmod(dst, 0755);
    return 0;
}

int db_remove_scripts(const char *name) {
    char info_dir[4096];
    char path[8192];
    static const char * const scripts[] =
        { "preinst", "postinst", "prerm", "postrm", NULL };
    int i;
    apath(info_dir, sizeof(info_dir), "/info");
    for (i = 0; scripts[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s.%s", info_dir, name, scripts[i]);
        unlink(path);
    }
    return 0;
}
int db_find_file_owner(const char *filepath, const char *exclude_pkg,
                       char *owner, size_t ownersz) {
    char info_dir[4096];
    DIR *d;
    struct dirent *de;
    apath(info_dir, sizeof(info_dir), "/info");
    d = opendir(info_dir);
    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL) {
        char *dot;
        char pkgname[256];
        char listpath[8192];
        FILE *fp;
        char line[4096];
        size_t nlen;
        if (de->d_name[0] == '.')
            continue;
        dot = strrchr(de->d_name, '.');
        if (!dot || strcmp(dot, ".list") != 0)
            continue;
        nlen = (size_t)(dot - de->d_name);
        if (nlen >= sizeof(pkgname))
            nlen = sizeof(pkgname) - 1;
        memcpy(pkgname, de->d_name, nlen);
        pkgname[nlen] = '\0';
        if (exclude_pkg && strcmp(pkgname, exclude_pkg) == 0)
            continue;
        snprintf(listpath, sizeof(listpath), "%s/%s", info_dir, de->d_name);
        fp = fopen(listpath, "r");
        if (!fp)
            continue;
        while (fgets(line, sizeof(line), fp)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
            if (len == 0)
                continue;
            if (strcmp(line, filepath) == 0) {
                fclose(fp);
                closedir(d);
                strncpy(owner, pkgname, ownersz - 1);
                owner[ownersz - 1] = '\0';
                return 0;
            }
        }
        fclose(fp);
    }
    closedir(d);
    return -1;
}
