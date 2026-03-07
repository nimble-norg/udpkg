#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ar.h"

#define AR_MAGIC "!<arch>\n"

int ar_open(const char *path) {
    char magic[8];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (read(fd, magic, 8) != 8 || memcmp(magic, AR_MAGIC, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ar_next(int fd, ar_entry_t *entry) {
    char hdr[60];
    char szbuf[11];
    int i;
    ssize_t n;
    if (entry->next_offset > 0) {
        if (lseek(fd, entry->next_offset, SEEK_SET) < 0)
            return -1;
    }
    n = read(fd, hdr, 60);
    if (n == 0)
        return 0;
    if (n < 60)
        return -1;
    if ((unsigned char)hdr[58] != '`' || (unsigned char)hdr[59] != '\n')
        return -1;
    memcpy(entry->name, hdr, 16);
    entry->name[16] = '\0';
    for (i = 15; i >= 0 && entry->name[i] == ' '; i--)
        entry->name[i] = '\0';
    if (entry->name[0] && entry->name[strlen(entry->name) - 1] == '/')
        entry->name[strlen(entry->name) - 1] = '\0';
    memcpy(szbuf, hdr + 48, 10);
    szbuf[10] = '\0';
    entry->size = (size_t)strtoul(szbuf, NULL, 10);
    entry->data_offset = lseek(fd, 0, SEEK_CUR);
    if (entry->data_offset < 0)
        return -1;
    entry->next_offset = entry->data_offset + (off_t)entry->size;
    if (entry->size % 2 != 0)
        entry->next_offset++;
    return 1;
}

int ar_extract(int fd, const ar_entry_t *entry, const char *destpath) {
    char buf[8192];
    size_t remaining;
    ssize_t n;
    int outfd;
    if (lseek(fd, entry->data_offset, SEEK_SET) < 0)
        return -1;
    outfd = open(destpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outfd < 0)
        return -1;
    remaining = entry->size;
    while (remaining > 0) {
        size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        n = read(fd, buf, want);
        if (n <= 0) {
            close(outfd);
            return -1;
        }
        if ((size_t)write(outfd, buf, (size_t)n) != (size_t)n) {
            close(outfd);
            return -1;
        }
        remaining -= (size_t)n;
    }
    close(outfd);
    return 0;
}

static void ar_fmt_field(char *dst, size_t dstsz, const char *val) {
    size_t vlen = strlen(val);
    size_t i;
    if (vlen > dstsz)
        vlen = dstsz;
    for (i = 0; i < vlen; i++)
        dst[i] = val[i];
    for (; i < dstsz; i++)
        dst[i] = ' ';
}

static int ar_write_hdr(int fd, const char *membername,
                        size_t datasz, time_t mtime,
                        unsigned uid, unsigned gid, unsigned mode) {
    char hdr[60];
    char tmp[32];
    memset(hdr, ' ', sizeof(hdr));
    ar_fmt_field(hdr,      16, membername);
    snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)mtime);
    ar_fmt_field(hdr + 16, 12, tmp);
    snprintf(tmp, sizeof(tmp), "%u",  uid);
    ar_fmt_field(hdr + 28, 6,  tmp);
    snprintf(tmp, sizeof(tmp), "%u",  gid);
    ar_fmt_field(hdr + 34, 6,  tmp);
    snprintf(tmp, sizeof(tmp), "%o",  mode & 07777u);
    ar_fmt_field(hdr + 40, 8,  tmp);
    snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)datasz);
    ar_fmt_field(hdr + 48, 10, tmp);
    hdr[58] = '`';
    hdr[59] = '\n';
    return write(fd, hdr, 60) == 60 ? 0 : -1;
}

int ar_create(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, AR_MAGIC, 8) != 8) {
        close(fd);
        return -1;
    }
    return fd;
}

int ar_append_file(int fd, const char *membername, const char *srcpath) {
    struct stat st;
    char buf[8192];
    ssize_t n;
    int in;
    size_t remaining;
    if (stat(srcpath, &st) != 0)
        return -1;
    if (ar_write_hdr(fd, membername, (size_t)st.st_size,
                     st.st_mtime, (unsigned)st.st_uid,
                     (unsigned)st.st_gid,
                     (unsigned)st.st_mode) != 0)
        return -1;
    in = open(srcpath, O_RDONLY);
    if (in < 0)
        return -1;
    remaining = (size_t)st.st_size;
    while (remaining > 0) {
        size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        n = read(in, buf, want);
        if (n <= 0) {
            close(in);
            return -1;
        }
        if ((size_t)write(fd, buf, (size_t)n) != (size_t)n) {
            close(in);
            return -1;
        }
        remaining -= (size_t)n;
    }
    close(in);
    if (st.st_size % 2 != 0) {
        char pad = '\n';
        if (write(fd, &pad, 1) != 1)
            return -1;
    }
    return 0;
}

int ar_append_data(int fd, const char *membername,
                   const void *data, size_t datasz) {
    time_t now = (time_t)0;
    if (ar_write_hdr(fd, membername, datasz, now, 0, 0, 0100644) != 0)
        return -1;
    if (datasz > 0 && (size_t)write(fd, data, datasz) != datasz)
        return -1;
    if (datasz % 2 != 0) {
        char pad = '\n';
        if (write(fd, &pad, 1) != 1)
            return -1;
    }
    return 0;
}
