#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
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
