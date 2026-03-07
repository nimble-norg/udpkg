#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "deb_fmt.h"
#include "ar.h"

#define OLD_MAGIC "0.939000"
#define NEW_MAGIC "!<arch>\n"

int deb_detect(const char *path) {
    unsigned char buf[8];
    int fd;
    ssize_t n;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    n = read(fd, buf, 8);
    close(fd);
    if (n < 8)
        return -1;
    if (memcmp(buf, NEW_MAGIC, 8) == 0)
        return DEB_FMT_NEW;
    if (memcmp(buf, OLD_MAGIC, 8) == 0)
        return DEB_FMT_OLD;
    return -1;
}

static int copy_bytes(int fd, const char *dest, size_t nbytes) {
    char buf[8192];
    int out;
    size_t remaining = nbytes;
    out = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0)
        return -1;
    while (remaining > 0) {
        size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        ssize_t n = read(fd, buf, want);
        if (n <= 0) {
            close(out);
            return -1;
        }
        if (write(out, buf, (size_t)n) != n) {
            close(out);
            return -1;
        }
        remaining -= (size_t)n;
    }
    close(out);
    return 0;
}

static int copy_to_eof(int fd, const char *dest) {
    char buf[8192];
    int out;
    ssize_t n;
    out = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0)
        return -1;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            close(out);
            return -1;
        }
    }
    close(out);
    return n < 0 ? -1 : 0;
}

static int deb_open_old(const char *path, const char *outdir,
                        char *ctrl_tar, size_t ctrl_sz, size_t *ctrl_arch_sz,
                        char *data_tar, size_t data_sz,
                        int want_ctrl, int want_data) {
    int fd;
    char line1[32], line2[32];
    size_t ctrl_size;
    int i;
    char c;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    i = 0;
    while (i < (int)(sizeof(line1) - 1)) {
        if (read(fd, &c, 1) != 1) { close(fd); return -1; }
        if (c == '\n') break;
        line1[i++] = c;
    }
    line1[i] = '\0';
    if (strcmp(line1, "0.939000") != 0) {
        close(fd);
        return -1;
    }
    i = 0;
    while (i < (int)(sizeof(line2) - 1)) {
        if (read(fd, &c, 1) != 1) { close(fd); return -1; }
        if (c == '\n') break;
        line2[i++] = c;
    }
    line2[i] = '\0';
    ctrl_size = (size_t)strtoul(line2, NULL, 10);
    if (ctrl_size == 0) {
        close(fd);
        return -1;
    }
    if (ctrl_arch_sz)
        *ctrl_arch_sz = ctrl_size;
    if (want_ctrl) {
        snprintf(ctrl_tar, ctrl_sz, "%s/control.tar.gz", outdir);
        if (copy_bytes(fd, ctrl_tar, ctrl_size) != 0) {
            close(fd);
            return -1;
        }
    } else {
        if (lseek(fd, (off_t)ctrl_size, SEEK_CUR) < 0) {
            close(fd);
            return -1;
        }
    }
    if (want_data) {
        snprintf(data_tar, data_sz, "%s/data.tar.gz", outdir);
        if (copy_to_eof(fd, data_tar) != 0) {
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

static int deb_open_new(const char *path, const char *outdir,
                        char *ctrl_tar, size_t ctrl_sz, size_t *ctrl_arch_sz,
                        char *data_tar, size_t data_sz,
                        int want_ctrl, int want_data) {
    ar_entry_t entry;
    int arfd, ret;
    int have_ctrl = 0, have_data = 0;
    memset(&entry, 0, sizeof(entry));
    arfd = ar_open(path);
    if (arfd < 0)
        return -1;
    while ((ret = ar_next(arfd, &entry)) == 1) {
        if (want_ctrl && !have_ctrl &&
            strncmp(entry.name, "control.tar", 11) == 0) {
            snprintf(ctrl_tar, ctrl_sz, "%s/%s", outdir, entry.name);
            if (ar_extract(arfd, &entry, ctrl_tar) != 0) {
                close(arfd);
                return -1;
            }
            if (ctrl_arch_sz)
                *ctrl_arch_sz = entry.size;
            have_ctrl = 1;
        } else if (want_data && !have_data &&
                   strncmp(entry.name, "data.tar", 8) == 0) {
            snprintf(data_tar, data_sz, "%s/%s", outdir, entry.name);
            if (ar_extract(arfd, &entry, data_tar) != 0) {
                close(arfd);
                return -1;
            }
            have_data = 1;
        }
        if ((!want_ctrl || have_ctrl) && (!want_data || have_data))
            break;
    }
    close(arfd);
    if ((want_ctrl && !have_ctrl) || (want_data && !have_data))
        return -1;
    return 0;
}

int deb_open(const char *path, int fmt,
             const char *outdir,
             char *ctrl_tar, size_t ctrl_sz, size_t *ctrl_arch_sz,
             char *data_tar, size_t data_sz,
             int want_ctrl, int want_data,
             int *used_fmt) {
    int detected;
    if (fmt == DEB_FMT_AUTO) {
        detected = deb_detect(path);
        if (detected < 0)
            return -1;
    } else {
        detected = fmt;
    }
    if (used_fmt)
        *used_fmt = detected;
    if (detected == DEB_FMT_OLD)
        return deb_open_old(path, outdir,
                            ctrl_tar, ctrl_sz, ctrl_arch_sz,
                            data_tar, data_sz,
                            want_ctrl, want_data);
    return deb_open_new(path, outdir,
                        ctrl_tar, ctrl_sz, ctrl_arch_sz,
                        data_tar, data_sz,
                        want_ctrl, want_data);
}
