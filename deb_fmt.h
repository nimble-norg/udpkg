#ifndef UDPKG_DEB_FMT_H
#define UDPKG_DEB_FMT_H

#include <stddef.h>

#define DEB_FMT_AUTO 0
#define DEB_FMT_NEW  1
#define DEB_FMT_OLD  2

int deb_detect(const char *path);

int deb_open(const char *path, int fmt,
             const char *outdir,
             char *ctrl_tar, size_t ctrl_sz, size_t *ctrl_arch_sz,
             char *data_tar, size_t data_sz,
             int want_ctrl, int want_data,
             int *used_fmt);

#endif
