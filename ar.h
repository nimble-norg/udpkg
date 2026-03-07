#ifndef UDPKG_AR_H
#define UDPKG_AR_H

#include <stddef.h>
#include <sys/types.h>

typedef struct {
    char   name[17];
    size_t size;
    off_t  data_offset;
    off_t  next_offset;
} ar_entry_t;

int ar_open(const char *path);
int ar_next(int fd, ar_entry_t *entry);
int ar_extract(int fd, const ar_entry_t *entry, const char *destpath);

int ar_create(const char *path);
int ar_append_file(int fd, const char *membername, const char *srcpath);
int ar_append_data(int fd, const char *membername,
                   const void *data, size_t datasz);

#endif
