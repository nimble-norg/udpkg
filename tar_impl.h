#ifndef TAR_IMPL_H
#define TAR_IMPL_H

#define TARFMT_AUTO  0
#define TARFMT_POSIX 1
#define TARFMT_USTAR 2
#define TARFMT_PAX   3
#define TARFMT_V7    4

int tar_create(const char *archive, const char *srcdir,
               const char *exclude, int fmt, int verbose);

int tar_extract(const char *archive, const char *destdir,
                int fmt, int verbose);

int tar_list(const char *archive, int fmt, int verbose, char *outfile);

#endif
