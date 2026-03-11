#ifndef UTAR_H
#define UTAR_H

#include "tar_impl.h"

#define TARIMPL_INTERNAL 0
#define TARIMPL_EXTERNAL 1

void utar_set_impl(int impl);
void utar_set_fmt(int fmt);
int  utar_get_impl(void);
int  utar_get_fmt(void);

const char *utar_impl_name(void);
const char *utar_fmt_name(int fmt);

int utar_create(const char *archive, const char *srcdir,
                const char *exclude, int verbose);

int utar_extract(const char *archive, const char *destdir,
                 int verbose);

int utar_list(const char *archive, int verbose, char *outfile);

int utar_list_stdout(const char *archive, int verbose);

#endif
