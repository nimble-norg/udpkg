#ifndef UDPKG_DB_H
#define UDPKG_DB_H

#include <stddef.h>
#include "ctrl.h"

#define DB_DIR   "/var/lib/udpkg"
#define INFO_DIR "/var/lib/udpkg/info"
#define STATUS_F "/var/lib/udpkg/status"
#define TMP_CI   "/var/lib/udpkg/tmp.ci"

int db_init(void);
int db_install(const ctrl_t *c, const char *listfile);
int db_remove(const char *name);
int db_is_installed(const char *name);
int db_get(const char *name, ctrl_t *c);
int db_get_version(const char *name, char *buf, size_t bufsz);
int db_list(const char *pattern);
int db_list_files(const char *name);
int db_get_listpath(const char *name, char *buf, size_t bufsz);
int db_get_scriptpath(const char *name, const char *script,
                      char *buf, size_t bufsz);
int db_install_script(const char *name, const char *script,
                      const char *srcpath);
int db_remove_scripts(const char *name);

#endif
