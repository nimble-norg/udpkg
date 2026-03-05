#ifndef UDPKG_DB_H
#define UDPKG_DB_H

#include <stddef.h>
#include "ctrl.h"

void        db_set_root(const char *root);
void        db_set_admindir(const char *dir);
const char *db_tmpci(void);
const char *db_tmpci_ctrl(void);

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
int db_find_file_owner(const char *filepath, const char *exclude_pkg,
                       char *owner, size_t ownersz);

#endif
