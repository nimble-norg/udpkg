#ifndef UDPKG_DB_H
#define UDPKG_DB_H

#include <stddef.h>
#include "ctrl.h"

void        db_set_root(const char *root);
void        db_set_admindir(const char *dir);
const char *db_tmpci(void);
const char *db_tmpci_ctrl(void);

int db_init(void);
#define DB_BLOCK_MAX 16384

typedef struct block_node {
    char               name[256];
    char               text[DB_BLOCK_MAX];
    struct block_node *next;
} block_node_t;

block_node_t *status_read_pub(void);
void          status_free_pub(block_node_t *head);
int db_install(const ctrl_t *c, const char *listfile);
int db_install_unpacked(const ctrl_t *c, const char *listfile);
int db_remove(const char *name);
int db_is_installed(const char *name);
int db_get(const char *name, ctrl_t *c);
int db_get_version(const char *name, char *buf, size_t bufsz);
int db_list(const char *pattern, int no_pager);
int db_list_files(const char *name);
int db_get_listpath(const char *name, char *buf, size_t bufsz);
int db_get_scriptpath(const char *name, const char *script,
                      char *buf, size_t bufsz);
int db_install_script(const char *name, const char *script,
                      const char *srcpath);
int db_remove_scripts(const char *name);
int db_find_file_owner(const char *filepath, const char *exclude_pkg,
                       char *owner, size_t ownersz);
int db_install_conffiles(const char *name, const char *srcpath);
int db_get_conffiles_path(const char *name, char *buf, size_t bufsz);
int db_remove_conffiles(const char *name);
int db_is_conffile(const char *name, const char *filepath);
void apath_pub(char *buf, size_t sz, const char *suffix);
int db_set_state(const char *name,
                 const char *sel, const char *flag, const char *state);
int db_has_conffiles(const char *name);

#endif
