#ifndef UDPKG_CTRL_H
#define UDPKG_CTRL_H

#define CTRL_MAX_FIELDS 64
#define CTRL_KEY_MAX    64
#define CTRL_VAL_MAX    4096

typedef struct {
    char key[CTRL_KEY_MAX];
    char val[CTRL_VAL_MAX];
} ctrl_field_t;

typedef struct {
    ctrl_field_t fields[CTRL_MAX_FIELDS];
    int          nfields;
} ctrl_t;

#define CTRL_VALID_OK      0
#define CTRL_VALID_WARN    1
#define CTRL_VALID_FATAL   2

typedef struct {
    int         severity;
    char        field[CTRL_KEY_MAX];
    int         line;
    char        msg[256];
} ctrl_diag_t;

#define CTRL_DIAG_MAX 32

typedef struct {
    ctrl_diag_t items[CTRL_DIAG_MAX];
    int         ndiags;
} ctrl_diags_t;

int         ctrl_parse(const char *path, ctrl_t *c);
int         ctrl_parse_str(const char *str, ctrl_t *c);
const char *ctrl_get(const ctrl_t *c, const char *key);
void        ctrl_validate(const ctrl_t *c, ctrl_diags_t *d);

#endif
