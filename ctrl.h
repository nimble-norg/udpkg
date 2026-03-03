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

int         ctrl_parse(const char *path, ctrl_t *c);
int         ctrl_parse_str(const char *str, ctrl_t *c);
const char *ctrl_get(const ctrl_t *c, const char *key);

#endif
