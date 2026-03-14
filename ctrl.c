#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "ctrl.h"

static int parse_fp(FILE *fp, ctrl_t *c) {
    char line[4096];
    int cur = -1;
    c->nfields = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0)
            continue;
        if (line[0] == ' ' || line[0] == '\t') {
            if (cur >= 0) {
                ctrl_field_t *f = &c->fields[cur];
                size_t vlen = strlen(f->val);
                if (vlen + 1 + len < CTRL_VAL_MAX) {
                    f->val[vlen] = '\n';
                    memcpy(f->val + vlen + 1, line, len + 1);
                }
            }
        } else {
            char *colon = strchr(line, ':');
            if (!colon || c->nfields >= CTRL_MAX_FIELDS)
                continue;
            cur = c->nfields++;
            {
                ctrl_field_t *f = &c->fields[cur];
                size_t klen = (size_t)(colon - line);
                char *v;
                size_t vlen;
                if (klen >= CTRL_KEY_MAX)
                    klen = CTRL_KEY_MAX - 1;
                memcpy(f->key, line, klen);
                f->key[klen] = '\0';
                v = colon + 1;
                while (*v == ' ')
                    v++;
                vlen = strlen(v);
                if (vlen >= CTRL_VAL_MAX)
                    vlen = CTRL_VAL_MAX - 1;
                memcpy(f->val, v, vlen);
                f->val[vlen] = '\0';
            }
        }
    }
    return 0;
}

int ctrl_parse(const char *path, ctrl_t *c) {
    FILE *fp = fopen(path, "r");
    int ret;
    if (!fp)
        return -1;
    ret = parse_fp(fp, c);
    fclose(fp);
    return ret;
}

int ctrl_parse_str(const char *str, ctrl_t *c) {
    char *copy = strdup(str);
    FILE *fp;
    int ret;
    if (!copy)
        return -1;
    fp = fmemopen(copy, strlen(copy), "r");
    if (!fp) {
        free(copy);
        return -1;
    }
    ret = parse_fp(fp, c);
    fclose(fp);
    free(copy);
    return ret;
}

const char *ctrl_get(const ctrl_t *c, const char *key) {
    int i;
    for (i = 0; i < c->nfields; i++) {
        if (strcasecmp(c->fields[i].key, key) == 0)
            return c->fields[i].val;
    }
    return NULL;
}

static void diag_add(ctrl_diags_t *d, int severity,
                     const char *field, int line, const char *msg)
{
    ctrl_diag_t *item;
    if (!d || d->ndiags >= CTRL_DIAG_MAX)
        return;
    item = &d->items[d->ndiags++];
    item->severity = severity;
    strncpy(item->field, field, CTRL_KEY_MAX - 1);
    item->field[CTRL_KEY_MAX - 1] = '\0';
    item->line = line;
    strncpy(item->msg, msg, sizeof(item->msg) - 1);
    item->msg[sizeof(item->msg) - 1] = '\0';
}

static int field_line(const ctrl_t *c, const char *key)
{
    int i, line = 1;
    for (i = 0; i < c->nfields; i++) {
        if (strcasecmp(c->fields[i].key, key) == 0)
            return line;
        line++;
    }
    return -1;
}

static int is_blank(const char *s)
{
    if (!s || *s == '\0')
        return 1;
    while (*s) {
        if (*s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
            return 0;
        s++;
    }
    return 1;
}

void ctrl_validate(const ctrl_t *c, ctrl_diags_t *d)
{
    static const char *required[] = {
        "Package", "Version", "Architecture", NULL
    };
    static const char *recommended[] = {
        "Maintainer", "Description", NULL
    };
    int i;
    const char *val;
    char msg[256];
    int ln;

    d->ndiags = 0;

    for (i = 0; required[i]; i++) {
        val = ctrl_get(c, required[i]);
        if (!val) {
            snprintf(msg, sizeof(msg),
                     "required field '%s' is missing", required[i]);
            diag_add(d, CTRL_VALID_FATAL, required[i], -1, msg);
        } else if (is_blank(val)) {
            ln = field_line(c, required[i]);
            snprintf(msg, sizeof(msg),
                     "required field '%s' has empty value", required[i]);
            diag_add(d, CTRL_VALID_FATAL, required[i], ln, msg);
        }
    }

    for (i = 0; recommended[i]; i++) {
        val = ctrl_get(c, recommended[i]);
        if (!val) {
            snprintf(msg, sizeof(msg),
                     "recommended field '%s' is missing", recommended[i]);
            diag_add(d, CTRL_VALID_WARN, recommended[i], -1, msg);
        } else if (is_blank(val)) {
            ln = field_line(c, recommended[i]);
            snprintf(msg, sizeof(msg),
                     "recommended field '%s' has empty value", recommended[i]);
            diag_add(d, CTRL_VALID_WARN, recommended[i], ln, msg);
        }
    }
}
