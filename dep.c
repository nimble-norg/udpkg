#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include "dep.h"
#include "db.h"

#define IGNORE_MAX 64

static const char *g_ignore[IGNORE_MAX];
static int         g_nignore = 0;

void dep_set_ignore(const char * const *pkgs, int n) {
    int i;
    g_nignore = 0;
    for (i = 0; i < n && g_nignore < IGNORE_MAX; i++)
        g_ignore[g_nignore++] = pkgs[i];
}

static int is_ignored(const char *name) {
    int i;
    for (i = 0; i < g_nignore; i++)
        if (strcmp(g_ignore[i], name) == 0)
            return 1;
    return 0;
}

static void trim(char *s) {
    char *e;
    while (*s == ' ' || *s == '\t')
        memmove(s, s + 1, strlen(s));
    e = s + strlen(s);
    while (e > s && (*(e-1) == ' ' || *(e-1) == '\t'))
        *--e = '\0';
}

static void extract_pkgname(const char *token, char *out, size_t outsz) {
    const char *p = token;
    size_t n;
    while (*p == ' ' || *p == '\t')
        p++;
    n = 0;
    while (p[n] && p[n] != ' ' && p[n] != '\t' && p[n] != '(' && p[n] != ':')
        n++;
    if (n >= outsz)
        n = outsz - 1;
    memcpy(out, p, n);
    out[n] = '\0';
}

void dep_parse(const char *depends, dep_list_t *dl) {
    char buf[4096];
    char *save_comma, *save_pipe;
    char *group_tok, *alt_tok;
    dl->ngroups = 0;
    if (!depends || depends[0] == '\0')
        return;
    strncpy(buf, depends, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    group_tok = strtok_r(buf, ",", &save_comma);
    while (group_tok && dl->ngroups < DEP_GROUP_MAX) {
        dep_group_t *g = &dl->groups[dl->ngroups];
        char gbuf[512];
        g->nalts = 0;
        strncpy(gbuf, group_tok, sizeof(gbuf) - 1);
        gbuf[sizeof(gbuf) - 1] = '\0';
        alt_tok = strtok_r(gbuf, "|", &save_pipe);
        while (alt_tok && g->nalts < DEP_ALT_MAX) {
            char name[DEP_PKG_MAX];
            extract_pkgname(alt_tok, name, sizeof(name));
            trim(name);
            if (name[0] != '\0') {
                strncpy(g->alts[g->nalts], name, DEP_PKG_MAX - 1);
                g->alts[g->nalts][DEP_PKG_MAX - 1] = '\0';
                g->nalts++;
            }
            alt_tok = strtok_r(NULL, "|", &save_pipe);
        }
        if (g->nalts > 0)
            dl->ngroups++;
        group_tok = strtok_r(NULL, ",", &save_comma);
    }
}

int dep_check(const dep_list_t *dl,
              const char * const *batch, int nbatch,
              char missing[][DEP_PKG_MAX], int *nmissing, int miss_cap) {
    int i, j, k;
    *nmissing = 0;
    for (i = 0; i < dl->ngroups; i++) {
        const dep_group_t *g = &dl->groups[i];
        int satisfied = 0;
        for (j = 0; j < g->nalts && !satisfied; j++) {
            if (is_ignored(g->alts[j])) {
                satisfied = 1;
                break;
            }
            if (db_is_installed(g->alts[j])) {
                satisfied = 1;
                break;
            }
            for (k = 0; k < nbatch && !satisfied; k++) {
                if (strcmp(batch[k], g->alts[j]) == 0)
                    satisfied = 1;
            }
        }
        if (!satisfied) {
            if (*nmissing < miss_cap) {
                strncpy(missing[*nmissing], g->alts[0], DEP_PKG_MAX - 1);
                missing[*nmissing][DEP_PKG_MAX - 1] = '\0';
                (*nmissing)++;
            }
        }
    }
    return *nmissing == 0 ? 0 : -1;
}
