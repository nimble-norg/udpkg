#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "dep.h"
#include "db.h"
#include "ctrl.h"

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
    size_t len;
    char *e;
    while (*s == ' ' || *s == '\t')
        memmove(s, s + 1, strlen(s) + 1);
    len = strlen(s);
    e = s + len;
    while (e > s && (*(e-1) == ' ' || *(e-1) == '\t'))
        *--e = '\0';
}

static int char_order(unsigned char c) {
    if (c == '~')        return -1;
    if (c == '\0')       return  0;
    if (isalpha(c))      return (int)c;
    return (int)c + 256;
}

static int ver_cmp_str(const char *a, const char *b) {
    while (*a || *b) {
        int first_diff = 0;
        while ((*a && !isdigit((unsigned char)*a)) ||
               (*b && !isdigit((unsigned char)*b))) {
            int oa = char_order((unsigned char)*a);
            int ob = char_order((unsigned char)*b);
            if (oa != ob)
                return oa < ob ? -1 : 1;
            if (*a) a++;
            if (*b) b++;
        }
        while (*a == '0') a++;
        while (*b == '0') b++;
        while (isdigit((unsigned char)*a) && isdigit((unsigned char)*b)) {
            if (!first_diff)
                first_diff = (unsigned char)*a - (unsigned char)*b;
            a++;
            b++;
        }
        if (isdigit((unsigned char)*a)) return  1;
        if (isdigit((unsigned char)*b)) return -1;
        if (first_diff)                 return first_diff < 0 ? -1 : 1;
    }
    return 0;
}

static int ver_compare(const char *a, const char *b) {
    long ea = 0, eb = 0;
    const char *ca, *cb;
    char ua[DEP_VER_MAX], ub[DEP_VER_MAX];
    char ra[DEP_VER_MAX], rb[DEP_VER_MAX];
    const char *sep_a, *sep_b;
    size_t ulen;
    int r;
    ca = strchr(a, ':');
    cb = strchr(b, ':');
    if (ca) { ea = atol(a); a = ca + 1; }
    if (cb) { eb = atol(b); b = cb + 1; }
    if (ea != eb) return ea < eb ? -1 : 1;
    sep_a = strrchr(a, '-');
    sep_b = strrchr(b, '-');
    if (sep_a) {
        ulen = (size_t)(sep_a - a);
        if (ulen >= sizeof(ua)) ulen = sizeof(ua) - 1;
        memcpy(ua, a, ulen); ua[ulen] = '\0';
        strncpy(ra, sep_a + 1, sizeof(ra) - 1); ra[sizeof(ra)-1] = '\0';
    } else {
        strncpy(ua, a, sizeof(ua) - 1); ua[sizeof(ua)-1] = '\0';
        ra[0] = '\0';
    }
    if (sep_b) {
        ulen = (size_t)(sep_b - b);
        if (ulen >= sizeof(ub)) ulen = sizeof(ub) - 1;
        memcpy(ub, b, ulen); ub[ulen] = '\0';
        strncpy(rb, sep_b + 1, sizeof(rb) - 1); rb[sizeof(rb)-1] = '\0';
    } else {
        strncpy(ub, b, sizeof(ub) - 1); ub[sizeof(ub)-1] = '\0';
        rb[0] = '\0';
    }
    r = ver_cmp_str(ua, ub);
    if (r) return r;
    return ver_cmp_str(ra, rb);
}

int ver_cmp_public(const char *a, const char *b) {
    return ver_compare(a, b);
}

static int ver_satisfies(const char *installed, int op, const char *required) {
    int c;
    if (op == DEPOP_NONE)
        return 1;
    c = ver_compare(installed, required);
    switch (op) {
        case DEPOP_LT: return c <  0;
        case DEPOP_LE: return c <= 0;
        case DEPOP_EQ: return c == 0;
        case DEPOP_GE: return c >= 0;
        case DEPOP_GT: return c >  0;
    }
    return 1;
}

static int parse_op(const char *s) {
    if (strcmp(s, "<<") == 0 || strcmp(s, "<") == 0) return DEPOP_LT;
    if (strcmp(s, "<=") == 0)                         return DEPOP_LE;
    if (strcmp(s, "=")  == 0)                         return DEPOP_EQ;
    if (strcmp(s, ">=") == 0)                         return DEPOP_GE;
    if (strcmp(s, ">>") == 0 || strcmp(s, ">") == 0) return DEPOP_GT;
    return DEPOP_NONE;
}

static void parse_constraint(const char *token,
                              char *name, size_t namesz,
                              int *op, char *ver, size_t versz) {
    const char *p = token;
    const char *open_p;
    size_t n;
    *op = DEPOP_NONE;
    ver[0] = '\0';
    while (*p == ' ' || *p == '\t') p++;
    n = 0;
    while (p[n] && p[n] != ' ' && p[n] != '\t' && p[n] != '(' && p[n] != ':')
        n++;
    if (n >= namesz) n = namesz - 1;
    memcpy(name, p, n);
    name[n] = '\0';
    open_p = strchr(token, '(');
    if (open_p) {
        char opbuf[8];
        const char *q = open_p + 1;
        size_t olen = 0, vlen = 0;
        const char *close_p;
        while (*q == ' ') q++;
        while (olen < sizeof(opbuf) - 1 && *q &&
               *q != ' ' && *q != '\t' && !isdigit((unsigned char)*q) &&
               *q != '~' && !isalpha((unsigned char)*q))
            opbuf[olen++] = *q++;
        opbuf[olen] = '\0';
        *op = parse_op(opbuf);
        while (*q == ' ') q++;
        close_p = strchr(q, ')');
        if (close_p) {
            vlen = (size_t)(close_p - q);
            while (vlen > 0 && (q[vlen-1] == ' ' || q[vlen-1] == '\t'))
                vlen--;
            if (vlen >= versz) vlen = versz - 1;
            memcpy(ver, q, vlen);
            ver[vlen] = '\0';
        }
    }
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
            int  op;
            char ver[DEP_VER_MAX];
            parse_constraint(alt_tok, name, sizeof(name), &op, ver, sizeof(ver));
            trim(name);
            if (name[0] != '\0') {
                strncpy(g->alts[g->nalts], name, DEP_PKG_MAX - 1);
                g->alts[g->nalts][DEP_PKG_MAX - 1] = '\0';
                g->alt_op[g->nalts] = op;
                strncpy(g->alt_ver[g->nalts], ver, DEP_VER_MAX - 1);
                g->alt_ver[g->nalts][DEP_VER_MAX - 1] = '\0';
                g->nalts++;
            }
            alt_tok = strtok_r(NULL, "|", &save_pipe);
        }
        if (g->nalts > 0)
            dl->ngroups++;
        group_tok = strtok_r(NULL, ",", &save_comma);
    }
}

static const char *op_str(int op) {
    switch (op) {
        case DEPOP_LT: return "<<";
        case DEPOP_LE: return "<=";
        case DEPOP_EQ: return "=";
        case DEPOP_GE: return ">=";
        case DEPOP_GT: return ">>";
    }
    return "";
}

static int pkg_provides(const char *pkgname, const char *virtual_name,
                        int vop, const char *vver) {
    ctrl_t c;
    const char *prov;
    dep_list_t dl;
    int i, j;
    if (db_get(pkgname, &c) != 0)
        return 0;
    prov = ctrl_get(&c, "Provides");
    if (!prov)
        return 0;
    dep_parse(prov, &dl);
    for (i = 0; i < dl.ngroups; i++) {
        for (j = 0; j < dl.groups[i].nalts; j++) {
            if (strcmp(dl.groups[i].alts[j], virtual_name) == 0) {
                if (vop == DEPOP_NONE)
                    return 1;
                {
                    const char *pver = dl.groups[i].alt_ver[j];
                    if (pver[0] == '\0')
                        return (vop == DEPOP_NONE);
                    return ver_satisfies(pver, vop, vver);
                }
            }
        }
    }
    return 0;
}

static int any_installed_provides(const char *virtual_name, int vop,
                                   const char *vver) {
    char info_dir[4096];
    DIR *dir;
    struct dirent *de;
    int found = 0;
    apath_pub(info_dir, sizeof(info_dir), "/info");
    dir = opendir(info_dir);
    if (!dir)
        return 0;
    while (!found && (de = readdir(dir)) != NULL) {
        char *dot;
        char pkgname[256];
        size_t nlen;
        if (de->d_name[0] == '.')
            continue;
        dot = strrchr(de->d_name, '.');
        if (!dot || strcmp(dot, ".list") != 0)
            continue;
        nlen = (size_t)(dot - de->d_name);
        if (nlen == 0 || nlen >= sizeof(pkgname))
            continue;
        memcpy(pkgname, de->d_name, nlen);
        pkgname[nlen] = '\0';
        if (pkg_provides(pkgname, virtual_name, vop, vver))
            found = 1;
    }
    closedir(dir);
    return found;
}

static int pkg_is_active(const char *name) {
    ctrl_t c;
    const char *sv;
    char sel[64], flag[64], state[64];
    if (db_get(name, &c) != 0)
        return 0;
    sv = ctrl_get(&c, "Status");
    if (!sv)
        return 0;
    if (sscanf(sv, "%63s %63s %63s", sel, flag, state) < 3)
        return 0;
    return (strcmp(state, "installed")      == 0 ||
            strcmp(state, "unpacked")       == 0 ||
            strcmp(state, "half-installed") == 0 ||
            strcmp(state, "half-configured") == 0 ||
            strcmp(state, "triggers-pending") == 0 ||
            strcmp(state, "triggers-awaited") == 0);
}

static void format_dep(char *slot, size_t sz, const char *name,
                        int op, const char *ver) {
    if (op != DEPOP_NONE) {
        size_t nlen = strlen(name);
        const char *ops = op_str(op);
        size_t olen = strlen(ops);
        size_t vlen = strlen(ver);
        size_t pos = 0;
        if (nlen > sz - 1) nlen = sz - 1;
        memcpy(slot, name, nlen); pos = nlen;
        if (pos + 2 < sz) { slot[pos++] = ' '; slot[pos++] = '('; }
        if (pos + olen < sz) { memcpy(slot + pos, ops, olen); pos += olen; }
        if (pos + 1 < sz)  slot[pos++] = ' ';
        if (pos + vlen < sz) { memcpy(slot + pos, ver, vlen); pos += vlen; }
        if (pos + 1 < sz)  slot[pos++] = ')';
        slot[pos < sz ? pos : sz - 1] = '\0';
    } else {
        strncpy(slot, name, sz - 1);
        slot[sz - 1] = '\0';
    }
}

int dep_check(const dep_list_t *dl,
              const char * const *batch, int nbatch,
              char missing[][DEP_MISS_MAX], int *nmissing, int miss_cap) {
    int i, j, k;
    *nmissing = 0;
    for (i = 0; i < dl->ngroups; i++) {
        const dep_group_t *g = &dl->groups[i];
        int satisfied = 0;
        for (j = 0; j < g->nalts && !satisfied; j++) {
            const char *aname = g->alts[j];
            int aop            = g->alt_op[j];
            const char *aver   = g->alt_ver[j];
            if (is_ignored(aname)) {
                satisfied = 1;
                break;
            }
            if (pkg_is_active(aname)) {
                if (aop == DEPOP_NONE) {
                    satisfied = 1;
                } else {
                    char inst_ver[DEP_VER_MAX];
                    if (db_get_version(aname, inst_ver, sizeof(inst_ver)) == 0
                        && ver_satisfies(inst_ver, aop, aver))
                        satisfied = 1;
                }
            }
            if (!satisfied && any_installed_provides(aname, aop, aver))
                satisfied = 1;
            if (!satisfied) {
                for (k = 0; k < nbatch && !satisfied; k++) {
                    if (strcmp(batch[k], aname) == 0)
                        satisfied = 1;
                }
            }
        }
        if (!satisfied && *nmissing < miss_cap) {
            if (g->nalts == 1) {
                format_dep(missing[*nmissing], (size_t)DEP_MISS_MAX,
                           g->alts[0], g->alt_op[0], g->alt_ver[0]);
            } else {
                char tmp[DEP_MISS_MAX];
                size_t pos = 0;
                for (j = 0; j < g->nalts; j++) {
                    char part[128];
                    format_dep(part, sizeof(part),
                               g->alts[j], g->alt_op[j], g->alt_ver[j]);
                    if (j > 0 && pos + 3 < (size_t)DEP_MISS_MAX - 1) {
                        memcpy(tmp + pos, " | ", 3);
                        pos += 3;
                    }
                    {
                        size_t plen = strlen(part);
                        if (pos + plen >= (size_t)DEP_MISS_MAX - 1)
                            plen = (size_t)DEP_MISS_MAX - 1 - pos;
                        memcpy(tmp + pos, part, plen);
                        pos += plen;
                    }
                }
                tmp[pos] = '\0';
                strncpy(missing[*nmissing], tmp, (size_t)DEP_MISS_MAX - 1);
                missing[*nmissing][(size_t)DEP_MISS_MAX - 1] = '\0';
            }
            (*nmissing)++;
        }
    }
    return *nmissing == 0 ? 0 : -1;
}

int dep_check_conflicts(const char *pkgname, const char *conflicts_str,
                         const char * const *batch, int nbatch) {
    dep_list_t dl;
    int i, j, k, found = 0;
    dep_parse(conflicts_str, &dl);
    for (i = 0; i < dl.ngroups; i++) {
        const dep_group_t *g = &dl.groups[i];
        for (j = 0; j < g->nalts; j++) {
            const char *cname = g->alts[j];
            int cop = g->alt_op[j];
            const char *cver = g->alt_ver[j];
            if (strcmp(cname, pkgname) == 0)
                continue;
            if (is_ignored(cname))
                continue;
            if (pkg_is_active(cname)) {
                int conflict = 0;
                if (cop == DEPOP_NONE) {
                    conflict = 1;
                } else {
                    char inst_ver[DEP_VER_MAX];
                    if (db_get_version(cname, inst_ver, sizeof(inst_ver)) == 0
                        && ver_satisfies(inst_ver, cop, cver))
                        conflict = 1;
                }
                if (conflict) {
                    fprintf(stderr,
                        "udpkg: %s conflicts with installed package %s\n",
                        pkgname, cname);
                    found = 1;
                }
            }
            for (k = 0; k < nbatch; k++) {
                if (strcmp(batch[k], cname) == 0) {
                    fprintf(stderr,
                        "udpkg: %s conflicts with %s (in batch)\n",
                        pkgname, cname);
                    found = 1;
                }
            }
        }
    }
    return found ? -1 : 0;
}
