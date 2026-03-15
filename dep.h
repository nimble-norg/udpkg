#ifndef UDPKG_DEP_H
#define UDPKG_DEP_H

#define DEP_PKG_MAX    64
#define DEP_VER_MAX    64
#define DEP_MISS_MAX   128
#define DEP_ALT_MAX    8
#define DEP_GROUP_MAX  32

#define DEPOP_NONE  0
#define DEPOP_LT    1
#define DEPOP_LE    2
#define DEPOP_EQ    3
#define DEPOP_GE    4
#define DEPOP_GT    5

typedef struct {
    char alts[DEP_ALT_MAX][DEP_PKG_MAX];
    int  alt_op[DEP_ALT_MAX];
    char alt_ver[DEP_ALT_MAX][DEP_VER_MAX];
    int  nalts;
} dep_group_t;

typedef struct {
    dep_group_t groups[DEP_GROUP_MAX];
    int         ngroups;
} dep_list_t;

void dep_set_ignore(const char * const *pkgs, int n);
void dep_parse(const char *depends, dep_list_t *dl);

int dep_check(const dep_list_t *dl,
              const char * const *batch, int nbatch,
              char missing[][DEP_MISS_MAX], int *nmissing, int miss_cap);

int ver_cmp_public(const char *a, const char *b);

#endif

int dep_check_conflicts(const char *pkgname, const char *conflicts_str,
                         const char * const *batch, int nbatch);
