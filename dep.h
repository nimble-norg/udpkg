#ifndef UDPKG_DEP_H
#define UDPKG_DEP_H

#define DEP_PKG_MAX    64
#define DEP_ALT_MAX    8
#define DEP_GROUP_MAX  32

typedef struct {
    char alts[DEP_ALT_MAX][DEP_PKG_MAX];
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
              char missing[][DEP_PKG_MAX], int *nmissing, int miss_cap);

#endif
