#define _POSIX_C_SOURCE 200809L
#include "divert.h"
#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fnmatch.h>

#define DIV_PATH_MAX 4096
#define DIV_PKG_MAX  256
#define DIV_LINE_MAX 8192

static char g_admindir[4096] = "";
static char g_instdir[4096]  = "";
static char g_root[4096]     = "";

static const char *diversions_path(void) {
    static char buf[8192];
    if (g_admindir[0]) {
        strncpy(buf, g_admindir, sizeof(buf)-13);
        strncat(buf, "/diversions", sizeof(buf)-strlen(buf)-1);
    }
    else if (g_root[0]) {
        strncpy(buf, g_root, sizeof(buf)-26);
        strncat(buf, "/var/lib/udpkg/diversions", sizeof(buf)-strlen(buf)-1);
    }
    else
        strncpy(buf, "/var/lib/udpkg/diversions", sizeof(buf)-1);
    return buf;
}

static const char *effective_root(void) {
    if (g_instdir[0]) return g_instdir;
    if (g_root[0])    return g_root;
    return "";
}

typedef struct {
    char orig[DIV_PATH_MAX];
    char divto[DIV_PATH_MAX];
    char pkg[DIV_PKG_MAX];
} divert_entry_t;

#define MAX_DIVERTS 4096

static int read_diversions(divert_entry_t *out, int maxn) {
    FILE *fp;
    char line[DIV_LINE_MAX];
    int n = 0;
    fp = fopen(diversions_path(), "r");
    if (!fp)
        return 0;
    while (n < maxn && fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        char orig[DIV_PATH_MAX], divto[DIV_PATH_MAX], pkg[DIV_PKG_MAX];
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0)
            continue;
        strncpy(orig, line, DIV_PATH_MAX - 1);
        orig[DIV_PATH_MAX - 1] = '\0';
        if (!fgets(line, sizeof(line), fp)) break;
        len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        strncpy(divto, line, DIV_PATH_MAX - 1);
        divto[DIV_PATH_MAX - 1] = '\0';
        if (!fgets(line, sizeof(line), fp)) break;
        len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        strncpy(pkg, line, DIV_PKG_MAX - 1);
        pkg[DIV_PKG_MAX - 1] = '\0';
        strncpy(out[n].orig,  orig,  DIV_PATH_MAX - 1);
        strncpy(out[n].divto, divto, DIV_PATH_MAX - 1);
        strncpy(out[n].pkg,   pkg,   DIV_PKG_MAX - 1);
        n++;
    }
    fclose(fp);
    return n;
}

static int write_diversions(const divert_entry_t *entries, int n) {
    FILE *fp;
    int i;
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s.new", diversions_path());
    fp = fopen(tmp, "w");
    if (!fp) {
        fprintf(stderr, "udpkg --divert: cannot write '%s': %s\n",
                tmp, strerror(errno));
        return -1;
    }
    for (i = 0; i < n; i++)
        fprintf(fp, "%s\n%s\n%s\n",
                entries[i].orig, entries[i].divto, entries[i].pkg);
    fclose(fp);
    if (rename(tmp, diversions_path()) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void ensure_parent_dir(const char *path) {
    char tmp[8192];
    char *slash;
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    slash = strrchr(tmp, '/');
    if (!slash || slash == tmp)
        return;
    *slash = '\0';
    {
        struct stat st;
        if (stat(tmp, &st) == 0)
            return;
    }
    {
        char *p = tmp + 1;
        while (*p) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
            p++;
        }
        mkdir(tmp, 0755);
    }
}

static void ensure_diversions_file(void) {
    struct stat st;
    const char *p = diversions_path();
    if (stat(p, &st) == 0)
        return;
    ensure_parent_dir(p);
    {
        FILE *fp = fopen(p, "w");
        if (fp) fclose(fp);
    }
}

static int do_rename(const char *src, const char *dst, int doit) {
    const char *root = effective_root();
    char fsrc[DIV_PATH_MAX * 2], fdst[DIV_PATH_MAX * 2];
    struct stat st;
    if (root[0]) {
        snprintf(fsrc, sizeof(fsrc), "%s%s", root, src);
        snprintf(fdst, sizeof(fdst), "%s%s", root, dst);
    } else {
        strncpy(fsrc, src, sizeof(fsrc) - 1);
        strncpy(fdst, dst, sizeof(fdst) - 1);
    }
    if (!doit) {
        printf("Would rename '%s' to '%s'\n", fsrc, fdst);
        return 0;
    }
    if (stat(fsrc, &st) != 0)
        return 0;
    if (rename(fsrc, fdst) != 0) {
        fprintf(stderr, "udpkg --divert: rename '%s' -> '%s': %s\n",
                fsrc, fdst, strerror(errno));
        return -1;
    }
    return 0;
}

static int cmd_add(const char *file, const char *pkg, const char *divert_to,
                   int local, int rename_flag, int test) {
    divert_entry_t *entries;
    entries = (divert_entry_t *)malloc(sizeof(divert_entry_t) * MAX_DIVERTS);
    if (!entries) { fprintf(stderr, "udpkg --divert: out of memory\n"); return 1; }
    int n, i;
    char divto[DIV_PATH_MAX];
    char pkgname[DIV_PKG_MAX];
    ensure_diversions_file();
    n = read_diversions(entries, MAX_DIVERTS);
    if (divert_to && divert_to[0])
        strncpy(divto, divert_to, DIV_PATH_MAX - 1);
    else
        snprintf(divto, sizeof(divto), "%s.distrib", file);
    divto[DIV_PATH_MAX - 1] = '\0';
    if (local)
        strncpy(pkgname, ":local", DIV_PKG_MAX - 1);
    else if (pkg && pkg[0])
        strncpy(pkgname, pkg, DIV_PKG_MAX - 1);
    else
        strncpy(pkgname, ":any", DIV_PKG_MAX - 1);
    pkgname[DIV_PKG_MAX - 1] = '\0';
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].orig, file) == 0) {
            if (strcmp(entries[i].divto, divto) == 0 &&
                strcmp(entries[i].pkg,   pkgname) == 0) {
                printf("Leaving '%s'\n", file);
                return 0;
            }
            fprintf(stderr,
                "udpkg --divert: '%s' already diverted by '%s' to '%s'\n",
                file, entries[i].pkg, entries[i].divto);
            free(entries); return 1;
        }
    }
    if (n >= MAX_DIVERTS) {
        fprintf(stderr, "udpkg --divert: too many diversions\n");
        free(entries); return 1;
    }
    if (!test) {
        strncpy(entries[n].orig,  file,    DIV_PATH_MAX - 1);
        strncpy(entries[n].divto, divto,   DIV_PATH_MAX - 1);
        strncpy(entries[n].pkg,   pkgname, DIV_PKG_MAX  - 1);
        n++;
        if (write_diversions(entries, n) != 0) {
            free(entries); return 1;
        }
    }
    if (rename_flag)
        do_rename(file, divto, !test);
    printf("Adding '%s'\n",
           test ? "(test) diversion" : "diversion");
    printf("  local:     %s\n",   local ? "yes" : "no");
    printf("  divert to: %s\n",   divto);
    printf("  package:   %s\n",   pkgname);
    free(entries); return 0;
}

static int cmd_remove(const char *file, int rename_flag, int test) {
    divert_entry_t *entries;
    entries = (divert_entry_t *)malloc(sizeof(divert_entry_t) * MAX_DIVERTS);
    if (!entries) { fprintf(stderr, "udpkg --divert: out of memory\n"); return 1; }
    int n, i, found = -1;
    ensure_diversions_file();
    n = read_diversions(entries, MAX_DIVERTS);
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].orig, file) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        printf("No diversion for '%s'.\n", file);
        return 0;
    }
    if (rename_flag)
        do_rename(entries[found].divto, file, !test);
    if (!test) {
        for (i = found; i < n - 1; i++)
            entries[i] = entries[i + 1];
        n--;
        if (write_diversions(entries, n) != 0) {
            free(entries); return 1;
        }
    }
    printf("Removing '%s'\n", test ? "(test) diversion" : "diversion");
    free(entries); return 0;
}

static int cmd_list(const char *pattern) {
    divert_entry_t *entries;
    entries = (divert_entry_t *)malloc(sizeof(divert_entry_t) * MAX_DIVERTS);
    if (!entries) { fprintf(stderr, "udpkg --divert: out of memory\n"); return 1; }
    int n, i;
    ensure_diversions_file();
    n = read_diversions(entries, MAX_DIVERTS);
    for (i = 0; i < n; i++) {
        if (pattern && pattern[0]) {
            if (fnmatch(pattern, entries[i].orig,  0) != 0 &&
                fnmatch(pattern, entries[i].divto, 0) != 0 &&
                fnmatch(pattern, entries[i].pkg,   0) != 0)
                continue;
        }
        printf("diversion of %s to %s by %s\n",
               entries[i].orig, entries[i].divto, entries[i].pkg);
    }
    return 0;
}

static int cmd_listpackage(const char *file) {
    divert_entry_t *entries;
    entries = (divert_entry_t *)malloc(sizeof(divert_entry_t) * MAX_DIVERTS);
    if (!entries) { fprintf(stderr, "udpkg --divert: out of memory\n"); return 1; }
    int n, i;
    ensure_diversions_file();
    n = read_diversions(entries, MAX_DIVERTS);
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].orig, file) == 0) {
            printf("%s\n", entries[i].pkg);
            return 0;
        }
    }
    free(entries); return 1;
}

static int cmd_truename(const char *file) {
    divert_entry_t *entries;
    entries = (divert_entry_t *)malloc(sizeof(divert_entry_t) * MAX_DIVERTS);
    if (!entries) { fprintf(stderr, "udpkg --divert: out of memory\n"); return 1; }
    int n, i;
    ensure_diversions_file();
    n = read_diversions(entries, MAX_DIVERTS);
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].orig, file) == 0) {
            printf("%s\n", entries[i].divto);
            return 0;
        }
    }
    printf("%s\n", file);
    free(entries); return 0;
}

int op_divert(int argc, char **argv) {
    int i;
    const char *subcmd    = "--add";
    g_admindir[0] = '\0';
    g_instdir[0]  = '\0';
    g_root[0]     = '\0';
    const char *file      = NULL;
    const char *pkg       = NULL;
    const char *divert_to = NULL;
    int local             = 0;
    int rename_flag       = 0;
    int test              = 0;
    int no_rename         = 0;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--add") == 0) {
            subcmd = "--add";
        } else if (strcmp(argv[i], "--remove") == 0) {
            subcmd = "--remove";
        } else if (strcmp(argv[i], "--list") == 0) {
            subcmd = "--list";
        } else if (strcmp(argv[i], "--listpackage") == 0) {
            subcmd = "--listpackage";
        } else if (strcmp(argv[i], "--truename") == 0) {
            subcmd = "--truename";
        } else if (strcmp(argv[i], "--local") == 0) {
            local = 1;
        } else if (strcmp(argv[i], "--rename") == 0) {
            rename_flag = 1; no_rename = 0;
        } else if (strcmp(argv[i], "--no-rename") == 0) {
            no_rename = 1; rename_flag = 0;
        } else if (strcmp(argv[i], "--test") == 0) {
            test = 1;
        } else if (strcmp(argv[i], "--package") == 0) {
            if (i + 1 < argc) pkg = argv[++i];
        } else if (strncmp(argv[i], "--package=", 10) == 0) {
            pkg = argv[i] + 10;
        } else if (strcmp(argv[i], "--divert") == 0) {
            if (i + 1 < argc) divert_to = argv[++i];
        } else if (strncmp(argv[i], "--divert=", 9) == 0) {
            divert_to = argv[i] + 9;
        } else if (strcmp(argv[i], "--admindir") == 0) {
            if (i + 1 < argc) {
                strncpy(g_admindir, argv[++i], sizeof(g_admindir) - 1);
                g_admindir[sizeof(g_admindir) - 1] = '\0';
            }
        } else if (strncmp(argv[i], "--admindir=", 11) == 0) {
            strncpy(g_admindir, argv[i] + 11, sizeof(g_admindir) - 1);
            g_admindir[sizeof(g_admindir) - 1] = '\0';
        } else if (strcmp(argv[i], "--instdir") == 0) {
            if (i + 1 < argc) {
                strncpy(g_instdir, argv[++i], sizeof(g_instdir) - 1);
                g_instdir[sizeof(g_instdir) - 1] = '\0';
            }
        } else if (strncmp(argv[i], "--instdir=", 10) == 0) {
            strncpy(g_instdir, argv[i] + 10, sizeof(g_instdir) - 1);
            g_instdir[sizeof(g_instdir) - 1] = '\0';
        } else if (strcmp(argv[i], "--root") == 0) {
            if (i + 1 < argc) {
                strncpy(g_root, argv[++i], sizeof(g_root) - 1);
                g_root[sizeof(g_root) - 1] = '\0';
            }
        } else if (strncmp(argv[i], "--root=", 7) == 0) {
            strncpy(g_root, argv[i] + 7, sizeof(g_root) - 1);
            g_root[sizeof(g_root) - 1] = '\0';
        } else if (argv[i][0] != '-') {
            file = argv[i];
        } else {
            fprintf(stderr, "udpkg --divert: unknown option '%s'\n", argv[i]);
            return 2;
        }
    }
    (void)no_rename;
    if (strcmp(subcmd, "--list") == 0)
        return cmd_list(file);
    if (!file || file[0] == '\0') {
        fprintf(stderr, "udpkg --divert: %s requires a file argument\n", subcmd);
        return 2;
    }
    if (strcmp(subcmd, "--add") == 0)
        return cmd_add(file, pkg, divert_to, local, rename_flag, test);
    if (strcmp(subcmd, "--remove") == 0)
        return cmd_remove(file, rename_flag, test);
    if (strcmp(subcmd, "--listpackage") == 0)
        return cmd_listpackage(file);
    if (strcmp(subcmd, "--truename") == 0)
        return cmd_truename(file);
    fprintf(stderr, "udpkg --divert: unknown subcommand '%s'\n", subcmd);
    return 2;
}
