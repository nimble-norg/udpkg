#define _POSIX_C_SOURCE 200809L
#include "trigger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#define TRIG_NAME_MAX 256
#define TRIG_PKG_MAX  256

static char g_admindir[4096] = "";

static const char *admindir(void) {
    if (g_admindir[0])
        return g_admindir;
    return "/var/lib/udpkg";
}

void trig_set_admindir(const char *dir) {
    if (!dir || dir[0] == '\0') {
        g_admindir[0] = '\0';
        return;
    }
    strncpy(g_admindir, dir, sizeof(g_admindir) - 1);
    g_admindir[sizeof(g_admindir) - 1] = '\0';
}

static void trim(char *s) {
    size_t len = strlen(s);
    char *p;
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                        s[len-1] == ' '  || s[len-1] == '\t'))
        s[--len] = '\0';
    p = s;
    while (*p == ' ' || *p == '\t')
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
}

static void strip_comment(char *s) {
    char *h = strchr(s, '#');
    if (h)
        *h = '\0';
}

int trig_parse_file(const char *path,
                    void (*icb)(const char *, int, void *), void *idata,
                    void (*acb)(const char *, int, void *), void *adata) {
    FILE *fp;
    char line[1024];
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char name[TRIG_NAME_MAX];
        strip_comment(line);
        trim(line);
        if (line[0] == '\0')
            continue;
        if (strncmp(line, "interest-noawait ", 17) == 0) {
            strncpy(name, line + 17, TRIG_NAME_MAX - 1);
            name[TRIG_NAME_MAX - 1] = '\0';
            trim(name);
            if (name[0] && icb)
                icb(name, TRIG_NOAWAIT, idata);
        } else if (strncmp(line, "interest-await ", 15) == 0) {
            strncpy(name, line + 15, TRIG_NAME_MAX - 1);
            name[TRIG_NAME_MAX - 1] = '\0';
            trim(name);
            if (name[0] && icb)
                icb(name, TRIG_AWAIT, idata);
        } else if (strncmp(line, "interest ", 9) == 0) {
            strncpy(name, line + 9, TRIG_NAME_MAX - 1);
            name[TRIG_NAME_MAX - 1] = '\0';
            trim(name);
            if (name[0] && icb)
                icb(name, TRIG_AWAIT, idata);
        } else if (strncmp(line, "activate-noawait ", 17) == 0) {
            strncpy(name, line + 17, TRIG_NAME_MAX - 1);
            name[TRIG_NAME_MAX - 1] = '\0';
            trim(name);
            if (name[0] && acb)
                acb(name, TRIG_NOAWAIT, adata);
        } else if (strncmp(line, "activate-await ", 15) == 0) {
            strncpy(name, line + 15, TRIG_NAME_MAX - 1);
            name[TRIG_NAME_MAX - 1] = '\0';
            trim(name);
            if (name[0] && acb)
                acb(name, TRIG_AWAIT, adata);
        } else if (strncmp(line, "activate ", 9) == 0) {
            strncpy(name, line + 9, TRIG_NAME_MAX - 1);
            name[TRIG_NAME_MAX - 1] = '\0';
            trim(name);
            if (name[0] && acb)
                acb(name, TRIG_AWAIT, adata);
        } else {
            fclose(fp);
            return -2;
        }
    }
    fclose(fp);
    return 0;
}

int trig_install_interests(const char *pkg, const char *src) {
    char dst[4096];
    FILE *fs, *fd;
    char buf[4096];
    size_t nr;
    snprintf(dst, sizeof(dst), "%s/info/%s.triggers", admindir(), pkg);
    fs = fopen(src, "r");
    if (!fs)
        return -1;
    fd = fopen(dst, "w");
    if (!fd) {
        fclose(fs);
        return -1;
    }
    while ((nr = fread(buf, 1, sizeof(buf), fs)) > 0)
        fwrite(buf, 1, nr, fd);
    fclose(fs);
    fclose(fd);
    return 0;
}

int trig_remove_interests(const char *pkg) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/info/%s.triggers", admindir(), pkg);
    unlink(path);
    return 0;
}

static const char *pending_path(void) {
    static char buf[4096];
    snprintf(buf, sizeof(buf), "%s/triggers", admindir());
    return buf;
}

int trig_pending_add(const char *trigname, const char *by_pkg, int noawait) {
    FILE *fp;
    fp = fopen(pending_path(), "a");
    if (!fp)
        return -1;
    fprintf(fp, "%s %s %s\n",
            trigname,
            by_pkg && by_pkg[0] ? by_pkg : "-",
            noawait ? "noawait" : "await");
    fclose(fp);
    return 0;
}

typedef struct {
    char trigname[TRIG_NAME_MAX];
    char by_pkg[TRIG_PKG_MAX];
    int  noawait;
} pending_entry_t;

#define PEND_MAX 512

static int read_pending(pending_entry_t *out, int maxn) {
    FILE *fp;
    char line[1024];
    int n = 0;
    fp = fopen(pending_path(), "r");
    if (!fp)
        return 0;
    while (n < maxn && fgets(line, sizeof(line), fp)) {
        char trig[TRIG_NAME_MAX], pkg[TRIG_PKG_MAX], mode[32];
        strip_comment(line);
        trim(line);
        if (line[0] == '\0')
            continue;
        if (sscanf(line, "%255s %255s %31s", trig, pkg, mode) < 2)
            continue;
        strncpy(out[n].trigname, trig, TRIG_NAME_MAX - 1);
        out[n].trigname[TRIG_NAME_MAX - 1] = '\0';
        strncpy(out[n].by_pkg, pkg, TRIG_PKG_MAX - 1);
        out[n].by_pkg[TRIG_PKG_MAX - 1] = '\0';
        out[n].noawait = (strcmp(mode, "noawait") == 0);
        n++;
    }
    fclose(fp);
    return n;
}

static int pkg_interested_in(const char *pkg, const char *trigname,
                              int *out_noawait) {
    char path[4096];
    FILE *fp;
    char line[1024];
    snprintf(path, sizeof(path), "%s/info/%s.triggers", admindir(), pkg);
    fp = fopen(path, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char name[TRIG_NAME_MAX];
        int na = 0;
        strip_comment(line);
        trim(line);
        if (line[0] == '\0')
            continue;
        if (strncmp(line, "interest-noawait ", 17) == 0) {
            strncpy(name, line + 17, TRIG_NAME_MAX - 1);
            na = 1;
        } else if (strncmp(line, "interest-await ", 15) == 0) {
            strncpy(name, line + 15, TRIG_NAME_MAX - 1);
        } else if (strncmp(line, "interest ", 9) == 0) {
            strncpy(name, line + 9, TRIG_NAME_MAX - 1);
        } else {
            continue;
        }
        name[TRIG_NAME_MAX - 1] = '\0';
        trim(name);
        if (strcmp(name, trigname) == 0) {
            fclose(fp);
            if (out_noawait)
                *out_noawait = na;
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int trig_pending_run(int (*run_postinst)(const char *, const char *)) {
    pending_entry_t pend[PEND_MAX];
    int npend;
    int i;
    char info_dir[4096];
    DIR *dp;
    struct dirent *de;
    int ran_any = 0;

    snprintf(info_dir, sizeof(info_dir), "%s/info", admindir());

    npend = read_pending(pend, PEND_MAX);
    if (npend == 0)
        return 0;

    dp = opendir(info_dir);
    if (!dp)
        return 0;

    while ((de = readdir(dp)) != NULL) {
        char *dot;
        char pkg[TRIG_PKG_MAX];
        size_t nlen;
        if (de->d_name[0] == '.')
            continue;
        dot = strrchr(de->d_name, '.');
        if (!dot || strcmp(dot, ".triggers") != 0)
            continue;
        nlen = (size_t)(dot - de->d_name);
        if (nlen == 0 || nlen >= TRIG_PKG_MAX)
            continue;
        memcpy(pkg, de->d_name, nlen);
        pkg[nlen] = '\0';
        for (i = 0; i < npend; i++) {
            int na = 0;
            if (pkg_interested_in(pkg, pend[i].trigname, &na)) {
                if (run_postinst)
                    run_postinst(pkg, pend[i].trigname);
                ran_any = 1;
                break;
            }
        }
    }
    closedir(dp);
    (void)ran_any;
    return 0;
}

void trig_pending_clear(void) {
    unlink(pending_path());
}

typedef struct {
    const char *by_pkg;
    int         force_noawait;
} activate_ctx_t;

static void do_activate(const char *name, int noawait, void *data) {
    activate_ctx_t *ctx = (activate_ctx_t *)data;
    int na = (noawait || ctx->force_noawait) ? TRIG_NOAWAIT : TRIG_AWAIT;
    trig_pending_add(name, ctx->by_pkg, na);
}

int trig_activate_from_file(const char *triggers_file, const char *by_pkg,
                             int force_noawait) {
    activate_ctx_t ctx;
    ctx.by_pkg       = by_pkg;
    ctx.force_noawait = force_noawait;
    return trig_parse_file(triggers_file, NULL, NULL, do_activate, &ctx);
}

int trig_process_for_pkg(const char *pkg_triggers_file,
                          int (*run_postinst)(const char *, const char *)) {
    (void)pkg_triggers_file;
    (void)run_postinst;
    return 0;
}

int op_trigger(const char *trigname, const char *by_pkg,
               int noawait, int no_act) {
    if (!trigname || trigname[0] == '\0') {
        fprintf(stderr, "udpkg: --trigger requires a trigger name\n");
        return 1;
    }
    if (no_act) {
        printf("Would activate trigger: %s\n", trigname);
        return 0;
    }
    if (trig_pending_add(trigname, by_pkg ? by_pkg : "-", noawait) != 0) {
        fprintf(stderr, "udpkg: failed to activate trigger '%s'\n", trigname);
        return 2;
    }
    return 0;
}

int op_check_supported(void) {
    return 0;
}
