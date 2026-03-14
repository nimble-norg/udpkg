#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include "ar.h"
#include "ctrl.h"
#include "db.h"
#include "deb_fmt.h"
#include "dep.h"
#include "lock.h"
#include "log.h"
#include "utar.h"
#include "status_notify.h"

extern int chroot(const char *);

#define BATCH_MAX      256
#define MISS_MAX       DEP_MISS_MAX
#define IGNORE_DEP_MAX 64

static char g_root[4096]          = "";
static char g_instdir[4096]       = "";
static int  g_force_chrootless    = 0;
static int  g_force_deps          = 0;
static int  g_force_not_root      = 0;
static int  g_force_overwrite     = 0;
static int  g_force_overwrite_dir = 0;
static int  g_force_confnew       = 0;
static int  g_force_confold       = 0;
static int  g_skip_same_version   = 0;
static int  g_refuse_downgrade    = 0;
static int  g_no_check            = 0;
static int  g_build_fmt           = DEB_FMT_NEW;

#define COMP_GZIP 0
#define COMP_XZ   1
#define COMP_ZSTD 2
#define COMP_NONE 3
static int  g_compression         = COMP_GZIP;
static int  g_comp_level          = -1;
static int  g_comp_strat_gz       = -1;
static int  g_comp_strat_xz       = 0;
static int  g_verbose             = 0;
static int  g_root_owner_group    = 0;
static int  g_abort_after         = 0;
static int  g_simulate            = 0;
static int  g_format              = DEB_FMT_AUTO;
static int  g_no_pager            = 0;

static const char *g_ignore_dep[IGNORE_DEP_MAX];
static int         g_nignore_dep = 0;

static const char *effective_instdir(void) {
    if (g_instdir[0])
        return g_instdir;
    if (g_root[0])
        return g_root;
    return "/";
}

static int cmd_available(const char *cmd) {
    const char *path_env;
    char buf[4096];
    char *p, *save;
    struct stat st;
    if (strchr(cmd, '/'))
        return stat(cmd, &st) == 0 && (st.st_mode & S_IXUSR);
    path_env = getenv("PATH");
    if (!path_env)
        path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    strncpy(buf, path_env, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    p = strtok_r(buf, ":", &save);
    while (p) {
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", p, cmd);
        if (stat(full, &st) == 0 && (st.st_mode & S_IXUSR))
            return 1;
        p = strtok_r(NULL, ":", &save);
    }
    return 0;
}

static int check_prereqs(void) {
    static const char * const required_always[] = { "rm", "sh", NULL };
    int i, ok = 1;
    for (i = 0; required_always[i]; i++) {
        if (!cmd_available(required_always[i])) {
            fprintf(stderr, "udpkg: required command not found in PATH: %s\n",
                    required_always[i]);
            ok = 0;
        }
    }
    if (utar_get_impl() == TARIMPL_EXTERNAL && !cmd_available("tar")) {
        fprintf(stderr, "udpkg: required command not found in PATH: tar\n");
        ok = 0;
    }
    return ok;
}

static int xrun(char *const argv[]) {
    pid_t pid;
    int status;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void cleanup_dir(const char *dir) {
    char *const argv[] = { "rm", "-rf", "--", (char *)dir, NULL };
    pid_t pid = fork();
    if (pid == 0) {
        execvp("rm", argv);
        _exit(1);
    }
    if (pid > 0)
        waitpid(pid, NULL, 0);
}

#define CONFFILE_MAX  256
#define CONF_ACT_NEW  1
#define CONF_ACT_OLD  2

typedef struct {
    char path[4096];
    char fspath[4096];
    char tmpbak[4096];
    int  existed;
    int  action;
} conf_entry_t;

static int copy_file(const char *src, const char *dst) {
    char buf[8192];
    ssize_t n;
    int in, out;
    in = open(src, O_RDONLY);
    if (in < 0)
        return -1;
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            close(in);
            close(out);
            return -1;
        }
    }
    close(in);
    close(out);
    return n < 0 ? -1 : 0;
}

static int load_conffiles(const char *ctrl_dir,
                           conf_entry_t *confs, int *nconfs) {
    char cfpath[4096];
    char line[4096];
    FILE *fp;
    struct stat st;
    *nconfs = 0;
    snprintf(cfpath, sizeof(cfpath), "%s/conffiles", ctrl_dir);
    if (stat(cfpath, &st) != 0) {
        snprintf(cfpath, sizeof(cfpath), "%s/DEBIAN/conffiles", ctrl_dir);
        if (stat(cfpath, &st) != 0)
            return 0;
    }
    fp = fopen(cfpath, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp) && *nconfs < CONFFILE_MAX) {
        size_t len = strlen(line);
        while (len > 0 &&
               (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
            line[--len] = '\0';
        if (len == 0 || line[0] != '/')
            continue;
        strncpy(confs[*nconfs].path,   line, sizeof(confs[0].path)   - 1);
        confs[*nconfs].path[sizeof(confs[0].path)-1]   = '\0';
        confs[*nconfs].fspath[0]  = '\0';
        confs[*nconfs].tmpbak[0]  = '\0';
        confs[*nconfs].existed    = 0;
        confs[*nconfs].action     = 0;
        (*nconfs)++;
    }
    fclose(fp);
    return 0;
}

static int prompt_conffile(const char *cfpath, const char *fspath) {
    char answer[64];
    int action = CONF_ACT_OLD;
    while (1) {
        printf("\nConfiguration file '%s'\n", cfpath);
        printf(" ==> Modified since installation.\n");
        printf(" ==> Package distributor has shipped an updated version.\n\n");
        printf("   What would you like to do about it?\n\n");
        printf("    Y or I  : install the package maintainer's version\n");
        printf("    N or O  : keep your currently-installed version\n");
        printf("    Z       : start a shell to examine the situation\n");
        printf("\n*** '%s' (Y/I/N/O/Z) [default=N] ? ", cfpath);
        fflush(stdout);
        if (!fgets(answer, sizeof(answer), stdin)) {
            action = CONF_ACT_OLD;
            break;
        }
        {
            size_t len = strlen(answer);
            while (len > 0 && (answer[len-1] == '\n' || answer[len-1] == '\r'
                               || answer[len-1] == ' '))
                answer[--len] = '\0';
        }
        if (answer[0] == '\0' || strcmp(answer, "N") == 0
            || strcmp(answer, "n") == 0 || strcmp(answer, "O") == 0
            || strcmp(answer, "o") == 0) {
            action = CONF_ACT_OLD;
            break;
        }
        if (strcmp(answer, "Y") == 0 || strcmp(answer, "y") == 0
            || strcmp(answer, "I") == 0 || strcmp(answer, "i") == 0) {
            action = CONF_ACT_NEW;
            break;
        }
        if (strcmp(answer, "Z") == 0 || strcmp(answer, "z") == 0) {
            pid_t pid;
            int status;
            char dir[4096];
            const char *sh;
            strncpy(dir, fspath, sizeof(dir) - 1);
            dir[sizeof(dir) - 1] = '\0';
            {
                char *sl = strrchr(dir, '/');
                if (sl && sl != dir)
                    *sl = '\0';
                else
                    strncpy(dir, "/", sizeof(dir) - 1);
            }
            sh = getenv("SHELL");
            if (!sh || sh[0] == '\0')
                sh = "/bin/sh";
            printf("\nType 'exit' to return to the prompt.\n");
            fflush(stdout);
            pid = fork();
            if (pid == 0) {
                if (chdir(dir) != 0)
                    chdir("/");
                execl(sh, sh, (char *)NULL);
                _exit(127);
            }
            if (pid > 0)
                waitpid(pid, &status, 0);
        }
    }
    return action;
}

static int conffiles_presave(conf_entry_t *confs, int nconfs,
                              const char *pkgname, int is_upgrade) {
    int i;
    const char *base = effective_instdir();
    struct stat st;
    for (i = 0; i < nconfs; i++) {
        if (strcmp(base, "/") == 0)
            strncpy(confs[i].fspath, confs[i].path, sizeof(confs[i].fspath) - 1);
        else
            snprintf(confs[i].fspath, sizeof(confs[i].fspath),
                     "%s%s", base, confs[i].path);
        confs[i].fspath[sizeof(confs[i].fspath) - 1] = '\0';
        if (lstat(confs[i].fspath, &st) != 0)
            continue;
        if (!g_force_confnew && !g_force_confold) {
            if (is_upgrade && db_is_conffile(pkgname, confs[i].path))
                continue;
        }
        confs[i].existed = 1;
        {
            size_t fslen = strlen(confs[i].fspath);
            size_t tbsz  = sizeof(confs[i].tmpbak);
            size_t copy  = fslen < tbsz - 10 ? fslen : tbsz - 10;
            memcpy(confs[i].tmpbak, confs[i].fspath, copy);
            memcpy(confs[i].tmpbak + copy, ".dpkg-tmp", 10);
        }
        copy_file(confs[i].fspath, confs[i].tmpbak);
    }
    return 0;
}

static void conffiles_apply(conf_entry_t *confs, int nconfs) {
    int i;
    for (i = 0; i < nconfs; i++) {
        int act;
        if (!confs[i].existed)
            continue;
        if (g_force_confnew)
            act = CONF_ACT_NEW;
        else if (g_force_confold)
            act = CONF_ACT_OLD;
        else
            act = prompt_conffile(confs[i].path, confs[i].fspath);
        if (act == CONF_ACT_NEW) {
            char dpkg_old[4096];
            size_t fslen = strlen(confs[i].fspath);
            size_t copy  = fslen < sizeof(dpkg_old) - 10 ? fslen : sizeof(dpkg_old) - 10;
            memcpy(dpkg_old, confs[i].fspath, copy);
            memcpy(dpkg_old + copy, ".dpkg-old", 10);
            rename(confs[i].tmpbak, dpkg_old);
        } else {
            char dpkg_dist[4096];
            size_t fslen = strlen(confs[i].fspath);
            size_t copy  = fslen < sizeof(dpkg_dist) - 11 ? fslen : sizeof(dpkg_dist) - 11;
            memcpy(dpkg_dist, confs[i].fspath, copy);
            memcpy(dpkg_dist + copy, ".dpkg-dist", 11);
            rename(confs[i].fspath, dpkg_dist);
            rename(confs[i].tmpbak, confs[i].fspath);
        }
    }
}

static void conffiles_cleanup_tmp(conf_entry_t *confs, int nconfs) {
    int i;
    for (i = 0; i < nconfs; i++) {
        if (confs[i].tmpbak[0])
            unlink(confs[i].tmpbak);
    }
}

static int tmpci_setup(void) {
    cleanup_dir(db_tmpci());
    if (mkdir(db_tmpci(), 0700) != 0)
        return -1;
    if (mkdir(db_tmpci_ctrl(), 0700) != 0)
        return -1;
    return 0;
}

static void tmpci_cleanup(void) {
    cleanup_dir(db_tmpci());
}

static int normalize_filelist(const char *src, const char *dst) {
    FILE *in = fopen(src, "r");
    FILE *out;
    char line[4096];
    if (!in)
        return -1;
    out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return -1;
    }
    while (fgets(line, sizeof(line), in)) {
        char *p = line;
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r'))
            p[--len] = '\0';
        if (len == 0)
            continue;
        while (p[0] == '.' && p[1] == '/')
            p += 2;
        if (p[0] == '\0' || strcmp(p, ".") == 0 || strcmp(p, "/") == 0)
            continue;
        if (len > 0 && p[len-1] == '/')
            p[--len] = '\0';
        if (len == 0)
            continue;
        if (p[0] != '/')
            fprintf(out, "/%s\n", p);
        else
            fprintf(out, "%s\n", p);
    }
    fclose(in);
    fclose(out);
    return 0;
}

static int count_lines(const char *path) {
    FILE *fp = fopen(path, "r");
    int n = 0, c;
    if (!fp)
        return 0;
    while ((c = fgetc(fp)) != EOF)
        if (c == '\n')
            n++;
    fclose(fp);
    return n;
}

static int run_script_chroot(const char *path_rel,
                              const char *arg1, const char *arg2,
                              int *chroot_failed) {
    int pipefd[2];
    pid_t pid;
    int status;
    char ch;
    *chroot_failed = 0;
    if (pipe(pipefd) != 0) {
        *chroot_failed = 1;
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        *chroot_failed = 1;
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (chroot(g_root) != 0 || chdir("/") != 0) {
            write(pipefd[1], "F", 1);
            close(pipefd[1]);
            _exit(125);
        }
        close(pipefd[1]);
        if (arg2)
            execl(path_rel, path_rel, arg1, arg2, (char *)NULL);
        else
            execl(path_rel, path_rel, arg1, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    *chroot_failed = (read(pipefd[0], &ch, 1) == 1 && ch == 'F');
    close(pipefd[0]);
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_script_chrootless(const char *path,
                                  const char *arg1, const char *arg2) {
    pid_t pid;
    int status;
    const char *dpkg_root;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* --instdir takes priority; fall back to --root if set */
        if (g_instdir[0] != '\0')
            dpkg_root = g_instdir;
        else if (g_root[0] != '\0')
            dpkg_root = g_root;
        else
            dpkg_root = NULL;
        if (dpkg_root)
            setenv("DPKG_ROOT", dpkg_root, 1);
        if (arg2)
            execl(path, path, arg1, arg2, (char *)NULL);
        else
            execl(path, path, arg1, (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_script(const char *path, const char *arg1, const char *arg2) {
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!(st.st_mode & S_IXUSR))
        return 0;
    /* --instdir explicitly means no chroot; always use chrootless path */
    if (g_instdir[0] != '\0')
        return run_script_chrootless(path, arg1, arg2);
    if (g_root[0] != '\0' && !g_force_chrootless) {
        const char *rel = path + strlen(g_root);
        int chroot_failed = 0;
        int rc = run_script_chroot(rel, arg1, arg2, &chroot_failed);
        if (!chroot_failed && rc != 127)
            return rc;
        if (chroot_failed)
            fprintf(stderr,
                "udpkg: chroot into '%s' failed, "
                "falling back to chrootless execution\n", g_root);
        else
            fprintf(stderr,
                "udpkg: script failed inside chroot (exit 127), "
                "falling back to chrootless execution\n");
    }
    return run_script_chrootless(path, arg1, arg2);
}

static int run_installed_script(const char *pkgname, const char *script,
                                 const char *arg1, const char *arg2) {
    char path[4096];
    db_get_scriptpath(pkgname, script, path, sizeof(path));
    return run_script(path, arg1, arg2);
}

static int read_ctrl_from_deb(const char *debpath, ctrl_t *ctrl) {
    char tmpscan[64];
    char ctrl_tar[256];
    char ctrl_dir[256];
    char ctrl_file[512];
    int used_fmt, ret;
    struct stat st;
    strncpy(tmpscan, "/tmp/udpkg_scan_XXXXXX", sizeof(tmpscan) - 1);
    tmpscan[sizeof(tmpscan) - 1] = '\0';
    if (!mkdtemp(tmpscan))
        return -1;
    if (deb_open(debpath, g_format, tmpscan,
                 ctrl_tar, sizeof(ctrl_tar), NULL,
                 NULL, 0,
                 1, 0, &used_fmt) != 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", tmpscan);
    if (mkdir(ctrl_dir, 0755) != 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    {
        if (utar_extract(ctrl_tar, ctrl_dir, 0) != 0) {
            cleanup_dir(tmpscan);
            return -1;
        }
    }
    snprintf(ctrl_file, sizeof(ctrl_file), "%s/control", ctrl_dir);
    if (stat(ctrl_file, &st) != 0) {
        char ctrl_file2[512];
        snprintf(ctrl_file2, sizeof(ctrl_file2), "%s/DEBIAN/control", ctrl_dir);
        if (stat(ctrl_file2, &st) != 0) {
            cleanup_dir(tmpscan);
            return -1;
        }
        strncpy(ctrl_file, ctrl_file2, sizeof(ctrl_file) - 1);
        ctrl_file[sizeof(ctrl_file) - 1] = '\0';
    }
    ret = ctrl_parse(ctrl_file, ctrl);
    cleanup_dir(tmpscan);
    return ret;
}

static int op_info(const char *debpath) {
    char tmpscan[64];
    char ctrl_tar[256];
    char ctrl_dir[256];
    size_t ctrl_archive_size = 0;
    struct stat deb_st;
    ctrl_t ctrl;
    int i, used_fmt;
    if (stat(debpath, &deb_st) != 0) {
        fprintf(stderr, "udpkg: cannot stat '%s': %s\n",
                debpath, strerror(errno));
        return -1;
    }
    strncpy(tmpscan, "/tmp/udpkg_info_XXXXXX", sizeof(tmpscan) - 1);
    tmpscan[sizeof(tmpscan) - 1] = '\0';
    if (!mkdtemp(tmpscan))
        return -1;
    if (deb_open(debpath, g_format, tmpscan,
                 ctrl_tar, sizeof(ctrl_tar), &ctrl_archive_size,
                 NULL, 0,
                 1, 0, &used_fmt) != 0) {
        fprintf(stderr, "udpkg: cannot open '%s': not a valid .deb archive\n",
                debpath);
        cleanup_dir(tmpscan);
        return -1;
    }
    log_write("info %s format:%s", debpath,
              used_fmt == DEB_FMT_OLD ? "old" : "new");
    snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", tmpscan);
    if (mkdir(ctrl_dir, 0755) != 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    {
        if (utar_extract(ctrl_tar, ctrl_dir, 0) != 0) {
            fprintf(stderr, "udpkg: failed to extract control archive\n");
            cleanup_dir(tmpscan);
            return -1;
        }
    }
    {
        char ctrl_file[512];
        char ctrl_file2[512];
        struct stat cst;
        snprintf(ctrl_file, sizeof(ctrl_file), "%s/control", ctrl_dir);
        if (stat(ctrl_file, &cst) != 0) {
            snprintf(ctrl_file2, sizeof(ctrl_file2),
                     "%s/DEBIAN/control", ctrl_dir);
            if (stat(ctrl_file2, &cst) != 0 ||
                ctrl_parse(ctrl_file2, &ctrl) != 0) {
                fprintf(stderr, "udpkg: cannot parse control file\n");
                cleanup_dir(tmpscan);
                return -1;
            }
        } else if (ctrl_parse(ctrl_file, &ctrl) != 0) {
            fprintf(stderr, "udpkg: cannot parse control file\n");
            cleanup_dir(tmpscan);
            return -1;
        }
    }
    if (used_fmt == DEB_FMT_OLD)
        printf(" old Debian package, version 0.939000.\n");
    else
        printf(" new Debian package, version 2.0.\n");
    printf(" size %lld bytes: control archive=%zu bytes.\n",
           (long long)deb_st.st_size, ctrl_archive_size);
    {
        DIR *dir;
        struct dirent *de;
        dir = opendir(ctrl_dir);
        if (dir) {
            while ((de = readdir(dir)) != NULL) {
                char fpath[512];
                struct stat fst;
                int lines;
                if (de->d_name[0] == '.')
                    continue;
                snprintf(fpath, sizeof(fpath), "%s/%s", ctrl_dir, de->d_name);
                if (stat(fpath, &fst) != 0 || S_ISDIR(fst.st_mode))
                    continue;
                lines = count_lines(fpath);
                printf(" %7lld bytes, %5d lines      %s\n",
                       (long long)fst.st_size, lines, de->d_name);
            }
            closedir(dir);
        }
    }
    for (i = 0; i < ctrl.nfields; i++)
        printf(" %s: %s\n", ctrl.fields[i].key, ctrl.fields[i].val);
    cleanup_dir(tmpscan);
    return 0;
}

static int op_install_one(const char *debpath,
                           const char * const *batch, int nbatch,
                           int force) {
    char ctrl_tar[4096];
    char data_tar[4096];
    char ctrl_file[4096];
    char raw_list[4096];
    char norm_list[4096];
    char conffiles_src[4096];
    conf_entry_t confs[CONFFILE_MAX];
    int nconfs = 0;
    struct stat st;
    ctrl_t ctrl;
    const char *pkgname, *depends, *arch, *ver;
    dep_list_t dl;
    char missing[MISS_MAX][DEP_MISS_MAX];
    int nmissing = 0;
    int is_upgrade = 0;
    int used_fmt = DEB_FMT_AUTO;
    char oldver[256];
    static const char * const mscripts[] =
        { "preinst", "postinst", "prerm", "postrm", NULL };
    int i;
    if (!g_simulate && !g_no_check && !check_prereqs())
        return -1;
    if (tmpci_setup() != 0) {
        fprintf(stderr, "udpkg: cannot create %s\n", db_tmpci());
        return -1;
    }
    if (deb_open(debpath, g_format, db_tmpci(),
                 ctrl_tar, sizeof(ctrl_tar), NULL,
                 data_tar, sizeof(data_tar),
                 1, 1, &used_fmt) != 0) {
        fprintf(stderr,
            "udpkg: cannot open '%s': not a valid .deb archive\n", debpath);
        tmpci_cleanup();
        return -1;
    }
    {
        if (utar_extract(ctrl_tar, db_tmpci_ctrl(), 0) != 0) {
            fprintf(stderr, "udpkg: failed to extract control archive\n");
            tmpci_cleanup();
            return -1;
        }
    }
    snprintf(ctrl_file, sizeof(ctrl_file), "%s/control", db_tmpci_ctrl());
    if (stat(ctrl_file, &st) != 0) {
        char ctrl_file2[4096];
        snprintf(ctrl_file2, sizeof(ctrl_file2),
                 "%s/DEBIAN/control", db_tmpci_ctrl());
        if (stat(ctrl_file2, &st) != 0) {
            fprintf(stderr, "udpkg: control file not found in package\n");
            tmpci_cleanup();
            return -1;
        }
        strncpy(ctrl_file, ctrl_file2, sizeof(ctrl_file) - 1);
        ctrl_file[sizeof(ctrl_file) - 1] = '\0';
    }
    if (ctrl_parse(ctrl_file, &ctrl) != 0) {
        fprintf(stderr, "udpkg: cannot parse control file\n");
        tmpci_cleanup();
        return -1;
    }
    {
        ctrl_diags_t diags;
        int di;
        ctrl_validate(&ctrl, &diags);
        for (di = 0; di < diags.ndiags; di++) {
            const ctrl_diag_t *dg = &diags.items[di];
            const char *pkg_id = ctrl_get(&ctrl, "Package");
            if (dg->severity == CTRL_VALID_FATAL) {
                if (pkg_id && dg->line >= 0)
                    fprintf(stderr,
                        "udpkg: %s: control field error at line %d (%s): %s\n",
                        pkg_id, dg->line, dg->field, dg->msg);
                else if (pkg_id)
                    fprintf(stderr,
                        "udpkg: %s: control field error (%s): %s\n",
                        pkg_id, dg->field, dg->msg);
                else if (dg->line >= 0)
                    fprintf(stderr,
                        "udpkg: control field error at line %d (%s): %s\n",
                        dg->line, dg->field, dg->msg);
                else
                    fprintf(stderr,
                        "udpkg: control field error (%s): %s\n",
                        dg->field, dg->msg);
                tmpci_cleanup();
                return -1;
            }
            if (dg->severity == CTRL_VALID_WARN) {
                const char *pkg_id2 = ctrl_get(&ctrl, "Package");
                if (pkg_id2 && dg->line >= 0)
                    fprintf(stderr,
                        "udpkg: warning: %s: line %d (%s): %s\n",
                        pkg_id2, dg->line, dg->field, dg->msg);
                else if (pkg_id2)
                    fprintf(stderr,
                        "udpkg: warning: %s: (%s): %s\n",
                        pkg_id2, dg->field, dg->msg);
                else if (dg->line >= 0)
                    fprintf(stderr,
                        "udpkg: warning: line %d (%s): %s\n",
                        dg->line, dg->field, dg->msg);
                else
                    fprintf(stderr,
                        "udpkg: warning: (%s): %s\n",
                        dg->field, dg->msg);
            }
        }
    }
    pkgname = ctrl_get(&ctrl, "Package");
    if (!pkgname) {
        fprintf(stderr, "udpkg: control file missing Package field\n");
        tmpci_cleanup();
        return -1;
    }
    log_write("format %s %s", pkgname,
              used_fmt == DEB_FMT_OLD ? "old(0.939000)" : "new(2.0)");
    conffiles_src[0] = '\0';
    {
        char cf1[4096], cf2[4096];
        snprintf(cf1, sizeof(cf1), "%s/conffiles", db_tmpci_ctrl());
        snprintf(cf2, sizeof(cf2), "%s/DEBIAN/conffiles", db_tmpci_ctrl());
        if (stat(cf1, &st) == 0)
            strncpy(conffiles_src, cf1, sizeof(conffiles_src) - 1);
        else if (stat(cf2, &st) == 0)
            strncpy(conffiles_src, cf2, sizeof(conffiles_src) - 1);
        conffiles_src[sizeof(conffiles_src) - 1] = '\0';
    }
    if (conffiles_src[0])
        load_conffiles(db_tmpci_ctrl(), confs, &nconfs);
    arch = ctrl_get(&ctrl, "Architecture");
    ver  = ctrl_get(&ctrl, "Version");
    {
        char inst_ver[256];
        inst_ver[0] = '\0';
        if (db_is_installed(pkgname))
            db_get_version(pkgname, inst_ver, sizeof(inst_ver));
        if (inst_ver[0] && ver) {
            if (g_skip_same_version) {
                int cmp = ver_cmp_public(ver, inst_ver);
                if (cmp == 0) {
                    fprintf(stderr,
                        "udpkg: %s: skipping, same version (%s) already installed\n",
                        pkgname, inst_ver);
                    tmpci_cleanup();
                    return 0;
                }
            }
            if (g_refuse_downgrade) {
                int cmp = ver_cmp_public(ver, inst_ver);
                if (cmp < 0) {
                    fprintf(stderr,
                        "udpkg: %s: skipping, would downgrade from %s to %s\n",
                        pkgname, inst_ver, ver);
                    tmpci_cleanup();
                    return 0;
                }
            }
        }
    }
    depends = ctrl_get(&ctrl, "Depends");
    dep_parse(depends ? depends : "", &dl);
    dep_check(&dl, batch, nbatch, missing, &nmissing, MISS_MAX);
    if (nmissing > 0) {
        if (!force) {
            int m;
            fprintf(stderr,
                "udpkg: %s: dependency problems prevent installation:\n",
                pkgname);
            for (m = 0; m < nmissing; m++)
                fprintf(stderr,
                    "  udpkg: %s depends on %s; however:\n"
                    "   Package %s is not installed.\n",
                    pkgname, missing[m], missing[m]);
            fprintf(stderr,
                "\nudpkg: error processing package %s (--install):\n"
                " dependency problems - leaving unconfigured\n"
                " Use -f to force installation despite unmet dependencies.\n",
                pkgname);
            tmpci_cleanup();
            return -1;
        }
        {
            int m;
            fprintf(stderr,
                "udpkg: warning: %s: ignoring dependency problems:\n",
                pkgname);
            for (m = 0; m < nmissing; m++)
                fprintf(stderr, "  missing: %s\n", missing[m]);
        }
    }
    snprintf(raw_list,  sizeof(raw_list),  "%s/raw.list",  db_tmpci());
    snprintf(norm_list, sizeof(norm_list), "%s/norm.list", db_tmpci());
    {
        utar_list(data_tar, 0, raw_list);
    }
    normalize_filelist(raw_list, norm_list);
    {
        FILE *fp;
        char line[4096];
        int conflict_found = 0;
        fp = fopen(norm_list, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                char owner[256];
                char fspath[4096];
                size_t len = strlen(line);
                int is_dir;
                while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                    line[--len] = '\0';
                if (len == 0)
                    continue;
                if (db_find_file_owner(line, pkgname, owner, sizeof(owner)) != 0)
                    continue;
                {
                    int ci, is_conffile_path = 0;
                    for (ci = 0; ci < nconfs; ci++) {
                        if (strcmp(confs[ci].path, line) == 0) {
                            is_conffile_path = 1;
                            break;
                        }
                    }
                    if (is_conffile_path)
                        continue;
                }
                {
                    const char *base = effective_instdir();
                    if (strcmp(base, "/") == 0)
                        strncpy(fspath, line, sizeof(fspath) - 1);
                    else
                        snprintf(fspath, sizeof(fspath), "%s%s", base, line);
                    fspath[sizeof(fspath) - 1] = '\0';
                }
                is_dir = (lstat(fspath, &st) == 0 && S_ISDIR(st.st_mode));
                if (is_dir)
                    continue;
                if (g_force_overwrite)
                    continue;
                fprintf(stderr,
                    "udpkg: error: trying to overwrite '%s',"
                    " which is also in package %s\n",
                    line, owner);
                conflict_found = 1;
            }
            fclose(fp);
        }
        if (conflict_found) {
            fprintf(stderr,
                "udpkg: error processing package %s (--install):\n"
                " conflicting files\n"
                " Use --force-overwrite to allow overwriting files.\n"
                " Use --force-overwrite-dir to allow overwriting directories.\n",
                pkgname);
            tmpci_cleanup();
            return -1;
        }
    }
    oldver[0] = '\0';
    is_upgrade = db_is_installed(pkgname);
    if (is_upgrade)
        db_get_version(pkgname, oldver, sizeof(oldver));
    if (g_simulate) {
        if (is_upgrade)
            printf("Inst %s [%s] (%s) (simulated)\n",
                   pkgname, oldver[0] ? oldver : "?", ver ? ver : "?");
        else
            printf("Inst %s (%s) (simulated)\n",
                   pkgname, ver ? ver : "?");
        log_write("%s %s:%s %s %s",
                  is_upgrade ? "update" : "install",
                  pkgname, arch ? arch : "unknown",
                  is_upgrade && oldver[0] ? oldver : "<none>",
                  ver ? ver : "<none>");
        tmpci_cleanup();
        return 0;
    }
    if (is_upgrade)
        printf("(Reading database ... )\nPreparing to unpack %s ...\n",
               debpath);
    else
        printf("Selecting previously unselected package %s.\n"
               "(Reading database ... )\nPreparing to unpack %s ...\n",
               pkgname, debpath);
    sn_processing(is_upgrade ? "upgrade" : "install", pkgname);
    {
        char script_path[4096];
        snprintf(script_path, sizeof(script_path),
                 "%s/preinst", db_tmpci_ctrl());
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc;
            sn_status(pkgname, ver ? ver : "", "half-installed");
            if (is_upgrade)
                sc = run_script(script_path, "upgrade",
                                oldver[0] ? oldver : NULL);
            else
                sc = run_script(script_path, "install", NULL);
            if (sc != 0) {
                fprintf(stderr,
                    "udpkg: subprocess preinst returned error code %d\n", sc);
                tmpci_cleanup();
                return -1;
            }
        }
    }
    printf("Unpacking %s (%s) ...\n", pkgname, ver ? ver : "?");
    {
        char instroot[4096];
        strncpy(instroot, effective_instdir(), sizeof(instroot) - 1);
        instroot[sizeof(instroot) - 1] = '\0';
        if (nconfs > 0)
            conffiles_presave(confs, nconfs, pkgname, is_upgrade);
        {
            if (utar_extract(data_tar, instroot, 0) != 0) {
                fprintf(stderr, "udpkg: failed to extract data archive\n");
                conffiles_cleanup_tmp(confs, nconfs);
                tmpci_cleanup();
                return -1;
            }
        }
        if (nconfs > 0)
            conffiles_apply(confs, nconfs);
    }
    sn_status(pkgname, ver ? ver : "", "unpacked");
    printf("Setting up %s (%s) ...\n", pkgname, ver ? ver : "?");
    if (db_install(&ctrl, norm_list) != 0) {
        fprintf(stderr, "udpkg: failed to update package database\n");
        tmpci_cleanup();
        return -1;
    }
    if (conffiles_src[0])
        db_install_conffiles(pkgname, conffiles_src);
    for (i = 0; mscripts[i]; i++) {
        char src[4096];
        snprintf(src, sizeof(src), "%s/%s", db_tmpci_ctrl(), mscripts[i]);
        if (stat(src, &st) == 0)
            db_install_script(pkgname, mscripts[i], src);
    }
    {
        char script_path[4096];
        db_get_scriptpath(pkgname, "postinst", script_path, sizeof(script_path));
        sn_processing("configure", pkgname);
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc = run_script(script_path, "configure",
                                is_upgrade && oldver[0] ? oldver : NULL);
            if (sc != 0)
                fprintf(stderr,
                    "udpkg: subprocess postinst returned error code %d\n",
                    sc);
        }
    }
    sn_status(pkgname, ver ? ver : "", "installed");
    log_write("%s %s:%s %s %s",
              is_upgrade ? "update" : "install",
              pkgname, arch ? arch : "unknown",
              is_upgrade && oldver[0] ? oldver : "<none>",
              ver ? ver : "<none>");
    tmpci_cleanup();
    return 0;
}

static int op_install_batch(char **debpaths, int ndeb, int force) {
    char *batch_names[BATCH_MAX];
    int nbatch = 0;
    ctrl_t ctrl;
    const char *pkgname;
    int i, ret = 0, nerr = 0;
    log_write("startup archives install tar:%s fmt:%s",
              utar_impl_name(), utar_fmt_name(utar_get_fmt()));
    for (i = 0; i < ndeb && nbatch < BATCH_MAX; i++) {
        if (read_ctrl_from_deb(debpaths[i], &ctrl) == 0) {
            pkgname = ctrl_get(&ctrl, "Package");
            if (pkgname) {
                batch_names[nbatch] = strdup(pkgname);
                if (batch_names[nbatch])
                    nbatch++;
            }
        }
    }
    for (i = 0; i < ndeb; i++) {
        if (op_install_one(debpaths[i],
                           (const char * const *)batch_names, nbatch,
                           force) != 0) {
            ret = 1;
            if (g_abort_after > 0) {
                nerr++;
                if (nerr >= g_abort_after) {
                    fprintf(stderr,
                        "udpkg: abort-after limit (%d) reached\n",
                        g_abort_after);
                    break;
                }
            }
        }
    }
    for (i = 0; i < nbatch; i++)
        free(batch_names[i]);
    return ret;
}

static int op_remove(const char *name) {
    char listpath[4096];
    char line[4096];
    FILE *fp;
    struct stat st;
    char **files = NULL;
    int nfiles = 0, cap = 0;
    int i;
    char ver[256];
    ctrl_t c;
    const char *arch = NULL;
    if (!db_is_installed(name)) {
        fprintf(stderr, "udpkg: %s: package not installed\n", name);
        return -1;
    }
    if (!g_simulate && !g_no_check && !check_prereqs())
        return -1;
    ver[0] = '\0';
    db_get_version(name, ver, sizeof(ver));
    if (db_get(name, &c) == 0)
        arch = ctrl_get(&c, "Architecture");
    log_write("startup archives remove tar:%s fmt:%s",
              utar_impl_name(), utar_fmt_name(utar_get_fmt()));
    log_write("remove %s:%s %s <none>",
              name, arch ? arch : "unknown", ver[0] ? ver : "<none>");
    if (g_simulate) {
        printf("Remv %s [%s] (simulated)\n", name, ver[0] ? ver : "?");
        return 0;
    }
    printf("Removing %s ...\n", name);
    sn_processing("remove", name);
    {
        int sc = run_installed_script(name, "prerm", "remove", NULL);
        if (sc != 0)
            fprintf(stderr,
                "udpkg: subprocess prerm returned error code %d\n", sc);
    }
    db_get_listpath(name, listpath, sizeof(listpath));
    fp = fopen(listpath, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;
            size_t len = strlen(p);
            char **tmp;
            while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r'))
                p[--len] = '\0';
            if (len == 0)
                continue;
            if (nfiles >= cap) {
                int newcap = cap == 0 ? 64 : cap * 2;
                tmp = realloc(files, (size_t)newcap * sizeof(char *));
                if (!tmp)
                    break;
                files = tmp;
                cap = newcap;
            }
            files[nfiles] = strdup(p);
            if (!files[nfiles])
                break;
            nfiles++;
        }
        fclose(fp);
    }
    for (i = nfiles - 1; i >= 0; i--) {
        char fpath[4096];
        const char *base = effective_instdir();
        if (db_is_conffile(name, files[i])) {
            free(files[i]);
            continue;
        }
        if (strcmp(base, "/") == 0)
            strncpy(fpath, files[i], sizeof(fpath) - 1);
        else
            snprintf(fpath, sizeof(fpath), "%s%s", base, files[i]);
        if (lstat(fpath, &st) == 0) {
            if (S_ISDIR(st.st_mode))
                rmdir(fpath);
            else
                unlink(fpath);
        }
        free(files[i]);
    }
    free(files);
    db_remove(name);
    {
        char script_path[4096];
        db_get_scriptpath(name, "postrm", script_path, sizeof(script_path));
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc = run_script(script_path, "remove", NULL);
            if (sc != 0)
                fprintf(stderr,
                    "udpkg: subprocess postrm returned error code %d\n", sc);
        }
    }
    sn_status(name, ver[0] ? ver : "", "not-installed");
    db_remove_scripts(name);
    return 0;
}

static int op_purge(const char *name) {
    char conffiles_path[4096];
    char line[4096];
    FILE *fp;
    struct stat st;
    int has_conffiles;
    int rc = 0;
    db_get_conffiles_path(name, conffiles_path, sizeof(conffiles_path));
    has_conffiles = (stat(conffiles_path, &st) == 0);
    if (!db_is_installed(name) && !has_conffiles) {
        fprintf(stderr, "udpkg: %s: package not installed\n", name);
        return -1;
    }
    if (db_is_installed(name))
        rc = op_remove(name);
    sn_processing("purge", name);
    fp = fopen(conffiles_path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char fpath[4096];
            const char *base;
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
            if (len == 0 || line[0] != '/')
                continue;
            base = effective_instdir();
            if (strcmp(base, "/") == 0)
                strncpy(fpath, line, sizeof(fpath) - 1);
            else
                snprintf(fpath, sizeof(fpath), "%s%s", base, line);
            fpath[sizeof(fpath) - 1] = '\0';
            if (lstat(fpath, &st) == 0 && !S_ISDIR(st.st_mode))
                unlink(fpath);
        }
        fclose(fp);
    }
    db_remove_conffiles(name);
    sn_status(name, "", "not-installed");
    return rc;
}

static int op_status(const char *name) {
    ctrl_t c;
    int i;
    if (db_get(name, &c) != 0) {
        fprintf(stderr, "udpkg: %s: package not installed\n", name);
        return -1;
    }
    for (i = 0; i < c.nfields; i++)
        printf("%s: %s\n", c.fields[i].key, c.fields[i].val);
    return 0;
}

static int extract_data_tar(const char *debpath, char *out_tar, size_t outsz) {
    char tmpdir[64];
    int used_fmt;
    strncpy(tmpdir, "/tmp/udpkg_xtr_XXXXXX", sizeof(tmpdir) - 1);
    tmpdir[sizeof(tmpdir) - 1] = '\0';
    if (!mkdtemp(tmpdir))
        return -1;
    if (deb_open(debpath, g_format, tmpdir,
                 NULL, 0, NULL,
                 out_tar, outsz,
                 0, 1, &used_fmt) != 0) {
        fprintf(stderr, "udpkg: cannot open '%s': not a valid .deb archive\n",
                debpath);
        cleanup_dir(tmpdir);
        return -1;
    }
    return 0;
}

static int op_extract(const char *debpath, const char *destdir, int verbose) {
    char data_tar[4096];
    struct stat st;
    int rc;
    if (stat(destdir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "udpkg: %s: not a directory\n", destdir);
        return -1;
    }
    if (extract_data_tar(debpath, data_tar, sizeof(data_tar)) != 0)
        return -1;
    rc = utar_extract(data_tar, destdir, verbose);
    {
        char tmpdir[4096];
        char *slash = strrchr(data_tar, '/');
        if (slash) {
            size_t len = (size_t)(slash - data_tar);
            if (len < sizeof(tmpdir)) {
                memcpy(tmpdir, data_tar, len);
                tmpdir[len] = '\0';
                cleanup_dir(tmpdir);
            }
        }
    }
    return rc == 0 ? 0 : -1;
}

static int op_contents(const char *debpath) {
    char data_tar[4096];
    int rc;
    if (extract_data_tar(debpath, data_tar, sizeof(data_tar)) != 0)
        return -1;
    rc = utar_list_stdout(data_tar, 1);
    {
        char tmpdir[4096];
        char *slash = strrchr(data_tar, '/');
        if (slash) {
            size_t len = (size_t)(slash - data_tar);
            if (len < sizeof(tmpdir)) {
                memcpy(tmpdir, data_tar, len);
                tmpdir[len] = '\0';
                cleanup_dir(tmpdir);
            }
        }
    }
    return rc == 0 ? 0 : -1;
}

static int op_show(const char *debpath) {
    ctrl_t ctrl;
    const char *name, *ver;
    if (read_ctrl_from_deb(debpath, &ctrl) != 0) {
        fprintf(stderr, "udpkg: cannot read control from '%s'\n", debpath);
        return -1;
    }
    name = ctrl_get(&ctrl, "Package");
    ver  = ctrl_get(&ctrl, "Version");
    printf("%s %s\n",
           name ? name : "(unknown)",
           ver  ? ver  : "(unknown)");
    return 0;
}

static int op_field(const char *debpath, char **fields, int nfields) {
    ctrl_t ctrl;
    int i;
    if (read_ctrl_from_deb(debpath, &ctrl) != 0) {
        fprintf(stderr, "udpkg: cannot read control from '%s'\n", debpath);
        return -1;
    }
    if (nfields == 0) {
        for (i = 0; i < ctrl.nfields; i++)
            printf("%s: %s\n", ctrl.fields[i].key, ctrl.fields[i].val);
        return 0;
    }
    if (nfields == 1) {
        const char *val = ctrl_get(&ctrl, fields[0]);
        if (!val) {
            fprintf(stderr, "udpkg: field '%s' not found in control\n",
                    fields[0]);
            return -1;
        }
        printf("%s\n", val);
        return 0;
    }
    for (i = 0; i < nfields; i++) {
        const char *val = ctrl_get(&ctrl, fields[i]);
        if (val)
            printf("%s: %s\n", fields[i], val);
        else
            fprintf(stderr, "udpkg: field '%s' not found in control\n",
                    fields[i]);
    }
    return 0;
}

static const char *comp_tar_flag(void) {
    switch (g_compression) {
        case COMP_XZ:   return "-J";
        case COMP_ZSTD: return "--zstd";
        case COMP_NONE: return NULL;
        default:        return "-z";
    }
}

static const char *comp_ext(void) {
    switch (g_compression) {
        case COMP_XZ:   return ".xz";
        case COMP_ZSTD: return ".zst";
        case COMP_NONE: return "";
        default:        return ".gz";
    }
}

static int compress_file(const char *inpath, const char *outpath) {
    const char *comp_cmd = NULL;
    char level_arg[8]    = "";
    char extra_arg[16]   = "";
    char *cargv[10];
    int ca = 0;
    pid_t pid;
    int status, in, out;
    if (g_compression == COMP_NONE) {
        char buf[65536];
        ssize_t n;
        in = open(inpath, O_RDONLY);
        if (in < 0) return -1;
        out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out < 0) { close(in); return -1; }
        while ((n = read(in, buf, sizeof(buf))) > 0)
            if (write(out, buf, (size_t)n) != n) { close(in); close(out); return -1; }
        close(in);
        close(out);
        return 0;
    }
    switch (g_compression) {
        case COMP_GZIP: comp_cmd = "gzip"; break;
        case COMP_XZ:   comp_cmd = "xz";   break;
        case COMP_ZSTD: comp_cmd = "zstd"; break;
        default:        return 0;
    }
    if (g_comp_level >= 0)
        snprintf(level_arg, sizeof(level_arg), "-%d", g_comp_level);
    if (g_compression == COMP_XZ && g_comp_strat_xz == 1)
        strncpy(extra_arg, "--extreme", sizeof(extra_arg) - 1);
    in  = open(inpath,  O_RDONLY);
    if (in < 0) return -1;
    out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
    cargv[ca++] = (char *)comp_cmd;
    if (level_arg[0]) cargv[ca++] = level_arg;
    if (extra_arg[0]) cargv[ca++] = extra_arg;
    cargv[ca++] = "-c";
    cargv[ca]   = NULL;
    pid = fork();
    if (pid < 0) { close(in); close(out); return -1; }
    if (pid == 0) {
        dup2(in, STDIN_FILENO);
        dup2(out, STDOUT_FILENO);
        close(in); close(out);
        execvp(cargv[0], cargv);
        _exit(127);
    }
    close(in); close(out);
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int build_tar(const char *srcdir, const char *exclude,
                     const char *outpath) {
    if (utar_get_impl() == TARIMPL_EXTERNAL) {
        const char *flag = comp_tar_flag();
        char prog_buf[128];
        char *argv[24];
        int n = 0;
        int use_prog = 0;
        prog_buf[0] = '\0';
        if (g_compression == COMP_GZIP) {
            if (g_comp_level >= 0) {
                snprintf(prog_buf, sizeof(prog_buf), "gzip -%d", g_comp_level);
                use_prog = 1;
            }
        } else if (g_compression == COMP_XZ) {
            if (g_comp_level >= 0 || g_comp_strat_xz == 1) {
                int pos = 0;
                pos += snprintf(prog_buf + pos, sizeof(prog_buf) - (size_t)pos, "xz");
                if (g_comp_level >= 0)
                    pos += snprintf(prog_buf + pos, sizeof(prog_buf) - (size_t)pos,
                                    " -%d", g_comp_level);
                if (g_comp_strat_xz == 1)
                    pos += snprintf(prog_buf + pos, sizeof(prog_buf) - (size_t)pos,
                                    " --extreme");
                use_prog = 1;
                (void)pos;
            }
        } else if (g_compression == COMP_ZSTD) {
            if (g_comp_level >= 0) {
                snprintf(prog_buf, sizeof(prog_buf), "zstd -%d", g_comp_level);
                use_prog = 1;
            }
        }
        argv[n++] = "tar";
        argv[n++] = "-C";
        argv[n++] = (char *)srcdir;
        if (g_verbose) argv[n++] = "-v";
        if (use_prog) {
            argv[n++] = "-I";
            argv[n++] = prog_buf;
        } else if (flag) {
            argv[n++] = (char *)flag;
        }
        argv[n++] = "-cf";
        argv[n++] = (char *)outpath;
        if (exclude) {
            argv[n++] = "--exclude";
            argv[n++] = (char *)exclude;
        }
        argv[n++] = ".";
        argv[n]   = NULL;
        return xrun(argv);
    }
    {
        char tmp_raw[4096];
        int rc;
        snprintf(tmp_raw, sizeof(tmp_raw), "%s.tmp_raw", outpath);
        rc = utar_create(tmp_raw, srcdir, exclude, g_verbose);
        if (rc != 0) return rc;
        if (g_compression == COMP_NONE) {
            if (rename(tmp_raw, outpath) != 0) { unlink(tmp_raw); return -1; }
            return 0;
        }
        rc = compress_file(tmp_raw, outpath);
        unlink(tmp_raw);
        return rc;
    }
}

static int op_extract_control(const char *debpath, const char *outdir) {
    char tmpdir[64];
    char ctrl_tar[4096];
    struct stat st;
    int used_fmt;
    strncpy(tmpdir, "/tmp/udpkg_ce_XXXXXX", sizeof(tmpdir) - 1);
    tmpdir[sizeof(tmpdir) - 1] = '\0';
    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "udpkg: cannot create tmpdir\n");
        return -1;
    }
    if (deb_open(debpath, g_format, tmpdir,
                 ctrl_tar, sizeof(ctrl_tar), NULL,
                 NULL, 0,
                 1, 0, &used_fmt) != 0) {
        fprintf(stderr, "udpkg: cannot open '%s': not a valid .deb archive\n",
                debpath);
        cleanup_dir(tmpdir);
        return -1;
    }
    if (stat(outdir, &st) != 0) {
        if (mkdir(outdir, 0755) != 0) {
            fprintf(stderr, "udpkg: cannot create directory '%s'\n", outdir);
            cleanup_dir(tmpdir);
            return -1;
        }
    }
    {
        if (utar_extract(ctrl_tar, outdir, 0) != 0) {
            fprintf(stderr, "udpkg: failed to extract control archive\n");
            cleanup_dir(tmpdir);
            return -1;
        }
    }
    cleanup_dir(tmpdir);
    return 0;
}

static int write_old_deb(const char *outpath,
                          const char *ctrl_tar, const char *data_tar) {
    char buf[8192];
    ssize_t n;
    int out, in;
    struct stat st;
    if (stat(ctrl_tar, &st) != 0)
        return -1;
    out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0)
        return -1;
    {
        char hdr[64];
        int hlen;
        hlen = snprintf(hdr, sizeof(hdr),
                        "0.939000\n%lu\n", (unsigned long)st.st_size);
        if (write(out, hdr, (size_t)hlen) != hlen) {
            close(out);
            return -1;
        }
    }
    in = open(ctrl_tar, O_RDONLY);
    if (in < 0) {
        close(out);
        return -1;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            close(in);
            close(out);
            return -1;
        }
    }
    close(in);
    in = open(data_tar, O_RDONLY);
    if (in < 0) {
        close(out);
        return -1;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            close(in);
            close(out);
            return -1;
        }
    }
    close(in);
    close(out);
    return 0;
}

static int check_build_ctrl(const char *ctrl_path) {
    ctrl_t c;
    static const char * const required[] =
        { "Package", "Version", "Architecture", "Maintainer", "Description", NULL };
    int i, ok = 1;
    if (ctrl_parse(ctrl_path, &c) != 0) {
        fprintf(stderr, "udpkg: cannot parse control file '%s'\n", ctrl_path);
        return -1;
    }
    for (i = 0; required[i]; i++) {
        if (!ctrl_get(&c, required[i])) {
            fprintf(stderr,
                "udpkg: control file missing required field: %s\n", required[i]);
            ok = 0;
        }
    }
    return ok ? 0 : -1;
}

static int op_build(const char *srcdir, const char *outarg) {
    char debian_dir[4096];
    char ctrl_path[4096];
    char tmpdir[64];
    char ctrl_tar[4096];
    char data_tar[4096];
    char ctrl_member[64];
    char data_member[64];
    char outpath[4096];
    struct stat st;
    int arfd, rc = 0;
    if (!g_no_check && utar_get_impl() == TARIMPL_EXTERNAL
        && !cmd_available("tar")) {
        fprintf(stderr, "udpkg: required command not found in PATH: tar\n");
        return -1;
    }
    snprintf(debian_dir, sizeof(debian_dir), "%s/DEBIAN", srcdir);
    snprintf(ctrl_path,  sizeof(ctrl_path),  "%s/DEBIAN/control", srcdir);
    if (stat(debian_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr,
            "udpkg: %s: DEBIAN directory not found\n", srcdir);
        return -1;
    }
    if (stat(ctrl_path, &st) != 0) {
        fprintf(stderr,
            "udpkg: %s: control file not found\n", debian_dir);
        return -1;
    }
    {
        struct stat dst;
        int perm_err = 0;
        if (stat(debian_dir, &dst) == 0) {
            if ((dst.st_mode & 07777) != 0755 || dst.st_uid != 0 || dst.st_gid != 0) {
                fprintf(stderr,
                    "udpkg: %s: DEBIAN directory should be 755 root:root\n",
                    g_root_owner_group ? "error" : "warning");
                perm_err = 1;
            }
        }
        if ((st.st_mode & 07777) != 0644 || st.st_uid != 0 || st.st_gid != 0) {
            fprintf(stderr,
                "udpkg: %s: control file should be 644 root:root\n",
                g_root_owner_group ? "error" : "warning");
            perm_err = 1;
        }
        if (g_root_owner_group && perm_err)
            return -1;
    }
    if (check_build_ctrl(ctrl_path) != 0)
        return -1;
    if (outarg && outarg[0]) {
        strncpy(outpath, outarg, sizeof(outpath) - 1);
        outpath[sizeof(outpath) - 1] = '\0';
    } else {
        const char *base = srcdir;
        const char *sl   = strrchr(srcdir, '/');
        if (sl && sl[1])
            base = sl + 1;
        else if (sl && sl == srcdir)
            base = sl + 1;
        snprintf(outpath, sizeof(outpath), "%s.deb", base);
    }
    strncpy(tmpdir, "/tmp/udpkg_bld_XXXXXX", sizeof(tmpdir) - 1);
    tmpdir[sizeof(tmpdir) - 1] = '\0';
    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "udpkg: cannot create build tmpdir\n");
        return -1;
    }
    snprintf(ctrl_member, sizeof(ctrl_member), "control.tar%s", comp_ext());
    snprintf(data_member, sizeof(data_member), "data.tar%s",    comp_ext());
    snprintf(ctrl_tar, sizeof(ctrl_tar), "%s/%s", tmpdir, ctrl_member);
    snprintf(data_tar, sizeof(data_tar), "%s/%s", tmpdir, data_member);
    if (build_tar(debian_dir, NULL, ctrl_tar) != 0) {
        fprintf(stderr, "udpkg: failed to build control archive\n");
        cleanup_dir(tmpdir);
        return -1;
    }
    if (build_tar(srcdir, "./DEBIAN", data_tar) != 0) {
        fprintf(stderr, "udpkg: failed to build data archive\n");
        cleanup_dir(tmpdir);
        return -1;
    }
    if (g_build_fmt == DEB_FMT_OLD) {
        rc = write_old_deb(outpath, ctrl_tar, data_tar);
        if (rc != 0)
            fprintf(stderr, "udpkg: failed to write old-format deb\n");
    } else {
        arfd = ar_create(outpath);
        if (arfd < 0) {
            fprintf(stderr, "udpkg: cannot create '%s'\n", outpath);
            cleanup_dir(tmpdir);
            return -1;
        }
        if (ar_append_data(arfd, "debian-binary", "2.0\n", 4) != 0
            || ar_append_file(arfd, ctrl_member, ctrl_tar) != 0
            || ar_append_file(arfd, data_member, data_tar) != 0) {
            fprintf(stderr, "udpkg: error writing ar members\n");
            close(arfd);
            cleanup_dir(tmpdir);
            return -1;
        }
        close(arfd);
    }
    cleanup_dir(tmpdir);
    if (rc == 0) {
        ctrl_t c;
        const char *pkgname = "?";
        if (ctrl_parse(ctrl_path, &c) == 0)
            pkgname = ctrl_get(&c, "Package");
        printf("dpkg-deb: building package '%s' in '%s'\n",
               pkgname ? pkgname : "?", outpath);
        log_write("build %s %s tar:%s fmt:%s compression:%s",
                  pkgname ? pkgname : "?", outpath,
                  utar_impl_name(), utar_fmt_name(utar_get_fmt()),
                  g_compression == COMP_XZ   ? "xz"   :
                  g_compression == COMP_ZSTD ? "zstd" :
                  g_compression == COMP_NONE ? "none" : "gzip");
    }
    return rc;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <action> ...\n"
        "\n"
        "Actions:\n"
        "  -i, --install [-f] <pkg.deb> [...]   Install package(s)\n"
        "  -r, --remove <pkg> [...]              Remove package(s)\n"
        "  -P, --purge <pkg> [...]               Purge package(s) and conffiles\n"
        "  -b, --build <dir> [<output.deb>]      Build a .deb from a directory\n"
        "  -e, --control <pkg.deb> <dir>         Extract control files to dir\n"
        "  -l, --list [pattern]                  List installed packages\n"
        "  -L, --list-files <pkg>                List files owned by package\n"
        "  -s, --status <pkg>                    Show package status\n"
        "  -W, --show <pkg.deb>                  Show name and version\n"
        "      --showformat=<pkg.deb>            Like --show, uses --format= explicitly\n"
        "      --info <pkg.deb>                  Show package file info\n"
        "      --contents <pkg.deb>              List contents of package\n"
        "      --extract <pkg.deb> <dir>         Extract package files to dir\n"
        "      --vextract <pkg.deb> <dir>        Extract verbosely to dir\n"
        "      --field <pkg.deb> [field ...]     Show control field(s)\n"
        "      --help, -?                        Show this help\n"
        "\n"
        "Options:\n"
        "  -f                             Force install despite dep errors\n"
        "  --simulate, --dry-run,\n"
        "    --no-act                     Simulate actions without applying\n"
        "  --root=PATH                    Set both admindir and instdir prefix\n"
        "  --admindir=DIR                 Override database directory\n"
        "  --instdir=DIR                  Override installation target directory\n"
        "  --log=FILE                     Log operations to FILE\n"
        "  --format=auto|new|old          Force package format for reading (default: auto)\n"
        "  --deb-format=2.0|0.939000      Package format for --build (default: 2.0)\n"
        "  -Z gzip|xz|zstd|none          Compression for --build (default: gzip)\n"
        "  --compression=gzip|xz|...     Same as -Z\n"
        "  -z <level>                     Compression level (0-9) for --build\n"
        "  --compression-level=<level>   Same as -z\n"
        "  -S <strategy>                  Compression strategy for --build (gzip/xz only)\n"
        "  --compression-strategy=<s>    Same as -S\n"
        "                                 gzip: filtered, huffman, rle, fixed\n"
        "                                 xz:   none, extreme\n"
        "  -v, --verbose                  Verbose output during --build\n"
        "  --root-owner-group             Make perm warnings in --build into errors\n"
        "  --ignore-depends=P1[,P2,...]   Ignore dependency on listed packages\n"
        "  --force-script-chrootless      Skip chroot, run scripts on host\n"
        "  --force-not-root               Skip superuser privilege check\n"
        "  --force-overwrite              Allow overwriting files from other packages\n"
        "  --force-overwrite-dir          Allow overwriting dirs from other packages\n"
        "  --force-confnew                Always install maintainer's conffile version\n"
        "  --force-confold                Always keep existing conffile version\n"
        "  -E, --skip-same-version        Skip install if same version already installed\n"
        "  -G, --refuse-downgrade         Skip install if it would downgrade the package\n"
        "  --no-check, --nocheck          Skip PATH tool availability checks\n"
        "  --abort-after=<n>              Abort batch operation after <n> errors\n"
        "  --status-fd <n>               Send status updates to file descriptor <n>\n"
        "  --status-fd=<n>               Same as --status-fd <n>\n"
        "  --status-logger <cmd>         Send status updates to <cmd>'s stdin\n"
        "  --status-logger=<cmd>         Same as --status-logger <cmd>\n"
        "  -T internal|external           Tar implementation (default: internal)\n"
        "  --tar-implementation=...       Same as -T\n"
        "  -t auto|gnu|pax|ustar|v7       Tar format (default: auto)\n"
        "  --tar-format=...               Same as -t\n"
        "                                 Note: --build defaults to pax when auto\n"
        "  --no-pager                     Do not use a pager for -l output\n"
        "  --force-all                    Enable all --force-* options\n",
        prog);
}

static const char *normalize_action(const char *arg) {
    if (strcmp(arg, "--install")    == 0) return "-i";
    if (strcmp(arg, "--remove")     == 0) return "-r";
    if (strcmp(arg, "--purge")      == 0) return "-P";
    if (strcmp(arg, "--build")      == 0) return "-b";
    if (strcmp(arg, "--control")    == 0) return "-e";
    if (strcmp(arg, "--list")       == 0) return "-l";
    if (strcmp(arg, "--list-files") == 0) return "-L";
    if (strcmp(arg, "--status")     == 0) return "-s";
    if (strcmp(arg, "--show")       == 0) return "-W";
    return arg;
}

static int needs_root_priv(const char *action) {
    return strcmp(action, "-i") == 0
        || strcmp(action, "-r") == 0
        || strcmp(action, "-P") == 0;
}

static void parse_ignore_depends(const char *val) {
    char buf[4096];
    char *tok, *save;
    strncpy(buf, val, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    tok = strtok_r(buf, ",", &save);
    while (tok && g_nignore_dep < IGNORE_DEP_MAX) {
        while (*tok == ' ')
            tok++;
        if (*tok) {
            g_ignore_dep[g_nignore_dep] = strdup(tok);
            if (g_ignore_dep[g_nignore_dep])
                g_nignore_dep++;
        }
        tok = strtok_r(NULL, ",", &save);
    }
}


static const char *action_long_name(const char *a) {
    if (strcmp(a, "-i")         == 0) return "--install";
    if (strcmp(a, "-r")         == 0) return "--remove";
    if (strcmp(a, "-P")         == 0) return "--purge";
    if (strcmp(a, "-b")         == 0) return "--build";
    if (strcmp(a, "-e")         == 0) return "--control";
    if (strcmp(a, "-l")         == 0) return "--list";
    if (strcmp(a, "-L")         == 0) return "--list-files";
    if (strcmp(a, "-s")         == 0) return "--status";
    if (strcmp(a, "-W")         == 0) return "--show";
    if (strcmp(a, "--info")     == 0) return "--info";
    if (strcmp(a, "--contents") == 0) return "--contents";
    if (strcmp(a, "--extract")  == 0) return "--extract";
    if (strcmp(a, "--vextract") == 0) return "--vextract";
    if (strcmp(a, "--field")    == 0) return "--field";
    if (strcmp(a, "--help")     == 0) return "--help";
    if (strcmp(a, "-h")         == 0) return "--help";
    if (strcmp(a, "-?")         == 0) return "--help";
    return NULL;
}

static int is_action(const char *a) {
    return action_long_name(a) != NULL;
}

int main(int argc, char *argv[]) {
    char *fwd[1024];
    int  nfwd = 0;
    int  i, ret = 0, nerr = 0;
    char admindir_arg[4096] = "";
    for (i = 0; i < argc && nfwd < 1024; i++) {
        if (strncmp(argv[i], "--root=", 7) == 0) {
            strncpy(g_root, argv[i] + 7, sizeof(g_root) - 1);
            g_root[sizeof(g_root) - 1] = '\0';
            {
                size_t len = strlen(g_root);
                while (len > 0 && g_root[len - 1] == '/')
                    g_root[--len] = '\0';
                if (strcmp(g_root, "/") == 0)
                    g_root[0] = '\0';
            }
        } else if (strncmp(argv[i], "--admindir=", 11) == 0) {
            strncpy(admindir_arg, argv[i] + 11, sizeof(admindir_arg) - 1);
            admindir_arg[sizeof(admindir_arg) - 1] = '\0';
        } else if (strncmp(argv[i], "--instdir=", 10) == 0) {
            strncpy(g_instdir, argv[i] + 10, sizeof(g_instdir) - 1);
            g_instdir[sizeof(g_instdir) - 1] = '\0';
            {
                size_t len = strlen(g_instdir);
                while (len > 1 && g_instdir[len - 1] == '/')
                    g_instdir[--len] = '\0';
                if (strcmp(g_instdir, "/") == 0)
                    g_instdir[0] = '\0';
            }
        } else if (strcmp(argv[i], "-Z") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: -Z requires an argument\n");
                return 1;
            }
            i++;
            if (strcmp(argv[i], "gzip") == 0)       g_compression = COMP_GZIP;
            else if (strcmp(argv[i], "xz")   == 0)  g_compression = COMP_XZ;
            else if (strcmp(argv[i], "zstd") == 0)  g_compression = COMP_ZSTD;
            else if (strcmp(argv[i], "none") == 0)  g_compression = COMP_NONE;
            else {
                fprintf(stderr,
                    "udpkg: unknown compression '%s' (use: gzip, xz, zstd, none)\n",
                    argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--compression=", 14) == 0) {
            const char *val = argv[i] + 14;
            if (strcmp(val, "gzip") == 0)       g_compression = COMP_GZIP;
            else if (strcmp(val, "xz")   == 0)  g_compression = COMP_XZ;
            else if (strcmp(val, "zstd") == 0)  g_compression = COMP_ZSTD;
            else if (strcmp(val, "none") == 0)  g_compression = COMP_NONE;
            else {
                fprintf(stderr,
                    "udpkg: unknown compression '%s' (use: gzip, xz, zstd, none)\n",
                    val);
                return 1;
            }
        } else if (strncmp(argv[i], "--deb-format=", 13) == 0) {
            const char *val = argv[i] + 13;
            if (strcmp(val, "2.0")      == 0) g_build_fmt = DEB_FMT_NEW;
            else if (strcmp(val, "0.939000") == 0) g_build_fmt = DEB_FMT_OLD;
            else {
                fprintf(stderr,
                    "udpkg: unknown deb format '%s' (use: 2.0, 0.939000)\n", val);
                return 1;
            }
        } else if (strncmp(argv[i], "--format=", 9) == 0) {
            const char *val = argv[i] + 9;
            if (strcmp(val, "new")  == 0)      g_format = DEB_FMT_NEW;
            else if (strcmp(val, "old") == 0)  g_format = DEB_FMT_OLD;
            else if (strcmp(val, "auto") == 0) g_format = DEB_FMT_AUTO;
            else {
                fprintf(stderr,
                    "udpkg: unknown format '%s' (use: auto, new, old)\n", val);
                return 1;
            }
        } else if (strncmp(argv[i], "--log=", 6) == 0) {
            log_open(argv[i] + 6);
        } else if (strcmp(argv[i], "--status-fd") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: --status-fd requires an argument\n");
                return 1;
            }
            i++;
            {
                char *end;
                long fd_val = strtol(argv[i], &end, 10);
                if (*end != '\0' || fd_val < 0) {
                    fprintf(stderr,
                        "udpkg: --status-fd: invalid file descriptor '%s'\n",
                        argv[i]);
                    return 1;
                }
                sn_open_fd((int)fd_val);
            }
        } else if (strncmp(argv[i], "--status-fd=", 12) == 0) {
            {
                const char *arg = argv[i] + 12;
                char *end;
                long fd_val = strtol(arg, &end, 10);
                if (*end != '\0' || fd_val < 0) {
                    fprintf(stderr,
                        "udpkg: --status-fd: invalid file descriptor '%s'\n",
                        arg);
                    return 1;
                }
                sn_open_fd((int)fd_val);
            }
        } else if (strncmp(argv[i], "--status-logger=", 16) == 0) {
            sn_open_logger(argv[i] + 16);
        } else if (strcmp(argv[i], "--status-logger") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: --status-logger requires an argument\n");
                return 1;
            }
            i++;
            sn_open_logger(argv[i]);
        } else if (strncmp(argv[i], "--ignore-depends=", 17) == 0) {
            parse_ignore_depends(argv[i] + 17);
        } else if (strcmp(argv[i], "--simulate") == 0
                   || strcmp(argv[i], "--dry-run") == 0
                   || strcmp(argv[i], "--no-act")  == 0) {
            g_simulate = 1;
        } else if (strcmp(argv[i], "--force-script-chrootless") == 0) {
            g_force_chrootless = 1;
        } else if (strcmp(argv[i], "--force-not-root") == 0) {
            g_force_not_root = 1;
        } else if (strcmp(argv[i], "--force-overwrite") == 0) {
            g_force_overwrite = 1;
        } else if (strcmp(argv[i], "--force-overwrite-dir") == 0) {
            g_force_overwrite_dir = 1;
        } else if (strcmp(argv[i], "--force-confnew") == 0) {
            g_force_confnew = 1;
            g_force_confold = 0;
        } else if (strcmp(argv[i], "--force-confold") == 0) {
            g_force_confold = 1;
            g_force_confnew = 0;
        } else if (strcmp(argv[i], "-E") == 0
                   || strcmp(argv[i], "--skip-same-version") == 0) {
            g_skip_same_version = 1;
        } else if (strcmp(argv[i], "-G") == 0
                   || strcmp(argv[i], "--refuse-downgrade") == 0) {
            g_refuse_downgrade = 1;
        } else if (strcmp(argv[i], "--no-pager") == 0) {
            g_no_pager = 1;
        } else if (strcmp(argv[i], "--no-check") == 0
                   || strcmp(argv[i], "--nocheck") == 0) {
            g_no_check = 1;
        } else if (strcmp(argv[i], "-T") == 0
                   || strcmp(argv[i], "--tar-implementation") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: %s requires an argument\n", argv[i]);
                return 1;
            }
            i++;
            if (strcmp(argv[i], "internal") == 0)
                utar_set_impl(TARIMPL_INTERNAL);
            else if (strcmp(argv[i], "external") == 0)
                utar_set_impl(TARIMPL_EXTERNAL);
            else {
                fprintf(stderr,
                    "udpkg: unknown tar implementation '%s'"
                    " (use: internal, external)\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--tar-implementation=", 21) == 0) {
            const char *val = argv[i] + 21;
            if (strcmp(val, "internal") == 0)
                utar_set_impl(TARIMPL_INTERNAL);
            else if (strcmp(val, "external") == 0)
                utar_set_impl(TARIMPL_EXTERNAL);
            else {
                fprintf(stderr,
                    "udpkg: unknown tar implementation '%s'"
                    " (use: internal, external)\n", val);
                return 1;
            }
        } else if (strcmp(argv[i], "-t") == 0
                   || strcmp(argv[i], "--tar-format") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: %s requires an argument\n", argv[i]);
                return 1;
            }
            i++;
            if (strcmp(argv[i], "auto")  == 0) utar_set_fmt(TARFMT_AUTO);
            else if (strcmp(argv[i], "gnu")   == 0 ||
                     strcmp(argv[i], "posix") == 0) utar_set_fmt(TARFMT_POSIX);
            else if (strcmp(argv[i], "ustar") == 0) utar_set_fmt(TARFMT_USTAR);
            else if (strcmp(argv[i], "pax")   == 0) utar_set_fmt(TARFMT_PAX);
            else if (strcmp(argv[i], "v7")    == 0) utar_set_fmt(TARFMT_V7);
            else {
                fprintf(stderr,
                    "udpkg: unknown tar format '%s'"
                    " (use: auto, gnu, pax, ustar, v7)\n", argv[i]);
                return 1;
            }
        } else if (strncmp(argv[i], "--tar-format=", 13) == 0) {
            const char *val = argv[i] + 13;
            if (strcmp(val, "auto")  == 0) utar_set_fmt(TARFMT_AUTO);
            else if (strcmp(val, "gnu")   == 0 ||
                     strcmp(val, "posix") == 0) utar_set_fmt(TARFMT_POSIX);
            else if (strcmp(val, "ustar") == 0) utar_set_fmt(TARFMT_USTAR);
            else if (strcmp(val, "pax")   == 0) utar_set_fmt(TARFMT_PAX);
            else if (strcmp(val, "v7")    == 0) utar_set_fmt(TARFMT_V7);
            else {
                fprintf(stderr,
                    "udpkg: unknown tar format '%s'"
                    " (use: auto, gnu, pax, ustar, v7)\n", val);
                return 1;
            }
        } else if (strcmp(argv[i], "-v") == 0
                   || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "--root-owner-group") == 0) {
            g_root_owner_group = 1;
        } else if (strcmp(argv[i], "-z") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: -z requires a level argument\n");
                return 1;
            }
            i++;
            g_comp_level = atoi(argv[i]);
            if (g_comp_level < 0 || g_comp_level > 9) {
                fprintf(stderr,
                    "udpkg: compression level must be 0-9\n");
                return 1;
            }
        } else if (strncmp(argv[i], "--compression-level=", 20) == 0) {
            g_comp_level = atoi(argv[i] + 20);
            if (g_comp_level < 0 || g_comp_level > 9) {
                fprintf(stderr,
                    "udpkg: compression level must be 0-9\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-S") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "udpkg: -S requires a strategy name\n");
                return 1;
            }
            i++;
            if (g_compression == COMP_GZIP) {
                if (strcmp(argv[i], "filtered") == 0)      g_comp_strat_gz = 1;
                else if (strcmp(argv[i], "huffman") == 0)  g_comp_strat_gz = 2;
                else if (strcmp(argv[i], "rle")     == 0)  g_comp_strat_gz = 3;
                else if (strcmp(argv[i], "fixed")   == 0)  g_comp_strat_gz = 4;
                else {
                    fprintf(stderr,
                        "udpkg: unknown gzip strategy '%s'"
                        " (use: filtered, huffman, rle, fixed)\n", argv[i]);
                    return 1;
                }
            } else if (g_compression == COMP_XZ) {
                if (strcmp(argv[i], "none")    == 0)     g_comp_strat_xz = 0;
                else if (strcmp(argv[i], "extreme") == 0) g_comp_strat_xz = 1;
                else {
                    fprintf(stderr,
                        "udpkg: unknown xz strategy '%s'"
                        " (use: none, extreme)\n", argv[i]);
                    return 1;
                }
            } else {
                fprintf(stderr,
                    "udpkg: -S is only supported with gzip or xz compression\n");
                return 1;
            }
        } else if (strncmp(argv[i], "--compression-strategy=", 23) == 0) {
            const char *val = argv[i] + 23;
            if (g_compression == COMP_GZIP) {
                if (strcmp(val, "filtered") == 0)      g_comp_strat_gz = 1;
                else if (strcmp(val, "huffman") == 0)  g_comp_strat_gz = 2;
                else if (strcmp(val, "rle")     == 0)  g_comp_strat_gz = 3;
                else if (strcmp(val, "fixed")   == 0)  g_comp_strat_gz = 4;
                else {
                    fprintf(stderr,
                        "udpkg: unknown gzip strategy '%s'"
                        " (use: filtered, huffman, rle, fixed)\n", val);
                    return 1;
                }
            } else if (g_compression == COMP_XZ) {
                if (strcmp(val, "none")    == 0)     g_comp_strat_xz = 0;
                else if (strcmp(val, "extreme") == 0) g_comp_strat_xz = 1;
                else {
                    fprintf(stderr,
                        "udpkg: unknown xz strategy '%s'"
                        " (use: none, extreme)\n", val);
                    return 1;
                }
            } else {
                fprintf(stderr,
                    "udpkg: --compression-strategy is only supported"
                    " with gzip or xz\n");
                return 1;
            }
        } else if (strncmp(argv[i], "--abort-after=", 14) == 0) {
            g_abort_after = atoi(argv[i] + 14);
            if (g_abort_after <= 0) {
                fprintf(stderr,
                    "udpkg: --abort-after requires a positive integer\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--force-all") == 0) {
            g_force_chrootless    = 1;
            g_force_deps          = 1;
            g_force_not_root      = 1;
            g_force_overwrite     = 1;
            g_force_overwrite_dir = 1;
            g_force_confnew       = 1;
        } else {
            fwd[nfwd++] = argv[i];
        }
    }
    if (g_nignore_dep > 0)
        dep_set_ignore(g_ignore_dep, g_nignore_dep);
    if (nfwd < 2) {
        usage(fwd[0] ? fwd[0] : argv[0]);
        sn_close(); log_close();
        return 1;
    }
    fwd[1] = (char *)normalize_action(fwd[1]);
    {
        int ai;
        for (ai = 2; ai < nfwd; ai++) {
            const char *norm = normalize_action(fwd[ai]);
            if (is_action(norm)) {
                fprintf(stderr,
                    "udpkg: error: conflicting actions %s (%s) and %s (%s)\n",
                    fwd[1], action_long_name(fwd[1])
                        ? action_long_name(fwd[1]) : fwd[1],
                    norm, action_long_name(norm)
                        ? action_long_name(norm) : norm);
                sn_close(); log_close();
                return 1;
            }
        }
    }
    if (needs_root_priv(fwd[1]) && geteuid() != 0 && !g_force_not_root) {
        fprintf(stderr,
            "udpkg: error: requested operation requires superuser privilege\n");
        sn_close(); log_close();
        return 1;
    }
    if (strcmp(fwd[1], "--help") == 0 || strcmp(fwd[1], "-h") == 0
        || strcmp(fwd[1], "-?") == 0) {
        usage(fwd[0]);
        sn_close(); log_close();
        return 0;
    }
    if (strcmp(fwd[1], "--info") == 0) {
        int rc = 0;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: --info requires a package file\n");
            sn_close(); log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_info(fwd[i]) != 0)
                rc = 1;
        }
        sn_close(); log_close();
        return rc;
    }
    if (strcmp(fwd[1], "-W") == 0) {
        int rc = 0;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -W/--show requires a package file\n");
            sn_close(); log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_show(fwd[i]) != 0)
                rc = 1;
        }
        sn_close(); log_close();
        return rc;
    }
    if (strcmp(fwd[1], "--contents") == 0) {
        int rc = 0;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: --contents requires a package file\n");
            sn_close(); log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_contents(fwd[i]) != 0)
                rc = 1;
        }
        sn_close(); log_close();
        return rc;
    }
    if (strcmp(fwd[1], "--extract") == 0 || strcmp(fwd[1], "--vextract") == 0) {
        int verbose = (strcmp(fwd[1], "--vextract") == 0);
        if (nfwd < 4) {
            fprintf(stderr, "udpkg: %s requires <pkg.deb> <dir>\n", fwd[1]);
            sn_close(); log_close();
            return 1;
        }
        ret = op_extract(fwd[2], fwd[3], verbose);
        sn_close(); log_close();
        return ret == 0 ? 0 : 1;
    }
    if (strcmp(fwd[1], "--field") == 0) {
        int rc;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: --field requires a package file\n");
            sn_close(); log_close();
            return 1;
        }
        rc = op_field(fwd[2], fwd + 3, nfwd - 3);
        sn_close(); log_close();
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(fwd[1], "-b") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -b requires a source directory\n");
            sn_close(); log_close();
            return 1;
        }
        ret = op_build(fwd[2], nfwd > 3 ? fwd[3] : NULL);
        sn_close(); log_close();
        return ret == 0 ? 0 : 1;
    }
    if (strcmp(fwd[1], "-e") == 0) {
        if (nfwd < 4) {
            fprintf(stderr, "udpkg: -e requires <pkg.deb> <dir>\n");
            sn_close(); log_close();
            return 1;
        }
        ret = op_extract_control(fwd[2], fwd[3]);
        sn_close(); log_close();
        return ret == 0 ? 0 : 1;
    }
    if (strncmp(fwd[1], "--showformat=", 13) == 0) {
        const char *debpath = fwd[1] + 13;
        if (debpath[0] == '\0') {
            fprintf(stderr, "udpkg: --showformat= requires a package file\n");
            sn_close(); log_close();
            return 1;
        }
        ret = op_show(debpath);
        sn_close(); log_close();
        return ret == 0 ? 0 : 1;
    }
    db_set_root(g_root);
    if (admindir_arg[0])
        db_set_admindir(admindir_arg);
    if (admindir_arg[0]) {
        char lkpath[8192];
        snprintf(lkpath, sizeof(lkpath), "%s/lock", admindir_arg);
        lock_set_path(lkpath);
    } else {
        lock_set_root(g_root);
    }
    if (!g_simulate) {
        if (db_init() != 0) {
            fprintf(stderr,
                "udpkg: cannot initialize database\n");
            sn_close(); log_close();
            return 1;
        }
    }
    if (strcmp(fwd[1], "-i") == 0) {
        int force = g_force_deps;
        int start = 2;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            sn_close(); log_close();
            return 1;
        }
        if (nfwd > 2 && strcmp(fwd[2], "-f") == 0) {
            force = 1;
            start = 3;
        }
        if (start >= nfwd) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            sn_close(); log_close();
            return 1;
        }
        if (!g_simulate && lock_acquire() != 0) {
            sn_close(); log_close();
            return 1;
        }
        ret = op_install_batch(fwd + start, nfwd - start, force);
        if (!g_simulate)
            lock_release();
        sn_close(); log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-r") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -r requires at least one package name\n");
            sn_close(); log_close();
            return 1;
        }
        if (!g_simulate && lock_acquire() != 0) {
            sn_close(); log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_remove(fwd[i]) != 0) {
                ret = 1;
                if (g_abort_after > 0) {
                    nerr++;
                    if (nerr >= g_abort_after) {
                        fprintf(stderr,
                            "udpkg: abort-after limit (%d) reached\n",
                            g_abort_after);
                        break;
                    }
                }
            }
        }
        if (!g_simulate)
            lock_release();
        sn_close(); log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-P") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -P requires at least one package name\n");
            sn_close(); log_close();
            return 1;
        }
        if (!g_simulate && lock_acquire() != 0) {
            sn_close(); log_close();
            return 1;
        }
        {
            int nerr2 = 0;
            for (i = 2; i < nfwd; i++) {
                if (op_purge(fwd[i]) != 0) {
                    ret = 1;
                    if (g_abort_after > 0) {
                        nerr2++;
                        if (nerr2 >= g_abort_after) {
                            fprintf(stderr,
                                "udpkg: abort-after limit (%d) reached\n",
                                g_abort_after);
                            break;
                        }
                    }
                }
            }
        }
        if (!g_simulate)
            lock_release();
        sn_close(); log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-l") == 0) {
        ret = db_list(nfwd > 2 ? fwd[2] : NULL, g_no_pager) == 0 ? 0 : 1;
        sn_close(); log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-L") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -L requires a package name\n");
            sn_close(); log_close();
            return 1;
        }
        ret = db_list_files(fwd[2]) == 0 ? 0 : 1;
        sn_close(); log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-s") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -s requires a package name\n");
            sn_close(); log_close();
            return 1;
        }
        ret = op_status(fwd[2]) == 0 ? 0 : 1;
        sn_close(); log_close();
        return ret;
    }
    fprintf(stderr, "udpkg: unknown action '%s'\n", fwd[1]);
    usage(fwd[0]);
    sn_close(); log_close();
    return 1;
}
