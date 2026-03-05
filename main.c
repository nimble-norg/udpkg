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
#include "dep.h"
#include "lock.h"
#include "log.h"

extern int chroot(const char *);

#define BATCH_MAX      256
#define MISS_MAX       DEP_MISS_MAX
#define IGNORE_DEP_MAX 64

static char g_root[4096]       = "";
static char g_instdir[4096]    = "";
static int  g_force_chrootless    = 0;
static int  g_force_deps          = 0;
static int  g_force_not_root      = 0;
static int  g_force_overwrite     = 0;
static int  g_force_overwrite_dir = 0;
static int  g_simulate         = 0;

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
    static const char * const required[] = { "tar", "rm", "sh", NULL };
    int i, ok = 1;
    for (i = 0; required[i]; i++) {
        if (!cmd_available(required[i])) {
            fprintf(stderr, "udpkg: required command not found in PATH: %s\n",
                    required[i]);
            ok = 0;
        }
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

static int xrun_out(char *const argv[], const char *outfile) {
    pid_t pid;
    int status, fd;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
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
    ar_entry_t entry;
    int arfd, ret, have_ctrl = 0;
    struct stat st;
    strncpy(tmpscan, "/tmp/udpkg_scan_XXXXXX", sizeof(tmpscan) - 1);
    tmpscan[sizeof(tmpscan) - 1] = '\0';
    if (!mkdtemp(tmpscan))
        return -1;
    memset(&entry, 0, sizeof(entry));
    arfd = ar_open(debpath);
    if (arfd < 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    while ((ret = ar_next(arfd, &entry)) == 1) {
        if (strncmp(entry.name, "control.tar", 11) == 0) {
            snprintf(ctrl_tar, sizeof(ctrl_tar), "%s/%s", tmpscan, entry.name);
            ar_extract(arfd, &entry, ctrl_tar);
            have_ctrl = 1;
            break;
        }
    }
    close(arfd);
    if (!have_ctrl) {
        cleanup_dir(tmpscan);
        return -1;
    }
    snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", tmpscan);
    if (mkdir(ctrl_dir, 0755) != 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    {
        char *const argv[] = { "tar", "-C", ctrl_dir, "-xf", ctrl_tar, NULL };
        if (xrun(argv) != 0) {
            cleanup_dir(tmpscan);
            return -1;
        }
    }
    snprintf(ctrl_file, sizeof(ctrl_file), "%s/control", ctrl_dir);
    if (stat(ctrl_file, &st) != 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    ret = ctrl_parse(ctrl_file, ctrl);
    cleanup_dir(tmpscan);
    return ret;
}

static int op_info(const char *debpath) {
    char tmpscan[64];
    char ctrl_tar[256];
    char ctrl_dir[256];
    ar_entry_t entry;
    int arfd, ret;
    int have_ctrl = 0;
    size_t ctrl_archive_size = 0;
    struct stat deb_st;
    ctrl_t ctrl;
    int i;
    if (stat(debpath, &deb_st) != 0) {
        fprintf(stderr, "udpkg: cannot stat '%s': %s\n",
                debpath, strerror(errno));
        return -1;
    }
    strncpy(tmpscan, "/tmp/udpkg_info_XXXXXX", sizeof(tmpscan) - 1);
    tmpscan[sizeof(tmpscan) - 1] = '\0';
    if (!mkdtemp(tmpscan))
        return -1;
    memset(&entry, 0, sizeof(entry));
    arfd = ar_open(debpath);
    if (arfd < 0) {
        fprintf(stderr, "udpkg: cannot open '%s': not a valid .deb archive\n",
                debpath);
        cleanup_dir(tmpscan);
        return -1;
    }
    while ((ret = ar_next(arfd, &entry)) == 1) {
        if (strncmp(entry.name, "control.tar", 11) == 0) {
            ctrl_archive_size = entry.size;
            snprintf(ctrl_tar, sizeof(ctrl_tar), "%s/%s", tmpscan, entry.name);
            ar_extract(arfd, &entry, ctrl_tar);
            have_ctrl = 1;
            break;
        }
    }
    close(arfd);
    if (!have_ctrl) {
        fprintf(stderr, "udpkg: malformed .deb: missing control member\n");
        cleanup_dir(tmpscan);
        return -1;
    }
    snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", tmpscan);
    if (mkdir(ctrl_dir, 0755) != 0) {
        cleanup_dir(tmpscan);
        return -1;
    }
    {
        char *const argv[] = { "tar", "-C", ctrl_dir, "-xf", ctrl_tar, NULL };
        if (xrun(argv) != 0) {
            fprintf(stderr, "udpkg: failed to extract control archive\n");
            cleanup_dir(tmpscan);
            return -1;
        }
    }
    {
        char ctrl_file[512];
        snprintf(ctrl_file, sizeof(ctrl_file), "%s/control", ctrl_dir);
        if (ctrl_parse(ctrl_file, &ctrl) != 0) {
            fprintf(stderr, "udpkg: cannot parse control file\n");
            cleanup_dir(tmpscan);
            return -1;
        }
    }
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
    int arfd, ret;
    int have_ctrl = 0, have_data = 0;
    struct stat st;
    ctrl_t ctrl;
    const char *pkgname, *depends, *arch, *ver;
    dep_list_t dl;
    char missing[MISS_MAX][DEP_MISS_MAX];
    int nmissing = 0;
    ar_entry_t entry;
    int is_upgrade = 0;
    char oldver[256];
    static const char * const mscripts[] =
        { "preinst", "postinst", "prerm", "postrm", NULL };
    int i;
    if (!g_simulate && !check_prereqs())
        return -1;
    if (tmpci_setup() != 0) {
        fprintf(stderr, "udpkg: cannot create %s\n", db_tmpci());
        return -1;
    }
    memset(&entry, 0, sizeof(entry));
    arfd = ar_open(debpath);
    if (arfd < 0) {
        fprintf(stderr,
            "udpkg: cannot open '%s': not a valid .deb archive\n", debpath);
        tmpci_cleanup();
        return -1;
    }
    while ((ret = ar_next(arfd, &entry)) == 1) {
        if (strncmp(entry.name, "control.tar", 11) == 0) {
            snprintf(ctrl_tar, sizeof(ctrl_tar),
                     "%s/%s", db_tmpci(), entry.name);
            ar_extract(arfd, &entry, ctrl_tar);
            have_ctrl = 1;
        } else if (strncmp(entry.name, "data.tar", 8) == 0) {
            snprintf(data_tar, sizeof(data_tar),
                     "%s/%s", db_tmpci(), entry.name);
            ar_extract(arfd, &entry, data_tar);
            have_data = 1;
        }
    }
    close(arfd);
    if (!have_ctrl || !have_data) {
        fprintf(stderr,
            "udpkg: malformed .deb: missing control or data member\n");
        tmpci_cleanup();
        return -1;
    }
    {
        char *const argv[] =
            { "tar", "-C", (char *)db_tmpci_ctrl(), "-xf", ctrl_tar, NULL };
        if (xrun(argv) != 0) {
            fprintf(stderr, "udpkg: failed to extract control archive\n");
            tmpci_cleanup();
            return -1;
        }
    }
    snprintf(ctrl_file, sizeof(ctrl_file), "%s/control", db_tmpci_ctrl());
    if (stat(ctrl_file, &st) != 0) {
        fprintf(stderr, "udpkg: control file not found in package\n");
        tmpci_cleanup();
        return -1;
    }
    if (ctrl_parse(ctrl_file, &ctrl) != 0) {
        fprintf(stderr, "udpkg: cannot parse control file\n");
        tmpci_cleanup();
        return -1;
    }
    pkgname = ctrl_get(&ctrl, "Package");
    if (!pkgname) {
        fprintf(stderr, "udpkg: control file missing Package field\n");
        tmpci_cleanup();
        return -1;
    }
    arch = ctrl_get(&ctrl, "Architecture");
    ver  = ctrl_get(&ctrl, "Version");
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
        char *const argv[] = { "tar", "-tf", data_tar, NULL };
        xrun_out(argv, raw_list);
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
    {
        char script_path[4096];
        snprintf(script_path, sizeof(script_path),
                 "%s/preinst", db_tmpci_ctrl());
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc;
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
        {
            char *const argv[] =
                { "tar", "-C", instroot, "-xf", data_tar, NULL };
            if (xrun(argv) != 0) {
                fprintf(stderr, "udpkg: failed to extract data archive\n");
                tmpci_cleanup();
                return -1;
            }
        }
    }
    printf("Setting up %s (%s) ...\n", pkgname, ver ? ver : "?");
    if (db_install(&ctrl, norm_list) != 0) {
        fprintf(stderr, "udpkg: failed to update package database\n");
        tmpci_cleanup();
        return -1;
    }
    for (i = 0; mscripts[i]; i++) {
        char src[4096];
        snprintf(src, sizeof(src), "%s/%s", db_tmpci_ctrl(), mscripts[i]);
        if (stat(src, &st) == 0)
            db_install_script(pkgname, mscripts[i], src);
    }
    {
        char script_path[4096];
        db_get_scriptpath(pkgname, "postinst", script_path, sizeof(script_path));
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc = run_script(script_path, "configure",
                                is_upgrade && oldver[0] ? oldver : NULL);
            if (sc != 0)
                fprintf(stderr,
                    "udpkg: subprocess postinst returned error code %d\n",
                    sc);
        }
    }
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
    int i, ret = 0;
    log_write("startup archives install");
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
                           force) != 0)
            ret = 1;
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
    if (!g_simulate && !check_prereqs())
        return -1;
    ver[0] = '\0';
    db_get_version(name, ver, sizeof(ver));
    if (db_get(name, &c) == 0)
        arch = ctrl_get(&c, "Architecture");
    log_write("startup archives remove");
    log_write("remove %s:%s %s <none>",
              name, arch ? arch : "unknown", ver[0] ? ver : "<none>");
    if (g_simulate) {
        printf("Remv %s [%s] (simulated)\n", name, ver[0] ? ver : "?");
        return 0;
    }
    printf("Removing %s ...\n", name);
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
    db_remove_scripts(name);
    return 0;
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
    ar_entry_t entry;
    int arfd, ret, found = 0;
    strncpy(tmpdir, "/tmp/udpkg_xtr_XXXXXX", sizeof(tmpdir) - 1);
    tmpdir[sizeof(tmpdir) - 1] = '\0';
    if (!mkdtemp(tmpdir))
        return -1;
    memset(&entry, 0, sizeof(entry));
    arfd = ar_open(debpath);
    if (arfd < 0) {
        fprintf(stderr, "udpkg: cannot open '%s': not a valid .deb archive\n",
                debpath);
        cleanup_dir(tmpdir);
        return -1;
    }
    while ((ret = ar_next(arfd, &entry)) == 1) {
        if (strncmp(entry.name, "data.tar", 8) == 0) {
            snprintf(out_tar, outsz, "%s/%s", tmpdir, entry.name);
            ar_extract(arfd, &entry, out_tar);
            found = 1;
            break;
        }
    }
    close(arfd);
    if (!found) {
        fprintf(stderr, "udpkg: malformed .deb: missing data member\n");
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
    {
        char taropt[8];
        strncpy(taropt, verbose ? "-xvf" : "-xf", sizeof(taropt) - 1);
        taropt[sizeof(taropt) - 1] = '\0';
        {
            char *const argv[] = { "tar", "-C", (char *)destdir,
                                   taropt, data_tar, NULL };
            rc = xrun(argv);
        }
    }
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
    {
        char *const argv[] = { "tar", "-tvf", data_tar, NULL };
        rc = xrun(argv);
    }
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

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <action> ...\n"
        "\n"
        "Actions:\n"
        "  -i, --install [-f] <pkg.deb> [...]   Install package(s)\n"
        "  -r, --remove <pkg> [...]              Remove package(s)\n"
        "  -l, --list [pattern]                  List installed packages\n"
        "  -L, --list-files <pkg>                List files owned by package\n"
        "  -s, --status <pkg>                    Show package status\n"
        "  -W, --show <pkg.deb>                  Show name and version\n"
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
        "  --ignore-depends=P1[,P2,...]   Ignore dependency on listed packages\n"
        "  --force-script-chrootless      Skip chroot, run scripts on host\n"
        "  --force-not-root               Skip superuser privilege check\n"
        "  --force-overwrite              Allow overwriting files from other packages\n"
        "  --force-overwrite-dir          Allow overwriting dirs from other packages\n"
        "  --force-all                    Enable all --force-* options\n",
        prog);
}

static const char *normalize_action(const char *arg) {
    if (strcmp(arg, "--install")    == 0) return "-i";
    if (strcmp(arg, "--remove")     == 0) return "-r";
    if (strcmp(arg, "--list")       == 0) return "-l";
    if (strcmp(arg, "--list-files") == 0) return "-L";
    if (strcmp(arg, "--status")     == 0) return "-s";
    if (strcmp(arg, "--show")       == 0) return "-W";
    return arg;
}

static int needs_root_priv(const char *action) {
    return strcmp(action, "-i") == 0 || strcmp(action, "-r") == 0;
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

int main(int argc, char *argv[]) {
    char *fwd[1024];
    int  nfwd = 0;
    int  i, ret = 0;
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
        } else if (strncmp(argv[i], "--log=", 6) == 0) {
            log_open(argv[i] + 6);
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
        } else if (strcmp(argv[i], "--force-all") == 0) {
            g_force_chrootless    = 1;
            g_force_deps          = 1;
            g_force_not_root      = 1;
            g_force_overwrite     = 1;
            g_force_overwrite_dir = 1;
        } else {
            fwd[nfwd++] = argv[i];
        }
    }
    if (g_nignore_dep > 0)
        dep_set_ignore(g_ignore_dep, g_nignore_dep);
    if (nfwd < 2) {
        usage(fwd[0] ? fwd[0] : argv[0]);
        log_close();
        return 1;
    }
    fwd[1] = (char *)normalize_action(fwd[1]);
    if (needs_root_priv(fwd[1]) && geteuid() != 0 && !g_force_not_root) {
        fprintf(stderr,
            "udpkg: error: requested operation requires superuser privilege\n");
        log_close();
        return 1;
    }
    if (strcmp(fwd[1], "--help") == 0 || strcmp(fwd[1], "-h") == 0
        || strcmp(fwd[1], "-?") == 0) {
        usage(fwd[0]);
        log_close();
        return 0;
    }
    if (strcmp(fwd[1], "--info") == 0) {
        int rc = 0;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: --info requires a package file\n");
            log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_info(fwd[i]) != 0)
                rc = 1;
        }
        log_close();
        return rc;
    }
    if (strcmp(fwd[1], "-W") == 0) {
        int rc = 0;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -W/--show requires a package file\n");
            log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_show(fwd[i]) != 0)
                rc = 1;
        }
        log_close();
        return rc;
    }
    if (strcmp(fwd[1], "--contents") == 0) {
        int rc = 0;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: --contents requires a package file\n");
            log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_contents(fwd[i]) != 0)
                rc = 1;
        }
        log_close();
        return rc;
    }
    if (strcmp(fwd[1], "--extract") == 0 || strcmp(fwd[1], "--vextract") == 0) {
        int verbose = (strcmp(fwd[1], "--vextract") == 0);
        if (nfwd < 4) {
            fprintf(stderr, "udpkg: %s requires <pkg.deb> <dir>\n", fwd[1]);
            log_close();
            return 1;
        }
        ret = op_extract(fwd[2], fwd[3], verbose);
        log_close();
        return ret == 0 ? 0 : 1;
    }
    if (strcmp(fwd[1], "--field") == 0) {
        int rc;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: --field requires a package file\n");
            log_close();
            return 1;
        }
        rc = op_field(fwd[2], fwd + 3, nfwd - 3);
        log_close();
        return rc == 0 ? 0 : 1;
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
            log_close();
            return 1;
        }
    }
    if (strcmp(fwd[1], "-i") == 0) {
        int force = g_force_deps;
        int start = 2;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            log_close();
            return 1;
        }
        if (nfwd > 2 && strcmp(fwd[2], "-f") == 0) {
            force = 1;
            start = 3;
        }
        if (start >= nfwd) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            log_close();
            return 1;
        }
        if (!g_simulate && lock_acquire() != 0) {
            log_close();
            return 1;
        }
        ret = op_install_batch(fwd + start, nfwd - start, force);
        if (!g_simulate)
            lock_release();
        log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-r") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -r requires at least one package name\n");
            log_close();
            return 1;
        }
        if (!g_simulate && lock_acquire() != 0) {
            log_close();
            return 1;
        }
        for (i = 2; i < nfwd; i++) {
            if (op_remove(fwd[i]) != 0)
                ret = 1;
        }
        if (!g_simulate)
            lock_release();
        log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-l") == 0) {
        ret = db_list(nfwd > 2 ? fwd[2] : NULL) == 0 ? 0 : 1;
        log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-L") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -L requires a package name\n");
            log_close();
            return 1;
        }
        ret = db_list_files(fwd[2]) == 0 ? 0 : 1;
        log_close();
        return ret;
    }
    if (strcmp(fwd[1], "-s") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -s requires a package name\n");
            log_close();
            return 1;
        }
        ret = op_status(fwd[2]) == 0 ? 0 : 1;
        log_close();
        return ret;
    }
    fprintf(stderr, "udpkg: unknown action '%s'\n", fwd[1]);
    usage(fwd[0]);
    log_close();
    return 1;
}
