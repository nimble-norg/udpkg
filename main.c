#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include "ar.h"
#include "ctrl.h"
#include "db.h"
#include "dep.h"
#include "lock.h"

extern int chroot(const char *);

#define BATCH_MAX 256
#define MISS_MAX  128

static char g_root[4096]      = "";
static int  g_force_chrootless = 0;

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
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (g_root[0] != '\0')
            setenv("DPKG_ROOT", g_root, 1);
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

static int op_install_one(const char *debpath,
                           const char * const *batch, int nbatch,
                           int force) {
    char ctrl_tar[4096];
    char data_tar[4096];
    char ctrl_file[4096];
    char raw_list[4096];
    char norm_list[4096];
    char tar_root[4096];
    int arfd, ret;
    int have_ctrl = 0, have_data = 0;
    struct stat st;
    ctrl_t ctrl;
    const char *pkgname, *depends;
    dep_list_t dl;
    char missing[MISS_MAX][DEP_PKG_MAX];
    int nmissing = 0;
    ar_entry_t entry;
    int is_upgrade = 0;
    char oldver[256];
    static const char * const mscripts[] =
        { "preinst", "postinst", "prerm", "postrm", NULL };
    int i;
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
    oldver[0] = '\0';
    is_upgrade = db_is_installed(pkgname);
    if (is_upgrade)
        db_get_version(pkgname, oldver, sizeof(oldver));
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
    printf("Unpacking %s (%s) ...\n", pkgname,
        ctrl_get(&ctrl, "Version") ? ctrl_get(&ctrl, "Version") : "?");
    strncpy(tar_root, g_root[0] ? g_root : "/", sizeof(tar_root) - 1);
    {
        char *const argv[] =
            { "tar", "-C", tar_root, "-xf", data_tar, NULL };
        if (xrun(argv) != 0) {
            fprintf(stderr, "udpkg: failed to extract data archive\n");
            tmpci_cleanup();
            return -1;
        }
    }
    snprintf(raw_list,  sizeof(raw_list),  "%s/raw.list",  db_tmpci());
    snprintf(norm_list, sizeof(norm_list), "%s/norm.list", db_tmpci());
    {
        char *const argv[] = { "tar", "-tf", data_tar, NULL };
        xrun_out(argv, raw_list);
    }
    normalize_filelist(raw_list, norm_list);
    printf("Setting up %s (%s) ...\n", pkgname,
        ctrl_get(&ctrl, "Version") ? ctrl_get(&ctrl, "Version") : "?");
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
    tmpci_cleanup();
    return 0;
}

static int op_install_batch(char **debpaths, int ndeb, int force) {
    char *batch_names[BATCH_MAX];
    int nbatch = 0;
    ctrl_t ctrl;
    const char *pkgname;
    int i, ret = 0;
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
    if (!db_is_installed(name)) {
        fprintf(stderr, "udpkg: %s: package not installed\n", name);
        return -1;
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
        if (g_root[0])
            snprintf(fpath, sizeof(fpath), "%s%s", g_root, files[i]);
        else
            strncpy(fpath, files[i], sizeof(fpath) - 1);
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
        "      --help                            Show this help\n"
        "\n"
        "Options:\n"
        "  -f                             Force install despite dep errors\n"
        "  --root=PATH                    Use PATH as filesystem root\n"
        "  --force-script-chrootless      Skip chroot, run scripts on host\n",
        prog);
}

static const char *normalize_action(const char *arg) {
    if (strcmp(arg, "--install")    == 0) return "-i";
    if (strcmp(arg, "--remove")     == 0) return "-r";
    if (strcmp(arg, "--list")       == 0) return "-l";
    if (strcmp(arg, "--list-files") == 0) return "-L";
    if (strcmp(arg, "--status")     == 0) return "-s";
    return arg;
}

static int needs_root_priv(const char *action) {
    return strcmp(action, "-i") == 0 || strcmp(action, "-r") == 0;
}

int main(int argc, char *argv[]) {
    char *fwd[1024];
    int  nfwd = 0;
    int  i, ret = 0;
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
        } else if (strcmp(argv[i], "--force-script-chrootless") == 0) {
            g_force_chrootless = 1;
        } else {
            fwd[nfwd++] = argv[i];
        }
    }
    if (nfwd < 2) {
        usage(fwd[0] ? fwd[0] : argv[0]);
        return 1;
    }
    fwd[1] = (char *)normalize_action(fwd[1]);
    if (needs_root_priv(fwd[1]) && geteuid() != 0) {
        fprintf(stderr,
            "udpkg: error: requested operation requires superuser privilege\n");
        return 1;
    }
    db_set_root(g_root);
    lock_set_root(g_root);
    if (db_init() != 0) {
        fprintf(stderr,
            "udpkg: cannot initialize database%s%s\n",
            g_root[0] ? " under " : "",
            g_root[0] ? g_root : "");
        return 1;
    }
    if (strcmp(fwd[1], "-i") == 0) {
        int force = 0;
        int start = 2;
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            return 1;
        }
        if (nfwd > 2 && strcmp(fwd[2], "-f") == 0) {
            force = 1;
            start = 3;
        }
        if (start >= nfwd) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            return 1;
        }
        if (lock_acquire() != 0)
            return 1;
        ret = op_install_batch(fwd + start, nfwd - start, force);
        lock_release();
        return ret;
    }
    if (strcmp(fwd[1], "-r") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -r requires at least one package name\n");
            return 1;
        }
        if (lock_acquire() != 0)
            return 1;
        for (i = 2; i < nfwd; i++) {
            if (op_remove(fwd[i]) != 0)
                ret = 1;
        }
        lock_release();
        return ret;
    }
    if (strcmp(fwd[1], "-l") == 0)
        return db_list(nfwd > 2 ? fwd[2] : NULL) == 0 ? 0 : 1;
    if (strcmp(fwd[1], "-L") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -L requires a package name\n");
            return 1;
        }
        return db_list_files(fwd[2]) == 0 ? 0 : 1;
    }
    if (strcmp(fwd[1], "-s") == 0) {
        if (nfwd < 3) {
            fprintf(stderr, "udpkg: -s requires a package name\n");
            return 1;
        }
        return op_status(fwd[2]) == 0 ? 0 : 1;
    }
    if (strcmp(fwd[1], "--help") == 0 || strcmp(fwd[1], "-h") == 0) {
        usage(fwd[0]);
        return 0;
    }
    fprintf(stderr, "udpkg: unknown action '%s'\n", fwd[1]);
    usage(fwd[0]);
    return 1;
}
