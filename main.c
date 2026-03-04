#define _POSIX_C_SOURCE 200809L
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

#define BATCH_MAX    256
#define MISS_MAX     128
#define TMP_CI_CTRL  TMP_CI "/ctrl"

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
    cleanup_dir(TMP_CI);
    if (mkdir(TMP_CI, 0700) != 0)
        return -1;
    if (mkdir(TMP_CI_CTRL, 0700) != 0)
        return -1;
    return 0;
}

static void tmpci_cleanup(void) {
    cleanup_dir(TMP_CI);
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

static int run_script(const char *path, const char *arg1, const char *arg2) {
    struct stat st;
    pid_t pid;
    int status;
    if (stat(path, &st) != 0)
        return 0;
    if (!(st.st_mode & S_IXUSR))
        return 0;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
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

static int run_installed_script(const char *pkgname, const char *script,
                                const char *arg1, const char *arg2) {
    char path[512];
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
    char ctrl_tar[256];
    char data_tar[256];
    char ctrl_file[512];
    char raw_list[512];
    char norm_list[512];
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
        fprintf(stderr, "udpkg: cannot create " TMP_CI "\n");
        return -1;
    }

    memset(&entry, 0, sizeof(entry));
    arfd = ar_open(debpath);
    if (arfd < 0) {
        fprintf(stderr, "udpkg: cannot open '%s': not a valid .deb archive\n",
                debpath);
        tmpci_cleanup();
        return -1;
    }
    while ((ret = ar_next(arfd, &entry)) == 1) {
        if (strncmp(entry.name, "control.tar", 11) == 0) {
            snprintf(ctrl_tar, sizeof(ctrl_tar), TMP_CI "/%s", entry.name);
            ar_extract(arfd, &entry, ctrl_tar);
            have_ctrl = 1;
        } else if (strncmp(entry.name, "data.tar", 8) == 0) {
            snprintf(data_tar, sizeof(data_tar), TMP_CI "/%s", entry.name);
            ar_extract(arfd, &entry, data_tar);
            have_data = 1;
        }
    }
    close(arfd);
    if (!have_ctrl || !have_data) {
        fprintf(stderr, "udpkg: malformed .deb: missing control or data member\n");
        tmpci_cleanup();
        return -1;
    }
    {
        char *const argv[] = { "tar", "-C", TMP_CI_CTRL, "-xf", ctrl_tar, NULL };
        if (xrun(argv) != 0) {
            fprintf(stderr, "udpkg: failed to extract control archive\n");
            tmpci_cleanup();
            return -1;
        }
    }
    snprintf(ctrl_file, sizeof(ctrl_file), TMP_CI_CTRL "/control");
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
        printf("(Reading database ... )\nPreparing to unpack %s ...\n", debpath);
    else
        printf("Selecting previously unselected package %s.\n"
               "(Reading database ... )\nPreparing to unpack %s ...\n",
               pkgname, debpath);
    {
        char script_path[512];
        snprintf(script_path, sizeof(script_path),
                 TMP_CI_CTRL "/%s", "preinst");
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc;
            if (is_upgrade)
                sc = run_script(script_path, "upgrade", oldver[0] ? oldver : NULL);
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
    {
        char *const argv[] = { "tar", "-C", "/", "-xf", data_tar, NULL };
        if (xrun(argv) != 0) {
            fprintf(stderr, "udpkg: failed to extract data archive\n");
            tmpci_cleanup();
            return -1;
        }
    }
    snprintf(raw_list,  sizeof(raw_list),  TMP_CI "/raw.list");
    snprintf(norm_list, sizeof(norm_list), TMP_CI "/norm.list");
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
        char src[512];
        snprintf(src, sizeof(src), TMP_CI_CTRL "/%s", mscripts[i]);
        if (stat(src, &st) == 0)
            db_install_script(pkgname, mscripts[i], src);
    }
    {
        char script_path[512];
        db_get_scriptpath(pkgname, "postinst", script_path, sizeof(script_path));
        if (stat(script_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int sc = run_script(script_path, "configure",
                                is_upgrade && oldver[0] ? oldver : NULL);
            if (sc != 0)
                fprintf(stderr,
                    "udpkg: subprocess postinst returned error code %d\n", sc);
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
    char listpath[512];
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
        if (lstat(files[i], &st) == 0) {
            if (S_ISDIR(st.st_mode))
                rmdir(files[i]);
            else
                unlink(files[i]);
        }
        free(files[i]);
    }
    free(files);
    db_remove(name);
    {
        char script_path[512];
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
        "Usage: %s <action> [options] ...\n"
        "\n"
        "Actions:\n"
        "  -i [-f] <pkg.deb> [...]   Install package(s)\n"
        "  -r <pkg> [...]            Remove package(s)\n"
        "  -l [pattern]              List installed packages\n"
        "  -L <pkg>                  List files owned by package\n"
        "  -s <pkg>                  Show package status\n"
        "  --help                    Show this help\n"
        "\n"
        "Options:\n"
        "  -f                        Force install, ignoring dependency errors\n",
        prog);
}

static int needs_root(const char *action) {
    return strcmp(action, "-i") == 0 || strcmp(action, "-r") == 0;
}

int main(int argc, char *argv[]) {
    int i, ret = 0;
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    if (needs_root(argv[1]) && geteuid() != 0) {
        fprintf(stderr,
            "udpkg: error: requested operation requires superuser privilege\n");
        return 1;
    }
    if (db_init() != 0) {
        fprintf(stderr, "udpkg: cannot initialize database at %s\n", DB_DIR);
        return 1;
    }
    if (strcmp(argv[1], "-i") == 0) {
        int force = 0;
        int start = 2;
        if (argc < 3) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            return 1;
        }
        if (argc > 2 && strcmp(argv[2], "-f") == 0) {
            force = 1;
            start = 3;
        }
        if (start >= argc) {
            fprintf(stderr, "udpkg: -i requires at least one package file\n");
            return 1;
        }
        if (lock_acquire() != 0)
            return 1;
        ret = op_install_batch(argv + start, argc - start, force);
        lock_release();
        return ret;
    }
    if (strcmp(argv[1], "-r") == 0) {
        if (argc < 3) {
            fprintf(stderr, "udpkg: -r requires at least one package name\n");
            return 1;
        }
        if (lock_acquire() != 0)
            return 1;
        for (i = 2; i < argc; i++) {
            if (op_remove(argv[i]) != 0)
                ret = 1;
        }
        lock_release();
        return ret;
    }
    if (strcmp(argv[1], "-l") == 0)
        return db_list(argc > 2 ? argv[2] : NULL) == 0 ? 0 : 1;
    if (strcmp(argv[1], "-L") == 0) {
        if (argc < 3) {
            fprintf(stderr, "udpkg: -L requires a package name\n");
            return 1;
        }
        return db_list_files(argv[2]) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "-s") == 0) {
        if (argc < 3) {
            fprintf(stderr, "udpkg: -s requires a package name\n");
            return 1;
        }
        return op_status(argv[2]) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage(argv[0]);
        return 0;
    }
    fprintf(stderr, "udpkg: unknown action '%s'\n", argv[1]);
    usage(argv[0]);
    return 1;
}
