#define _XOPEN_SOURCE 700
#include "utar.h"
#include "tar_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

static int g_impl = TARIMPL_INTERNAL;
static int g_fmt  = TARFMT_AUTO;

void utar_set_impl(int impl) { g_impl = impl; }
void utar_set_fmt(int fmt)   { g_fmt  = fmt;  }
int  utar_get_impl(void)     { return g_impl; }
int  utar_get_fmt(void)      { return g_fmt;  }

const char *utar_impl_name(void) {
    return g_impl == TARIMPL_EXTERNAL ? "external" : "internal";
}

const char *utar_fmt_name(int fmt) {
    switch (fmt) {
        case TARFMT_POSIX: return "gnu";
        case TARFMT_USTAR: return "ustar";
        case TARFMT_PAX:   return "pax";
        case TARFMT_V7:    return "v7";
        default:           return "auto";
    }
}

static int xrun_ext(char *const argv[]) {
    pid_t pid;
    int status;
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execvp(argv[0], argv); _exit(127); }
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int xrun_ext_out(char *const argv[], const char *outfile) {
    pid_t pid;
    int status, fd;
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (outfile) {
            fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static const char *ext_fmt_flag(void) {
    switch (g_fmt) {
        case TARFMT_POSIX: return "--format=gnu";
        case TARFMT_USTAR: return "--format=ustar";
        case TARFMT_PAX:   return "--format=pax";
        case TARFMT_V7:    return "--format=v7";
        default:           return NULL;
    }
}

int utar_create(const char *archive, const char *srcdir,
                const char *exclude, int verbose) {
    if (g_impl == TARIMPL_INTERNAL)
        return tar_create(archive, srcdir, exclude, g_fmt, verbose);
    {
        char *argv[20];
        int n = 0;
        const char *fmt_flag = ext_fmt_flag();
        argv[n++] = "tar";
        argv[n++] = "-C";
        argv[n++] = (char *)srcdir;
        if (verbose) argv[n++] = "-v";
        if (fmt_flag) argv[n++] = (char *)fmt_flag;
        argv[n++] = "-cf";
        argv[n++] = (char *)archive;
        if (exclude) {
            argv[n++] = "--exclude";
            argv[n++] = (char *)exclude;
        }
        argv[n++] = ".";
        argv[n]   = NULL;
        return xrun_ext(argv);
    }
}

int utar_extract(const char *archive, const char *destdir, int verbose) {
    if (g_impl == TARIMPL_INTERNAL)
        return tar_extract(archive, destdir, g_fmt, verbose);
    {
        char taropt[8];
        char *argv[12];
        int n = 0;
        strncpy(taropt, verbose ? "-xvf" : "-xf", sizeof(taropt) - 1);
        taropt[sizeof(taropt) - 1] = '\0';
        argv[n++] = "tar";
        argv[n++] = "-C";
        argv[n++] = (char *)destdir;
        argv[n++] = taropt;
        argv[n++] = (char *)archive;
        argv[n]   = NULL;
        return xrun_ext(argv);
    }
}

int utar_list(const char *archive, int verbose, char *outfile) {
    if (g_impl == TARIMPL_INTERNAL)
        return tar_list(archive, g_fmt, verbose, outfile);
    {
        char *argv[8];
        int n = 0;
        argv[n++] = "tar";
        argv[n++] = "-tf";
        argv[n++] = (char *)archive;
        argv[n]   = NULL;
        return xrun_ext_out(argv, outfile);
    }
}

int utar_list_stdout(const char *archive, int verbose) {
    if (g_impl == TARIMPL_INTERNAL)
        return tar_list(archive, g_fmt, verbose, NULL);
    {
        char *argv[8];
        int n = 0;
        argv[n++] = "tar";
        argv[n++] = verbose ? "-tvf" : "-tf";
        argv[n++] = (char *)archive;
        argv[n]   = NULL;
        return xrun_ext(argv);
    }
}
