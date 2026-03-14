#define _XOPEN_SOURCE 700
#include "status_notify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

static int   g_sn_fd     = -1;
static int   g_sn_log_fd = -1;
static pid_t g_sn_pid    = -1;

void sn_open_fd(int fd)
{
    g_sn_fd = fd;
}

void sn_open_logger(const char *cmd)
{
    int pipefd[2];
    pid_t pid;

    if (!cmd || cmd[0] == '\0')
        return;
    signal(SIGPIPE, SIG_IGN);
    if (pipe(pipefd) != 0)
        return;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    if (pid == 0) {
        close(pipefd[1]);
        if (dup2(pipefd[0], STDIN_FILENO) < 0)
            _exit(127);
        close(pipefd[0]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(pipefd[0]);
    g_sn_log_fd = pipefd[1];
    g_sn_pid    = pid;
}

void sn_close(void)
{
    if (g_sn_fd >= 0) {
        close(g_sn_fd);
        g_sn_fd = -1;
    }
    if (g_sn_log_fd >= 0) {
        close(g_sn_log_fd);
        g_sn_log_fd = -1;
    }
    if (g_sn_pid > 0) {
        int st;
        waitpid(g_sn_pid, &st, 0);
        g_sn_pid = -1;
    }
}

static void sn_write_fd(int *fdp, const char *msg, size_t len)
{
    size_t written = 0;
    ssize_t n;

    while (written < len) {
        n = write(*fdp, msg + written, len - written);
        if (n < 0) {
            if (errno == EPIPE) {
                close(*fdp);
                *fdp = -1;
            }
            break;
        }
        if (n == 0)
            break;
        written += (size_t)n;
    }
}

static void sn_write(const char *msg)
{
    size_t len;

    if (g_sn_fd < 0 && g_sn_log_fd < 0)
        return;
    len = strlen(msg);
    if (g_sn_fd >= 0)
        sn_write_fd(&g_sn_fd, msg, len);
    if (g_sn_log_fd >= 0)
        sn_write_fd(&g_sn_log_fd, msg, len);
}

void sn_processing(const char *action, const char *pkg)
{
    char buf[2048];

    if (g_sn_fd < 0 && g_sn_log_fd < 0)
        return;
    snprintf(buf, sizeof(buf), "processing:%s:%s\n",
             action ? action : "",
             pkg    ? pkg    : "");
    sn_write(buf);
}

void sn_status(const char *pkg, const char *ver, const char *state)
{
    char buf[2048];

    if (g_sn_fd < 0 && g_sn_log_fd < 0)
        return;
    snprintf(buf, sizeof(buf), "status:%s:%s:%s\n",
             pkg   ? pkg   : "",
             ver   ? ver   : "",
             state ? state : "");
    sn_write(buf);
}
