#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "lock.h"

static int lock_fd = -1;

static int pid_is_alive(pid_t pid) {
    if (pid <= 0)
        return 0;
    if (kill(pid, 0) == 0)
        return 1;
    return errno != ESRCH;
}

static pid_t read_lock_pid(int fd) {
    char buf[32];
    ssize_t n;
    lseek(fd, 0, SEEK_SET);
    n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    return (pid_t)atoi(buf);
}

int lock_acquire(void) {
    struct flock fl;
    int fd;
    pid_t stale_pid;
    fd = open(LOCK_F, O_RDWR | O_CREAT, 0640);
    if (fd < 0)
        return -1;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    if (fcntl(fd, F_SETLK, &fl) != 0) {
        struct flock who;
        memset(&who, 0, sizeof(who));
        who.l_type   = F_WRLCK;
        who.l_whence = SEEK_SET;
        who.l_start  = 0;
        who.l_len    = 0;
        if (fcntl(fd, F_GETLK, &who) == 0 && who.l_type != F_UNLCK) {
            fprintf(stderr,
                "udpkg: error: cannot acquire lock on " LOCK_F "\n"
                "udpkg: another instance of udpkg is running (pid %d)\n"
                "udpkg: wait for it to finish, or if it crashed:\n"
                "udpkg:   rm " LOCK_F "  (not recommended)\n",
                (int)who.l_pid);
        } else {
            fprintf(stderr,
                "udpkg: error: cannot acquire lock on " LOCK_F "\n");
        }
        close(fd);
        return -1;
    }
    stale_pid = read_lock_pid(fd);
    if (stale_pid > 0 && pid_is_alive(stale_pid)) {
        fprintf(stderr,
            "udpkg: error: cannot acquire lock on " LOCK_F "\n"
            "udpkg: another instance of udpkg is running (pid %d)\n"
            "udpkg: wait for it to finish, or if it crashed:\n"
            "udpkg:   rm " LOCK_F "  (not recommended)\n",
            (int)stale_pid);
        {
            struct flock ul;
            memset(&ul, 0, sizeof(ul));
            ul.l_type   = F_UNLCK;
            ul.l_whence = SEEK_SET;
            ul.l_start  = 0;
            ul.l_len    = 0;
            fcntl(fd, F_SETLK, &ul);
        }
        close(fd);
        return -1;
    }
    if (stale_pid > 0) {
        fprintf(stderr,
            "udpkg: error: lock file " LOCK_F " found with stale pid %d\n"
            "udpkg: the previous udpkg process may have crashed\n"
            "udpkg:   rm " LOCK_F "  (not recommended)\n",
            (int)stale_pid);
        {
            struct flock ul;
            memset(&ul, 0, sizeof(ul));
            ul.l_type   = F_UNLCK;
            ul.l_whence = SEEK_SET;
            ul.l_start  = 0;
            ul.l_len    = 0;
            fcntl(fd, F_SETLK, &ul);
        }
        close(fd);
        return -1;
    }
    ftruncate(fd, 0);
    lseek(fd, 0, SEEK_SET);
    {
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        write(fd, buf, (size_t)len);
    }
    lock_fd = fd;
    return 0;
}

void lock_release(void) {
    struct flock fl;
    if (lock_fd < 0)
        return;
    ftruncate(lock_fd, 0);
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    fcntl(lock_fd, F_SETLK, &fl);
    close(lock_fd);
    lock_fd = -1;
}
