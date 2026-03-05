#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"

static FILE *g_log = NULL;

void log_open(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;
    g_log = fdopen(fd, "a");
}

void log_close(void) {
    if (!g_log)
        return;
    fclose(g_log);
    g_log = NULL;
}

void log_write(const char *fmt, ...) {
    char tsbuf[32];
    time_t now;
    struct tm tm_s;
    va_list ap;
    if (!g_log)
        return;
    now = time(NULL);
    localtime_r(&now, &tm_s);
    strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", &tm_s);
    fprintf(g_log, "%s ", tsbuf);
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}
