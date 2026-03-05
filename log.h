#ifndef UDPKG_LOG_H
#define UDPKG_LOG_H

void log_open(const char *path);
void log_close(void);
void log_write(const char *fmt, ...);

#endif
