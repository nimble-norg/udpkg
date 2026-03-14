#ifndef STATUS_NOTIFY_H
#define STATUS_NOTIFY_H

void sn_open_fd(int fd);
void sn_open_logger(const char *cmd);
void sn_close(void);
void sn_processing(const char *action, const char *pkg);
void sn_status(const char *pkg, const char *ver, const char *state);

#endif
