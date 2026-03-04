#ifndef UDPKG_LOCK_H
#define UDPKG_LOCK_H

void lock_set_root(const char *root);
int  lock_acquire(void);
void lock_release(void);

#endif
