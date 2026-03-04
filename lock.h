#ifndef UDPKG_LOCK_H
#define UDPKG_LOCK_H

#define LOCK_F "/var/lib/udpkg/lock"

int  lock_acquire(void);
void lock_release(void);

#endif
