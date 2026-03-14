CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
TARGET = udpkg
OBJS   = ar.o ctrl.o db.o deb_fmt.o dep.o lock.o log.o tar_impl.o utar.o status_notify.o main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS)

ar.o: ar.c ar.h
	$(CC) $(CFLAGS) -c ar.c

ctrl.o: ctrl.c ctrl.h
	$(CC) $(CFLAGS) -c ctrl.c

deb_fmt.o: deb_fmt.c deb_fmt.h ar.h
	$(CC) $(CFLAGS) -c deb_fmt.c

db.o: db.c db.h ctrl.h
	$(CC) $(CFLAGS) -c db.c

dep.o: dep.c dep.h db.h
	$(CC) $(CFLAGS) -c dep.c

lock.o: lock.c lock.h
	$(CC) $(CFLAGS) -c lock.c

log.o: log.c log.h
	$(CC) $(CFLAGS) -c log.c

tar_impl.o: tar_impl.c tar_impl.h
	$(CC) $(CFLAGS) -c tar_impl.c

utar.o: utar.c utar.h tar_impl.h
	$(CC) $(CFLAGS) -c utar.c

status_notify.o: status_notify.c status_notify.h
	$(CC) $(CFLAGS) -c status_notify.c

main.o: main.c ar.h ctrl.h db.h deb_fmt.h dep.h lock.h log.h utar.h status_notify.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: all clean install
