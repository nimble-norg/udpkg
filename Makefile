CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
TARGET = udpkg
OBJS   = ar.o ctrl.o db.o dep.o lock.o main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS)

ar.o: ar.c ar.h
	$(CC) $(CFLAGS) -c ar.c

ctrl.o: ctrl.c ctrl.h
	$(CC) $(CFLAGS) -c ctrl.c

lock.o: lock.c lock.h
	$(CC) $(CFLAGS) -c lock.c

dep.o: dep.c dep.h db.h
	$(CC) $(CFLAGS) -c dep.c

	$(CC) $(CFLAGS) -c lock.c

db.o: db.c db.h ctrl.h
	$(CC) $(CFLAGS) -c db.c

main.o: main.c ar.h ctrl.h db.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: all clean install
