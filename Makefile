CC = gcc
CFLAGS = -g -Wall
CHMOD := $(shell which chmod)
SETCAP := $(shell which setcap)
USER := $(shell whoami)

all: sshpot

sshpot: main.o auth.o
	$(CC) $(CFLAGS) $^ -lssh -o $@

main.o: main.c config.h
	$(CC) $(CFLAGS) -c main.c

auth.o: auth.c auth.h config.h
	$(CC) $(CFLAGS) -c auth.c

install:
	@if [ $(USER) != "root" ]; then echo make install must be run as root.; false; fi
	cp sshpot /usr/sbin/sshpot
	$(CHMOD) 755 /usr/sbin/sshpot
	$(SETCAP) 'cap_net_bind_service=+ep' /usr/sbin/sshpot

clean:
	\/bin/rm -f *.o
