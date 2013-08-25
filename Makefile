CFLAGS  = -pipe -pedantic -Wall -std=c99
LDFLAGS =

VERSION=$(shell git show -s --pretty=format:"%ci [git commit: %h]")

KERNEL  = $(shell uname -s)

FLAGS	= -DVERSION="\"$(VERSION)\""

all: catnip catnipd

ifeq ($(KERNEL), Linux)
CFLAGS	+= -D_BSD_SOURCE -D_GNU_SOURCE
else ifneq (,$(filter $(KERNEL),FreeBSD NetBSD Darwin))
	@echo $(KERNEL) untested, expect your pants to explode!
CFLAGS	+= -D__BSD_VISIBLE
else
	@echo Sorry \'$(KERNEL)\' is not supported
	@false
endif

ifdef EMBEDDED
	CFLAGS  += -DNDEBUG -Os
else 
	CFLAGS  += -g -O0
	LDFLAGS += -g

	ifdef PROFILE
		CFLAGS  += -pg
		LDFLAGS += -pg
	endif
endif

catnip: catnip.o getopt-client.o cmd.o

catnipd: catnipd.o getopt-daemon.o cmd.o

getopt-client.o: getopt.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) -Iinclude $(FLAGS) -o $@ $<

getopt-daemon.o: getopt.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) -Iinclude $(FLAGS) -DDAEMON -o $@ $<

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) -Iinclude $(FLAGS) $<

%: %.o
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o $@
ifdef EMBEDDED
	$(CROSS_COMPILE)strip $@
endif

clean:
	rm -f *.o catnip catnipd
