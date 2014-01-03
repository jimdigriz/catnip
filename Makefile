KERNEL  = $(shell uname -s)
LDFLAGS	= -lpthread

CFLAGS  = -pipe -pedantic -Wall -std=c99

VERSION	= $(shell git show -s --pretty=format:"%ci [git commit: %h]")

FLAGS	= -DVERSION="\"$(VERSION)\""

all: catnip catnipd

ifeq ($(KERNEL), Linux)
CFLAGS	+= -fdata-sections -ffunction-sections
LDFLAGS	+= -Wl,--gc-sections

CFLAGS	+= -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
else ifneq (,$(filter $(KERNEL),FreeBSD NetBSD Darwin))
	@echo $(KERNEL) untested, expect your pants to explode!
CFLAGS	+=
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

catnip: catnip.o getopt-client.o common.o
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) -lpcap $^ -o $@
ifdef EMBEDDED
	$(CROSS_COMPILE)strip $@
endif

catnipd: catnipd.o getopt-daemon.o common.o

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
