CFLAGS  = -pipe -Wall -pedantic -std=c99
#LDFLAGS = 

VERSION=$(shell git show -s --pretty=format:"%ci [git commit: %h]")

KERNEL  = $(shell uname -s)

OBJS    = catnip.o

all: env catnip

env:
ifeq ($(KERNEL), Linux)
CFLAGS += -D_BSD_SOURCE -D_GNU_SOURCE
else ifeq ($(KERNEL), FreeBSD)
	@echo FreeBSD untested, expect your pants to explode!
CFLAGS += -D__BSD_VISIBLE
else ifeq ($(KERNEL), FreeBSD)
	@echo NetBSD untested, expect your pants to explode!
CFLAGS += -D__BSD_VISIBLE
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

catnip: $(OBJS)
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o catnip
ifdef EMBEDDED
	$(CROSS_COMPILE)strip catnip
endif

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) -Iinclude -DVERSION="\"$(VERSION)\"" $<

clean:
	rm -f $(OBJS) catnip
