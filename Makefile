# Makefile for Isolate
# (c) 2015--2017 Martin Mares <mj@ucw.cz>
# (c) 2017 Bernard Blackham <bernard@blackham.com.au>

all: isolate isolate.1 isolate.1.html isolate-check-environment

CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Wno-parentheses -Wno-unused-result -Wno-missing-field-initializers -Wstrict-prototypes -Wmissing-prototypes -D_GNU_SOURCE
LIBS=-lcap

VERSION=1.3
YEAR=2016
BUILD_DATE:=$(shell date '+%Y-%m-%d')
BUILD_COMMIT:=$(shell if git rev-parse >/dev/null 2>/dev/null ; then git describe --always ; else echo '<unknown>' ; fi)

PREFIX = $(DESTDIR)/usr/local
VARPREFIX = $(DESTDIR)/var/local
CONFIGDIR = $(PREFIX)/etc
CONFIG = $(CONFIGDIR)/isolate
BINDIR = $(PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
MANDIR = $(DATADIR)/man
MAN1DIR = $(MANDIR)/man1
BOXDIR = $(VARPREFIX)/lib/isolate

isolate: isolate.o util.o rules.o cg.o config.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c isolate.h config.h
	$(CC) $(CFLAGS) -c -o $@ $<

isolate.o: CFLAGS += -DVERSION='"$(VERSION)"' -DYEAR='"$(YEAR)"' -DBUILD_DATE='"$(BUILD_DATE)"' -DBUILD_COMMIT='"$(BUILD_COMMIT)"'
config.o: CFLAGS += -DCONFIG_FILE='"$(CONFIG)"'

isolate.1: isolate.1.txt
	a2x -f manpage $<

# The dependency on isolate.1 is there to serialize both calls of asciidoc,
# which does not name temporary files safely.
isolate.1.html: isolate.1.txt isolate.1
	a2x -f xhtml -D . $<

clean:
	rm -f *.o
	rm -f isolate isolate.1 isolate.1.html
	rm -f docbook-xsl.css

install: isolate isolate-check-environment
	install -D $^ $(BINDIR)
	chmod u+s $(BINDIR)/$<
	install -d $(BOXDIR)
	install -m 644 -D default.cf $(CONFIG)

install-doc: isolate.1
	install -m 644 -D $< $(MAN1DIR)/$<

.PHONY: all clean install install-doc
