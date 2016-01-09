# Makefile for Isolate
# (c) 2015 Martin Mares <mj@ucw.cz>

all: isolate isolate.1 isolate.1.html

CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Wno-parentheses -Wno-unused-result -Wno-missing-field-initializers

VERSION=1.1
YEAR=2015
BUILD_DATE:=$(shell date '+%Y-%m-%d')
BUILD_COMMIT:=$(shell if git rev-parse >/dev/null 2>/dev/null ; then git describe --always ; else echo '<unknown>' ; fi)
CFLAGS += -DVERSION='"$(VERSION)"' -DYEAR='"$(YEAR)"' -DBUILD_DATE='"$(BUILD_DATE)"' -DBUILD_COMMIT='"$(BUILD_COMMIT)"'

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
MANDIR = $(DATADIR)/man
MAN1DIR = $(MANDIR)/man1

isolate: isolate.c config.h
	$(CC) $(CFLAGS) -o $@ $^

isolate.1: isolate.1.txt
	a2x -f manpage -D . $<

# The dependency on isolate.1 is there to serialize both calls of asciidoc,
# which does not name temporary files safely.
isolate.1.html: isolate.1.txt isolate.1
	a2x -f xhtml -D . $<

clean:
	rm -f isolate isolate.1 isolate.1.html
	rm -f docbook-xsl.css

install: isolate
	install -D $< $(BINDIR)/$<
	chmod u+s $(BINDIR)/$<

install-doc: isolate.1
	install -D $< $(MAN1DIR)/$<

.PHONY: all clean install install-doc
