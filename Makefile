# Makefile for Isolate
# (c) 2015--2025 Martin Mares <mj@ucw.cz>
# (c) 2017 Bernard Blackham <bernard@blackham.com.au>

VERSION=2.2.1
YEAR=2025

PROGRAMS=isolate isolate-check-environment isolate-cg-keeper
MANPAGES=isolate.1 isolate-check-environment.8 isolate-cg-keeper.8
CONFIGS=default.cf systemd/isolate.slice systemd/isolate.service

all: $(PROGRAMS) $(MANPAGES) $(addsuffix .html, $(MANPAGES)) $(CONFIGS)

CC=gcc
CFLAGS=-std=gnu99 -O2 -Wall -Wextra -Wno-parentheses -Wno-unused-result -Wno-missing-field-initializers -Wstrict-prototypes -Wmissing-prototypes $(CFLAGS_HARDEN) -D_GNU_SOURCE $(CFLAGS_EXTRA)
LDFLAGS=$(LDFLAGS_HARDEN)
LIBS=-lcap

# Inspiration: https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
CFLAGS_HARDEN=-D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection -fPIE -pie
LDFLAGS_HARDEN=-Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now

CFLAGS_BUILD=-DISOLATE_VERSION='"$(VERSION)"' -DISOLATE_YEAR='"$(YEAR)"'

# If we are building from a checked out repository, include build date and commit
BUILD_FROM_GIT := $(shell if [ -d .git ] ; then echo yes ; fi)
ifdef BUILD_FROM_GIT
BUILD_DATE := $(shell date '+%Y-%m-%d')
BUILD_COMMIT := $(shell if git rev-parse >/dev/null 2>/dev/null ; then git describe --always --tags ; else echo '<unknown>' ; fi)
CFLAGS_BUILD += -DBUILD_DATE='"$(BUILD_DATE)"' -DBUILD_COMMIT='"$(BUILD_COMMIT)"'
endif

PREFIX = /usr/local
VARPREFIX = /var/local
CONFIGDIR = $(PREFIX)/etc
CONFIG = $(CONFIGDIR)/isolate
BINDIR = $(PREFIX)/bin
LIBDIR = $(PREFIX)/lib
SBINDIR = $(PREFIX)/sbin
DATADIR = $(PREFIX)/share
MANDIR = $(DATADIR)/man
MAN1DIR = $(MANDIR)/man1
MAN8DIR = $(MANDIR)/man8
BOXDIR = $(VARPREFIX)/lib/isolate
UNITDIR = $(LIBDIR)/systemd/system

SYSTEMD_CFLAGS := $(shell pkg-config libsystemd --cflags)
SYSTEMD_LIBS := $(shell pkg-config libsystemd --libs)

isolate: isolate.o util.o rules.o cg.o config.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

isolate-cg-keeper: isolate-cg-keeper.o config.o util.o
	$(CC) $(LDFLAGS) -o $@ $^ $(SYSTEMD_LIBS)

%.o: %.c isolate.h
	$(CC) $(CFLAGS) -c -o $@ $<

isolate.o: CFLAGS += $(CFLAGS_BUILD)
config.o: CFLAGS += -DCONFIG_FILE='"$(CONFIG)"'
isolate-cg-keeper.o: CFLAGS += $(SYSTEMD_CFLAGS)

%.1: %.1.txt
	a2x -f manpage $<

%.8: %.8.txt
	a2x -f manpage $<

# The dependency on %.1 is there to serialize both calls of asciidoc,
# which does not name temporary files safely.
%.1.html: %.1.txt %.1
	a2x -f xhtml -D . $<

%.8.html: %.8.txt %.8
	a2x -f xhtml -D . $<

%: %.in
	sed "s|@SBINDIR@|$(SBINDIR)|g; s|@BOXDIR@|$(BOXDIR)|g" <$< >$@

clean:
	rm -f *.o
	rm -f isolate isolate-cg-keeper
	rm -f $(MANPAGES) $(addsuffix .html, $(MANPAGES))
	rm -f docbook-xsl.css
	rm -f default.cf
	rm -f systemd/isolate.service

install: $(PROGRAMS) $(CONFIGS)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BOXDIR) $(DESTDIR)$(CONFIGDIR) $(DESTDIR)$(UNITDIR)
	install isolate-check-environment $(DESTDIR)$(BINDIR)
	install isolate-cg-keeper $(DESTDIR)$(SBINDIR)
	install -m 4755 isolate $(DESTDIR)$(BINDIR)
	install -m 644 default.cf $(DESTDIR)$(CONFIG)
	install -m 644 systemd/isolate.slice systemd/isolate.service $(DESTDIR)$(UNITDIR)

install-doc: $(MANPAGES)
	install -d $(DESTDIR)$(MAN1DIR) $(DESTDIR)$(MAN8DIR)
	install -m 644 isolate.1 $(DESTDIR)$(MAN1DIR)/
	install -m 644 isolate-check-environment.8 isolate-cg-keeper.8 $(DESTDIR)$(MAN8DIR)/

release: $(addsuffix .html,$(MANPAGES))
	git tag v$(VERSION)
	git push --tags
	git archive --format=tar --prefix=isolate-$(VERSION)/ HEAD | gzip >isolate-$(VERSION).tar.gz
	rsync isolate-$(VERSION).tar.gz jw:/home/ftp/pub/mj/isolate/
	rsync $(addsuffix .html,$(MANPAGES)) jw:/projects/isolate/www/
	ssh jw 'cd web && bin/release-prog isolate $(VERSION)'

.PHONY: all clean install install-doc release
