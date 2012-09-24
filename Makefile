# Makefile for MO-Eval isolator
# (c) 2012 Martin Mares <mj@ucw.cz>

DIRS+=isolate
PROGS+=$(o)/isolate/isolate

DOCS+=$(o)/isolate/isolate.1 $(o)/isolate/isolate.1.html
MAN1DIR=share/man/man1
EXTRA_RUNDIRS+=$(MAN1DIR)

$(o)/isolate/isolate: $(o)/isolate/isolate.o

$(o)/isolate/isolate.1: $(s)/isolate/isolate.1.txt
	$(M)"MAN $<"
	$(Q)a2x -f manpage -D $(o)/isolate $<
	$(Q)$(call symlink,$@,run/$(MAN1DIR))

$(o)/isolate/isolate.1.html: $(s)/isolate/isolate.1.txt
	$(M)"HTML $<"
	$(Q)a2x -f xhtml -D $(o)/isolate $<
