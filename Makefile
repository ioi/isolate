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

# The dependency on isolate.1 is there to serialize both calls of asciidoc,
# which does not name temporary files safely.
$(o)/isolate/isolate.1.html: $(s)/isolate/isolate.1.txt $(o)/isolate/isolate.1
	$(M)"HTML $<"
	$(Q)a2x -f xhtml -D $(o)/isolate $<
