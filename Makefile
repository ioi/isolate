# Makefile for MO-Eval isolator
# (c) 2012 Martin Mares <mj@ucw.cz>

DIRS+=isolate
PROGS+=$(o)/isolate/isolate
DOCS+=$(o)/isolate/isolate.1

$(o)/isolate/isolate: $(o)/isolate/isolate.o

$(o)/isolate/isolate.1: $(s)/isolate/isolate.1.txt
	$(M)"MAN $<"
	$(Q)a2x -f manpage -D $(o)/isolate $<
