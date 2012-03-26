# Makefile for MO-Eval isolator
# (c) 2012 Martin Mares <mj@ucw.cz>

DIRS+=isolate
PROGS+=$(o)/isolate/isolate

$(o)/isolate/isolate: $(o)/isolate/isolate.o
