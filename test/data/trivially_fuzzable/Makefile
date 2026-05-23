# Build the trivially-fuzzable target for RAPTOR end-to-end tests.
#
# Default target builds with -fsanitize=address (the variant
# /fuzz --execute-exploits and exploit_verify with sanitizers=
# expect, so ASAN reports flow into Witness SANITIZER_REPORT
# outcomes).
#
# `make plain` builds without sanitizers — useful for the
# baseline SIGSEGV path or for AFL++ runs that supply their own
# instrumentation.

CC      ?= gcc
CFLAGS  ?= -O0 -g -fno-omit-frame-pointer -fsanitize=address -Wall
LDFLAGS ?=

all: target

target: target.c
	$(CC) $(CFLAGS) -o target target.c $(LDFLAGS)

plain: target.c
	$(CC) -O0 -g -Wall -o target-plain target.c

clean:
	rm -f target target-plain

.PHONY: all plain clean
