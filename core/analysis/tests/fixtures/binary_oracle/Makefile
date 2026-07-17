# Binary-oracle reachability fixture.
#
# Builds ``demo`` with -O2 -g + per-function sections + --gc-sections so the
# `dead_*` cases actually get DCE'd. ICF (folded_a/folded_b merging) requires
# an ICF-capable linker; the build tries lld first, then GNU ld's --icf=safe,
# and silently degrades to "no ICF" if neither is available — the classifier
# correctly produces ``symbol_present`` for the folded_* pair in that mode.

CC      ?= gcc
CFLAGS  ?= -O2 -g -ffunction-sections -fdata-sections
LDFLAGS ?= -Wl,--gc-sections

# Detect an ICF-capable linker. lld supports --icf=all unconditionally;
# GNU ld grew --icf=safe later (binutils 2.38+). Order: lld → GNU ld --icf.
HAVE_LLD := $(shell command -v ld.lld 2>/dev/null)
HAVE_ICF := $(shell echo 'int main(){return 0;}' | $(CC) -x c - -o /dev/null -Wl,--icf=safe 2>/dev/null && echo yes)

ifneq ($(HAVE_LLD),)
    LDFLAGS += -fuse-ld=lld -Wl,--icf=all
    ICF_MODE := lld
else ifeq ($(HAVE_ICF),yes)
    LDFLAGS += -Wl,--icf=safe
    ICF_MODE := gnu-safe
else
    ICF_MODE := none
endif

OBJS = lib.o main.o

.PHONY: all clean print-icf-mode
all: demo

demo: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c lib.h
	$(CC) $(CFLAGS) -c -o $@ $<

print-icf-mode:
	@echo $(ICF_MODE)

clean:
	rm -f demo $(OBJS)
