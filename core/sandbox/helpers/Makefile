# Makefile for RAPTOR's privileged sandbox helpers.
#
# Targets:
#   raptor-coord-launcher — privileged bootstrap for the netns
#       coordinator. Used by core/sandbox/netns_coordinator.py when an
#       unprivileged unshare(NEWUSER|NEWNET) is blocked by the host's LSM.
#
# Operator workflow:
#   1. make                         # builds the helper in place
#   2. Pick the grant for your distro and install the matching template
#      (see `make help`). The helper lives at its build location —
#      core/sandbox/helpers/raptor-coord-launcher — and stays there.
#      core/sandbox/netns_coordinator.py resolves the binary against
#      its own checkout, so each RAPTOR clone has its own helper.
#
# There is no `make install` and never will be. RAPTOR does not, and must
# not, auto-elevate during a build — the operator's grant of LSM or file
# capabilities is the explicit consent step, and it can't move into a
# Makefile target without weakening the trust model.
#
# `make test` builds and runs the unprivileged contract harness
# (helpers_test.c): the helpers' argument-validation functions are
# compiled with -DRAPTOR_HELPERS_TEST (which drops their main()) and
# exercised against temp files and a self-created user namespace. No
# capability grant is needed to run it.

.PHONY: all help clean check test apparmor-profile

CC ?= cc

# Safety-critical compile + link flags. These define the hardening contract
# of each helper and MUST be applied. Appended AFTER the operator's
# CFLAGS/LDFLAGS so that overrides (e.g. CFLAGS=-O0,
# CFLAGS=-fno-stack-protector) cannot strip the hardening — gcc resolves
# conflicting flags left-to-right with last-write-wins.
SAFETY_CFLAGS  = -O2 -std=c11 -Wall -Wextra -Werror -Wshadow -Wformat=2 \
                 -Wformat-security -Wstrict-prototypes \
                 -Wmissing-prototypes -fstack-protector-strong -fPIE \
                 -D_FORTIFY_SOURCE=2

# Linker hardening is GNU/ELF-specific. On Darwin, PIE is the default for
# executables (and clang's -Werror,-Wunused-command-line-argument rejects a
# redundant -pie on the compile+link line), ld64 has no -z now/relro/
# noexecstack equivalents to opt into — full bind-at-launch and
# non-executable stacks are already the platform behaviour.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SAFETY_LDFLAGS =
    COORD_SAFETY_LDFLAGS =
else
    SAFETY_LDFLAGS = -pie -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack
    # The coord launcher is STATICALLY linked (static PIE). In the
    # AppArmor grant mode the profile attaches by path with no file
    # capabilities, so exec of the launcher does not set AT_SECURE and
    # a dynamic loader would honour the INVOKER's LD_PRELOAD/LD_AUDIT/
    # LD_LIBRARY_PATH — running a local user's constructor inside the
    # profiled process (userns + capability grant) before main() and
    # the invoker-identity gate. No dynamic loader ⇒ that injection
    # class is inert by construction. Trade-off (accepted, documented
    # in the .c header): libc security updates require a rebuild.
    COORD_SAFETY_LDFLAGS = -static-pie -Wl,-z,now -Wl,-z,relro \
                           -Wl,-z,noexecstack
endif

CFLAGS  ?=
LDFLAGS ?=

COORD_BIN    := raptor-coord-launcher
COORD_SRC    := raptor-coord-launcher.c

GIDMAP_BIN   := raptor-gidmap-allow
GIDMAP_SRC   := raptor-gidmap-allow.c

VALIDATE_HDR := helpers_validate.h

TEST_BIN     := helpers-test
TEST_SRC     := helpers_test.c

all: $(COORD_BIN) $(GIDMAP_BIN)

$(COORD_BIN): $(COORD_SRC) $(VALIDATE_HDR)
	$(CC) $(CFLAGS) $(SAFETY_CFLAGS) $(LDFLAGS) $(COORD_SAFETY_LDFLAGS) -o $@ $<
ifneq ($(UNAME_S),Darwin)
	@if command -v readelf >/dev/null 2>&1; then \
	    if readelf -l $@ 2>/dev/null | grep -q 'INTERP'; then \
	        echo "ERROR: $@ is dynamically linked (PT_INTERP present)" \
	             "— the static-pie hardening did not apply; the" \
	             "AppArmor grant mode would honour the invoker's" \
	             "LD_PRELOAD pre-main. Refusing the build."; \
	        rm -f $@; exit 1; \
	    fi; \
	fi
endif

$(GIDMAP_BIN): $(GIDMAP_SRC) $(VALIDATE_HDR)
	$(CC) $(CFLAGS) $(SAFETY_CFLAGS) $(LDFLAGS) $(SAFETY_LDFLAGS) -o $@ $<
	@echo
	@echo "  Built: $$(realpath $@)"
	@echo
	@echo "  Grant CAP_SETGID so it can write gid_map without denying setgroups:"
	@echo "      sudo setcap cap_setgid=ep $$(realpath $@)"
	@echo
	@echo "  core/sandbox/_spawn.py auto-detects this binary and uses it"
	@echo "  instead of newgidmap when CAP_SETGID is present."
	@echo

# Unprivileged contract harness — validation functions only, mains
# compiled out via -DRAPTOR_HELPERS_TEST. Runs without any grant.
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(COORD_SRC) $(GIDMAP_SRC) $(VALIDATE_HDR)
	$(CC) $(CFLAGS) $(SAFETY_CFLAGS) $(LDFLAGS) $(SAFETY_LDFLAGS) \
	    -DRAPTOR_HELPERS_TEST -o $@ $(TEST_SRC) $(COORD_SRC) $(GIDMAP_SRC)

# Informational target. We never auto-grant anything.
help:
	@echo
	@echo "  RAPTOR sandbox helpers — operator setup guide"
	@echo "  ============================================="
	@echo
	@echo "  The netns coordinator puts two sibling-sandboxed processes"
	@echo "  in the same isolated netns so they can talk on 127.0.0.1"
	@echo "  while the host's network stack stays untouched. On hosts where"
	@echo "  unprivileged userns is permitted (sysctl=0), the Python"
	@echo "  coordinator does this directly. On hardened hosts the"
	@echo "  coordinator delegates to this directory's launcher binary"
	@echo "  which must hold an LSM grant matching the distro's"
	@echo "  hardening mechanism. Pick ONE of:"
	@echo
	@echo "  (1) Disable the system-wide restriction (Ubuntu 24.04+):"
	@echo "      sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0"
	@echo "      Persist:"
	@echo "        echo 'kernel.apparmor_restrict_unprivileged_userns=0' \\"
	@echo "          | sudo tee /etc/sysctl.d/99-raptor.conf"
	@echo
	@echo "  (2) Install the AppArmor profile (Ubuntu hardened):"
	@echo "      make apparmor-profile   # renders for THIS checkout"
	@echo "      sudo cp raptor-coord-launcher.apparmor \\"
	@echo "             /etc/apparmor.d/raptor-coord-launcher"
	@echo "      sudo apparmor_parser -r /etc/apparmor.d/raptor-coord-launcher"
	@echo "      (Attachment is this checkout's ABSOLUTE path — re-run"
	@echo "       both steps if you relocate the checkout.)"
	@echo
	@echo "  (3) Apply file capabilities (Debian / older Ubuntu / etc.):"
	@echo "      sudo setcap cap_net_admin,cap_sys_admin+ep \\"
	@echo "          $$(realpath $(COORD_BIN) 2>/dev/null || echo $(COORD_BIN))"
	@echo
	@echo "  (4) Install SELinux policy module (RHEL hardened):"
	@echo "      See raptor-coord-launcher.selinux.te — UNVALIDATED"
	@echo "      template; customise to your local policy."
	@echo
	@echo "  Validate (after picking ONE):"
	@echo "      $$(realpath $(COORD_BIN) 2>/dev/null || echo $(COORD_BIN)) \\"
	@echo "          /usr/bin/python3 -c 'print(\"ok\")'"
	@echo "      (should print 'ok' with no errors)"
	@echo

# Capability inspection. Doesn't validate apparmor or selinux state.
check:
	@if [ -e $(COORD_BIN) ] && [ "$(UNAME_S)" != "Darwin" ] \
	    && command -v readelf >/dev/null 2>&1; then \
	    if readelf -l $(COORD_BIN) 2>/dev/null | grep -q 'INTERP'; then \
	        echo "  WARNING: $(COORD_BIN) is DYNAMICALLY linked — a stale"; \
	        echo "  pre-static build. The AppArmor grant mode honours the"; \
	        echo "  invoker's LD_PRELOAD at its exec. Rebuild: make clean all"; \
	    fi; \
	    if [ $(COORD_BIN) -ot $(COORD_SRC) ]; then \
	        echo "  WARNING: $(COORD_BIN) is older than its source —"; \
	        echo "  rebuild: make clean all"; \
	    fi; \
	fi
	@if [ -e $(COORD_BIN) ]; then \
	    if command -v getcap >/dev/null 2>&1; then \
	        caps="$$(getcap $(COORD_BIN) 2>/dev/null || true)"; \
	        if [ -n "$$caps" ]; then echo "  $(COORD_BIN): $$caps"; \
	        else echo "  $(COORD_BIN): no file capabilities"; fi; \
	    fi; \
	    if command -v aa-status >/dev/null 2>&1; then \
	        sudo -n aa-status 2>/dev/null | grep raptor-coord-launcher \
	            && echo "  AppArmor profile: loaded" \
	            || echo "  AppArmor profile: not loaded (or no sudo)"; \
	    fi; \
	else \
	    echo "  $(COORD_BIN): not built. Run 'make' first."; \
	fi

# Render the AppArmor profile for THIS checkout. The shipped file is
# a template whose attachment path is the unparseable @@RAPTOR_DIR@@
# placeholder — AppArmor attaches by exact path match and a suffix
# wildcard would hand this profile's userns grant to any local user
# who stages a matching path (see the template's WHY A TEMPLATE
# block). Rendering stays sudo-free; installing the result is the
# operator's explicit consent step, as ever.
APPARMOR_TEMPLATE = raptor-coord-launcher.apparmor.template
APPARMOR_RENDERED = raptor-coord-launcher.apparmor
RAPTOR_ROOT = $(abspath $(CURDIR)/../../..)

apparmor-profile: $(APPARMOR_TEMPLATE)
	@case '$(RAPTOR_ROOT)' in \
	    *'|'* | *' '* | *'	'*) \
	        echo "ERROR: checkout path '$(RAPTOR_ROOT)' contains" \
	             "whitespace or '|' — render manually."; exit 1;; \
	esac
	sed 's|@@RAPTOR_DIR@@|$(RAPTOR_ROOT)|g' $(APPARMOR_TEMPLATE) \
	    > $(APPARMOR_RENDERED)
	@grep -q '@@RAPTOR_DIR@@' $(APPARMOR_RENDERED) && \
	    { echo "ERROR: placeholder survived rendering"; \
	      rm -f $(APPARMOR_RENDERED); exit 1; } || true
	@echo "Rendered $(APPARMOR_RENDERED) for $(RAPTOR_ROOT)."
	@echo "Install (operator-explicit):"
	@echo "  sudo cp $(APPARMOR_RENDERED) /etc/apparmor.d/raptor-coord-launcher"
	@echo "  sudo apparmor_parser -r /etc/apparmor.d/raptor-coord-launcher"

clean:
	rm -f $(COORD_BIN) $(GIDMAP_BIN) $(TEST_BIN) $(APPARMOR_RENDERED)
