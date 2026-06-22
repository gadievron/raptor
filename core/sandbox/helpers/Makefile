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

.PHONY: all help clean check

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
SAFETY_LDFLAGS = -pie -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack

CFLAGS  ?=
LDFLAGS ?=

COORD_BIN    := raptor-coord-launcher
COORD_SRC    := raptor-coord-launcher.c

all: $(COORD_BIN)

$(COORD_BIN): $(COORD_SRC)
	$(CC) $(CFLAGS) $(SAFETY_CFLAGS) $(LDFLAGS) $(SAFETY_LDFLAGS) -o $@ $<
	@echo
	@echo "  Built: $$(realpath $@)"
	@echo
	@echo "  This is the COORDINATOR LAUNCHER. The Python side resolves"
	@echo "  it against this checkout's path; leave it here."
	@echo
	@echo "  Pick the grant for your distro:"
	@echo
	@echo "  Ubuntu 24.04+ (sysctl=1 default, AppArmor confinement):"
	@echo "      sudo cp raptor-coord-launcher.apparmor \\"
	@echo "             /etc/apparmor.d/raptor-coord-launcher"
	@echo "      sudo apparmor_parser -r /etc/apparmor.d/raptor-coord-launcher"
	@echo
	@echo "  RHEL with hardened SELinux:"
	@echo "      # Customise raptor-coord-launcher.selinux.te first."
	@echo "      make -f /usr/share/selinux/devel/Makefile raptor-coord-launcher.pp"
	@echo "      sudo semodule -i raptor-coord-launcher.pp"
	@echo "      sudo chcon -t raptor_coord_launcher_exec_t $$(realpath $@)"
	@echo
	@echo "  Debian / older Ubuntu (unprivileged_userns_clone=0):"
	@echo "      sudo setcap cap_net_admin,cap_sys_admin+ep $$(realpath $@)"
	@echo
	@echo "  Easiest (if your admin agrees to relax system hardening):"
	@echo "      echo 'kernel.apparmor_restrict_unprivileged_userns=0' \\"
	@echo "          | sudo tee /etc/sysctl.d/99-raptor.conf"
	@echo "      sudo sysctl --system"
	@echo "      (no per-binary grant needed; coord.py uses direct unshare)"
	@echo

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
	@echo "      sudo cp raptor-coord-launcher.apparmor \\"
	@echo "             /etc/apparmor.d/raptor-coord-launcher"
	@echo "      sudo apparmor_parser -r /etc/apparmor.d/raptor-coord-launcher"
	@echo "      (Edit the .apparmor file's path glob if your checkout"
	@echo "       is somewhere other than /home/<user>/raptor/.)"
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

clean:
	rm -f $(COORD_BIN)
