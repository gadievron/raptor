"""Shared mutable module state for the sandbox package.

Centralising these globals in one place means consumers access them via
`from core.sandbox import state; state.<name>` (not `from state import <name>`,
which captures the binding at import time and misses later updates).

What lives here:
- `_cache_lock`: RLock guarding every module-level cache below. RLock (not
  Lock) because check_mount_available() calls check_net_available() while
  holding it.
- Availability caches — `None` = not probed, False/True or ABI version
  once probed. Each `check_*_available()` function populates its cache
  once per process.
- CLI-override flags — set ONLY by argparse-backed entry points, never
  by env/config/target-repo content. This keeps the sandbox unescapable
  by prompt injection.
- Once-per-process WARNING throttles — kernel capability is static, and
  scan loops can open hundreds of sandbox() contexts; we warn once.
"""

import threading

# RLock because check_mount_available() calls check_net_available() while
# holding it; Lock would deadlock on that nested path.
_cache_lock = threading.RLock()

# Availability caches. None = not probed yet.
_net_available_cache = None
_mount_available_cache = None
# _mount_ns_available_cache: True if the full fork+newuidmap+pivot_root
# path is usable (i.e. newuidmap/newgidmap binaries are present and
# user-ns unshare works). None = unchecked, False = not usable.
_mount_ns_available_cache = None
# Landlock cache uses -1 for "unavailable", >0 for ABI version, None for unchecked.
_landlock_cache = None
# Seccomp cache: None = unchecked, 0 = unavailable, CDLL handle = available.
_libseccomp_cache = None
# ptrace cache: None = unchecked, True/False = probed result. Used by
# `--audit` to decide whether b2 (syscall audit via SCMP_ACT_TRACE)
# and b3 (filesystem audit) can engage. Probed by core.sandbox.ptrace_probe.
_ptrace_available_cache = None
# macOS sandbox-exec cache: None = unprobed, True/False = probed.
# True iff /usr/bin/sandbox-exec exists AND a smoke-test invocation
# under (allow default) baseline succeeds. Set by check_seatbelt_
# available() in probes.py. Linux hosts always cache False.
_seatbelt_available_cache = None
# User-supplied rlimit overrides from ~/.config/raptor/sandbox.json.
_user_limits_cache = None
# Resolved absolute paths to sandbox-setup binaries. We use absolute paths
# to prevent PATH hijacking — a polluted PATH (e.g., a malicious .envrc
# that direnv activated, or `.` in the user's PATH) could otherwise
# shadow these with attacker binaries. unshare/prlimit are resolved for
# the namespace-creation step; mount/mkdir for the mount-script setup
# (only active when mount-ns is available, e.g. not on Ubuntu 24.04 with
# kernel.apparmor_restrict_unprivileged_userns=1).
# All are resolved against a hardcoded safe bin-dir list, not PATH.
_unshare_path_cache = None
_prlimit_path_cache = None
_mount_path_cache = None
_mkdir_path_cache = None

# CLI overrides — set ONLY from entry-point argparse, never from env vars
# or config files. A malicious .envrc or target repo must not be able to
# disable its own sandbox.
_cli_sandbox_disabled = False   # True when --no-sandbox passed
_cli_sandbox_profile = None     # str profile name when --sandbox <name> passed
# Audit flags — orthogonal to profile. `--audit` engages audit mode on
# the active profile (proxy log-and-allow + SCMP_ACT_TRACE + tracer);
# `--verbose` (only with --audit) flips the tracer from filtered to
# strace-style. Same prompt-injection-safety rule applies: only entry-
# point argparse sets these, never env/config/repo content.
_cli_sandbox_audit = False
_cli_sandbox_audit_verbose = False
# Operator override of the global audit-record cap (default 10000;
# see core.sandbox.audit_budget.DEFAULT_GLOBAL_CAP). None = use the
# default; positive integer = override. Per-category and per-PID
# sub-caps scale proportionally inside AuditBudget.__init__.
_cli_sandbox_audit_budget = None

# Degradation warnings are logged once per process, not once per sandbox()
# context — kernel capability doesn't change at runtime and scan loops
# can open hundreds of contexts.
_landlock_warned_unavailable = False
_landlock_warned_abi_v4 = False
_landlock_warned_abi_v3 = False  # TRUNCATE coverage missing (kernel <6.2)
_landlock_warned_abi_v2 = False  # REFER coverage missing (kernel <5.19)
_sandbox_unavailable_warned = False
# Mount-ns unavailable but Landlock did engage — see THREAT_MODEL.md I2-(a).
# Distinguished from `_mount_unavailable_warned` (which is set by the lower-
# level mount probe); this flag is for the user-facing warning emitted from
# the public sandbox() path that names the practical posture and remediation.
_sandbox_landlock_only_warned = False
_net_and_tcp_allowlist_warned = False
_seccomp_arch_missing_warned = False
_mount_unavailable_warned = False
_ptrace_unavailable_warned = False
_audit_warned_no_spawn = False
# NOTE: B's mount-ns Landlock fallback logs at DEBUG (no warn-once
# flag needed — workflow proceeds correctly at Landlock-only, same
# posture as Ubuntu defaults). The speculative-C retry uses the
# per-cmd cache below to avoid both repeated mount-ns attempts AND
# repeated log noise — first failure for a given binary fires one
# INFO line; subsequent calls are silent (cache-hit path).
#
# Per-cmd cache of "tool_paths bind set was insufficient for this
# binary, mount-ns will fail at exec". Populated by context.py's
# speculative-C retry on first failure for a given cmd[0]. Subsequent
# calls for the same cmd[0] skip the mount-ns attempt entirely and
# go straight to Landlock-only — saves the doubled subprocess setup
# cost (mount-ns try + retry) on every scanner invocation.
#
# Keyed on the resolved path (shutil.which(cmd[0]) or cmd[0]) so two
# spellings of the same binary share a cache entry. Process-local; a
# fresh RAPTOR invocation re-probes (handles operator changing their
# install layout between runs).
_speculative_failure_cache: dict = {}


def warn_once(flag_name: str) -> bool:
    """Atomic test-and-set for a module-level warn-once flag.

    Returns True the first time called with a given flag name, False
    thereafter. Callers should log the warning only when this returns True.

    Without this helper, two threads can both read `flag = False`, both
    log the warning, and both set it True — producing duplicate warnings
    under concurrent sandbox() use. Wrapping the test-and-set in
    `_cache_lock` collapses that race.
    """
    import sys
    mod = sys.modules[__name__]
    with _cache_lock:
        # AttributeError-on-typo defense: if a caller passes a flag
        # name that doesn't exist on this module (typo, refactor
        # missed an update), the bare getattr would raise an opaque
        # AttributeError from inside state.py. Surface a clearer
        # error that names the offending flag so the caller can
        # find their typo immediately.
        if not hasattr(mod, flag_name):
            raise AttributeError(
                f"warn_once: unknown flag {flag_name!r}. Add to "
                f"core/sandbox/state.py module-level globals before "
                f"using. (Likely a typo — most flag names follow "
                f"the `_<feature>_warned_<reason>` pattern.)"
            )
        if getattr(mod, flag_name):
            return False
        setattr(mod, flag_name, True)
        return True
