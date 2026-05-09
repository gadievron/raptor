"""Availability probes for the user-namespace layers.

`check_net_available()` tests `unshare --user --net`; `check_mount_available()`
tests bind-mount capability (requires uidmap + no AppArmor restriction).
Both results are cached per-process — the cost of probing is a subprocess
spawn, done at most once.

Landlock and seccomp have their own probes in landlock.py and seccomp.py
respectively, because those tests are syscall-level (ctypes) rather than
subprocess-level.
"""

import logging
import shutil
import subprocess
from pathlib import Path

from . import state

logger = logging.getLogger(__name__)


def check_sandbox_available() -> bool:
    """Check if any sandboxing is available (network at minimum)."""
    return check_net_available()


# Hardcoded system binary directories — searched in this order for
# sandbox-setup binaries. Deliberately NOT using the inherited PATH,
# which a malicious .envrc / direnv / attacker-compatible shell rc could
# have poisoned. If util-linux isn't in one of these standard dirs,
# the host is too unusual for us to auto-resolve safely.
_SAFE_BIN_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/bin")


def _resolve_sandbox_binary(name: str) -> str:
    """Return the absolute path of a sandbox-setup binary (unshare, prlimit).

    Resolves by searching a HARDCODED list of system binary dirs — NOT via
    the inherited PATH. This defeats PATH hijacking: a polluted PATH could
    otherwise shadow our namespace-creating binaries with attacker code
    that runs within our already-installed Landlock+seccomp filters but
    skips the namespace unshare itself, leaving the child in the host's
    network/pid/ipc namespaces (= full outbound network).

    Cached once per process. Raises FileNotFoundError when the binary
    isn't present in any standard dir — previously we fell back to the
    bare name (letting subprocess.run's execvp resolve via PATH), but
    that defeats the entire point of hardcoding: a system missing the
    binary in /usr/bin is also the system most likely to have a
    polluted PATH (custom Nix/guix profile, user-local install, direnv-
    rewritten PATH), and on those exact systems we would hand control
    of the sandbox bootstrap to whatever that PATH pointed at.
    Fail-closed with an actionable error instead.
    """
    import os
    with state._cache_lock:
        cache_attr = f"_{name}_path_cache"
        cached = getattr(state, cache_attr, None)
        if cached is not None:
            if cached is False:
                # Previous lookup failed — re-raise with the same
                # message so callers see a stable error rather than a
                # different one on the second call.
                raise FileNotFoundError(
                    f"Sandbox: {name!r} not found in {_SAFE_BIN_DIRS}. "
                    f"Install util-linux (provides unshare, prlimit, "
                    f"mount, mkdir) into a standard location. Refusing "
                    f"to fall back to $PATH — a poisoned PATH could "
                    f"hijack the sandbox bootstrap."
                )
            return cached
        for d in _SAFE_BIN_DIRS:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                setattr(state, cache_attr, candidate)
                return candidate
        # Cache the failure so subsequent calls don't repeat the
        # filesystem probe.
        setattr(state, cache_attr, False)
        raise FileNotFoundError(
            f"Sandbox: {name!r} not found in {_SAFE_BIN_DIRS}. "
            f"Install util-linux (provides unshare, prlimit, mount, "
            f"mkdir) into a standard location. Refusing to fall back "
            f"to $PATH — a poisoned PATH could hijack the sandbox "
            f"bootstrap."
        )


def check_net_available() -> bool:
    """Check if network isolation via user namespaces is available.

    Tests: unshare command exists, unprivileged user namespaces enabled,
    and a functional test passes. Result is cached for the session.
    """
    with state._cache_lock:
        if state._net_available_cache is not None:
            return state._net_available_cache

        try:
            unshare_path = _resolve_sandbox_binary("unshare")
        except FileNotFoundError as e:
            # util-linux not installed in a standard location — record
            # the reason at debug so startup diagnostics surface it,
            # then treat as "no network isolation available". Fail-
            # closed: caller sees a disabled sandbox, not a PATH-
            # hijacked one.
            logger.debug(f"Sandbox: {e}")
            state._net_available_cache = False
            return False

        try:
            # Pre-fix this was `if sysctl.exists() and
            # sysctl.read_text() == "0": ...`. The exists() call
            # creates a TOCTOU window between the existence
            # check and the read — between them the kernel
            # module exporting the sysctl could be unloaded
            # (rare, but `rmmod user_namespaces` during a probe
            # is possible on test / CI hosts), or the path could
            # be intercepted by an attacker via /proc remount.
            #
            # Single-step it: just attempt the read and treat
            # FileNotFoundError as "no sysctl, assume kernel
            # default (enabled)". OSError covers the broader
            # "/proc not mounted" case (containers without
            # /proc, exotic init systems).
            sysctl = Path("/proc/sys/kernel/unprivileged_userns_clone")
            try:
                value = sysctl.read_text().strip()
            except FileNotFoundError:
                value = ""  # No sysctl on this kernel — defaults to enabled.
            if value == "0":
                logger.debug("Sandbox: unprivileged user namespaces disabled (sysctl)")
                state._net_available_cache = False
                return False
        except OSError:
            pass

        try:
            # Pass safe env to our own probe — consistent with the module's
            # philosophy of never letting inherited env shell-eval tools
            # (TERMINAL, EDITOR, etc.). Absolute path for unshare so a
            # polluted PATH can't shadow it at probe time either.
            from core.config import RaptorConfig
            result = subprocess.run(
                [unshare_path, "--user", "--net", "true"],
                capture_output=True, timeout=5,
                env=RaptorConfig.get_safe_env(),
            )
            if result.returncode != 0:
                logger.debug(f"Sandbox: network test failed: {result.stderr.strip()}")
                state._net_available_cache = False
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            state._net_available_cache = False
            return False

        state._net_available_cache = True
        return True


def check_mount_available() -> bool:
    """Check if mount namespace isolation is available.

    Requires user namespaces + mount with propagation unchanged + UID mapping
    for bind mount capability. Blocked by:
    - kernel.apparmor_restrict_unprivileged_userns=1 (Ubuntu 24.04+ default)
    - Missing uidmap package (newuidmap/newgidmap)
    - Container/VM restrictions
    """
    with state._cache_lock:
        if state._mount_available_cache is not None:
            return state._mount_available_cache

        if not check_net_available():
            state._mount_available_cache = False
            return False

        # Check AppArmor restriction — fast path, avoids functional test.
        # Ubuntu 24.04+ ships with apparmor_restrict_unprivileged_userns=1
        # by default. When present, tell the operator exactly how to
        # enable mount-ns if they want the stronger isolation (read-only
        # root bind, per-sandbox /tmp tmpfs, /dev/shm isolation).
        try:
            sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            if sysctl.exists() and sysctl.read_text().strip() == "1":
                if state.warn_once("_mount_unavailable_warned"):
                    logger.info(
                        "Sandbox: mount-namespace isolation UNAVAILABLE — "
                        "kernel.apparmor_restrict_unprivileged_userns=1 "
                        "blocks unprivileged mount. Fallback: Landlock-only "
                        "(per-sandbox /tmp, read-only root bind, /dev/shm "
                        "isolation all missing). To enable, run: "
                        "sudo sysctl -w "
                        "kernel.apparmor_restrict_unprivileged_userns=0"
                    )
                state._mount_available_cache = False
                return False
        except OSError:
            pass

        # Functional test: the mount-ns path we actually use is
        # fork+newuidmap+ctypes mount ops in core.sandbox._spawn. That
        # path needs:
        #   1. `newuidmap` / `newgidmap` binaries (uidmap package)
        #   2. unshare of user-ns + mount-ns (gated by the AppArmor
        #      sysctl already checked above)
        #
        # The legacy probe (`unshare --map-root-user` + mkdir at /)
        # falsely reported unavailable on modern Ubuntu even with the
        # sysctl flipped to 0. The newuidmap-driven path works there.
        # Probe for the tools and trust the ns-probe already done via
        # the AppArmor check — no need to re-fork a functional test.
        have_newuidmap = shutil.which("newuidmap") is not None
        have_newgidmap = shutil.which("newgidmap") is not None
        state._mount_available_cache = have_newuidmap and have_newgidmap
        if (not state._mount_available_cache
                and state.warn_once("_mount_unavailable_warned")):
            logger.info(
                "Sandbox: mount-namespace isolation UNAVAILABLE — "
                "the `uidmap` package is not installed (newuidmap / "
                "newgidmap missing). Fallback: Landlock-only. "
                "To enable, run: sudo apt install uidmap"
            )
        return state._mount_available_cache


def check_seatbelt_available() -> bool:
    """macOS-only: check if `sandbox-exec` works for our use case.

    Returns True iff:
      - Running on darwin
      - /usr/bin/sandbox-exec exists
      - A smoke-test invocation under (allow default) baseline
        succeeds (verifies SBPL parser + kernel support).

    Cached per-process. Linux always returns False without invoking
    sandbox-exec (saves the subprocess fork on every check).

    The `(allow default)` baseline is the minimal SBPL profile that
    lets dyld + libSystem load on modern macOS — pure deny-default
    SIGABRT's the process before dyld can finish. Spike-validated
    on macOS 26.4.1 (see scripts/macos_sandbox_spike.py).
    """
    import sys
    if sys.platform != "darwin":
        return False
    if state._seatbelt_available_cache is not None:
        return state._seatbelt_available_cache
    with state._cache_lock:
        if state._seatbelt_available_cache is not None:
            return state._seatbelt_available_cache
        sandbox_exec = "/usr/bin/sandbox-exec"
        if not Path(sandbox_exec).exists():
            state._seatbelt_available_cache = False
            return False
        # Smoke test: minimal valid profile + /usr/bin/true (always
        # present on macOS). 5s timeout — sandbox-exec normally
        # returns in <50ms; anything longer means a real problem.
        profile = "(version 1)\n(allow default)\n"
        try:
            # `env=` to a stripped environment so the smoke-test
            # subprocess can't pick up DYLD_INSERT_LIBRARIES /
            # DYLD_LIBRARY_PATH (the macOS equivalents of LD_PRELOAD)
            # from the parent. Pre-fix the bare subprocess inherited
            # the parent's full env — a poisoned operator shell could
            # have the smoke-test load attacker code via dyld at
            # startup, AND the result of the smoke test (which
            # determines whether subsequent subprocesses get
            # sandboxed) could be skewed by the attacker controlling
            # what `/usr/bin/true` actually does.
            from core.config import RaptorConfig
            r = subprocess.run(
                [sandbox_exec, "-p", profile, "/usr/bin/true"],
                capture_output=True, timeout=5,
                env=RaptorConfig.get_safe_env(),
            )
            ok = (r.returncode == 0)
        except (subprocess.TimeoutExpired, OSError):
            ok = False
        state._seatbelt_available_cache = ok
        if not ok and state.warn_once("_sandbox_unavailable_warned"):
            logger.warning(
                "Sandbox: macOS sandbox-exec smoke test FAILED — "
                "subprocesses will run without isolation. Verify "
                "sandbox-exec works on this host: "
                "`sandbox-exec -p '(version 1)(allow default)' "
                "/usr/bin/true`"
            )
        return ok
