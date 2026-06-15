"""Availability probes for the user-namespace layers.

`check_net_available()` tests `unshare --user --net`; `check_mount_available()`
tests bind-mount capability (requires uidmap + no AppArmor restriction).
Both results are cached per-process — the cost of probing is a subprocess
spawn, done at most once.

Landlock and seccomp have their own probes in landlock.py and seccomp.py
respectively, because those tests are syscall-level (ctypes) rather than
subprocess-level.
"""

import functools
import logging
import os
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


# Actionable instruction appended to engagement-failure reasons. Surfaced
# to operators verbatim (also reused by context.py when it raises
# SandboxSetupError), so it must name the concrete escape hatch. Policy:
# RAPTOR never silently downgrades — the operator chooses.
# Namespace layer can't engage (unshare user/pid/ipc/net). This layer backs
# the network/PID/IPC isolation, so EVERY network-blocking profile (full,
# debug, network-only) needs it and fails here the same way — network-only
# does NOT help. The only profile that avoids the namespace layer is `none`.
ENGAGE_FAIL_INSTRUCTIONS = (
    "the sandbox namespace layer cannot engage on this host (common on "
    "rootless podman / distrobox / nested user namespaces, where the kernel "
    "restricts unprivileged user-namespace creation). This layer backs the "
    "network / PID / IPC isolation, so every network-blocking profile "
    "(full, debug, network-only) needs it and fails here the same way — "
    "`--sandbox network-only` will NOT help. Either enable unprivileged user "
    "namespaces on the host (distro-specific — e.g. the "
    "kernel.unprivileged_userns_clone or "
    "kernel.apparmor_restrict_unprivileged_userns sysctl, or the container "
    "runtime's userns policy), or re-run with `--sandbox none` to run "
    "without namespace isolation (resource limits only — last resort). "
    "RAPTOR will not silently downgrade for you."
)

# A hardening layer (Landlock or seccomp) passed its probe but failed to
# APPLY. Unlike the namespace layer, these ARE dropped by network-only, so
# it is a genuine downgrade here (keeps network + namespace isolation).
LAYER_FAIL_INSTRUCTIONS = (
    "a sandbox hardening layer (Landlock or seccomp) passed its probe but "
    "could not apply on this host. Re-run with `--sandbox network-only` to "
    "drop Landlock and seccomp while keeping network and namespace "
    "isolation, or `--sandbox none` to disable isolation entirely (last "
    "resort). RAPTOR will not silently downgrade for you."
)

# macOS seatbelt (sandbox-exec) could not apply its profile. There is no
# Landlock/namespace layering to fall back to — `none` is the only downgrade.
SEATBELT_FAIL_INSTRUCTIONS = (
    "the macOS seatbelt sandbox (sandbox-exec) could not apply its profile "
    "on this host. Re-run with `--sandbox none` to run without isolation "
    "(resource limits only — last resort). RAPTOR will not silently "
    "downgrade for you."
)


@functools.lru_cache(maxsize=1)
def unshare_supports_kill_child() -> bool:
    """Whether this host's ``unshare`` supports ``--kill-child`` (util-linux
    ≥ 2.32, 2018). Used as belt-and-braces teardown: ``unshare --kill-child=
    SIGKILL`` kills its pid-1 child (and thus cascades the pid-ns) if unshare
    itself dies. The primary orphan-teardown is the death-pipe in
    raptor-pid1-shim; this just covers "unshare killed directly". Probed via
    ``--help`` (cheap, no namespace creation) and cached for the process; a
    host without the flag silently runs without it.
    """
    try:
        from core.config import RaptorConfig
        # ``text=True`` keeps stdout/stderr as str regardless of caller-
        # imposed mocks. Help text is plain ASCII, no encoding concern; the
        # explicit text mode also stops ``str + b""`` blowing up under any
        # global ``subprocess.run`` mock that returns str-typed stdout (the
        # llm_analysis test_orchestrator pipeline patches subprocess.run
        # process-wide, and bytes-typed defaults would TypeError on the
        # membership check below).
        out = subprocess.run(
            [_resolve_sandbox_binary("unshare"), "--help"],
            capture_output=True, text=True, timeout=5,
            env=RaptorConfig.get_safe_env(),
        )
        return "--kill-child" in (out.stdout or "") + (out.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def check_unshare_engages(unshare_flags) -> tuple:
    """Return (engages, reason) for the EXACT unshare flag-set a real run uses.

    ``check_net_available()`` / ``check_mount_available()`` test NARROWER
    operations (``unshare --user --net``) than a sandboxed run actually
    performs (``unshare --user --pid --fork --ipc [--net]``). On rootless
    podman / distrobox (nested userns) the narrow probe can pass while the
    full flag-set fails — the wrapper then exits BEFORE exec, the target
    command never runs, and the run silently returns empty output, which a
    consumer reads as "0 findings". This runs the ACTUAL flag-set against
    ``true`` so engagement is decided by the same kernel capability the
    real run depends on. Namespace creation is a deterministic kernel
    check (not data-dependent), so a pass here means the real wrapper will
    engage too.

    ``unshare_flags`` is the namespace flag list WITHOUT the ``unshare``
    binary or the ``-- cmd`` tail, e.g.
    ``("--user","--pid","--fork","--ipc","--net")``.

    Returns ``(engages, reason)`` where ``engages`` is tri-state:
      True  — the flag-set engaged (cached).
      False — a DEFINITIVE kernel refusal: ``unshare`` ran and exited
              non-zero (the rootless-podman/nested-userns case). Cached.
              The caller fails loud on this.
      None  — the probe itself could not RUN (timeout under fork/memory
              pressure, transient OSError). NOT an engagement verdict and
              NOT cached. The caller must NOT fail loud on this — a 5s
              timeout on a trivial `unshare true` means the box is
              overloaded, not that namespaces are unavailable; aborting a
              scan that would have succeeded is the worse failure. A real
              engagement failure still surfaces at spawn (exec-status pipe).
    """
    key = tuple(unshare_flags)
    # Fast path under a BRIEF lock. The slow probe (an up-to-5s subprocess)
    # then runs OUTSIDE the lock so it never stalls every other thread's
    # cache op under concurrent first-use. Worst case is a few redundant
    # probes across racing threads — benign, and de-duped by setdefault on
    # publish (the first writer wins; racers adopt its verdict).
    with state._cache_lock:
        cached = state._unshare_engage_cache.get(key)
    if cached is not None:
        return cached

    try:
        unshare_path = _resolve_sandbox_binary("unshare")
    except FileNotFoundError as e:
        # util-linux missing → namespaces genuinely can't engage → fail loud.
        with state._cache_lock:
            return state._unshare_engage_cache.setdefault(key, (False, str(e)))

    # Absolute `true` keeps the probe consistent with the module's
    # no-PATH-trust posture. A poisoned PATH shadowing `true` could at
    # worst make engagement look FAILED (fail-closed), never falsely
    # succeed, so the fallback to a bare name is acceptable.
    true_bin = next(
        (p for p in ("/usr/bin/true", "/bin/true") if Path(p).exists()),
        "true",
    )
    try:
        from core.config import RaptorConfig
        proc = subprocess.run(
            [unshare_path, *key, "--", true_bin],
            capture_output=True, timeout=5,
            env=RaptorConfig.get_safe_env(),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        # Probe INFRASTRUCTURE failure (timeout under fork/memory pressure,
        # transient OSError) — NOT a definitive kernel refusal. Return None
        # (couldn't determine), NOT False: the caller must not fail loud, and
        # we do NOT cache it, so the next call re-probes. A genuine
        # deterministic refusal returns a non-zero returncode below (False).
        return (None, f"engagement probe could not run: {e}")
    if proc.returncode == 0:
        result = (True, "")
    else:
        reason = (proc.stderr or b"").decode("utf-8", "replace").strip()
        if not reason:
            reason = (
                f"unshare {' '.join(key)} exited {proc.returncode} "
                f"with no diagnostic"
            )
        result = (False, reason)
    with state._cache_lock:
        return state._unshare_engage_cache.setdefault(key, result)


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


def _mount_ns_functional_selftest() -> bool:
    """Fork a child and actually ``unshare(CLONE_NEWUSER|CLONE_NEWNS)`` to
    verify the kernel permits creating a user+mount namespace at runtime.

    The other ``check_mount_available()`` signals — uidmap binaries present,
    AppArmor sysctl != 1 — are necessary but NOT sufficient: an outer-container
    seccomp policy, a non-AppArmor LSM (SELinux), or a nested-userns mount
    restriction can still refuse ``unshare(CLONE_NEWNS)``. Without this test
    such a host reports mount-ns available, the _spawn child then dies on
    ``os.unshare`` (exit 126 + empty stdout) — a silent "0 findings". Testing
    it here means a NEWNS-incapable host instead falls back to Landlock-only
    and still produces real results. Same approach as the Landlock and seccomp
    functional self-tests. Child is ``os.unshare`` + ``os._exit`` only.
    """
    _CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
    _CLONE_NEWNS = getattr(os, "CLONE_NEWNS", 0x00020000)
    import warnings as _warnings
    with _warnings.catch_warnings():
        _warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:
        try:
            os.unshare(_CLONE_NEWUSER | _CLONE_NEWNS)
            os._exit(0)
        except BaseException:
            os._exit(1)
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return False
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


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
            # Same TOCTOU rationale as the unprivileged_userns_clone
            # check above: pre-fix `sysctl.exists() and
            # sysctl.read_text() == "1"` raced — the file could be
            # remounted between exists() and read_text(). Single-step
            # via attempt-read + FileNotFoundError-as-"no sysctl"
            # fallback. The default behaviour when the sysctl is
            # absent is "AppArmor restriction not in force" → no
            # warning needed (the fallback is the safe path).
            sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            try:
                _restrict_value = sysctl.read_text().strip()
            except FileNotFoundError:
                _restrict_value = ""
            except OSError:
                _restrict_value = ""
            if _restrict_value == "1":
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
        if not (have_newuidmap and have_newgidmap):
            if state.warn_once("_mount_unavailable_warned"):
                logger.info(
                    "Sandbox: mount-namespace isolation UNAVAILABLE — "
                    "the `uidmap` package is not installed (newuidmap / "
                    "newgidmap missing). Fallback: Landlock-only. "
                    "To enable, run: sudo apt install uidmap"
                )
            state._mount_available_cache = False
            return False

        # Functional test (see _mount_ns_functional_selftest): binary presence
        # + AppArmor-sysctl=0 are necessary but not sufficient — the kernel can
        # still refuse unshare(CLONE_NEWNS) (outer seccomp / SELinux / nested
        # userns). If it does, report unavailable so we degrade to Landlock-
        # only rather than dying mid-spawn with empty output.
        if not _mount_ns_functional_selftest():
            if state.warn_once("_mount_unavailable_warned"):
                logger.info(
                    "Sandbox: mount-namespace isolation UNAVAILABLE — "
                    "unshare(CLONE_NEWNS) refused at runtime (outer seccomp / "
                    "LSM / nested-userns restriction). Fallback: Landlock-only."
                )
            state._mount_available_cache = False
            return False

        state._mount_available_cache = True
        return True


def _selinux_enforcing() -> bool:
    """Return True iff SELinux is loaded AND enforcing on this host.

    Quickly distinguishes SELinux from AppArmor as the actual cause of
    ``unshare(CLONE_NEWNS)`` refusal. The functional probe in
    ``check_mount_available`` catches the refusal but can't see which
    LSM rejected it; this helper inspects ``/sys/fs/selinux/enforce``
    which is the kernel's authoritative answer.

    Returns False for: SELinux absent (file missing), SELinux disabled
    or permissive (``enforce`` is 0), unreadable file. Never raises —
    the caller wants a string-routing decision, not exception flow.
    """
    try:
        return Path("/sys/fs/selinux/enforce").read_text().strip() == "1"
    except (FileNotFoundError, OSError):
        return False


def mount_unavailable_reason() -> tuple[str, str]:
    """Diagnose WHY mount-ns isolation is unavailable on this host.

    Returns ``(condition, fix)`` strings suitable for surfacing to an
    operator. Four distinct branches: AppArmor restriction, missing
    uidmap binaries, SELinux enforcing, or (catch-all) outer seccomp /
    nested userns. Pre-fix the diagnostic at ``context.py``'s spawn-
    blockers branch hardcoded "AppArmor", misattributing the cause on
    SELinux hosts and on hosts where the uidmap package was simply not
    installed.

    Caller is responsible for only invoking this when
    ``check_mount_available()`` already returned False — this helper
    re-probes the specific conditions in priority order, but doesn't
    itself decide whether mount-ns is unavailable.
    """
    # 1. AppArmor sysctl (Ubuntu 24.04+ default).
    try:
        v = Path(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
        ).read_text().strip()
        if v == "1":
            return (
                "mount-ns blocked by host "
                "(apparmor_restrict_unprivileged_userns=1)",
                "set kernel.apparmor_restrict_unprivileged_userns=0 "
                "(Ubuntu 24.04+) and install the uidmap package; or "
                "rerun on a host where mount-ns is available.",
            )
    except (FileNotFoundError, OSError):
        pass
    # 2. uidmap binaries missing — distinct from the AppArmor case
    #    because the fix is package install, not sysctl flip.
    if not (shutil.which("newuidmap") and shutil.which("newgidmap")):
        return (
            "mount-ns blocked by host "
            "(uidmap binaries newuidmap/newgidmap not installed)",
            "install the uidmap package (apt install uidmap on "
            "Debian/Ubuntu, dnf install shadow-utils on Fedora/RHEL); "
            "or rerun on a host where mount-ns is available.",
        )
    # 3. SELinux enforcing — distinct from AppArmor; the fix is an
    #    SELinux booleans / policy change, not an AppArmor sysctl.
    if _selinux_enforcing():
        return (
            "mount-ns blocked by host (SELinux enforcing)",
            "set SELinux to permissive temporarily "
            "(`sudo setenforce 0`) to confirm, then grant the calling "
            "process the policy to unshare(CLONE_NEWNS) — typically "
            "the `container_use_userns` boolean: "
            "`sudo setsebool -P container_use_userns 1`; or rerun on a "
            "host where mount-ns is available.",
        )
    # 4. Catch-all: outer seccomp filter / nested userns / unknown LSM.
    return (
        "mount-ns blocked by host "
        "(unshare(CLONE_NEWNS) refused at runtime — likely outer "
        "seccomp filter, nested user-namespace restriction, or "
        "unknown LSM policy)",
        "rerun outside the restricting container / VM, or rerun on a "
        "host where mount-ns is available.",
    )


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
