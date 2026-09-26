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
        # Attribute-safe name: tool names may carry hyphens
        # (sandbox-exec) — the state module declares these caches as
        # identifiers, and the test-suite snapshot guard enumerates
        # them, so the attr must be a valid declared identifier.
        cache_attr = f"_{name.replace('-', '_')}_path_cache"
        cached = getattr(state, cache_attr, None)
        if cached is not None:
            if cached is False:
                # Previous lookup failed — re-raise with the same
                # message so callers see a stable error rather than a
                # different one on the second call.
                msg = (
                    f"Sandbox: {name!r} not found in {_SAFE_BIN_DIRS}. "
                    f"Install util-linux (provides unshare, prlimit, "
                    f"mount, mkdir) into a standard location. Refusing "
                    f"to fall back to $PATH — a poisoned PATH could "
                    f"hijack the sandbox bootstrap."
                )
                raise FileNotFoundError(msg)
            return cached
        for d in _SAFE_BIN_DIRS:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                setattr(state, cache_attr, candidate)
                return candidate
        # Cache the failure so subsequent calls don't repeat the
        # filesystem probe.
        setattr(state, cache_attr, False)
        msg = (
            f"Sandbox: {name!r} not found in {_SAFE_BIN_DIRS}. "
            f"Install util-linux (provides unshare, prlimit, mount, "
            f"mkdir) into a standard location. Refusing to fall back "
            f"to $PATH — a poisoned PATH could hijack the sandbox "
            f"bootstrap."
        )
        raise FileNotFoundError(msg)


def _find_sandbox_binary(name: str) -> str | None:
    """Non-raising ``_resolve_sandbox_binary``: same trusted-dirs-only
    resolution (never the inherited PATH), returning None when the
    binary is absent instead of raising.

    Availability probes and optional-helper lookups want a yes/no
    answer — but they must not derive it from a PATH an attacker-
    compatible ``.envrc``/direnv could have poisoned: a planted
    ``newuidmap`` stub would flip the mount-ns availability verdict on
    a host without uidmap, steering spawn onto a path that then
    resolves (and EXECUTES, in the unsandboxed parent) the same
    PATH-controlled stub. Same doctrine as ``_resolve_sandbox_binary``;
    a host with uidmap outside the standard dirs degrades to
    Landlock-only, exactly like a missing util-linux does.
    """
    try:
        return _resolve_sandbox_binary(name)
    except FileNotFoundError:
        return None


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
def unshare_supports_cgroup() -> bool:
    """Whether this host's ``unshare`` supports ``--cgroup`` (util-linux
    ≥ 2.32, 2018). Consumed by the namespace ENGAGEMENT PROBE
    (check_unshare_engages callers): the spawn backend unshares
    CLONE_NEWCGROUP unconditionally, and the probe must exercise the
    same kernel capability — the CLI flag is only expressible when
    the installed util-linux knows it. Probed via ``--help`` and
    cached.
    """
    try:
        from core.config import RaptorConfig
        out = subprocess.run(
            [_resolve_sandbox_binary("unshare"), "--help"],
            capture_output=True, text=True, timeout=5,
            env=RaptorConfig.get_safe_env(),
        )
        return "--cgroup" in (out.stdout or "") + (out.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _staged_pidns_selftest() -> bool:
    """Fork a child that runs the spawn backend's exact two-step
    namespace pattern: ``os.unshare(CLONE_NEWUSER)`` then a SECOND
    ``os.unshare(CLONE_NEWPID)`` with no exec in between.

    Restricted-userns hosts (Ubuntu's AppArmor transition; GitHub
    runners) allow single-call multi-namespace creation but deny the
    staged second call with EPERM — the shape the flat CLI engagement
    probe cannot see. In-process on purpose: the userns creator keeps
    full capabilities in the new namespace until an exec recalculates
    them, and the real spawn stages its pid-ns unshare in-process too,
    so an exec'd CLI form of this check false-negatives on capable
    hosts. Same fork/exit-code discipline as the sibling functional
    self-tests; the child is two ``os.unshare`` calls + ``os._exit``.
    Exit codes: 0 engaged; 190 the userns itself refused (the flat CLI
    probe reports that case with its own diagnostic); errno otherwise.
    """
    _CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
    _CLONE_NEWPID = getattr(os, "CLONE_NEWPID", 0x20000000)
    import warnings as _warnings
    with _warnings.catch_warnings():
        _warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:
        try:
            os.unshare(_CLONE_NEWUSER)
        except BaseException:
            os._exit(190)
        try:
            os.unshare(_CLONE_NEWPID)
        except OSError as e:
            os._exit((e.errno or 250) & 0xFF)
        except BaseException:
            os._exit(250)
        os._exit(0)
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return False
    if not os.WIFEXITED(status):
        return False
    code = os.WEXITSTATUS(status)
    # 190 = the user namespace itself refused; that is the flat CLI
    # probe's case to diagnose (its stderr names the real reason), not
    # a staged-creation refusal — don't mask it with this helper's
    # message.
    return code in (0, 190)


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

    Scope note: this single-call CLI probe cannot see the STAGED
    creation pattern the spawn backend uses (a second
    ``os.unshare(CLONE_NEWPID)`` from inside the new user namespace) —
    restricted-userns hosts allow the single call and refuse the staged
    one. That host class is excluded UPSTREAM: the namespace-backend
    foundation probe (``check_net_available`` →
    ``_staged_pidns_selftest``) reports the whole backend unavailable
    there, so backend selection routes to the degraded lanes and this
    gate is never consulted.

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


def check_pidns_fresh_proc_available() -> bool:
    """Whether this host allows mounting a fresh procfs inside a nested
    user+mount+pid namespace.

    The pid-ns spawn grandchild remounts /proc so /proc/<ns-pid>
    resolves for ptrace-family tools (gdb). Some host classes refuse
    that mount by kernel policy — most commonly containers whose host
    /proc carries masked overmounts (procfs "fully visible" rule) —
    and the refusal is STATIC for the host: probing it once lets the
    spawn path warn once per process instead of once per spawn, while
    the per-run posture stamp (``pidns_proc_mount_unavailable``) keeps
    the degradation on the forensic record.

    Fail-visible bias: only a determinate "namespaces engage but the
    proc mount is refused" returns False. Indeterminate outcomes
    (unshare missing, the namespace layer itself refusing, probe
    infrastructure failures) return True so the grandchild's per-spawn
    warning is never suppressed on unverified evidence; infrastructure
    failures are not cached so a later call re-probes.

    Lock discipline matches ``check_net_available``: brief lock holds
    around cache reads/writes, the slow subprocess probe runs outside
    the lock.
    """
    with state._cache_lock:
        if state._pidns_fresh_proc_cache is not None:
            return state._pidns_fresh_proc_cache

    available, cacheable = _probe_pidns_fresh_proc()

    with state._cache_lock:
        if cacheable and state._pidns_fresh_proc_cache is None:
            state._pidns_fresh_proc_cache = available
        return (state._pidns_fresh_proc_cache
                if state._pidns_fresh_proc_cache is not None
                else available)


def _probe_pidns_fresh_proc() -> tuple[bool, bool]:
    """Run the actual probe. Returns (available, cacheable). Never
    touches the cache — ``check_pidns_fresh_proc_available`` owns
    caching and locking."""
    unshare_path = _find_sandbox_binary("unshare")
    if unshare_path is None:
        # No unshare → the namespace spawn path can't run at all, so
        # the answer is never consulted; report available (nothing to
        # suppress) and cache it.
        return True, True
    true_bin = next(
        (p for p in ("/usr/bin/true", "/bin/true") if Path(p).exists()),
        "true",
    )
    base = [unshare_path, "--user", "--map-root-user", "--mount",
            "--pid", "--fork"]
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
        with_proc = subprocess.run(
            [*base, "--mount-proc", "--", true_bin],
            capture_output=True, timeout=5, env=env,
        )
        if with_proc.returncode == 0:
            return True, True
        # Attribute the failure: only "namespaces engage WITHOUT
        # --mount-proc but fail WITH it" is evidence about the proc
        # mount specifically.
        without_proc = subprocess.run(
            [*base, "--", true_bin],
            capture_output=True, timeout=5, env=env,
        )
        if without_proc.returncode == 0:
            logger.debug(
                "Sandbox: fresh procfs probe — namespaces engage but "
                "--mount-proc is refused: %s",
                (with_proc.stderr or b"").decode("utf-8", "replace").strip(),
            )
            return False, True
        # Namespace layer itself refused — indeterminate for the proc
        # mount question (and the spawn path that consults us won't
        # engage anyway). Cacheable: a kernel refusal is static too.
        return True, True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Probe infrastructure failure (load, transient OSError) — not
        # a kernel verdict. Don't cache; re-probe next call.
        return True, False


def check_net_available() -> bool:
    """Check if network isolation via user namespaces is available.

    Tests: unshare command exists, unprivileged user namespaces enabled,
    and a functional test passes. Result is cached for the session.

    Lock discipline (same as ``check_unshare_engages``): the cache is
    read and written under BRIEF ``_cache_lock`` holds; the slow probe
    (an up-to-5s subprocess) runs OUTSIDE the lock so it never stalls
    every other thread's cache op under concurrent first-use. Racing
    threads may probe redundantly — benign; the second lock acquisition
    re-checks the cache and the first published verdict wins.
    """
    with state._cache_lock:
        if state._net_available_cache is not None:
            return state._net_available_cache

    available = _probe_net_available()

    with state._cache_lock:
        if state._net_available_cache is None:
            state._net_available_cache = available
        return state._net_available_cache


def _probe_net_available() -> bool:
    """Run the actual (slow) network-isolation probe. Never touches the
    cache — ``check_net_available`` owns caching and locking."""
    try:
        unshare_path = _resolve_sandbox_binary("unshare")
    except FileNotFoundError as e:
        # util-linux not installed in a standard location — record
        # the reason at debug so startup diagnostics surface it,
        # then treat as "no network isolation available". Fail-
        # closed: caller sees a disabled sandbox, not a PATH-
        # hijacked one.
        logger.debug("Sandbox: %s", e)
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
            value = sysctl.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            value = ""  # No sysctl on this kernel — defaults to enabled.
        if value == "0":
            logger.debug("Sandbox: unprivileged user namespaces disabled (sysctl)")
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
            logger.debug("Sandbox: network test failed: %s", result.stderr.strip())
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

    # Namespace CREATION alone is not the backend: the fork-based spawn
    # stages a second os.unshare(CLONE_NEWPID) from inside the new user
    # namespace, and restricted-userns hosts (Ubuntu's AppArmor
    # transition — GitHub runners, live-confirmed from run artifacts)
    # allow every single-call creation above while refusing that staged
    # second call with EPERM. On such hosts the CLI probe passes, every
    # namespace-backed run then dies mid-child (silent rc-126 empty
    # results, demotion warnings for calls that were promised
    # isolation), and the capability-gated test suite mis-runs. Treat
    # the staged refusal as "no namespace backend": backend selection
    # then routes to the same degraded lanes an outright userns denial
    # gets — deny-all TCP via Landlock, floor consent, honest skips.
    if not _staged_pidns_selftest():
        logger.debug(
            "Sandbox: staged pid-namespace creation refused "
            "(restricted unprivileged user namespaces) — namespace "
            "backend unavailable")
        return False

    return True


def _mount_ns_functional_selftest() -> bool:
    """Fork a child, ``unshare(CLONE_NEWUSER|CLONE_NEWNS)`` AND perform a
    real mount inside the new namespace, to verify the kernel permits the
    operations the spawn path actually runs.

    The other ``check_mount_available()`` signals — uidmap binaries present,
    AppArmor sysctl != 1 — are necessary but NOT sufficient: an outer-container
    seccomp policy, a non-AppArmor LSM (SELinux), or a nested-userns mount
    restriction can still refuse ``unshare(CLONE_NEWNS)``. Without this test
    such a host reports mount-ns available, the _spawn child then dies on
    ``os.unshare`` (exit 126 + empty stdout) — a silent "0 findings". Testing
    it here means a NEWNS-incapable host instead falls back to Landlock-only
    and still produces real results. Same approach as the Landlock and seccomp
    functional self-tests.

    Namespace CREATION alone is still not sufficient: there are hosts where
    ``unshare(CLONE_NEWUSER|CLONE_NEWNS)`` succeeds but every mount(2) inside
    the owned namespace is denied — an outer-container seccomp that EPERMs
    the mount family is the concrete case (the feature-matrix ``no-mount``
    lane models it). On such a host a creation-only probe reports mount-ns
    available and every spawn then fails its bind tree mid-flight, so the
    child also remounts ``/`` recursively private and mounts a tmpfs at
    ``/tmp`` — the same first operations ``core.sandbox.mount_ns`` performs.
    Both live only in the child's namespace and evaporate with it. This
    gives the outer-seccomp class the same up-front Landlock-only posture
    the AppArmor-sysctl class already gets from the fast path above; the
    spawn ladder's mountless 'M' retry remains the mid-flight net for
    failures no probe saw coming.

    Child is ``os.unshare`` + two pre-resolved ``libc.mount`` calls +
    ``os._exit`` only (libc handle resolved before the fork).
    """
    _CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
    _CLONE_NEWNS = getattr(os, "CLONE_NEWNS", 0x00020000)
    _MS_REC = 0x4000
    _MS_PRIVATE = 1 << 18
    import ctypes
    try:
        _libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return False
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
        except BaseException:
            os._exit(1)
        try:
            if _libc.mount(b"none", b"/", None, _MS_REC | _MS_PRIVATE,
                           None) != 0:
                os._exit(2)
            if _libc.mount(b"none", b"/tmp", b"tmpfs", 0, None) != 0:
                os._exit(3)
        except BaseException:
            os._exit(4)
        os._exit(0)
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
                _restrict_value = sysctl.read_text(encoding="utf-8").strip()
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
        # Probe for the tools first; the forked functional self-test
        # below then confirms the kernel actually permits
        # unshare(CLONE_NEWNS) — binary presence + the AppArmor
        # sysctl check alone proved necessary but not sufficient.
        # Trusted-dirs resolution, NOT the inherited PATH — see
        # _find_sandbox_binary. A PATH-planted stub must not flip
        # this availability verdict.
        have_newuidmap = _find_sandbox_binary("newuidmap") is not None
        have_newgidmap = _find_sandbox_binary("newgidmap") is not None
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
        # still refuse unshare(CLONE_NEWNS), or allow it and refuse the
        # mounts inside the owned namespace (outer seccomp / SELinux /
        # nested userns). If it does, report unavailable so we degrade to
        # Landlock-only rather than dying mid-spawn with empty output.
        if not _mount_ns_functional_selftest():
            if state.warn_once("_mount_unavailable_warned"):
                logger.info(
                    "Sandbox: mount-namespace isolation UNAVAILABLE — "
                    "unshare(CLONE_NEWNS) or mount(2) inside the owned "
                    "namespace refused at runtime (outer seccomp / LSM / "
                    "nested-userns restriction). Fallback: Landlock-only."
                )
            state._mount_available_cache = False
            return False

        state._mount_available_cache = True
        return True


def check_child_unix_sockets_available() -> bool:
    """Whether a child sandboxed by ``core.sandbox.run`` can CREATE
    AF_UNIX sockets (``socket(AF_UNIX)`` + ``bind``).

    Consumers that host a unix-socket server INSIDE the sandbox (the
    persistent Ghidra worker) use this as a transport pre-flight: when
    it returns False the child's very first ``socket(2)`` dies with
    EPERM under the seccomp policy, so the caller must hand the child
    an inherited descriptor (socketpair) instead of a pathname socket.

    The verdict mirrors the spawn path's own gating:

    - darwin: the seatbelt profile does not filter socket creation —
      always True.
    - Linux: socket creation is allowed only on the NAMESPACE spawn
      lane (``core.sandbox._spawn``), and only when the connect-
      scoping supervisor can run (``probe_unix_scope`` — without it
      ``allow_unix_sockets`` stays disabled, fail-closed). Every other
      lane (subprocess+preexec) installs a seccomp filter that denies
      ``socket(AF_UNIX)`` unconditionally. ``check_mount_available()``
      stands in for "the namespace lane serves this host" — it implies
      ``check_net_available()`` (the staged pid-ns self-test included,
      which is exactly what nested-sandbox hosts fail).

    Deliberately conservative: a Linux host where seccomp itself is
    unavailable would let the preexec lane create sockets unfiltered,
    but this helper still reports False there — a false negative only
    steers the consumer onto the inherited-descriptor transport, which
    works on every lane. A false POSITIVE would boot-loop the child
    against EPERM, so the bias is the safe one.
    """
    import sys
    if sys.platform == "darwin":
        return True
    if not check_mount_available():
        return False
    from ._unix_scope import probe_unix_scope
    return probe_unix_scope()


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
        return Path("/sys/fs/selinux/enforce").read_text(encoding="utf-8").strip() == "1"
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
        ).read_text(encoding="utf-8").strip()
        if v == "1":
            return (
                "mount-ns blocked by host "
                "(kernel.apparmor_restrict_unprivileged_userns=1)",
                "set kernel.apparmor_restrict_unprivileged_userns=0 "
                "(Ubuntu 24.04+) and install the uidmap package; or "
                "rerun on a host where mount-ns is available.",
            )
    except (FileNotFoundError, OSError):
        pass
    # 2. uidmap binaries missing — distinct from the AppArmor case
    #    because the fix is package install, not sysctl flip. Trusted
    #    dirs only (mirrors check_mount_available): the diagnosis must
    #    agree with the probe it explains.
    if not (_find_sandbox_binary("newuidmap")
            and _find_sandbox_binary("newgidmap")):
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
    #    Names BOTH refusal points the functional self-test probes:
    #    namespace creation and the mounts inside the owned namespace —
    #    an outer seccomp that EPERMs only the mount family fails the
    #    second while the first succeeds.
    return (
        "mount-ns blocked by host "
        "(unshare(CLONE_NEWNS), or mount(2) inside the owned "
        "namespace, refused at runtime — likely outer "
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
