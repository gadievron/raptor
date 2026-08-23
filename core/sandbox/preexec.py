"""Resource rlimits + preexec_fn composition.

Ties the three isolation layers together into a single preexec_fn that
runs in the forked child after subprocess fork and before exec:
1. resource.setrlimit() for memory / CPU / file-size caps
2. Landlock filesystem + TCP-port rules (landlock.py)
3. Seccomp syscall blocklist (seccomp.py)

Order matters: Landlock's PR_SET_NO_NEW_PRIVS is required by seccomp, so
seccomp installs LAST — inheriting NO_NEW_PRIVS from Landlock's
restrict_self.
"""

import ctypes
import ctypes.util
import json
import logging
import os
import resource
import select
import signal
import sys
import time
import warnings
from pathlib import Path

from . import state
from ._fork_safe_warn import warn_post_fork
from .exit_codes import SANDBOX_EXIT_RLIMIT_CORE_FAIL
from .landlock import _make_landlock_preexec, check_landlock_available
from .seccomp import _make_seccomp_preexec

logger = logging.getLogger(__name__)

# Default resource limits (generous — catch malice, not constrain builds).
#
# `memory_mb` bounds RLIMIT_AS (virtual address space). Disabled by
# default (0 means "skip setrlimit") because ASAN-instrumented binaries
# reserve ~56 TiB of shadow-memory VA on x86_64 and ANY finite limit
# breaks them at startup — including values that far exceed physical
# RAM. Every memory-corruption PoC in /validate uses ASAN, so a tight
# RLIMIT_AS is a non-starter. Callers wanting an actual RAM bound
# should use an external cgroup v2 `memory.max`; rlimit was always a
# weak defence anyway (malicious code can defeat it via many small
# mmaps, and VA limits don't reflect physical RAM usage).
#
# `nproc` is enforced via RLIMIT_NPROC inside the user-namespace only:
# the sandboxed child runs as ns-UID nobody (65534) which has zero
# pre-existing processes, so the limit bounds fork-bomb expansion
# without affecting unrelated RAPTOR work on the host UID. Skipped
# when no user-namespace is active (i.e. Landlock-only / profile=none
# paths) because there the count would apply to the host UID.
_DEFAULT_LIMITS = {
    "memory_mb": 0,        # 0 = no RLIMIT_AS (ASAN-compatible; see rationale above)
    "max_file_mb": 10240,  # 10 GB max file size
    "cpu_seconds": 3600,   # 1 hour CPU time
    "nproc": 1024,         # 1024 processes inside the sandbox's user-ns
    # RLIMIT_NOFILE. Bounds fd-exhaustion DoS (a sandboxed child could
    # previously open descriptors until the host's per-process ceiling,
    # commonly 2^20). 4096 is far above any observed tool's need
    # (compilers, JVMs, scanners run in the low hundreds) while turning
    # "open until the kernel gives up" into an early, attributable
    # EMFILE. Clamped to the inherited hard limit; 0 disables.
    "nofile": 4096,
}

# User config path for limit overrides
_CONFIG_PATH = Path.home() / ".config/raptor/sandbox.json"


# How long the "no/invalid config → empty limits" decision is cached
# before we re-probe the config file. Operators correcting a typo'd
# sandbox.json shouldn't have to restart every RAPTOR process; 60s is
# long enough to amortise the parse cost across a busy run, short
# enough that a fix takes effect within one human iteration.
_FAIL_TTL_S = 60.0


def _load_user_limits() -> dict:
    """Load user-configured resource limits from ~/.config/raptor/sandbox.json.

    Successful loads cache for the session. Failure (no file, parse
    error, non-regular file) caches for ``_FAIL_TTL_S`` seconds so a
    corrected file is honoured without needing a process restart.

    Example config:
    {
        "memory_mb": 8192,
        "max_file_mb": 20480,
        "cpu_seconds": 7200
    }

    Missing keys use defaults. Invalid file logs a WARNING and falls back.
    """
    import time
    with state._cache_lock:
        # Cached SUCCESS: return immediately. No TTL — we trust the
        # operator who edited the config to clear the cache (or
        # restart) if they want to retry.
        if state._user_limits_cache:
            return state._user_limits_cache
        # Cached FAILURE (empty dict): re-probe after _FAIL_TTL_S.
        # A successfully-parsed config with no recognised keys is
        # also an empty dict, but its decided_at is stamped +inf on
        # the success path below, so this window never expires for
        # it — session-cached, not re-parsed as if it had failed.
        if (state._user_limits_cache is not None
            and (time.time() - state._user_limits_cache_decided_at)
                <= _FAIL_TTL_S):
            return state._user_limits_cache

        if not _CONFIG_PATH.exists():
            state._user_limits_cache = {}
            state._user_limits_cache_decided_at = time.time()
            return state._user_limits_cache
        try:
            # `is_file()` check before read_text. Pre-fix
            # `_CONFIG_PATH.exists()` returned True for FIFO,
            # device file, named pipe, or symlink-to-FIFO at the
            # config path. `read_text()` on a FIFO BLOCKS waiting
            # for a writer, hanging the import indefinitely.
            # An attacker (or operator misconfiguration) creating
            # `~/.config/raptor/sandbox.json` as a FIFO via
            # `mkfifo` would cause every RAPTOR process to hang
            # at startup. Treat non-regular files as missing.
            if not _CONFIG_PATH.is_file():
                state._user_limits_cache = {}
                state._user_limits_cache_decided_at = time.time()
                return state._user_limits_cache
            # Size cap before read — config is JSON metadata (key/int
            # pairs); 64 KiB is generous and catches a hostile or
            # mis-edited file ballooning to multi-MiB at module-load
            # time when the rest of the process can't yet log.
            _CONFIG_MAX_BYTES = 64 * 1024
            try:
                if _CONFIG_PATH.stat().st_size > _CONFIG_MAX_BYTES:
                    state._user_limits_cache = {}
                    state._user_limits_cache_decided_at = time.time()
                    return state._user_limits_cache
            except OSError:
                state._user_limits_cache = {}
                state._user_limits_cache_decided_at = time.time()
                return state._user_limits_cache
            # UnicodeDecodeError is possible if config isn't valid UTF-8 —
            # catching it alongside JSON/OS errors keeps module import safe
            # against a malformed config file.
            data = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # Accept non-negative ints; 0 is a valid "skip this rlimit"
                # sentinel (see _set_limits guards: `if mem > 0:` etc.).
                # Users may want memory_mb=0 specifically — ASAN-instrumented
                # binaries reserve ~56 TiB of shadow VA and break under any
                # finite RLIMIT_AS, so 0 is the explicit "unlimited" setting.
                # Reject negatives, floats, strings, None — those are config
                # errors.
                cleaned = {}
                for k, v in data.items():
                    if k not in _DEFAULT_LIMITS:
                        continue
                    # bool is a subclass of int in Python — exclude explicitly
                    # so `"nproc": true` doesn't silently become nproc=1.
                    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                        logger.warning(
                            "Sandbox: user limit %s=%r in %s is not a non-negative integer — ignoring, using default %s.", k, v, _CONFIG_PATH, _DEFAULT_LIMITS[k]
                        )
                        continue
                    cleaned[k] = v
                state._user_limits_cache = cleaned
                # +inf: successful parses never expire (session
                # cache), including a valid config that yields no
                # recognised keys — cleaned == {} must not be
                # mistaken for the failure sentinel above.
                state._user_limits_cache_decided_at = float("inf")
                return state._user_limits_cache
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.warning(
                "Sandbox: could not parse %s: %s — using default limits.", _CONFIG_PATH, e.__class__.__name__)
        state._user_limits_cache = {}
        state._user_limits_cache_decided_at = time.time()
        return state._user_limits_cache


def _make_preexec_fn(limits: dict, writable_paths: list | None = None,
                     allowed_tcp_ports: list | None = None,
                     seccomp_profile: str | None = None,
                     seccomp_block_udp: bool = False,
                     readable_paths: list | None = None,
                     deny_all_tcp_connect: bool = False,
                     host_nproc_cap: int | None = None,
                     reaper_cell: dict | None = None):
    """Create a preexec_fn that sets resource limits, Landlock, and seccomp.

    Resource limits (rlimit) apply for memory / CPU / file-size.
    RLIMIT_NPROC is NOT set here — if it were, it would apply on the
    host UID (preexec runs BEFORE unshare creates the user-ns) which
    would kill unrelated RAPTOR work. NPROC is applied separately via
    a `prlimit --nproc=N --` wrapper that sits INSIDE the unshare chain,
    so the limit counts against the ns-local UID (nobody/65534) which
    has zero pre-existing processes. See context.py.

    Landlock filesystem restrictions apply when writable_paths is provided
    and Landlock is available — allows read everywhere, write only to
    the specified paths.
    Seccomp filter applies when seccomp_profile is set and libseccomp is
    available. Installed AFTER Landlock's restrict_self so it inherits
    PR_SET_NO_NEW_PRIVS. `seccomp_block_udp=True` additionally rejects
    AF_INET/AF_INET6 SOCK_DGRAM (used by the egress-proxy mode to close
    DNS/UDP exfil).
    `deny_all_tcp_connect=True` engages Landlock's TCP-connect deny with
    no allow rules (degraded-mode network fallback — see context.py);
    it engages Landlock even when no writable paths are set, as a
    net-only ruleset that leaves filesystem semantics untouched.

    `reaper_cell` engages the NO-NAMESPACE TEARDOWN SWEEP: on the
    Landlock-only path there is no pid namespace, so a payload that
    setsid()s a daemon, SIGSTOP-parks a child, or leaves stragglers
    behind used to survive run() teardown outright. When a cell is
    passed, the composed preexec splits after rlimits: it forks, the
    fork-PARENT becomes a PR_SET_CHILD_SUBREAPER sweeper that never
    execs (subprocess sees IT as the child), and the fork-CHILD
    applies Landlock+seccomp and execs the payload. Every orphaned
    descendant of the payload — setsid daemons included — reparents
    to the sweeper, which SIGKILL-sweeps them when the payload exits
    or when the per-run death pipe (``reaper_cell["death_fd"]``,
    populated by context.run() before each spawn) reaches EOF. The
    sweeper mirrors the payload's exit status (128+N for signals) and
    stays OUTSIDE the Landlock domain, so on scoping-capable kernels
    (ABI >= 6) the payload cannot signal it. The payload re-arms
    PR_SET_PDEATHSIG against the sweeper, so a kill aimed at the
    direct child (subprocess timeout) still takes the payload down.

    `host_nproc_cap` is the no-user-namespace substitute for the
    prlimit/unshare NPROC containment: on the Landlock-only path the
    child shares the HOST uid, so a flat cap would count the
    operator's unrelated processes. context.py computes
    "current same-uid process count + nproc" in the parent and passes
    the absolute ceiling here; RLIMIT_NPROC then bounds fork-bomb
    growth to the configured headroom instead of leaving it unbounded.
    None (or 0) skips it — the namespace paths keep their stronger
    ns-local accounting.
    """
    landlock_fn = None
    # `readable_paths is not None` (not truthiness): an empty list means
    # "reads restricted to writable_paths only" — the MOST restrictive
    # setting — and must engage Landlock. Without readable_paths in this
    # gate, a restrict_reads-only caller (no writable paths, no ports,
    # no connect-deny) silently got no Landlock at all.
    if ((writable_paths or allowed_tcp_ports or deny_all_tcp_connect
         or readable_paths is not None)
            and check_landlock_available()):
        effective_paths = list(writable_paths) if writable_paths else []
        landlock_fn = _make_landlock_preexec(effective_paths, allowed_tcp_ports,
                                             readable_paths=readable_paths,
                                             deny_all_tcp_connect=deny_all_tcp_connect)

    seccomp_fn = (
        _make_seccomp_preexec(seccomp_profile, block_udp=seccomp_block_udp)
        if seccomp_profile else None
    )

    pdeathsig_fn = set_pdeathsig()

    def _set_limits() -> None:
        pdeathsig_fn()
        # Fallbacks below must stay in sync with _DEFAULT_LIMITS. Callers
        # through context.sandbox() always pass the merged effective_limits
        # (DEFAULT + user config + caller overrides) so the fallbacks only
        # matter for tests / direct callers of _make_preexec_fn.
        mem = limits.get("memory_mb", _DEFAULT_LIMITS["memory_mb"])
        file_mb = limits.get("max_file_mb", _DEFAULT_LIMITS["max_file_mb"])
        cpu = limits.get("cpu_seconds", _DEFAULT_LIMITS["cpu_seconds"])
        nofile = limits.get("nofile", _DEFAULT_LIMITS["nofile"])

        mem_bytes = mem * 1024 * 1024
        file_bytes = file_mb * 1024 * 1024

        if mem > 0:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError) as exc:
                _errno = getattr(exc, "errno", 0) or 0
                warn_post_fork(
                    b"preexec: RLIMIT_AS setrlimit failed (errno=%d); "
                    b"process may exceed requested virtual-address bound\n"
                    % _errno
                )
        if file_mb > 0:
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
            except (ValueError, OSError) as exc:
                _errno = getattr(exc, "errno", 0) or 0
                warn_post_fork(
                    b"preexec: RLIMIT_FSIZE setrlimit failed (errno=%d); "
                    b"process may exceed requested max-file-size\n"
                    % _errno
                )
        if cpu > 0:
            try:
                # Soft limit 1s before hard limit so the process gets SIGXCPU
                # (catchable, sets resource_exceeded=True) before SIGKILL.
                # With soft==hard, kernel sends both simultaneously and SIGKILL
                # wins — making resource_exceeded permanently False.
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
            except (ValueError, OSError) as exc:
                _errno = getattr(exc, "errno", 0) or 0
                warn_post_fork(
                    b"preexec: RLIMIT_CPU setrlimit failed (errno=%d); "
                    b"process may exceed requested CPU-time bound\n"
                    % _errno
                )

        if nofile > 0:
            try:
                # Clamp to the inherited hard limit — raising the hard
                # limit needs CAP_SYS_RESOURCE and would fail the whole
                # setrlimit otherwise.
                _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                eff = nofile if hard == resource.RLIM_INFINITY else min(
                    nofile, hard)
                resource.setrlimit(resource.RLIMIT_NOFILE, (eff, eff))
            except (ValueError, OSError) as exc:
                _errno = getattr(exc, "errno", 0) or 0
                warn_post_fork(
                    b"preexec: RLIMIT_NOFILE setrlimit failed (errno=%d); "
                    b"fd-exhaustion bound not applied\n" % _errno
                )
        # Core dumps off. A sandboxed process can read anywhere in the
        # filesystem (Landlock's read-everywhere default covers ~/.ssh,
        # ~/.aws/credentials, API-key files); if the process then crashes
        # with core dumps enabled system-wide (apport/abrt pipes in
        # /proc/sys/kernel/core_pattern, or dumps written to cwd), the
        # dump contains all that loaded memory — turning any crash into a
        # credential-exfiltration primitive. RLIMIT_CORE=0 blocks the dump
        # before the kernel writes it.
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError) as exc:
            # See block-comment above: without RLIMIT_CORE=0 the kernel
            # may write a core dump that contains the full address-space
            # of a sandboxed process — including ~/.ssh, ~/.aws, or any
            # other secret the process read under Landlock's permissive
            # default read policy. That turns any crash into a
            # credential-exfiltration primitive. The parent has no way
            # to recover from this post-fork, so fail-closed.
            # Per W35.C convention, fail-CLOSED sites use direct
            # os.write(2, ...) + os._exit(N) rather than the
            # warn_post_fork helper (helper is reserved for DiD
            # warn-only sites).
            _errno = getattr(exc, "errno", 0) or 0
            try:
                os.write(
                    2,
                    b"RAPTOR: preexec: RLIMIT_CORE setrlimit failed "
                    b"(errno=%d), exiting\n" % _errno,
                )
            except OSError:
                pass
            os._exit(SANDBOX_EXIT_RLIMIT_CORE_FAIL)


        # No-namespace teardown sweep (see the reaper_cell docstring):
        # split BEFORE Landlock/seccomp so the sweeper stays outside
        # the restriction domain (payload cannot signal it on Landlock
        # scoping kernels) while the payload gets the full stack.
        if reaper_cell is not None and sys.platform == "linux":
            _reaper_split(reaper_cell)

        # RLIMIT_NPROC ceiling for the no-namespace path — applied
        # AFTER the reaper split so it binds the PAYLOAD only: the
        # sweeper's own fork and kill work must never fail against the
        # cap it is meant to enforce on the payload's tree.
        if host_nproc_cap and host_nproc_cap > 0:
            try:
                _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
                eff = (host_nproc_cap
                       if hard == resource.RLIM_INFINITY
                       else min(host_nproc_cap, hard))
                resource.setrlimit(resource.RLIMIT_NPROC, (eff, eff))
            except (ValueError, OSError) as exc:
                _errno = getattr(exc, "errno", 0) or 0
                warn_post_fork(
                    b"preexec: RLIMIT_NPROC setrlimit failed (errno=%d); "
                    b"fork-bomb bound not applied on the no-namespace "
                    b"path\n" % _errno
                )

        # Apply Landlock filesystem restrictions after resource limits
        # and ns setup. Seccomp filter is installed LAST so it inherits
        # PR_SET_NO_NEW_PRIVS from Landlock's restrict_self (seccomp
        # requires NO_NEW_PRIVS unless the caller has CAP_SYS_ADMIN).
        if landlock_fn:
            landlock_fn()
        if seccomp_fn:
            seccomp_fn()

    return _set_limits


# ── No-namespace teardown sweeper ───────────────────────────────────
#
# On the Landlock-only path there is no pid namespace to cascade-kill
# the payload's process tree at teardown. The battery-proven escapes:
# a setsid double-fork daemon, a SIGSTOP-parked child, a delayed
# writer surviving a timeout — all outlived run() and kept host access
# (a post-teardown host write included). The sweeper is the pid-
# tracking substitute: PR_SET_CHILD_SUBREAPER makes every orphaned
# descendant reparent to it, so at payload exit (or death-pipe EOF)
# it can enumerate /proc/self/task/<pid>/children and SIGKILL the
# stragglers — stopped processes included (SIGKILL resumes-and-kills).

_PR_SET_CHILD_SUBREAPER = 36
# Grace budget for the kill loop: re-enumerate and re-kill until no
# children remain (a dying daemon may orphan ITS children onto us).
_SWEEP_DEADLINE_S = 3.0
_DEATH_TEARDOWN_EXIT = 137  # parity with the pid1 shim convention


def _reaper_split(reaper_cell: dict) -> None:
    """Fork inside the preexec: parent becomes the sweeper (never
    returns), child continues to Landlock/seccomp/exec. Post-fork
    safe: os.* + captured module refs only."""
    libc = _get_libc()
    if libc is None:
        return  # no prctl — keep the historic single-process shape
    death_fd = reaper_cell.get("death_fd")
    # Subreaper BEFORE the fork so no orphan can slip through the
    # window; the payload clears its inherited copy so mid-run
    # orphans reparent to the sweeper, not to the payload.
    libc.prctl(_PR_SET_CHILD_SUBREAPER, 1)
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:
        # Payload branch. Re-arm PDEATHSIG against the sweeper (the
        # new parent): a kill aimed at the direct child — subprocess
        # timeout kills Popen.pid, which is the sweeper — must take
        # the payload down with it.
        libc.prctl(_PR_SET_CHILD_SUBREAPER, 0)
        libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        return
    _sweeper_main(pid, death_fd)  # never returns


def _sweeper_main(payload_pid: int, death_fd) -> None:
    # Detach from the parent's stdio pipes so communicate() EOF is
    # governed by the payload tree alone; keep fd 2 for warnings.
    for _fd in (0, 1):
        try:
            os.close(_fd)
        except OSError:
            pass
    # Close everything else we inherited (subprocess errpipe included
    # — holding it would block Popen's exec-status read until the
    # sweeper exits) except the death pipe.
    # Enumerate the actually-open fds: the preexec rlimit step may
    # already have LOWERED the NOFILE soft limit, and lowering it does
    # not invalidate existing descriptors — a pre-existing inheritable
    # fd at/above the reduced limit would survive a range()-based
    # sweep. Fall back to the bounded range when /proc isn't listable.
    try:
        _open = [int(_n) for _n in os.listdir("/proc/self/fd")]
    except (OSError, ValueError):
        try:
            _max = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except (ValueError, OSError):
            _max = 4096
        _open = list(range(3, min(int(_max), 65536)))
    for _fd in _open:
        if _fd <= 2 or (death_fd is not None and _fd == death_fd):
            continue
        try:
            os.close(_fd)
        except OSError:
            pass

    poller = None
    if death_fd is not None:
        try:
            poller = select.poll()
            poller.register(death_fd, select.POLLIN)
        except OSError:
            poller = None

    payload_status = None
    teardown = False
    while True:
        # Reap anything that exited — the payload itself or orphans
        # reparented to us (their statuses are discarded; we only
        # track the payload's for exit-code mirroring).
        while True:
            try:
                wpid, wstatus = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                wpid = 0
            except OSError:
                wpid = 0
            if wpid == 0:
                break
            if wpid == payload_pid:
                payload_status = wstatus
        if payload_status is not None:
            break
        if poller is not None:
            try:
                events = poller.poll(50)
            except OSError:
                events = []
            if events:
                # Parent (orchestrator) closed the pipe — teardown or
                # death. Kill the payload and sweep everything.
                teardown = True
                try:
                    os.kill(payload_pid, signal.SIGKILL)
                except OSError:
                    pass
                break
        else:
            time.sleep(0.05)

    # Sweep: SIGKILL every remaining child until none are left or the
    # deadline passes (a dying daemon may orphan its own children
    # onto us — loop, don't single-pass).
    deadline = time.monotonic() + _SWEEP_DEADLINE_S
    swept_any = False
    while time.monotonic() < deadline:
        kids = _reaper_children()
        if not kids:
            break
        for kid in kids:
            swept_any = True
            try:
                os.kill(kid, signal.SIGKILL)
            except OSError:
                pass
        while True:
            try:
                if os.waitpid(-1, os.WNOHANG)[0] == 0:
                    break
            except (ChildProcessError, OSError):
                break
        time.sleep(0.02)
    if swept_any:
        try:
            os.write(2, b"RAPTOR sandbox: teardown sweep killed "
                        b"surviving descendants (no-namespace path)\n")
        except OSError:
            pass

    if teardown or payload_status is None:
        os._exit(_DEATH_TEARDOWN_EXIT)
    if os.WIFSIGNALED(payload_status):
        os._exit(128 + os.WTERMSIG(payload_status))
    os._exit(os.WEXITSTATUS(payload_status))


def _reaper_children() -> list:
    """Live children of this process (post-fork safe: /proc reads)."""
    me = os.getpid()
    try:
        with open(f"/proc/{me}/task/{me}/children", "rb") as f:
            data = f.read()
        return [int(x) for x in data.split()]
    except (OSError, ValueError):
        # CONFIG_PROC_CHILDREN missing — fall back to a /proc scan.
        kids = []
        try:
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open(f"/proc/{name}/stat", "rb") as f:
                        fields = f.read().rsplit(b") ", 1)[-1].split()
                    if int(fields[1]) == me:
                        kids.append(int(name))
                except (OSError, ValueError, IndexError):
                    continue
        except OSError:
            pass
        return kids


# ── PR_SET_PDEATHSIG ────────────────────────────────────────────────
#
# For non-sandboxed subprocess calls (git, readelf, codeql, gdb, etc.)
# the death-pipe mechanism in context.py doesn't apply — there is no
# pid-namespace shim watching for orchestrator exit.  If the parent is
# killed (SIGKILL, OOM, crash) while a child runs, the child orphans
# and lives forever.
#
# PR_SET_PDEATHSIG tells the kernel to deliver a signal to this process
# when its parent thread exits.  Unlike the death-pipe, it is cleared
# by setuid exec and by unshare(CLONE_NEWUSER) — which is why the
# sandboxed-spawn path uses the pipe instead.  For plain fork+exec
# without user-ns, PDEATHSIG is reliable.

_PR_SET_PDEATHSIG = 1
_libc = None

# ── OOM child scoring ───────────────────────────────────────────────
#
# Analysis children (scanners, builds, r2, gdb, CodeQL, target
# processes) are sacrificial: under memory pressure the kernel should
# kill THEM, never the RAPTOR session that orchestrates them — losing
# one tool invocation costs a retry; losing the session costs the run.
# oom_score_adj=+500 makes every spawned child a strongly preferred
# OOM victim relative to the session (which stays at its inherited
# score). Raising one's own score never needs privilege.
#
# Stickiness is honest, not absolute: an unprivileged child MAY lower
# its score back down to the floor it inherited at fork (only going
# BELOW that floor needs CAP_SYS_RESOURCE — the direction
# test_sandbox_attack_scenarios' oom probe pins). Outside the sandbox
# the stamp is therefore a default that well-behaved tools keep, not
# a boundary against a malicious child; under core.sandbox.run,
# Landlock denies the /proc/self write and the preference does stick
# through the child tree.
#
# Written post-fork/pre-exec, so on the sandboxed path it lands
# BEFORE Landlock restricts /proc writes and is inherited across the
# unshare chain. Silently skipped where /proc/self/oom_score_adj is
# unwritable (locked-down containers) or absent (non-Linux).

_OOM_SCORE_ADJ_PATH = "/proc/self/oom_score_adj"
_OOM_SCORE_ADJ = b"500"


def raise_oom_score_adj() -> None:
    """Mark the calling (child) process as a preferred OOM victim.

    Post-fork safe: raw os.open/os.write only. Never raises — an
    environment that refuses the write just keeps the inherited score.
    """
    try:
        fd = os.open(_OOM_SCORE_ADJ_PATH, os.O_WRONLY)
    except OSError:
        return
    try:
        os.write(fd, _OOM_SCORE_ADJ)
    except OSError:
        pass
    finally:
        os.close(fd)


def _get_libc():
    global _libc
    if _libc is None:
        name = ctypes.util.find_library("c")
        if name:
            _libc = ctypes.CDLL(name, use_errno=True)
    return _libc


def set_pdeathsig(sig=signal.SIGKILL):
    """Return a preexec_fn that sets PR_SET_PDEATHSIG on the child.

    Linux-only; returns a no-op on other platforms.  Callers pass this
    to ``subprocess.run(..., preexec_fn=set_pdeathsig())`` so the child
    is killed when the parent dies — no more orphaned git/readelf/gdb.

    Also raises the child's ``oom_score_adj`` to +500 (see the block
    comment above): this helper IS the shared child-preexec for every
    non-sandboxed tool spawn, and both properties serve one doctrine —
    analysis children are sacrificial, the session is not. The
    sandboxed path gets the same score via ``_make_preexec_fn``'s
    composed preexec, which calls this first.
    """
    if sys.platform != "linux":
        return lambda: None

    def _apply() -> None:
        libc = _get_libc()
        if libc is not None:
            libc.prctl(_PR_SET_PDEATHSIG, sig)
        raise_oom_score_adj()

    return _apply
