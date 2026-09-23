"""Landlock-only spawn variant with audit/observe tracer support.

The mount-ns spawn path (``_spawn.run_sandboxed``) is the load-bearing
audit/observe entry on hosts where unprivileged user-ns + mount-ns
are available. On Ubuntu 24.04+ with the AppArmor default
``apparmor_restrict_unprivileged_userns=1``, mount-ns is blocked and
the sandbox falls back to a Landlock-only ``subprocess.run`` —
which previously had NO tracer-fork machinery, so observe mode
silently degraded.

This module adds the missing piece: a focused spawn function that

  * does NOT touch namespaces (mount/user/pid/net) — Landlock plus
    seccomp do all of the per-call isolation;
  * forks a ``core.sandbox.tracer`` subprocess in parallel with the
    target child, mirroring the sync-pipe handshake from _spawn;
  * passes the same audit-config shape — via an ANONYMOUS fd
    (memfd; see core/sandbox/evidence.py), never a /tmp path — so
    observe records carry the per-run nonce + observe-stamp the
    parser validates, and the nonce never exists at a filesystem
    path the (namespace-less, same-UID) target can name;
  * creates the evidence JSONL in ``<run_dir>/.audit/`` with O_EXCL
    at spawn time and hands the held fd to the tracer, so appends
    survive path-level tampering and the inode is verified at
    finalisation.

Implementation note: uses ``os.fork()`` directly (not
``subprocess.Popen``) for the target child. ``Popen`` blocks until
the child execs successfully, but our preexec must wait on a sync
pipe BEFORE exec — Popen would deadlock the parent. The manual
fork mirrors ``_spawn.run_sandboxed``'s pattern; the post-fork
contract is the same (no Python objects, no GIL, ctypes-only
syscalls until execvpe).

Threat-model note: callers running on Landlock-only hosts already
trade away namespace-level isolation (no PID-ns visibility hiding,
no mount-ns filesystem hiding, no user-ns capability remapping).
This module does not regress that posture; it specifically only
restores AUDIT/OBSERVE signal that was missing. The Linux
``THREAT_MODEL.md`` Landlock-only-mode warning applies unchanged.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import json
import logging
import os
import resource
import select
import subprocess
import sys
import time
import warnings
from collections.abc import Iterable
from pathlib import Path

from . import evidence as _evidence_mod

logger = logging.getLogger(__name__)

# Python 3.12+ warns on every os.fork() in a multi-threaded process.
# Both fork sites in this module honour the fork-safety contract (the
# children only do fd plumbing, bare syscalls and exec — see
# _spawn.py's module docstring). The filter must live at module
# level, exactly like _spawn's: per-fork ``warnings.catch_warnings()``
# blocks mutate the PROCESS-GLOBAL filter list and race when this
# audit lane forks concurrently with _spawn sandboxes on another
# thread — one thread's restore re-exposes another thread's fork
# mid-flight, which is how the warning kept escaping into CI output.
warnings.filterwarnings(
    "ignore", category=DeprecationWarning,
    message=r".*use of fork\(\) may lead to deadlocks in the child.*",
)


# Default tracer-ready timeout. The tracer's PTRACE_SEIZE +
# SETOPTIONS dance is microseconds on a healthy host; the budget only
# binds the WEDGED-tracer case (a dead tracer delivers EOF instantly),
# so it trades wedge-detection latency against false kills on a badly
# stalled host. 15s matches the spawn lane's tracer-ready deadline —
# the two lanes fail the same way at the same threshold; a shorter
# value here previously bought nothing but a 3x-earlier misdiagnosis
# window on loaded CI hosts.
_TRACER_READY_TIMEOUT_S = 15.0

# How long to wait for the tracer to exit on its own after the target
# is reaped. A healthy tracer exits promptly once its last tracee is
# gone (it only appends the end-of-run summary record first); a wedged
# tracer must never hang the spawn parent, so the reap escalates to
# _kill_and_reap after this grace.
_TRACER_REAP_TIMEOUT_S = 5.0

# How long the stdio drain loop waits in one select() before
# re-checking that the target is still alive. Idle ticks are NOT
# treated as EOF — see _drain_pipes_until_eof.
_DRAIN_IDLE_POLL_S = 30.0

# Per-fd accumulation bound for _drain_pipes_until_eof. Audit pipes
# carry JSONL event records — 32 MiB is orders of magnitude above any
# legitimate run while keeping a hostile writer from ballooning the
# parent's memory.
_DRAIN_MAX_BYTES_PER_FD = 32 * 1024 * 1024

# Budget for the post-target-exit final sweep. Normally the sweep ends
# at the first empty poll (already-buffered bytes only), but a
# grandchild that inherited the write end and keeps writing can hold
# the pipe readable indefinitely — the sweep must not extend the run
# past the target's own lifetime by more than this.
_DRAIN_FINAL_SWEEP_S = 2.0

# Linux prctl(2) constants for PR_SET_PTRACER. Not in stdlib;
# duplicated here from the kernel headers.
_PR_SET_PTRACER = 0x59616d61
_PR_SET_PTRACER_ANY = 0xFFFFFFFFFFFFFFFF  # cast of (-1) to unsigned long


def _set_ptracer_any_in_child(libc: ctypes.CDLL | None) -> None:
    """``prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`` so a sibling
    tracer can attach under Yama scope 1.

    Linux's Yama LSM in scope 1 mode (default on Ubuntu / Debian /
    Fedora) only permits PTRACE_SEIZE on descendants of the tracer
    process. The audit tracer is a sibling here (both target and
    tracer are children of the parent), so the target must
    explicitly opt in to being traced by ``any`` process. Same
    approach the mount-ns spawn uses inside its preexec.

    ``libc`` is the CDLL handle resolved PRE-FORK by the parent
    (``run_landlock_audit``): this function runs in the forked target child,
    where ``ctypes.util.find_library("c")`` — which can shell out to
    /sbin/ldconfig — would be the banned fork-storm pattern (same
    parent-side capture as ``_spawn._parent_libc``).

    Failures are best-effort silent: ``libc is None`` (load failure)
    keeps the historic degrade; on hosts without Yama (older
    kernels, some containers) prctl returns EINVAL and ptrace
    works without this opt-in. If Yama IS the gate, the tracer's
    SEIZE will fail and the parent's diagnostic fires there.
    """
    if libc is None:
        return
    libc.prctl.argtypes = [
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.c_ulong, ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    libc.prctl(_PR_SET_PTRACER, _PR_SET_PTRACER_ANY, 0, 0, 0)


def _build_audit_config(
    *,
    audit_verbose: bool,
    observe_mode: bool,
    observe_nonce: str | None,
    writable_paths: Iterable[str],
    readable_paths: Iterable[str] | None,
    allowed_tcp_ports: Iterable[int] | None,
    output: str | None,
    target: str | None,
    restrict_reads: bool,
    evidence_fd: int | None = None,
) -> dict:
    """Construct the audit_config dict the tracer reads at startup.

    Mirrors the dict built in ``_spawn.run_sandboxed`` so the tracer
    sees the same shape regardless of which spawn path engaged it.
    Pinning is enforced by ``test_audit_filter.TestAuditConfigSchemaAgree``
    in the existing test suite.

    ``evidence_fd``: the held evidence fd the tracer inherits across
    its exec (see core/sandbox/evidence.py) — all tracer appends route
    through it so a path-level swap of the JSONL cannot redirect them.
    """
    import os.path as _osp

    from . import state as _state

    _writable: list = [_osp.abspath(p) for p in writable_paths or ()]
    if output:
        _writable.append(_osp.abspath(output))

    _system_ro = (
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/proc", "/sys",
    )
    _read_allow = list(_writable)
    _read_allow.extend(_osp.abspath(p) for p in readable_paths or ())
    _read_allow.extend(_system_ro)
    if target:
        _read_allow.append(_osp.abspath(target))

    return {
        "verbose": bool(audit_verbose),
        "writable_paths": _writable,
        "read_allowlist": (_read_allow if restrict_reads else None),
        "allowed_tcp_ports": list(allowed_tcp_ports)
            if allowed_tcp_ports else [],
        "audit_budget": getattr(
            _state, "_cli_sandbox_audit_budget", None,
        ),
        "observe_mode": bool(observe_mode),
        "observe_nonce": observe_nonce,
        "evidence_fd": evidence_fd,
    }


def _write_audit_config(audit_config: dict) -> int:
    """Serialise the audit-config dict into an anonymous fd; return it.

    F31: this used to be a ``/tmp/raptor-audit-cfg-*.json`` tempfile.
    On the Landlock-only path there are no namespaces — same UID,
    shared /tmp, and /tmp readable — so the target could glob the
    path and read the observe nonce inside. The config now lives in
    a memfd (Linux) / unlinked temp file (elsewhere): no filesystem
    path exists for the target to name. The caller passes the fd to
    the tracer as ``/proc/self/fd/N`` (cleared from CLOEXEC only for
    the TRACER's exec) and closes its own copy after the fork; the
    tracer closes the inherited fd right after parsing.

    sort_keys=True — deterministic serialisation: no consumer hashes
    or caches the config (nothing in the tree keys on its bytes),
    but stable key ordering keeps the fd contents byte-comparable
    across runs and interpreter dict-order changes, which matters
    for debugging and for any future consumer that DOES fingerprint
    it.
    """
    serialised = json.dumps(audit_config, sort_keys=True).encode("utf-8")
    return _evidence_mod.anonymous_fd(serialised)


def _close_safely(fd: int) -> None:
    """Close an fd, ignoring already-closed / -1 / EBADF cases."""
    if fd is None or fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _kill_and_reap(pid: int, timeout_s: float = 2.0) -> None:
    """Kill (TERM → KILL) and reap a child. Idempotent."""
    import time
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            return
        if done != 0:
            return
        time.sleep(0.02)
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        return
    try:
        os.waitpid(pid, 0)
    except (ChildProcessError, OSError):
        pass


def _drain_pipes_until_eof(
    fds: Iterable[int],
    target_pid: int,
    deadline: float | None = None,
) -> dict[int, bytes]:
    """Drain pipe fds until EOF on all of them, without deadlocking.

    A select() timeout is NOT EOF: the child may legitimately stay
    silent longer than one poll interval (long compile step, fuzz
    target between findings). Breaking on mere silence loses every
    later byte AND — when the caller passed ``timeout=None`` —
    deadlocks the parent/child pair: the parent proceeds to a
    blocking ``waitpid`` with the pipes never read again, while the
    child blocks writing to a full pipe buffer.

    We instead check whether the target is still alive via
    ``waitid(..., WNOWAIT)`` — which does NOT reap, so the caller's
    own ``waitpid`` still observes the exit status. The liveness probe
    runs on EVERY loop wake, not only on idle ticks and not on a time
    schedule: a grandchild that inherited the write end and writes
    continuously keeps ``select()`` non-empty forever, so an
    idle-branch-only probe never noticed the target's exit and a
    ``timeout=None`` run (legitimate callers exist — host.py) never
    finished draining; and a scheduled probe (one per poll interval)
    never fired at all when the caller's ``deadline`` was shorter
    than the interval, so a target that exited 0 immediately — its
    stdio held open by a backgrounded grandchild — broke out of the
    drain with its exit undetected. Draining stops when:

      * EOF is seen on every fd (normal case), or
      * ``deadline`` expires (caller kills the child and raises), or
      * the target has exited and the pipes have gone silent — a
        stray grandchild inherited the write end; don't wait for
        its EOF forever — or kept chattering past the bounded
        final sweep (``_DRAIN_FINAL_SWEEP_S``).

    Accumulation is byte-bounded per fd (``_DRAIN_MAX_BYTES_PER_FD``):
    a hostile or runaway child writing without limit must not OOM the
    parent. Past the cap the pipe is still READ — draining is what
    keeps the child from blocking on a full pipe buffer — but the
    bytes are discarded, with one warning per fd.

    Returns ``{fd: collected_bytes}``.
    """
    bufs: dict[int, list[bytes]] = {fd: [] for fd in fds}
    kept: dict[int, int] = dict.fromkeys(bufs, 0)
    truncated: set[int] = set()
    fds_open = set(bufs)
    target_exited = False
    sweep_deadline: float | None = None

    def _probe_target_exited() -> bool:
        try:
            res = os.waitid(
                os.P_PID, target_pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except (ChildProcessError, OSError):
            return True
        return res is not None

    while fds_open:
        # Liveness probe on EVERY wake (WNOWAIT — non-reaping and
        # cheap), not on a time schedule. The schedule (one probe per
        # _DRAIN_IDLE_POLL_S) had two starvation shapes: a
        # continuously-readable pipe starves the idle branch (the
        # 14d5c87c lesson — with timeout=None the idle probe was the
        # ONLY exit condition, so a chattering grandchild hung the
        # run forever after the target exited), and a caller deadline
        # SHORTER than the poll interval expired before the first
        # scheduled probe ever ran — the drain broke with the
        # target's exit unknown and a target that exited 0
        # immediately was reported as TimeoutExpired (its stdio held
        # open by a backgrounded grandchild). Probing per wake keeps
        # exit detection ahead of both the deadline and the chatter.
        if not target_exited and _probe_target_exited():
            target_exited = True
        # Enforce the caller's deadline on EVERY iteration, not only when
        # select() returns idle: a hostile target that keeps a pipe
        # continuously readable makes select() return non-empty each tick,
        # so control never entered the `if not ready:` branch below where
        # the deadline was previously the only checked (14d5c87c residual).
        # Skip while target_exited — the final sweep is a bounded, non-
        # blocking drain of already-buffered bytes and must not be cut.
        if (
            not target_exited
            and deadline is not None
            and time.monotonic() >= deadline
        ):
            break
        if target_exited and sweep_deadline is None:
            # Bounded final sweep: consume what the pipes still hold,
            # but a grandchild that KEEPS writing must not extend the
            # drain indefinitely — the run is over.
            sweep_deadline = time.monotonic() + _DRAIN_FINAL_SWEEP_S
        if target_exited:
            if (sweep_deadline is not None
                    and time.monotonic() >= sweep_deadline):
                logger.warning(
                    "audit drain: target exited but a grandchild kept "
                    "its stdio pipe busy past the %.1fs final sweep — "
                    "abandoning the remaining stream", _DRAIN_FINAL_SWEEP_S,
                )
                break
            # Final sweep: consume whatever is already buffered in
            # the pipes, but don't block for more.
            wait = 0.0
        else:
            wait = _DRAIN_IDLE_POLL_S
            if deadline is not None:
                wait = min(wait, max(0.0, deadline - time.monotonic()))
        ready, _, _ = select.select(list(fds_open), [], [], wait)
        if not ready:
            if target_exited:
                break
            if _probe_target_exited():
                # Probe BEFORE the deadline check: a target that
                # exited by the caller's deadline is an exit (drain
                # what's buffered, report its real status), not a
                # timeout.
                target_exited = True
                continue
            if deadline is not None and time.monotonic() >= deadline:
                break
            continue
        for fd in ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                fds_open.discard(fd)
                continue
            if chunk:
                room = _DRAIN_MAX_BYTES_PER_FD - kept[fd]
                if room > 0:
                    piece = chunk[:room]
                    bufs[fd].append(piece)
                    kept[fd] += len(piece)
                if len(chunk) > max(room, 0) and fd not in truncated:
                    truncated.add(fd)
                    logger.warning(
                        "audit pipe fd %d exceeded %d bytes; "
                        "further output discarded (still draining "
                        "to keep the child unblocked)",
                        fd, _DRAIN_MAX_BYTES_PER_FD,
                    )
            else:
                fds_open.discard(fd)
    return {fd: b"".join(chunks) for fd, chunks in bufs.items()}


def run_landlock_audit(
    cmd: list[str],
    *,
    audit_run_dir: str,
    audit_verbose: bool = False,
    observe_mode: bool = False,
    observe_nonce: str | None = None,
    writable_paths: Iterable[str] | None = None,
    readable_paths: Iterable[str] | None = None,
    allowed_tcp_ports: Iterable[int] | None = None,
    target: str | None = None,
    output: str | None = None,
    restrict_reads: bool = False,
    landlock_preexec=None,
    seccomp_preexec=None,
    rlimit_preexec=None,
    env: dict | None = None,
    cwd: str | None = None,
    timeout: float | None = None,
    capture_output: bool = True,
    text: bool = True,
    stdin=None,
    stdout=None,
    stderr=None,
    start_new_session: bool = True,
) -> subprocess.CompletedProcess:
    """Spawn ``cmd`` under Landlock + seccomp + ptrace tracer, no
    namespaces.

    Used when the host doesn't support unprivileged user-ns/mount-ns
    (Ubuntu 24.04+ default with AppArmor) but Landlock + ptrace +
    libseccomp work. Restores observe-mode signal that the bare
    ``subprocess.run`` fallback couldn't capture.

    Synchronisation: target child blocks on a sync pipe until the
    parent confirms the tracer has SEIZE'd it. Without this gate,
    the target's first traced syscall would fire SCMP_ACT_TRACE
    with no tracer attached → kernel SIGSYS-kills the process.

    Teardown containment on this lane is the tracer's
    PTRACE_O_EXITKILL. (The former ``install_death_fd=`` plumbing —
    the pid1-shim's orphan-teardown liveness pipe — was deleted with
    the unshare-CLI lane; ``cmd`` is always the bare target now.)

    Returns a CompletedProcess shaped to match subprocess.run's
    return value.
    """
    if not audit_run_dir:
        msg = (
            "run_landlock_audit requires audit_run_dir= so the "
            "tracer has a place to write the JSONL"
        )
        raise ValueError(msg)
    # F11: create the evidence JSONL up-front in <run_dir>/.audit/
    # (O_EXCL, held fd, inode recorded — see core/sandbox/evidence.py).
    # The tracer inherits the fd and appends through it.
    from .tracer import _resolve_output_filename as _out_name
    evidence_file = _evidence_mod.EvidenceFile.open(
        audit_run_dir, _out_name(bool(observe_mode)),
    )
    config_fd = -1
    try:
        audit_config = _build_audit_config(
            audit_verbose=audit_verbose,
            observe_mode=observe_mode,
            observe_nonce=observe_nonce,
            writable_paths=writable_paths or (),
            readable_paths=readable_paths,
            allowed_tcp_ports=allowed_tcp_ports,
            output=output,
            target=target,
            restrict_reads=restrict_reads,
            evidence_fd=evidence_file.fd,
        )
        config_fd = _write_audit_config(audit_config)
    except BaseException:
        evidence_file.close(verify=False)
        raise
    # argv spelling of the config fd — "self" resolves in the tracer.
    config_arg = _evidence_mod.fd_path(config_fd)

    # Sync pipes:
    #   p_go: parent → target ("tracer attached, proceed")
    #   t_ready: tracer → parent ("I'm attached")
    # Created under a guard: a mid-sequence failure (EMFILE) must not
    # leak the pipes already created, nor the evidence/config fds
    # opened above — the covering try below has not been entered yet.
    p_go_r = p_go_w = t_ready_r = t_ready_w = -1
    out_r = out_w = err_r = err_w = -1
    try:
        p_go_r, p_go_w = os.pipe()
        t_ready_r, t_ready_w = os.pipe()
        # The tracer subprocess inherits t_ready_w via execvpe →
        # mark inheritable (PEP 446 sets O_CLOEXEC by default).
        os.set_inheritable(t_ready_w, True)
        # Capture pipes (only when capture_output=True).
        if capture_output:
            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()
    except BaseException:
        for fd in (p_go_r, p_go_w, t_ready_r, t_ready_w,
                   out_r, out_w, err_r, err_w):
            _close_safely(fd)
        _close_safely(config_fd)
        evidence_file.close(verify=False)
        raise

    # env=None → scrubbed allowlist env, NOT the full host
    # environment (same contract as _spawn.run_sandboxed): the public
    # context.run() path always supplies an env, so this default only
    # serves direct callers — and an audited target must not inherit
    # ambient secrets (session credentials, cloud keys) because a
    # caller skipped the wrapper. This is the namespace-less lane,
    # where /proc-based exfil defences are weakest. env={} still
    # means an empty env. Resolved parent-side so the forked child
    # performs no post-fork imports.
    if env is None:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()

    # libc handle resolved PRE-FORK for the target child's
    # PR_SET_PTRACER opt-in: find_library("c") can shell out to
    # /sbin/ldconfig, and spawning a subprocess from the forked child
    # of this multi-threaded parent is the banned fork-storm pattern
    # (same parent-side capture as _spawn._parent_libc). None → the
    # child degrades best-effort silent, exactly as the load-failure
    # branch always did.
    _parent_libc: ctypes.CDLL | None = None
    with contextlib.suppress(OSError, AttributeError):
        _parent_libc = ctypes.CDLL(
            ctypes.util.find_library("c") or "libc.so.6",
            use_errno=True,
        )

    target_pid = -1
    tracer_pid = -1
    def _cleanup_fds() -> None:
        nonlocal p_go_r, p_go_w, t_ready_r, t_ready_w
        nonlocal out_r, out_w, err_r, err_w
        for fd in (p_go_r, p_go_w, t_ready_r, t_ready_w,
                   out_r, out_w, err_r, err_w):
            _close_safely(fd)
        p_go_r = p_go_w = t_ready_r = t_ready_w = -1
        out_r = out_w = err_r = err_w = -1

    try:
        # ----- Fork the target -----
        # (fork-warning suppression is the module-level filter above)
        target_pid = os.fork()

        if target_pid == 0:
            # ============== TARGET CHILD ==============
            # Close the pipe ends we don't use; keep p_go_r (we
            # read from it) and the capture write ends.
            _close_safely(p_go_w)
            _close_safely(t_ready_r)
            _close_safely(t_ready_w)
            # The guard starts HERE, before the stdio plumbing: a
            # dup2/fileno failure (e.g. a caller-supplied stdin
            # object whose fileno() raises ValueError — the closed-
            # file shape; the inner handler catches only
            # AttributeError/OSError) would otherwise unwind the
            # FORKED child through this function's finally (running
            # _cleanup_fds + evidence close in BOTH processes) and
            # on into the caller's stack — the classic forked-
            # child-runs-parent-code double execution _spawn's
            # child guard already refuses.
            try:
                if capture_output:
                    _close_safely(out_r)
                    _close_safely(err_r)
                    try:
                        os.dup2(out_w, 1)
                        os.dup2(err_w, 2)
                    finally:
                        _close_safely(out_w)
                        _close_safely(err_w)
                else:
                    # stdout=/stderr= redirects (int fd, file-like,
                    # DEVNULL, STDOUT for stderr). Same shape as
                    # _spawn's mount-ns child: pre-fix these kwargs
                    # were silently DROPPED on this lane — the child
                    # inherited the parent's fd 1/2 regardless, which
                    # also defeated run_untrusted's write-only tty
                    # reopen (the child kept the O_RDWR pty slave and
                    # could read() the operator's keystrokes through
                    # its own stdout). PIPE is unsupported here, same
                    # as stdin: fail closed to /dev/null with a
                    # stderr note.
                    for _redir, _fdnum, _label in ((stdout, 1,
                                                    b"stdout"),
                                                   (stderr, 2,
                                                    b"stderr")):
                        if _redir is None:
                            continue
                        if _redir == subprocess.PIPE:
                            with contextlib.suppress(OSError):
                                os.write(2, b"sandbox: %s=subprocess."
                                            b"PIPE not supported via "
                                            b"the Landlock-audit path;"
                                            b" falling back to "
                                            b"/dev/null.\n" % _label)
                            _redir = subprocess.DEVNULL
                        if _redir == subprocess.DEVNULL:
                            _dn = os.open("/dev/null", os.O_WRONLY)
                            os.dup2(_dn, _fdnum)
                            os.close(_dn)
                            continue
                        if _fdnum == 2 and _redir == subprocess.STDOUT:
                            os.dup2(1, 2)
                            continue
                        _rfd = (_redir if isinstance(_redir, int)
                                else _redir.fileno())
                        if _rfd != _fdnum:
                            os.dup2(_rfd, _fdnum)
                # stdin: caller-supplied or /dev/null. Same shape as
                # _spawn for parity (no PIPE on this path; that's a
                # caller-side construct that wouldn't survive exec).
                _use_devnull = (
                    stdin is None or stdin in (subprocess.DEVNULL, subprocess.PIPE)
                )
                if _use_devnull:
                    try:
                        devnull = os.open("/dev/null", os.O_RDONLY)
                        os.dup2(devnull, 0)
                        os.close(devnull)
                    except OSError:
                        pass
                else:
                    try:
                        stdin_fd = (stdin if isinstance(stdin, int)
                                    else stdin.fileno())
                        os.dup2(stdin_fd, 0)
                        if stdin_fd != 0:
                            _close_safely(stdin_fd)
                    except (AttributeError, OSError):
                        try:
                            devnull = os.open("/dev/null", os.O_RDONLY)
                            os.dup2(devnull, 0)
                            os.close(devnull)
                        except OSError:
                            pass

                if start_new_session:
                    try:
                        os.setsid()
                    except OSError:
                        pass

                # cwd
                if cwd is not None:
                    try:
                        os.chdir(cwd)
                    except OSError:
                        os._exit(126)

                # rlimits + ptracer-any
                if rlimit_preexec is not None:
                    rlimit_preexec()
                _set_ptracer_any_in_child(_parent_libc)

                # Block until parent says tracer is attached.
                byte = os.read(p_go_r, 1)
                _close_safely(p_go_r)
                if byte != b"G":
                    os._exit(125)

                # Full fd sweep before handing control to the
                # UNTRUSTED target. PEP 446 makes Python-opened fds
                # CLOEXEC by default, but fds inherited from C
                # extensions or opened with closefd tricks are not
                # guaranteed; relying on CLOEXEC alone leaves the
                # target a window onto whatever the parent had open.
                # Nothing needs to survive this exec except stdio.
                # Enumerate the ACTUALLY-open fds instead of sweeping
                # a range bounded by RLIMIT_NOFILE: rlimit_preexec
                # above already LOWERED that limit, and lowering
                # NOFILE does not invalidate existing descriptors — a
                # non-CLOEXEC fd numbered at/above the reduced soft
                # limit survived the old range-based sweep and rode
                # the exec into the target as an out-of-policy
                # capability (same shape _spawn's grandchild sweep
                # closes). Fall back to the bounded range only when
                # /proc isn't listable.
                _soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
                try:
                    _open_fds = [int(_n)
                                 for _n in os.listdir("/proc/self/fd")]
                except (OSError, ValueError):
                    _open_fds = list(range(3, min(_soft, 65536)))
                for _fd in _open_fds:
                    if _fd > 2:
                        try:
                            os.close(_fd)
                        except OSError:
                            pass

                # Apply Landlock then seccomp(audit). Ordering:
                # Landlock first (filesystem isolation in place),
                # then seccomp with TRACE action — every traced
                # syscall now hits the (already-attached) tracer.
                if landlock_preexec is not None:
                    landlock_preexec()
                if seccomp_preexec is not None:
                    seccomp_preexec()

                # Exec target. env was resolved parent-side: the
                # caller's dict verbatim (including {} = empty env),
                # or the scrubbed allowlist when the caller passed
                # None — never the full parent environment.
                os.execvpe(cmd[0], list(cmd), env)
            except FileNotFoundError:
                os._exit(127)
            except PermissionError:
                os._exit(126)
            except BaseException:  # noqa: BLE001 — post-fork guard; any failure must become an exit code, never a traceback in the child (BaseException: even SystemExit must not unwind the fork)
                os._exit(125)

        # ============== PARENT after target fork ==============
        # Close the read end of go-pipe and capture-write ends —
        # the target owns them now.
        _close_safely(p_go_r)
        p_go_r = -1
        if capture_output:
            _close_safely(out_w)
            out_w = -1
            _close_safely(err_w)
            err_w = -1

        # ----- Fork the tracer -----
        tracer_pid = os.fork()

        if tracer_pid == 0:
            # ============== TRACER CHILD ==============
            # Close every inherited fd except stdio + t_ready_w.
            try:
                soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                upper = min(soft, 65536)
                # Keep the sync write end, the anonymous config fd,
                # and the held evidence fd; closerange over the gaps.
                _keep = sorted(
                    fd for fd in (t_ready_w, config_fd, evidence_file.fd)
                    if fd is not None and 3 <= fd < upper
                )
                _lo = 3
                for _k in _keep:
                    os.closerange(_lo, _k)
                    _lo = _k + 1
                os.closerange(_lo, upper)
                # Clear CLOEXEC on config + evidence fds for the
                # TRACER's exec only — the target child's exec keeps
                # the default close-on-exec, so neither fd ever
                # reaches the target's fd table.
                if config_fd >= 0:
                    os.set_inheritable(config_fd, True)
                os.set_inheritable(evidence_file.fd, True)
                raptor_dir = os.environ.get("RAPTOR_DIR")
                if raptor_dir is None:
                    raptor_dir = str(
                        Path(__file__).resolve().parent.parent.parent
                    )
                tracer_env = {
                    "PYTHONPATH": raptor_dir,
                    "PATH": "/usr/bin:/bin",
                }
                tracer_argv = [
                    sys.executable, "-m", "core.sandbox.tracer",
                    str(target_pid), str(audit_run_dir),
                    str(t_ready_w), config_arg,
                ]
                # tracer_env is a hand-crafted dict with 2 keys only
                # (PYTHONPATH + PATH). No inheritance — strictly
                # safer than the default os.environ-copy path.
                # nosemgrep: python.lang.security.audit.dangerous-os-exec-tainted-env-args.dangerous-os-exec-tainted-env-args
                os.execvpe(sys.executable, tracer_argv, tracer_env)
            except FileNotFoundError:
                os._exit(127)
            except PermissionError:
                os._exit(126)
            except BaseException:  # noqa: BLE001 — post-fork guard; any failure must become an exit code, never a traceback in the child (BaseException: even SystemExit must not unwind the fork)
                os._exit(125)

        # ============== PARENT after tracer fork ==============
        # Parent doesn't keep the tracer's signalling write end;
        # without closing it the read below would never see EOF
        # if the tracer dies before signalling.
        _close_safely(t_ready_w)
        t_ready_w = -1
        # Drop our copy of the anonymous config fd — the tracer holds
        # its own inherited copy (closed right after parsing). This
        # minimises the window in which /proc/<parent-pid>/fd exposes
        # the nonce-carrying config to same-UID processes.
        _close_safely(config_fd)
        config_fd = -1

        # Wait for tracer to signal ready (or die).
        ready = b""
        ready_timed_out = False
        try:
            rlist, _, _ = select.select([t_ready_r], [], [], _TRACER_READY_TIMEOUT_S)
            if rlist:
                ready = os.read(t_ready_r, 1)
            else:
                ready_timed_out = True
        finally:
            _close_safely(t_ready_r)
            t_ready_r = -1
        if not ready:
            # Tracer failed before signalling. Reap it for diag,
            # kill the still-blocked target, raise. On the deadline
            # path the tracer may still be ALIVE but wedged (import
            # stall, PTRACE_SEIZE hang, SIGSTOP) — kill it FIRST so
            # the diagnostic waitpid cannot block forever (mirrors
            # _spawn's kill-first twin; pre-fix one wedged tracer
            # parked this parent in an unbounded blocking waitpid,
            # with the target child parked on its go-pipe for the
            # same duration and the caller's timeout= never engaged
            # — the deadline is computed after this handshake).
            if ready_timed_out:
                with contextlib.suppress(ProcessLookupError, OSError):
                    os.kill(tracer_pid, 9)
            tracer_status = None
            try:
                _, tracer_status = os.waitpid(tracer_pid, 0)
            except (ChildProcessError, OSError):
                pass
            finally:
                tracer_pid = -1
            # _kill_and_reap handles the expected cases internally;
            # what escapes is OSError (PermissionError when the pid
            # was recycled to a foreign process).
            with contextlib.suppress(OSError):
                _kill_and_reap(target_pid)
                target_pid = -1
            rc_hint = ""
            if (tracer_status is not None
                    and os.WIFEXITED(tracer_status)):
                rc_hint = (
                    f" (tracer exit code "
                    f"{os.WEXITSTATUS(tracer_status)})"
                )
            if ready_timed_out:
                # We SIGKILLed it ourselves above; a signal/exit-code
                # diagnostic would misattribute that.
                cause = (
                    f"tracer did not signal ready within the "
                    f"{_TRACER_READY_TIMEOUT_S:g}s deadline (wedged "
                    f"during attach or a badly stalled host) — killed"
                )
                rc_hint = ""
            else:
                cause = (
                    "likely PTRACE_SEIZE rejected (Yama scope, "
                    "container cap-drop, AppArmor)"
                )
            msg = (
                f"audit-mode tracer failed to attach to sandboxed "
                f"child{rc_hint} — {cause}"
            )
            raise RuntimeError(msg)

        # Tracer attached. Tell the target it can proceed.
        try:
            os.write(p_go_w, b"G")
        finally:
            _close_safely(p_go_w)
            p_go_w = -1

        # Drain both stdio pipes concurrently to avoid deadlock when
        # the child fills one pipe buffer while we block reading the
        # other. The deadline is computed HERE so the caller's timeout
        # bounds the whole drain+wait, not just the post-drain wait.
        deadline = (
            time.monotonic() + timeout if timeout is not None else None
        )
        stdout_bytes = stderr_bytes = b""
        if capture_output:
            drained = _drain_pipes_until_eof(
                (out_r, err_r), target_pid, deadline,
            )
            stdout_bytes = drained[out_r]
            stderr_bytes = drained[err_r]
            _close_safely(out_r)
            out_r = -1
            _close_safely(err_r)
            err_r = -1

        # waitpid the target. The reap attempt comes FIRST on every
        # iteration — deadline expiry is only checked after a WNOHANG
        # found the target still running, so a target that already
        # exited is NEVER reported as a timeout even when the drain
        # above consumed the whole budget (grandchild-held stdio kept
        # the pipes open past the deadline while the target itself
        # exited 0 long before). Mirrors _spawn's exited-target
        # exemption ("never call an exited-0 target a timeout").
        target_rc = -1
        if deadline is not None:
            while True:
                try:
                    done, status = os.waitpid(target_pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    target_pid = -1
                    target_rc = -1
                    break
                if done != 0:
                    if os.WIFEXITED(status):
                        target_rc = os.WEXITSTATUS(status)
                    elif os.WIFSIGNALED(status):
                        target_rc = -os.WTERMSIG(status)
                    target_pid = -1
                    break
                if time.monotonic() >= deadline:
                    # Genuinely still running past the deadline —
                    # kill, then re-wait, then raise.
                    _kill_and_reap(target_pid)
                    target_pid = -1
                    # Tracer is PTRACE_O_EXITKILL'd — should die soon.
                    if tracer_pid > 0:
                        _kill_and_reap(tracer_pid)
                        tracer_pid = -1
                    raise subprocess.TimeoutExpired(
                        cmd=list(cmd), timeout=timeout,
                        output=stdout_bytes if text is False else (
                            stdout_bytes.decode(errors="replace")
                        ),
                        stderr=stderr_bytes if text is False else (
                            stderr_bytes.decode(errors="replace")
                        ),
                    )
                time.sleep(0.02)
        else:
            try:
                _, status = os.waitpid(target_pid, 0)
                if os.WIFEXITED(status):
                    target_rc = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    target_rc = -os.WTERMSIG(status)
            except (ChildProcessError, OSError):
                pass
            finally:
                target_pid = -1

        # Reap the tracer — bounded. A healthy tracer exits promptly
        # once its last tracee is gone (should be fast), but a wedged
        # tracer must never convert into an indefinite parent hang:
        # after _TRACER_REAP_TIMEOUT_S escalate to TERM → KILL.
        if tracer_pid > 0:
            reap_deadline = time.monotonic() + _TRACER_REAP_TIMEOUT_S
            while time.monotonic() < reap_deadline:
                try:
                    done, _ = os.waitpid(tracer_pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    break
                if done != 0:
                    break
                time.sleep(0.02)
            else:
                logger.warning(
                    "landlock-audit: tracer (pid %d) still alive %.1fs "
                    "after target exit; killing it (observe/audit "
                    "records may be truncated)",
                    tracer_pid, _TRACER_REAP_TIMEOUT_S,
                )
                _kill_and_reap(tracer_pid)
            tracer_pid = -1

        # Marshal output to the requested type.
        if text:
            stdout_out = stdout_bytes.decode(errors="replace")
            stderr_out = stderr_bytes.decode(errors="replace")
        else:
            stdout_out = stdout_bytes
            stderr_out = stderr_bytes

        # Finalise the evidence file now that both children are
        # reaped: verify the on-disk path still names the inode
        # created at spawn time (loud warning on a swap), close the
        # fd, and PROPAGATE the verdict on the result instead of
        # discarding it — consumers deciding whether to trust the
        # on-disk JSONL (observe parsing, triage) can check
        # ``getattr(result, "evidence_verified", True)`` rather than
        # having to scrape the process log for the tamper warning.
        # The finally-block close below becomes an idempotent no-op.
        evidence_ok = evidence_file.close()
        result = subprocess.CompletedProcess(
            args=list(cmd),
            returncode=target_rc,
            stdout=stdout_out if capture_output else None,
            stderr=stderr_out if capture_output else None,
        )
        result.evidence_verified = evidence_ok
        return result
    finally:
        _cleanup_fds()
        # _kill_and_reap only escapes with OSError (PermissionError on
        # pid recycle); everything else it handles internally.
        if target_pid > 0:
            with contextlib.suppress(OSError):
                _kill_and_reap(target_pid)
        if tracer_pid > 0:
            with contextlib.suppress(OSError):
                _kill_and_reap(tracer_pid)
        # Release the anonymous config fd (normally already closed
        # right after the tracer fork; covers early-exit paths).
        _close_safely(config_fd)
        # Finalise the evidence file (idempotent — the normal-return
        # path already closed with verification; this covers
        # exception paths, where verify() still logs loudly).
        evidence_file.close()
