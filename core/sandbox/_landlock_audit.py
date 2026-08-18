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
import json
import logging
import os
import select
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

from . import evidence as _evidence_mod

logger = logging.getLogger(__name__)


# Default tracer-ready timeout. The tracer's PTRACE_SEIZE +
# SETOPTIONS dance is microseconds on a healthy host; allow 5s
# to absorb pathological scheduler stalls (CI under heavy load).
_TRACER_READY_TIMEOUT_S = 5.0

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

# Linux prctl(2) constants for PR_SET_PTRACER. Not in stdlib;
# duplicated here from the kernel headers.
_PR_SET_PTRACER = 0x59616d61
_PR_SET_PTRACER_ANY = 0xFFFFFFFFFFFFFFFF  # cast of (-1) to unsigned long


def _set_ptracer_any_in_child() -> None:
    """``prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`` so a sibling
    tracer can attach under Yama scope 1.

    Linux's Yama LSM in scope 1 mode (default on Ubuntu / Debian /
    Fedora) only permits PTRACE_SEIZE on descendants of the tracer
    process. The audit tracer is a sibling here (both target and
    tracer are children of the parent), so the target must
    explicitly opt in to being traced by ``any`` process. Same
    approach the mount-ns spawn uses inside its preexec.

    Failures are best-effort silent: on hosts without Yama (older
    kernels, some containers) prctl returns EINVAL and ptrace
    works without this opt-in. If Yama IS the gate, the tracer's
    SEIZE will fail and the parent's diagnostic fires there.
    """
    import ctypes
    import ctypes.util
    _libc_name = ctypes.util.find_library("c")
    if not _libc_name:
        return
    libc = ctypes.CDLL(_libc_name, use_errno=True)
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

    _writable: list = []
    for p in (writable_paths or ()):
        _writable.append(_osp.abspath(p))
    if output:
        _writable.append(_osp.abspath(output))

    _system_ro = (
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/proc", "/sys",
    )
    _read_allow = list(_writable)
    for p in (readable_paths or ()):
        _read_allow.append(_osp.abspath(p))
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

    sort_keys=True — the serialised audit config is hashed elsewhere
    for cache lookups and reproducibility. Without stable key
    ordering, dict-rebuild order changes (across Python versions /
    interpreter restarts) would break the cache identity contract.
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

    On each idle tick we instead check whether the target is still
    alive via ``waitid(..., WNOWAIT)`` — which does NOT reap, so the
    caller's own ``waitpid`` still observes the exit status.
    Draining stops when:

      * EOF is seen on every fd (normal case), or
      * ``deadline`` expires (caller kills the child and raises), or
      * the target has exited and the pipes have gone silent — a
        stray grandchild inherited the write end; don't wait for
        its EOF forever.

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
    while fds_open:
        if target_exited:
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
            if deadline is not None and time.monotonic() >= deadline:
                break
            try:
                res = os.waitid(
                    os.P_PID, target_pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except (ChildProcessError, OSError):
                break
            if res is not None:
                target_exited = True
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

    Returns a CompletedProcess shaped to match subprocess.run's
    return value.
    """
    if not audit_run_dir:
        raise ValueError(
            "run_landlock_audit requires audit_run_dir= so the "
            "tracer has a place to write the JSONL"
        )

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
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            target_pid = os.fork()

        if target_pid == 0:
            # ============== TARGET CHILD ==============
            # Close the pipe ends we don't use; keep p_go_r (we
            # read from it) and the capture write ends.
            _close_safely(p_go_w)
            _close_safely(t_ready_r)
            _close_safely(t_ready_w)
            if capture_output:
                _close_safely(out_r)
                _close_safely(err_r)
                try:
                    os.dup2(out_w, 1)
                    os.dup2(err_w, 2)
                finally:
                    _close_safely(out_w)
                    _close_safely(err_w)
            # stdin: caller-supplied or /dev/null. Same shape as
            # _spawn for parity (no PIPE on this path; that's a
            # caller-side construct that wouldn't survive exec).
            _use_devnull = (
                stdin is None
                or stdin == subprocess.DEVNULL
                or stdin == subprocess.PIPE
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
            try:
                if rlimit_preexec is not None:
                    rlimit_preexec()
                _set_ptracer_any_in_child()

                # Block until parent says tracer is attached.
                byte = os.read(p_go_r, 1)
                _close_safely(p_go_r)
                if byte != b"G":
                    os._exit(125)

                # Full fd-range sweep before handing control to the
                # UNTRUSTED target — parity with the tracer child's
                # sweep above. PEP 446 makes Python-opened fds CLOEXEC
                # by default, but fds inherited from C extensions or
                # opened with closefd tricks are not guaranteed;
                # relying on CLOEXEC alone leaves the target a window
                # onto whatever the parent had open. Nothing needs to
                # survive this exec except stdio.
                import resource as _resource
                _soft, _ = _resource.getrlimit(_resource.RLIMIT_NOFILE)
                os.closerange(3, min(_soft, 65536))

                # Apply Landlock then seccomp(audit). Ordering:
                # Landlock first (filesystem isolation in place),
                # then seccomp with TRACE action — every traced
                # syscall now hits the (already-attached) tracer.
                if landlock_preexec is not None:
                    landlock_preexec()
                if seccomp_preexec is not None:
                    seccomp_preexec()

                # Exec target. env=None → inherit parent's; env={} →
                # empty env. subprocess.run uses None-sentinel for
                # inherit; we honour the same.
                if env is None:
                    os.execvp(cmd[0], list(cmd))
                else:
                    os.execvpe(cmd[0], list(cmd), env)
            except FileNotFoundError:
                os._exit(127)
            except PermissionError:
                os._exit(126)
            except Exception:  # noqa: BLE001 — post-fork guard; any failure must become an exit code, never a traceback in the child
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
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            tracer_pid = os.fork()

        if tracer_pid == 0:
            # ============== TRACER CHILD ==============
            # Close every inherited fd except stdio + t_ready_w.
            try:
                import resource as _resource
                soft, _hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
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
            except Exception:  # noqa: BLE001 — post-fork guard; any failure must become an exit code, never a traceback in the child
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
        try:
            rlist, _, _ = select.select([t_ready_r], [], [], _TRACER_READY_TIMEOUT_S)
            if rlist:
                ready = os.read(t_ready_r, 1)
        finally:
            _close_safely(t_ready_r)
            t_ready_r = -1
        if not ready:
            # Tracer failed before signalling. Reap it for diag,
            # kill the still-blocked target, raise.
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
            raise RuntimeError(
                f"audit-mode tracer failed to attach to sandboxed "
                f"child{rc_hint} — likely PTRACE_SEIZE rejected "
                f"(Yama scope, container cap-drop, AppArmor)"
            )

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

        # waitpid the target.
        target_rc = -1
        if deadline is not None:
            while time.monotonic() < deadline:
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
                time.sleep(0.02)
            else:
                # Timed out — kill, then re-wait, then raise.
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

        return subprocess.CompletedProcess(
            args=list(cmd),
            returncode=target_rc,
            stdout=stdout_out if capture_output else None,
            stderr=stderr_out if capture_output else None,
        )
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
        # Finalise the evidence file AFTER both children are gone:
        # verify the on-disk path still names the inode created at
        # spawn time (loud warning on a swap), then close the fd.
        evidence_file.close()
