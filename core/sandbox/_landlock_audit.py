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
  * passes the same audit-config tempfile so observe records carry
    the per-run nonce + observe-stamp the parser validates.

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

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional


logger = logging.getLogger(__name__)


# Default tracer-ready timeout. The tracer's PTRACE_SEIZE +
# SETOPTIONS dance is microseconds on a healthy host; allow 5s
# to absorb pathological scheduler stalls (CI under heavy load).
_TRACER_READY_TIMEOUT_S = 5.0

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
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
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
    observe_nonce: Optional[str],
    writable_paths: Iterable[str],
    readable_paths: Optional[Iterable[str]],
    allowed_tcp_ports: Optional[Iterable[int]],
    output: Optional[str],
    target: Optional[str],
    restrict_reads: bool,
) -> dict:
    """Construct the audit_config dict the tracer reads at startup.

    Mirrors the dict built in ``_spawn.run_sandboxed`` so the tracer
    sees the same shape regardless of which spawn path engaged it.
    Pinning is enforced by ``test_audit_filter.TestAuditConfigSchemaAgree``
    in the existing test suite.
    """
    from . import state as _state
    import os.path as _osp

    _writable: list = []
    for p in (writable_paths or ()):
        _writable.append(_osp.abspath(p))
    _writable.append("/tmp")
    if output:
        _writable.append(_osp.abspath(output))

    _system_ro = (
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/proc", "/sys",
    )
    _read_allow = list(_writable)
    for p in (readable_paths or ()):
        _read_allow.append(_osp.abspath(p))
    for p in _system_ro:
        _read_allow.append(p)
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
    }


def _write_audit_config(audit_config: dict) -> str:
    """Persist the audit-config dict to /tmp; return path.

    Tempfile lives outside any sandbox view (random suffix in /tmp;
    targets see /tmp via the system_ro list but cannot guess the
    suffix). The nonce inside is therefore not readable by the
    target, defeating spoofs by record-content forgery.
    """
    fd, path = tempfile.mkstemp(
        prefix="raptor-audit-cfg-", suffix=".json",
    )
    serialised = json.dumps(audit_config).encode("utf-8")
    try:
        written = 0
        while written < len(serialised):
            n = os.write(fd, serialised[written:])
            if n <= 0:
                raise OSError(
                    "audit-config write returned 0 bytes — "
                    "filesystem full or read-only"
                )
            written += n
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return path


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


def _read_to_eof(fd: int, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    """Read from `fd` until EOF or `max_bytes`; returns the bytes.

    Bounded so a runaway child can't OOM the parent. Cap is
    generous (16 MiB) for most workloads; over-cap callers should
    use stdin/stdout passthrough (capture_output=False).
    """
    chunks: List[bytes] = []
    total = 0
    while total < max_bytes:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def run_landlock_audit(
    cmd: List[str],
    *,
    audit_run_dir: str,
    audit_verbose: bool = False,
    observe_mode: bool = False,
    observe_nonce: Optional[str] = None,
    writable_paths: Optional[Iterable[str]] = None,
    readable_paths: Optional[Iterable[str]] = None,
    allowed_tcp_ports: Optional[Iterable[int]] = None,
    target: Optional[str] = None,
    output: Optional[str] = None,
    restrict_reads: bool = False,
    landlock_preexec=None,
    seccomp_preexec=None,
    rlimit_preexec=None,
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
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
    )
    config_path = _write_audit_config(audit_config)

    # Sync pipes:
    #   p_go: parent → target ("tracer attached, proceed")
    #   t_ready: tracer → parent ("I'm attached")
    p_go_r, p_go_w = os.pipe()
    t_ready_r, t_ready_w = os.pipe()
    # The tracer subprocess inherits t_ready_w via execvpe →
    # mark inheritable (PEP 446 sets O_CLOEXEC by default).
    os.set_inheritable(t_ready_w, True)

    # Capture pipes (only when capture_output=True).
    if capture_output:
        out_r, out_w = os.pipe()
        err_r, err_w = os.pipe()
    else:
        out_r = out_w = err_r = err_w = -1

    target_pid = -1
    tracer_pid = -1
    parent_owned_fds = [
        p_go_r, p_go_w, t_ready_r, t_ready_w,
        out_r, out_w, err_r, err_w,
    ]

    def _cleanup_fds() -> None:
        for fd in parent_owned_fds:
            _close_safely(fd)

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
            except Exception:
                os._exit(125)

        # ============== PARENT after target fork ==============
        # Close the read end of go-pipe and capture-write ends —
        # the target owns them now.
        _close_safely(p_go_r); p_go_r = -1
        if capture_output:
            _close_safely(out_w); out_w = -1
            _close_safely(err_w); err_w = -1

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
                # Two ranges around t_ready_w.
                if 3 <= t_ready_w < upper:
                    os.closerange(3, t_ready_w)
                    os.closerange(t_ready_w + 1, upper)
                else:
                    os.closerange(3, upper)
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
                    str(t_ready_w), config_path,
                ]
                os.execvpe(sys.executable, tracer_argv, tracer_env)
            except FileNotFoundError:
                os._exit(127)
            except PermissionError:
                os._exit(126)
            except Exception:
                os._exit(125)

        # ============== PARENT after tracer fork ==============
        # Parent doesn't keep the tracer's signalling write end;
        # without closing it the read below would never see EOF
        # if the tracer dies before signalling.
        _close_safely(t_ready_w); t_ready_w = -1

        # Wait for tracer to signal ready (or die).
        ready = b""
        try:
            ready = os.read(t_ready_r, 1)
        finally:
            _close_safely(t_ready_r); t_ready_r = -1
        if not ready:
            # Tracer failed before signalling. Reap it for diag,
            # kill the still-blocked target, raise.
            tracer_status = None
            try:
                _, tracer_status = os.waitpid(tracer_pid, 0)
                tracer_pid = -1
            except (ChildProcessError, OSError):
                pass
            try:
                _kill_and_reap(target_pid)
                target_pid = -1
            except Exception:
                pass
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
            _close_safely(p_go_w); p_go_w = -1

        # Drain stdio capture pipes while waiting for target exit.
        # Simple sequential read since we don't expect huge stderr
        # interleaved with stdout in the cc_profile / probe use
        # cases. If a downstream consumer ever pumps GBs through
        # stdout, switch to selectors.
        stdout_bytes = stderr_bytes = b""
        if capture_output:
            try:
                stdout_bytes = _read_to_eof(out_r)
            finally:
                _close_safely(out_r); out_r = -1
            try:
                stderr_bytes = _read_to_eof(err_r)
            finally:
                _close_safely(err_r); err_r = -1

        # waitpid the target.
        target_rc = -1
        if timeout is not None:
            import time
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    done, status = os.waitpid(target_pid, os.WNOHANG)
                except (ChildProcessError, OSError):
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
                target_pid = -1
                if os.WIFEXITED(status):
                    target_rc = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    target_rc = -os.WTERMSIG(status)
            except (ChildProcessError, OSError):
                pass

        # Reap the tracer (PTRACE_O_EXITKILL means it exits when
        # the target's pid leaves; should be fast).
        if tracer_pid > 0:
            try:
                os.waitpid(tracer_pid, 0)
                tracer_pid = -1
            except (ChildProcessError, OSError):
                pass

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
        if target_pid > 0:
            try:
                _kill_and_reap(target_pid)
            except Exception:
                pass
        if tracer_pid > 0:
            try:
                _kill_and_reap(tracer_pid)
            except Exception:
                pass
        try:
            os.unlink(config_path)
        except OSError:
            pass
