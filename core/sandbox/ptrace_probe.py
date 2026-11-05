"""Detect whether the current process can ptrace its own children.

Foundation for `--audit` modes b2 (syscall audit via SCMP_ACT_TRACE)
and b3 (filesystem audit via syscall interception). Both depend on the
parent being able to PTRACE_SEIZE / PTRACE_TRACEME-with-its-own-children.

What can block ptrace in a Linux environment:
- Yama scope 3 (`/proc/sys/kernel/yama/ptrace_scope == 3`) — disables all
  ptrace, including parent→own-child. Rare; default Ubuntu/Debian/Fedora
  is scope 1 which permits tracing one's own descendants.
- Container `--cap-drop SYS_PTRACE` — Docker default for non-privileged
  containers; widespread.
- Restrictive container seccomp profile — Docker's default profile permits
  ptrace but custom hardened profiles often don't.
- AppArmor / SELinux MAC policy — uncommon outside hardened distros.

The probe forks a sentinel child that calls `PTRACE_TRACEME` and SIGSTOPs
itself. The parent waits for the stop, attempts `PTRACE_CONT` to release
it, and observes whether the syscalls succeeded.

Cached per-process: ptrace availability is a function of the kernel +
container policy, both static across a single RAPTOR run.

**Fork-after-threads caveat.** This probe calls `os.fork()`. By the time
`check_ptrace_available()` is first invoked, the egress proxy daemon
thread (and possibly ThreadPoolExecutor workers) may already be running.
Python 3.12+ emits a DeprecationWarning for fork-after-threads-have-
started because any libc-internal mutex (e.g. malloc lock) held by
another thread at fork-time stays locked in the child with no thread
alive to release it — the child can deadlock if it touches the held
resource.

The probe mitigates this by: (a) caching aggressively (one probe per
process, never re-runs in production); (b) keeping the child code
syscall-only after fork (`libc.ptrace`, `os.kill`, `os._exit`) — no
malloc, no Python-runtime calls beyond the necessary ones. Tests
deliberately invalidate the cache to re-probe; that's the only path
that re-forks, and it runs single-threaded under pytest.

Mirrors the same trade-off as the Landlock probe; conftest snapshots
the relevant state for test isolation.

**Asyncio caveat.** The egress proxy runs an asyncio event loop on a
daemon thread. `os.fork()` from inside an asyncio loop is undefined
behaviour (selectors, file descriptors, callback state can all break).
The probe must be called from the main thread, NOT from inside the
proxy thread or any other coroutine context. In RAPTOR's lifecycle
the probe runs at startup before any sandbox is constructed, so this
constraint is satisfied automatically.

**Bounded parent waits.** Stop and exit share one monotonic deadline.
On failure or cancellation the parent kills its unreaped probe child
and waits within a separate cleanup budget. A cleanup timeout is logged
rather than indefinitely blocking sandbox startup. No process-global
signal timer or signal handler is installed.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import logging
import os
import signal
import time

from . import state

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_S = 5.0
_REAP_TIMEOUT_S = 5.0
_WAIT_POLL_S = 0.01

# ptrace request constants (see <sys/ptrace.h>)
_PTRACE_TRACEME = 0
_PTRACE_CONT = 7

# Probe-result cache lives on `state._ptrace_available_cache` so the
# conftest snapshot picks it up automatically alongside the rest of the
# sandbox state. Direct attribute access throughout (no getattr indirection)
# — matches the pattern used by check_net_available, check_mount_available,
# etc. in probes.py.


def _get_libc() -> ctypes.CDLL | None:
    """Resolve libc via find_library — same pattern as mount_ns.py.

    Returns None if libc is missing OR if the loaded libc lacks the
    `ptrace` symbol. The symbol check defends against stripped/custom
    libc builds where the binding isn't exported — without it, the
    subsequent `libc.ptrace(...)` call would raise AttributeError out
    of _run_probe instead of routing through the clean False-return
    path (which is the contract _run_probe promises).
    """
    libname = ctypes.util.find_library("c")
    if libname is None:
        return None
    try:
        libc = ctypes.CDLL(libname, use_errno=True)
    except OSError:
        return None
    if not hasattr(libc, "ptrace"):
        return None
    return libc


def check_ptrace_available() -> bool:
    """Probe whether parent can ptrace its own children in this environment.

    Forks a sentinel child that calls PTRACE_TRACEME and SIGSTOPs itself.
    Parent waits for the stop, attempts PTRACE_CONT, observes outcome.

    Returns True iff:
    - libc is available
    - the child's PTRACE_TRACEME succeeded (didn't return EPERM)
    - the parent's PTRACE_CONT succeeded
    - the child eventually exited cleanly

    Result is cached per-process. Logs a one-time WARNING when ptrace is
    unavailable so operators reaching for `--audit` know which
    layers (b2 syscall, b3 filesystem) will degrade.
    """
    if state._ptrace_available_cache is not None:
        return state._ptrace_available_cache

    with state._cache_lock:
        # Re-check inside the lock (double-checked locking pattern matches
        # the other probes in this package).
        if state._ptrace_available_cache is not None:
            return state._ptrace_available_cache

        # Fail-closed wrapper for unexpected probe errors (ctypes
        # signature drift, kernel API changes). Sandbox setup must NOT
        # crash on probe failure — degrade to "ptrace unavailable" and
        # continue, matching the rest of the sandbox's fail-closed
        # degradation pattern.
        try:
            result = _run_probe()
        except Exception:  # noqa: BLE001 — never break sandbox setup
            logger.debug("ptrace probe: _run_probe raised unexpectedly",
                         exc_info=True)
            result = False

        state._ptrace_available_cache = result  # type: ignore[assignment]

        if not result and state.warn_once("_ptrace_unavailable_warned"):
            logger.warning(
                "Sandbox: ptrace unavailable in this environment — "
                "`--audit` filesystem and syscall layers will "
                "degrade to off. Network audit (egress proxy log-mode) "
                "is unaffected. Likely causes: Yama scope 3 "
                "(kernel.yama.ptrace_scope=3), container --cap-drop "
                "SYS_PTRACE, or a restrictive container seccomp profile. "
                "Workarounds: run outside the container, or set "
                "kernel.yama.ptrace_scope=1."
            )

        return result


def _run_probe() -> bool:
    """Fork a sentinel child and verify PTRACE_TRACEME + PTRACE_CONT work.

    Separated from check_ptrace_available so the cache layer can be
    tested without forking. Expected OS failures return False;
    cancellation propagates after child cleanup.
    """
    libc = _get_libc()
    if libc is None:
        logger.debug("ptrace probe: libc not available via find_library")
        return False

    # ptrace returns long; declare to avoid pointer-truncation on 64-bit.
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int,
                            ctypes.c_void_p, ctypes.c_void_p]

    try:
        # Suppress Python 3.12+ DeprecationWarning about multi-threaded
        # fork(). The probe's post-fork code is fork-safe: child does
        # only bare libc syscalls (PTRACE_TRACEME, kill, _exit), no
        # Python objects, no GIL acquisition. See module docstring
        # "Fork-after-threads caveat" for the mitigation contract.
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            pid = os.fork()
    except OSError as e:
        logger.debug("ptrace probe: fork failed: %s", e)
        return False

    if pid == 0:
        # Child: ask to be traced, then SIGSTOP self so the parent has a
        # well-defined moment to act. If TRACEME is rejected, exit 1.
        # Use os._exit to skip atexit hooks — we're a probe-fork, not a
        # legitimate Python termination.
        #
        # Outer try/except: if libc.ptrace, os.kill, or any other call
        # raises an unexpected exception (ctypes signature mismatch on
        # a new arch, kernel API change), we want a clean os._exit(1)
        # — NOT a Python traceback printed to the operator's terminal
        # during sandbox setup. Use os.write(2, ...) for the diagnostic
        # because the Python logger isn't fork-safe.
        try:
            ctypes.set_errno(0)
            rc = libc.ptrace(_PTRACE_TRACEME, 0, None, None)
            if rc != 0:
                os._exit(1)
            # Stop self — the parent will see WIFSTOPPED and decide.
            os.kill(os.getpid(), signal.SIGSTOP)
            # If we get here, the parent successfully resumed us. Exit clean.
            os._exit(0)
        except BaseException:  # noqa: BLE001 — catch SystemExit too in child
            try:
                os.write(2, b"sandbox: ptrace probe child unexpected exception\n")
            finally:
                os._exit(1)

    # Parent owns the child until a terminal wait status (or ECHILD)
    # proves it was reaped. Keep cleanup in finally so cancellation and
    # unexpected ctypes failures cannot strand a stopped child.
    child_owned = True
    deadline = time.monotonic() + _PROBE_TIMEOUT_S
    try:
        _, status = _waitpid_eintr_safe(pid, os.WUNTRACED, deadline=deadline)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            child_owned = False
        if not os.WIFSTOPPED(status):
            logger.debug("ptrace probe: child did not stop (status=%#x)", status)
            return False

        ctypes.set_errno(0)
        rc = libc.ptrace(_PTRACE_CONT, pid, None, None)
        err = ctypes.get_errno()
        if rc != 0:
            logger.debug("ptrace probe: PTRACE_CONT failed (errno=%d)", err)
            return False

        _, exit_status = _waitpid_eintr_safe(pid, 0, deadline=deadline)
        if os.WIFEXITED(exit_status) or os.WIFSIGNALED(exit_status):
            child_owned = False
        if not os.WIFEXITED(exit_status) or os.WEXITSTATUS(exit_status) != 0:
            logger.debug(
                "ptrace probe: child exited abnormally (status=%#x)", exit_status,
            )
            return False
        return True
    except OSError as exc:
        if isinstance(exc, ChildProcessError) or exc.errno == errno.ECHILD:
            child_owned = False
        logger.debug("ptrace probe: child wait failed: %s", exc)
        return False
    finally:
        if child_owned:
            _try_kill_and_reap(pid)


def _waitpid_eintr_safe(pid: int, options: int, *,
                       deadline: float | None = None) -> tuple:
    """Loop on EINTR — `os.waitpid` raises InterruptedError when
    interrupted by an unrelated signal (e.g. another child's SIGCHLD,
    SIGALRM from a timer). Treating that as "ptrace unavailable" would
    cache the wrong result for the rest of the process lifetime.

    PEP 475 (Python 3.5+) auto-retries many syscalls on EINTR, but the
    auto-retry is bypassed when a Python-side signal handler runs and
    raises an exception (e.g. signal.signal(SIGTERM, lambda *a: ...)).
    The retry covers that case. Harmless overhead in the common case.

    Other OSErrors (ECHILD, EINVAL) propagate to the caller. A deadline
    selects nonblocking polling and bounds both ordinary waits and EINTR
    retries without changing process-global signal handlers.
    """
    while True:
        try:
            result = os.waitpid(
                pid, options if deadline is None else options | os.WNOHANG,
            )
        except InterruptedError:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("ptrace probe child wait exceeded its deadline") from None
            continue
        if deadline is None or result[0] != 0:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ptrace probe child wait exceeded its deadline")
        time.sleep(min(_WAIT_POLL_S, remaining))


def _try_kill_and_reap(pid: int) -> None:
    """Best-effort cleanup of a probe child that didn't reach exit cleanly.

    Used after a probe failure path so we don't leave a zombie or a
    stopped process around. Swallows all errors — the child may already
    be gone, or the kill may race with natural exit.

    Routes through _waitpid_eintr_safe so a signal-interrupted reap
    doesn't silently leave a zombie (same EINTR concern as the main
    probe waitpid calls).

    The caller must still own an unreaped child. Never call this after
    a terminal wait status or ECHILD: opening a pidfd after ownership
    was lost cannot establish the original child's identity. A pidfd
    stabilizes signal delivery during cleanup where supported. If that
    signal API is unavailable or blocked, a PID fallback first verifies
    that the process is still our unreaped child.
    """
    if type(pid) is not int or not 0 < pid <= 0x7fffffff:
        return
    deadline = time.monotonic() + _REAP_TIMEOUT_S
    pidfd = None
    try:
        pidfd = os.pidfd_open(pid)
    except (OSError, AttributeError):
        # OSError (ENOSYS) on pre-5.3 kernels; AttributeError on
        # Python <3.9 (no os.pidfd_open). Fall through to PID-based.
        pass

    needs_pid_signal = pidfd is None
    if pidfd is not None:
        try:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except AttributeError:
                needs_pid_signal = True
            except OSError as exc:
                # ESRCH identifies the pinned process as gone. Other errors
                # can mean pidfd signaling is blocked while kill still works.
                needs_pid_signal = exc.errno != errno.ESRCH
        finally:
            try:
                os.close(pidfd)
            except OSError:
                pass
    if needs_pid_signal:
        # Never turn pidfd failure into a signal to an unowned/reused PID.
        # A nonblocking wait establishes that this is still our child; a
        # terminal status already completes cleanup without another signal.
        while True:
            try:
                waited, status = os.waitpid(pid, os.WNOHANG)
            except InterruptedError:
                if time.monotonic() >= deadline:
                    logger.warning("ptrace probe: child ownership check timed out")
                    return
                continue
            except OSError:
                return
            if waited and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                return
            break
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    try:
        while True:
            _, status = _waitpid_eintr_safe(pid, 0, deadline=deadline)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("ptrace probe cleanup exceeded its deadline")
    except TimeoutError:
        logger.warning(
            "ptrace probe: child %d did not reap within the cleanup budget", pid,
        )
    except (OSError, ChildProcessError):
        pass
