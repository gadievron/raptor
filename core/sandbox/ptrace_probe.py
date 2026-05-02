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

**No waitpid timeout.** The probe blocks indefinitely if the child
fails to stop or exit. In practice this completes in microseconds —
the child's TRACEME + self-SIGSTOP path is short and synchronous.
On a wedged system that can't schedule the probe child within seconds,
the broader sandbox setup is going to have problems anyway. Add a
SIGALRM-based timeout if this ever bites in the field.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import signal
from typing import Optional

from . import state

logger = logging.getLogger(__name__)

# ptrace request constants (see <sys/ptrace.h>)
_PTRACE_TRACEME = 0
_PTRACE_CONT = 7

# Probe-result cache lives on `state._ptrace_available_cache` so the
# conftest snapshot picks it up automatically alongside the rest of the
# sandbox state. Direct attribute access throughout (no getattr indirection)
# — matches the pattern used by check_net_available, check_mount_available,
# etc. in probes.py.


def _get_libc() -> Optional[ctypes.CDLL]:
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

        # Fail-closed wrapper: _run_probe is documented to never raise,
        # but a future change (ctypes signature drift, kernel API
        # change) could violate that. The sandbox-setup path must NOT
        # crash on probe failure — degrade to "ptrace unavailable" and
        # continue, matching the rest of the sandbox's fail-closed
        # degradation pattern.
        try:
            result = _run_probe()
        except Exception:  # noqa: BLE001 — never break sandbox setup
            logger.debug("ptrace probe: _run_probe raised unexpectedly",
                         exc_info=True)
            result = False

        state._ptrace_available_cache = result

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
    tested without forking. This function never raises — failures
    return False.
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
        pid = os.fork()
    except OSError as e:
        logger.debug(f"ptrace probe: fork failed: {e}")
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
            os.write(2, b"RAPTOR: ptrace probe child unexpected exception\n")
            os._exit(1)

    # Parent: wait for the child to stop, attempt PTRACE_CONT, then reap.
    try:
        wpid, status = _waitpid_eintr_safe(pid, os.WUNTRACED)
    except OSError as e:
        logger.debug(f"ptrace probe: waitpid failed: {e}")
        # Best-effort cleanup; the child may be a zombie.
        _try_kill_and_reap(pid)
        return False

    if not os.WIFSTOPPED(status):
        # Child didn't stop — TRACEME was rejected (child exited 1) or
        # the child died for some other reason. Either way, ptrace isn't
        # working as expected.
        logger.debug(f"ptrace probe: child did not stop (status={status:#x})")
        _try_kill_and_reap(pid)
        return False

    # Attempt to continue the traced child. If ptrace is restricted,
    # this returns -1 with EPERM/EACCES.
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_CONT, pid, None, None)
    err = ctypes.get_errno()
    if rc != 0:
        logger.debug(f"ptrace probe: PTRACE_CONT failed (errno={err})")
        _try_kill_and_reap(pid)
        return False

    # Reap the child. If everything worked, the child resumed from SIGSTOP
    # and exited 0.
    try:
        _, exit_status = _waitpid_eintr_safe(pid, 0)
    except OSError as e:
        logger.debug(f"ptrace probe: final waitpid failed: {e}")
        return False
    if not os.WIFEXITED(exit_status) or os.WEXITSTATUS(exit_status) != 0:
        logger.debug(
            f"ptrace probe: child exited abnormally (status={exit_status:#x})"
        )
        return False
    return True


def _waitpid_eintr_safe(pid: int, options: int) -> tuple:
    """Loop on EINTR — `os.waitpid` raises InterruptedError when
    interrupted by an unrelated signal (e.g. another child's SIGCHLD,
    SIGALRM from a timer). Treating that as "ptrace unavailable" would
    cache the wrong result for the rest of the process lifetime.

    PEP 475 (Python 3.5+) auto-retries many syscalls on EINTR, but the
    auto-retry is bypassed when a Python-side signal handler runs and
    raises an exception (e.g. signal.signal(SIGTERM, lambda *a: ...)).
    The retry covers that case. Harmless overhead in the common case.

    Other OSErrors (ECHILD, EINVAL) propagate to the caller.
    """
    while True:
        try:
            return os.waitpid(pid, options)
        except InterruptedError:
            continue


def _try_kill_and_reap(pid: int) -> None:
    """Best-effort cleanup of a probe child that didn't reach exit cleanly.

    Used after a probe failure path so we don't leave a zombie or a
    stopped process around. Swallows all errors — the child may already
    be gone, or the kill may race with natural exit.

    Routes through _waitpid_eintr_safe so a signal-interrupted reap
    doesn't silently leave a zombie (same EINTR concern as the main
    probe waitpid calls).
    """
    try:
        os.kill(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        _waitpid_eintr_safe(pid, 0)
    except (OSError, ChildProcessError):
        pass
