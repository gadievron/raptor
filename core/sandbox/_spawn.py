"""Fork-based sandbox-spawn helper.

Provides `run_sandboxed()` — a subprocess.run() replacement that supports
the ordering subprocess.Popen(preexec_fn=...) cannot: uid_map setup via
`newuidmap` (requires cooperation between parent and child), mount
operations (must run before Landlock install), and then Landlock/seccomp
install inside the child — all before the final execvp.

Why this exists:
    subprocess.Popen with preexec_fn runs preexec in a forked child that
    has already lost access to the parent's newuidmap invocation path,
    and runs Landlock BEFORE any mount ops. Kernel 6.15+ Landlock blocks
    mount topology changes once restrict_self has been called, so the
    legacy shell-script mount flow fails when mount-ns activates.

    The newuidmap helper (setuid-root, ships in the `uidmap` package) is
    the correct way to set up a user-ns with root-mapping under
    unprivileged operation. But newuidmap writes happen FROM THE PARENT
    against the child's /proc/<pid>/uid_map — requiring a synchronisation
    pipe between parent and child.

Flow:

    parent                              child (os.fork'd)
    ------                              -----------------
    1. os.pipe() × 2 (sync + stdout/stderr capture)
    2. os.fork() ─────────────────────▶ 3. os.unshare(USER|NS|IPC|[NET])
    4. wait for child 'ready'          5. write 'ready' to sync pipe
    6. newuidmap / newgidmap           7. wait for parent 'go'
    8. write 'go' to sync pipe ──────▶ 9. setup_mount_ns()  (ctypes mount)
                                       10. landlock_restrict_self()
                                       11. install seccomp filter
                                       12. os.unshare(NEWPID); os.fork()
                                       13.  grandchild: execvp(cmd)
    14. waitpid(child), collect output

Graceful degrade:
    - If newuidmap is missing or fails: skip mount-ns, fall back to the
      existing subprocess+preexec Landlock-only path. Caller checks
      `mount_ns_available()` before invoking.
    - If any single mount op in setup_mount_ns fails: raise; caller's
      fallback takes over.
    - If Landlock/seccomp install fails in child: abort child via
      os._exit(126); parent observes and returns non-zero.
"""

from __future__ import annotations

import contextlib
import logging
import os
import platform
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from . import state
from ._fork_safe_warn import warn_post_fork
from .landlock import _make_landlock_preexec
from .mount_ns import setup_mount_ns
from .probes import _find_sandbox_binary
from .seccomp import _make_seccomp_preexec

if TYPE_CHECKING:
    # Persona referenced by run_sandboxed's signature only; lazily
    # imported in the child branch to keep module-load cost the same
    # for callers that never engage fingerprint sanitisation.
    from .fingerprint import Persona

logger = logging.getLogger(__name__)

if sys.platform == "linux" and not hasattr(os, "unshare"):
    msg = (
        f"RAPTOR sandbox requires Python 3.12+ (os.unshare); "
        f"running {sys.version.split()[0]}"
    )
    raise RuntimeError(msg)

# CLONE flags from <linux/sched.h>. Python 3.12 exposes os.CLONE_* with the
# same values — we prefer the stdlib names when available so any future
# kernel-ABI churn surfaces via Python's own headers rather than our
# hardcoded copy. Requires Python 3.12+ (already enforced by the
# os.unshare() call below, which was also new in 3.12).
CLONE_NEWNS   = getattr(os, "CLONE_NEWNS",   0x00020000)
CLONE_NEWUTS  = getattr(os, "CLONE_NEWUTS",  0x04000000)
CLONE_NEWIPC  = getattr(os, "CLONE_NEWIPC",  0x08000000)
CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
CLONE_NEWPID  = getattr(os, "CLONE_NEWPID",  0x20000000)
CLONE_NEWNET  = getattr(os, "CLONE_NEWNET",  0x40000000)


def _write_setup_status(fd: int, category: bytes, reason: str = "") -> None:
    """Fork-safe write of a typed setup-failure status to the exec-status
    pipe.

    ``category`` is a single byte identifying WHICH step failed:
        b'M' mount-ns   b'L' Landlock   b'S' seccomp
        b'U' unshare (pid-ns)           b'X' target exec
    ``reason`` is a short diagnostic. The whole payload is one ``os.write``
    well under PIPE_BUF (4096) so it lands atomically. Runs in a dying
    child after fork — must not raise and must not touch the Python logger
    (not fork-safe), so swallow everything.
    """
    # Broad by design: fork-safe last-chance status write in a dying
    # child (see docstring) — any propagation here would run the
    # parent's stack in the child.
    with contextlib.suppress(BaseException):
        payload = category + b":" + reason.encode("utf-8", "replace")[:512]
        os.write(fd, payload)


def _parse_setup_status(raw: bytes):
    """Parse the exec-status payload (``<cat>:<reason>``) the child wrote.

    Returns ``None`` for empty input (EOF ⇒ the target execed; genuine
    result), else ``(category, reason)`` where category is one of
    M/L/S/U/X. Kept standalone for unit-testing the contract.
    """
    if not raw:
        return None
    return (
        chr(raw[0]),
        raw[2:].decode("utf-8", "replace") if len(raw) > 2 else "",
    )


def _drain_status_pipe(status_r: int, parent_fds: set):
    """Non-blocking read of the exec-status pipe, then close it. Returns the
    parsed (category, reason) or None.

    MUST be called on EVERY parent exit path (including timeout/exception) so
    status_r never leaks — an fd leak here exhausts the table over a long
    scan and breaks all subsequent sandboxing. NON-BLOCKING is load-bearing
    under concurrency: a sibling thread's fork can transiently inherit our
    status_w (it's CLOEXEC, so closed at the sibling's exec, but held open
    until then), which would keep EOF from arriving — we must not block on
    it. Any real status from OUR child was written before it was reaped
    (above), so it is already buffered and a non-blocking read sees it; a
    sibling cannot inject data (it never writes our status_w).
    """
    raw = b""
    try:
        while len(raw) < 1024:
            try:
                chunk = os.read(status_r, 256)
            except BlockingIOError:
                break  # no (more) data — EOF-equivalent for our purposes
            if not chunk:
                break
            raw += chunk
    except OSError:
        raw = b""
    finally:
        try:
            os.close(status_r)
        except OSError:
            pass
        parent_fds.discard(status_r)
    return _parse_setup_status(raw)


# Path to the raptor-gidmap-allow helper — same checkout-relative
# resolution as the coord-launcher.  When built and granted CAP_SETGID
# this binary writes gid_map WITHOUT denying setgroups, letting targets
# that call setgroups(2) during init (sudo, su, login) start normally.
GIDMAP_ALLOW_PATH = (
    Path(__file__).resolve().parent / "helpers" / "raptor-gidmap-allow"
)


def _gidmap_allow_available() -> str | None:
    """Return the path to raptor-gidmap-allow if built and capable.

    Probes once per process (cached in ``state._gidmap_allow_cache``).
    Returns the resolved path string if the binary exists and ``getcap``
    confirms ``cap_setgid``, else ``None``.
    """
    with state._cache_lock:
        if state._gidmap_allow_cache is not None:
            return state._gidmap_allow_cache or None
        result: str | bool = False
        try:
            if GIDMAP_ALLOW_PATH.is_file():
                # Trusted dirs only — getcap runs in the UNSANDBOXED
                # parent, and its output gates whether we exec the
                # helper; a PATH-resolved stub could vouch for (or
                # veto) anything. See probes._find_sandbox_binary.
                getcap = _find_sandbox_binary("getcap")
                if getcap:
                    r = subprocess.run(
                        [getcap, str(GIDMAP_ALLOW_PATH)],
                        capture_output=True, text=True, timeout=2,
                        check=False,
                    )
                    if "cap_setgid" in r.stdout:
                        result = str(GIDMAP_ALLOW_PATH)
        except (OSError, subprocess.SubprocessError):
            # Capability probe is best-effort; a probe failure
            # (unreadable path, missing/hung getcap) means "helper
            # unavailable", cached as False.
            pass
        state._gidmap_allow_cache = result
        return result or None


def mount_ns_available() -> bool:
    """Return True if the full mount-ns+newuidmap path is usable here.

    Gates on:
      - newuidmap + newgidmap binaries present
      - `newuidmap --help` is actually executable (catches permission
        weirdness / broken installs before we start spawning children)

    Unprivileged-user-ns + AppArmor sysctl is NOT re-checked here — the
    caller's `check_mount_available()` already gates on the sysctl, and
    run_sandboxed()'s own failure paths fall back cleanly if the child's
    unshare() returns EPERM at run time. A second fork-based probe here
    would double the startup cost on every cold sandbox() call.

    Takes `state._cache_lock` to match every other probe in the module;
    without it, concurrent first-calls (sandbox() from the main thread
    interacting with the asyncio proxy's thread) could double-probe and
    flap the cache between True and False.
    """
    with state._cache_lock:
        if state._mount_ns_available_cache is not None:
            return state._mount_ns_available_cache
        # Trusted-dirs resolution, never the inherited PATH: this is
        # the binary the parent will EXECUTE (unsandboxed) at step 6.
        # See probes._find_sandbox_binary.
        newuidmap = _find_sandbox_binary("newuidmap")
        newgidmap = _find_sandbox_binary("newgidmap")
        if not newuidmap or not newgidmap:
            state._mount_ns_available_cache = False
            return False
        try:
            import subprocess as _sp

            # `env=` to a stripped environment so the probe doesn't
            # inherit the parent's full env. Same rationale as the
            # adjacent sandbox probes: LD_PRELOAD / LD_LIBRARY_PATH
            # apply to setuid binaries (newuidmap is setuid root on
            # most distros) only via the ld-secure list, but other
            # env vars the binary inspects can still be operator-
            # controlled. Keep the probe consistent with the rest
            # of the sandbox-probe layer's env-hygiene posture.
            from core.config import RaptorConfig
            r = _sp.run(
                [newuidmap, "--help"],
                capture_output=True, timeout=2, check=False,
                env=RaptorConfig.get_safe_env(),
            )
            _ = r.returncode  # binary is callable
        except Exception:  # noqa: BLE001
            state._mount_ns_available_cache = False
            return False
        state._mount_ns_available_cache = True
        return True


def _run_newuidmap(child_pid: int, binary: str, mapping_lines: Sequence[str]) -> None:
    """Invoke newuidmap or newgidmap with the given mapping lines.

    `mapping_lines` is a flat list of strings passed as positional args:
        [inside_id_0, outside_id_0, count_0, inside_id_1, outside_id_1, count_1, ...]
    Example for `0 <host_uid> 1`:  ["0", "1000", "1"]
    """
    cmd = [binary, str(child_pid)] + list(mapping_lines)
    # Same env-hygiene as the probe above. newuidmap/newgidmap are
    # setuid root on most distros; the dynamic loader's secure-mode
    # filter strips LD_PRELOAD etc. for those automatically, but
    # belt-and-braces the env hygiene anyway.
    from core.config import RaptorConfig
    r = subprocess.run(
        cmd, capture_output=True, text=True, timeout=5, check=False,
        env=RaptorConfig.get_safe_env(),
    )
    if r.returncode != 0:
        msg = (
            f"{binary} for child {child_pid} failed "
            f"(rc={r.returncode}, stderr={r.stderr.strip()!r})"
        )
        raise RuntimeError(msg)


def _set_rlimits(limits: dict) -> None:
    """Apply rlimits in the child. Mirrors preexec.py's _set_limits but
    designed to run before mount ops / Landlock / seccomp.

    Each rlimit applies independently — a single failure no longer
    aborts the rest. Failures surface via fork-safe stderr warning so
    operators can spot when a documented cap silently became a no-op.
    One deliberate exception: RLIMIT_CORE is fail-closed — if
    suppressing coredumps fails, the child warns and os._exit(99)s
    rather than continuing (see the inline rationale).
    """
    import resource

    from .preexec import _DEFAULT_LIMITS
    mem = limits.get("memory_mb", _DEFAULT_LIMITS["memory_mb"])
    file_mb = limits.get("max_file_mb", _DEFAULT_LIMITS["max_file_mb"])
    cpu = limits.get("cpu_seconds", _DEFAULT_LIMITS["cpu_seconds"])
    nofile = limits.get("nofile", _DEFAULT_LIMITS.get("nofile", 0))
    mem_bytes = mem * 1024 * 1024
    file_bytes = file_mb * 1024 * 1024
    if mem > 0:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except (ValueError, OSError):
            warn_post_fork(b"RAPTOR: _set_rlimits RLIMIT_AS setrlimit failed -- memory cap not applied\n")
    if file_mb > 0:
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        except (ValueError, OSError):
            warn_post_fork(b"RAPTOR: _set_rlimits RLIMIT_FSIZE setrlimit failed -- file-size cap not applied\n")
    if cpu > 0:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        except (ValueError, OSError):
            warn_post_fork(b"RAPTOR: _set_rlimits RLIMIT_CPU setrlimit failed -- cpu cap not applied\n")
    if nofile > 0:
        try:
            # Clamp to the inherited hard limit — raising it needs
            # CAP_SYS_RESOURCE (host caps, not user-ns caps).
            _, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            _eff = (nofile if _hard == resource.RLIM_INFINITY
                    else min(nofile, _hard))
            resource.setrlimit(resource.RLIMIT_NOFILE, (_eff, _eff))
        except (ValueError, OSError):
            warn_post_fork(b"RAPTOR: _set_rlimits RLIMIT_NOFILE setrlimit failed -- fd-exhaustion bound not applied\n")
    # RLIMIT_CORE is unconditional — coredumps are always suppressed.
    # Fail-closed: without RLIMIT_CORE=0 the kernel may write a core
    # dump containing the full address-space (including secrets the
    # process read under Landlock's permissive default read policy).
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as exc:
        _errno = getattr(exc, "errno", 0) or 0
        try:
            os.write(2, b"RAPTOR: _spawn: RLIMIT_CORE setrlimit failed "
                     b"(errno=%d), exiting\n" % _errno)
        except OSError:
            pass
        os._exit(99)


def _kill_and_reap(pid: int) -> None:
    """SIGKILL `pid` AND its descendants, then reap. Best-effort — if
    the child already exited (ProcessLookupError) or was reaped
    elsewhere (ChildProcessError), we just return.

    Crucially this also kills the child's PROCESS GROUP, not just the
    direct child PID. Children spawned via ``start_new_session=True``
    become session leaders, and their descendants (think: codeql Java
    spawning python_tracer.py + multiprocessing forkserver workers)
    live in the same session group as the leader. ``os.kill(pid, …)``
    and ``pidfd_send_signal(pidfd, …)`` only target the leader; the
    descendants get reparented to init and run forever as orphans.
    Pre-fix this produced wedged codeql trees that accumulated CPU
    time for weeks. ``os.killpg(pgid, …)`` sends the signal to every
    process whose PGID matches the leader's — which is what we want.

    The pidfd path is kept as a defence-in-depth FIRST send (kills the
    leader's thread group reliably even if the leader has changed its
    PGID via setpgid). The killpg send follows to cover any descendants
    that stayed in the original group. Both raise ProcessLookupError
    silently — by the time the second call fires the first may have
    swept the leader; that's fine.
    """
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    # Capture the PGID FIRST — before any signal fires. If the leader
    # has been reaped elsewhere already, ``getpgid`` raises
    # ProcessLookupError and we skip the killpg cleanly; if the
    # leader called ``setpgid()`` to migrate to a different group, we
    # get the actual current PGID rather than assuming it equals
    # ``pid``. Both cases are why we CAN'T fall back to
    # ``os.killpg(pid, ...)`` after the pidfd/kill send lands: by
    # then the PID may have been reused by an unrelated process, and
    # ``killpg`` would signal whichever group that new process
    # happens to lead.
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        pgid = None
    if pidfd_open is not None and pidfd_send_signal is not None:
        pidfd = -1
        try:
            try:
                pidfd = pidfd_open(pid)
            except (ProcessLookupError, OSError):
                pidfd = -1
            if pidfd >= 0:
                try:
                    pidfd_send_signal(pidfd, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
        finally:
            if pidfd >= 0:
                try:
                    os.close(pidfd)
                except OSError:
                    pass
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    # Belt-and-braces: kill the whole process group so descendants
    # (codeql java → index.py → python_tracer.py → forkserver workers)
    # don't get orphaned to init. Uses the PGID captured pre-signal
    # above so we never target a group led by a PID-reuse victim.
    #
    # Confused-deputy guard: with the supported start_new_session=
    # False escape hatch (or a helper forked into the caller's own
    # group, e.g. a hung tracer) the captured PGID can be RAPTOR'S
    # OWN — an unconditional killpg would SIGKILL the orchestrator
    # and every unrelated same-group process on a timeout the target
    # itself provoked. Never signal our own group; the direct
    # pid/pidfd kill above already handled the leader, which is all
    # that exists in that shape.
    if pgid is not None and pgid != os.getpgrp():
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _teardown_target(child_pid: int, death_w: int, parent_fds: set,
                     grace_s: float = 1.0) -> None:
    """Timeout/exception teardown for the intermediate child and the
    sandboxed target it forked.

    ``_kill_and_reap(child_pid)`` alone has a kill-escape on this
    path: it SIGKILLs the intermediate — which holds the death-pipe
    watcher (the ``select`` loop on ``death_r``) — and then killpg's
    the intermediate's process group. A hostile target that called
    ``setsid()``/``setpgid()`` has LEFT that group, carries no
    PR_SET_PDEATHSIG, and ``death_w`` used to close only in the outer
    ``finally`` — after the watcher was already dead — so nothing
    signalled the target and it outlived the run teardown with its
    write grants (output dir, /tmp) still live.

    Close ``death_w`` FIRST, while the watcher is still alive: the
    intermediate's select loop reads EOF and SIGKILLs the grandchild
    BY PID — session/process-group escapes don't help, and in the
    pid-ns case killing the namespace's init collapses every process
    inside it, including double-forked stragglers. Give the watcher a
    short grace window to do that sweep (it polls every 50 ms and
    ``_exit(137)``s when done), then fall back to the usual
    ``_kill_and_reap`` for every remaining case: watcher already past
    its loop, wedged intermediate, pre-exec failures where no
    grandchild exists yet, or an already-reaped child.

    The intermediate's PGID is captured up front for the same
    PID-reuse rationale documented in ``_kill_and_reap``: when the
    grace loop reaps the intermediate we still sweep the ORIGINAL
    process group (descendants that stayed in it), but never
    re-signal the reaped PID itself.
    """
    try:
        pgid = os.getpgid(child_pid)
    except ProcessLookupError:
        pgid = None
    reaped = False
    if death_w in parent_fds:
        try:
            os.close(death_w)
        except OSError:
            pass
        parent_fds.discard(death_w)
        deadline = time.monotonic() + grace_s
        while time.monotonic() < deadline:
            try:
                pid_, _status = os.waitpid(child_pid, os.WNOHANG)
            except ChildProcessError:
                reaped = True  # reaped elsewhere — never re-signal the PID
                break
            if pid_ != 0:
                reaped = True
                break
            time.sleep(0.01)
    if not reaped:
        _kill_and_reap(child_pid)
    elif pgid is not None:
        # The watcher swept the grandchild and exited on its own;
        # sweep any descendants that stayed in the intermediate's
        # original process group (same belt-and-braces killpg
        # _kill_and_reap would have sent).
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _reap_tracer(tracer_pid: int, timeout_s: float = 2.0) -> None:
    """Wait for the audit-mode tracer subprocess to exit, then reap it.

    The tracer's main loop terminates when its `traced` set goes empty
    (all tracees have exited), which happens shortly after the target
    child reaches the parent's waitpid. Allow up to `timeout_s` for
    natural exit; SIGKILL + reap if it hangs (shouldn't happen in
    practice — PTRACE_O_EXITKILL has already cleared any orphaned
    tracees, leaving the tracer with nothing to wait for).
    """
    # time.monotonic() — wall clock (time.time()) can jump backward
    # under NTP/manual `date` adjustments, leaving the deadline never
    # expiring (or expiring instantly). monotonic is guaranteed
    # non-decreasing.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(tracer_pid, os.WNOHANG)
        except ChildProcessError:
            return  # already reaped by someone else
        if pid != 0:
            return
        time.sleep(0.02)
    # Tracer didn't exit; force.
    _kill_and_reap(tracer_pid)


def _sweep_stale_audit_configs(max_age_s: float = 3600.0) -> None:
    """Remove stale raptor-audit-cfg-* tempfiles in /tmp owned by
    the current UID, dating from prior crashed runs.

    Audit-config tempfiles get unlinked in the normal lifecycle path
    (BaseException + final finally in run_sandboxed) AND by the tracer
    itself right after it parses the config. But if both processes get
    SIGKILL'd mid-audit (OOM, kernel panic, operator's session
    terminated externally), the tempfile leaks. Accumulation is slow
    but real on long-lived dev machines.

    Runs on EVERY engaged-audit spawn. That is safe because of the
    ``max_age_s`` floor: a live config belongs to a concurrent spawn
    and exists only for the seconds between mkstemp and the tracer
    parsing (then deleting) it — an hour-old file is unambiguously an
    orphan. (The floor also fixes a latent race in the previous
    once-per-process form, which could delete a concurrent process's
    just-minted config.) Same-UID-only — never touch other operators'
    files. Best-effort: any unlink failure is silently ignored (file
    may have been cleaned up by another process, or ownership
    changed).
    """
    import glob
    import tempfile as _tempfile
    import time as _time
    my_uid = os.getuid()
    now = _time.time()
    # Sweep ``$TMPDIR`` when set, not the hardcoded ``/tmp``. On macOS
    # ``tempfile`` defaults to a per-UID ``/var/folders/...`` path; on
    # space-constrained Linux dev boxes ``TMPDIR=/data/tmp``. Pre-fix
    # the hardcoded ``/tmp`` glob silently never matched the actual
    # tempfile location on those systems, so stale audit-config files
    # accumulated under ``$TMPDIR`` indefinitely.
    tmp_root = _tempfile.gettempdir()
    for path in glob.glob(f"{tmp_root}/raptor-audit-cfg-*.json"):
        try:
            st = os.lstat(path)
            if st.st_uid != my_uid:
                continue
            if now - st.st_mtime < max_age_s:
                continue  # possibly a concurrent spawn's live config
            os.unlink(path)
        except OSError:
            continue


def _cleanup_stub(root_dir: str) -> None:
    """Remove the mkdtemp sandbox-root stub after the child exits.

    lstat-check defeats TOCTOU: if a same-UID attacker raced to replace
    the random-name stub with a symlink between tmpdir creation and our
    cleanup, the lstat + S_ISDIR guard returns without touching it.
    A plain rmdir is tried first; when partial setup left sub-dirs
    (pre-pivot makedirs) we fall back to a symlink-hardened manual walk
    (os.walk followlinks=False; unlink never follows, rmdir on a
    symlink fails ENOTDIR) — never a follow-happy shutil.rmtree.
    Whatever the hardened walk cannot remove is left behind: stale
    stubs are an acceptable leak, removing the wrong thing via
    symlink-follow is not.
    """
    try:
        st = os.lstat(root_dir)
    except OSError:
        return
    import stat as _stat
    if not _stat.S_ISDIR(st.st_mode):
        return
    try:
        os.rmdir(root_dir)
        return
    except OSError:
        pass
    # Partial setup can leave sub-dirs (pre-pivot makedirs). Walk with
    # O_NOFOLLOW-equivalent via os.walk(followlinks=False).
    for dirpath, dirnames, filenames in os.walk(
        root_dir, topdown=False, followlinks=False
    ):
        for f in filenames:
            try:
                os.unlink(os.path.join(dirpath, f))
            except OSError:
                pass
        for d in dirnames:
            try:
                os.rmdir(os.path.join(dirpath, d))
            except OSError:
                pass
    try:
        os.rmdir(root_dir)
    except OSError:
        pass


def _subid_range(path: str, user: str, numeric_id: str) -> tuple[int, int] | None:
    """First /etc/subuid|/etc/subgid entry for the user (matched by name
    or numeric id), as ``(start, count)``. None when absent/unreadable —
    the caller degrades to the single-id mapping with a warning."""
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(":")
            if len(parts) == 3 and parts[0] in (user, numeric_id):
                return int(parts[1]), min(int(parts[2]), 65536)
    except (OSError, ValueError):
        return None
    return None


def _pid1_split_for_waiter() -> None:
    """Fork so the exec target becomes PID 2 of the pid-ns; PID 1 (this
    process) stays as a minimal in-process init that reaps children and
    mirrors the target's exit.

    Rationale (rootfs mode): a container-image entrypoint running as
    pid-ns PID 1 has kill(2)-delivered signals silently filtered by the
    kernel (abort(), raise(SIGFPE), self-kill test harnesses) — the
    same problem libexec/raptor-pid1-shim solves for the subprocess
    path, solved here in-process because the shim's interpreter isn't
    guaranteed to exist inside a foreign image rootfs. PID 1 cannot
    re-raise the death signal on itself (same filter), so a signalled
    target is mirrored as exit ``128 + signum`` — the shim convention
    ``observe._interpret_result`` already decodes. SIGTERM / SIGINT /
    SIGHUP / SIGQUIT arriving at PID 1 are forwarded to the target;
    orphans are reaped and their statuses discarded.

    Returns in the CHILD (the exec path). The PID 1 side never returns
    (``os._exit``).
    """
    child = os.fork()
    if child == 0:
        return  # exec path continues as PID 2

    def _forward(signum, _frame, _child=child) -> None:
        with contextlib.suppress(OSError):
            os.kill(_child, signum)

    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
        with contextlib.suppress(OSError, ValueError):
            signal.signal(_sig, _forward)
    while True:
        try:
            pid_, status = os.wait()
        except InterruptedError:
            continue
        except ChildProcessError:
            os._exit(0)
        if pid_ != child:
            continue  # reap orphans; only the target's status mirrors
        if os.WIFEXITED(status):
            os._exit(os.WEXITSTATUS(status))
        if os.WIFSIGNALED(status):
            os._exit(128 + os.WTERMSIG(status))
        # stopped/continued — keep waiting


def run_sandboxed(
    cmd: Sequence[str],
    *,
    target: str | None,
    output: str | None,
    block_network: bool,
    nproc_limit: int,
    limits: dict,
    writable_paths: Iterable[str],
    readable_paths: Iterable[str] | None,
    allowed_tcp_ports: Iterable[int] | None,
    seccomp_profile: str | None,
    seccomp_block_udp: bool,
    env: dict | None,
    cwd: str | None,
    timeout: float | None,
    capture_output: bool = True,
    text: bool = True,
    stdin=None,
    stdout=None,
    stderr=None,
    start_new_session: bool = True,
    audit_mode: bool = False,
    audit_run_dir: str | None = None,
    audit_required: bool = False,
    audit_verbose: bool = False,
    observe_mode: bool = False,
    observe_nonce: str | None = None,
    restrict_reads: bool = False,
    strict_env: bool = False,
    persona: Persona | None = None,
    inherit_netns: bool = False,
    etc_overlay: dict | None = None,
    skip_pid_ns: bool = False,
    skip_mount_ns: bool = False,
    proxy_unix_socket: str | None = None,
    proxy_forwarder_port: int | None = None,
    extra_unix_bridges: Sequence[tuple[int, str]] | None = None,
    exec_pid_callback: Callable[[int], None] | None = None,
    child_pid_callback: Callable[[int], None] | None = None,
    rootfs: str | None = None,
) -> subprocess.CompletedProcess:
    """Run `cmd` inside a fully-isolated sandbox.

    child_pid_callback: optional callable invoked in the PARENT with
    the pid of the sandbox SETUP child (the root of the whole sandbox
    process tree — forwarder, intermediate init, and target are all
    its descendants) immediately after the fork. Used by context.py to
    register the run's process tree with the egress proxy's unix-lane
    peer-credential gate. Exceptions are logged and swallowed; the pid
    is guaranteed valid (unreaped) until this function returns.

    exec_pid_callback: optional callable invoked in the PARENT with the
    pid of the exec'ing grandchild while it is still running. The pid is
    valid in the parent's pid namespace (fork(2) returns caller-namespace
    pids, and /proc/<pid> stays host-visible even when the grandchild
    unshares its own pid-ns). Intended for callers that must observe a
    live sandboxed child — e.g. /proc/<pid>/maps sampling — without
    running it outside the sandbox. The callback runs before output
    collection starts, so it should return promptly (a child writing more
    than a pipe buffer of output stalls until the callback returns) and
    is itself responsible for terminating the child if it wants the call
    to return early (SIGKILL is fine; the normal reap flow handles the
    rest). Callback exceptions are logged and swallowed. Note the
    callback may be invoked slightly before the target's execve
    completes — callers reading /proc should poll for the state they
    need. If sandbox setup fails before the grandchild fork, the
    callback is not invoked.

    Sets up (in order inside the forked child): user-ns + mount-ns + ipc-ns
    [+ net-ns], newuidmap/newgidmap applied from parent, mount pivot_root
    onto a fresh tmpfs, Landlock + seccomp, then pid-ns via a second fork.

    audit_mode: when True, install the seccomp filter with SCMP_ACT_TRACE
    (for both the existing blocklist and b3's open/openat/connect set)
    and fork a tracer subprocess (core/sandbox/tracer) to receive the
    trace events. The target child blocks on the existing go-pipe until
    the tracer signals it's attached, then proceeds with exec — that
    ordering ensures no traced syscall fires before the tracer is in
    place (which would SIGSYS-kill the target). audit_run_dir is the
    directory where the tracer writes JSONL records — required when
    audit_mode is True.

    Yama scope 1 (default Ubuntu/Debian/Fedora) only permits tracing
    one's own descendants. Tracer is a sibling of target, so target
    calls prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) in its preexec to
    declare "any process can ptrace me," satisfying Yama without
    needing tracer's PID.

    If audit_mode=True but the ptrace probe reports the kernel won't
    allow it (Yama scope 3, container --cap-drop SYS_PTRACE, etc.),
    the function logs a warning and degrades — runs the workflow
    WITHOUT seccomp audit and WITHOUT a tracer. b1 (egress proxy
    audit) is configured separately and is unaffected.

    audit_required: when True, the three in-spawn audit degradations
    above (no seccomp profile / no libseccomp / ptrace blocked —
    F063a/b/c) raise SandboxSetupError after writing the per-run
    degrade marker, instead of running the command without a tracer.
    The raise happens before the fork, so the target never executes.
    """
    if rootfs is not None:
        # Rootfs mode is mount-ns-or-nothing: without the pivot there is
        # no image filesystem to run against — the command would execute
        # on the HOST fs while the caller believes it's containerised.
        if skip_mount_ns:
            msg = (
                "rootfs= requires the mount namespace; skip_mount_ns=True "
                "would run the command against the host filesystem"
            )
            raise ValueError(msg)
        rootfs = os.path.abspath(rootfs)
        if not os.path.isdir(rootfs):
            msg = f"rootfs is not a directory: {rootfs}"
            raise ValueError(msg)

    # Sandbox root directory. Created by the parent via tempfile.mkdtemp
    # so the path is random-suffixed (mode 0700) — a same-UID attacker
    # can't pre-plant the stub as a symlink pointing at /etc or another
    # sensitive location. The child mounts tmpfs on this path; parent
    # rmdir's it after waitpid. We lstat-check before cleanup to defeat
    # TOCTOU substitution.
    import tempfile as _tempfile
    _root_dir = _tempfile.mkdtemp(prefix=".raptor-sbx-")

    # Audit-mode pre-flight: probe ptrace availability. If unavailable
    # (Yama scope 3, container cap-drop, etc.), degrade to non-audit:
    # SCMP_ACT_TRACE without an attached tracer would SIGSYS-kill the
    # target on its first traced syscall. The probe + warning is
    # idempotent (cached + warn-once).
    _audit_engaged = False
    # Anonymous fd holding the tracer's audit-config JSON (F31: the
    # config carries the observe nonce, so it must never exist at a
    # filesystem path the target can name). Passed to the tracer as
    # /proc/self/fd/N; CLOEXEC everywhere except the tracer's exec.
    _audit_config_fd: int | None = None
    # argv spelling of the config fd for the tracer child.
    _audit_config_arg: str | None = None
    # Parent-held evidence file (F11): <run_dir>/.audit/<jsonl>,
    # created O_EXCL before the sandbox starts; the tracer inherits
    # the fd and appends through it; inode verified at finalisation.
    _evidence_file = None
    if audit_mode:
        if audit_run_dir is None:
            # Clean up the just-created mkdtemp stub before raising.
            # Pre-fix this raise leaked a `.raptor-sbx-*` directory on
            # every misuse of the API. The fork try/except below only
            # covers cleanup AFTER the audit-mode setup completes.
            _cleanup_stub(_root_dir)
            msg = "audit_mode=True requires audit_run_dir="
            raise ValueError(msg)
        # Audit mode requires seccomp to be active AND libseccomp to
        # be available — without a seccomp filter there's nothing to
        # install SCMP_ACT_TRACE on, and no tracer events would fire.
        # Three failure modes silently no-op tracer setup:
        #   1. seccomp_profile falsy (network-only / none / explicit
        #      None) — operator chose no seccomp
        #   2. libseccomp not installed on host — capability missing
        #   3. ptrace blocked (Yama / cap-drop / AppArmor) — separate
        #      check below
        # All three log at debug; the spawn-side warn-once for case 2
        # / 3 surfaces them at warn level once per process for
        # operator visibility.
        from . import summary as _summary_mod
        from .ptrace_probe import check_ptrace_available
        from .seccomp import check_seccomp_available
        if not seccomp_profile:
            logger.debug(
                "audit_mode=True but no seccomp filter active; "
                "skipping tracer (b2/b3 audit are no-ops without "
                "seccomp). Network audit (b1) is configured separately."
            )
            # F063a: surface the silent degrade to operators. Without
            # this marker, the empty run dir is indistinguishable
            # from "audit ran, found nothing."
            _summary_mod.record_audit_degraded(
                Path(audit_run_dir),
                reason="audit_mode=True but no seccomp filter is active",
                instructions=(
                    "pass seccomp_profile= (e.g. \"full\") so b2/b3 "
                    "audit can install SCMP_ACT_TRACE; or run without "
                    "audit_mode if seccomp is intentionally disabled"
                ),
            )
            if audit_required:
                # Fail closed BEFORE the fork: the caller demanded
                # audit evidence; running the target without a tracer
                # would return a successful-looking result with no
                # observe record. Marker above is kept — it documents
                # the refused degradation for run-dir readers.
                _cleanup_stub(_root_dir)
                from .errors import SandboxSetupError
                msg = (
                    "audit_required=True but no seccomp filter is "
                    "active — b2/b3 audit cannot engage; refusing to "
                    "run the target unaudited."
                )
                raise SandboxSetupError(
                    msg,
                    "pass seccomp_profile= (e.g. \"full\") or drop "
                    "audit_required= to accept marker-recorded "
                    "degradation.",
                )
        elif not check_seccomp_available():
            # libseccomp missing — tracer would attach but never
            # receive events (no filter installed). Skip the
            # ~200ms fork+SEIZE overhead.
            logger.debug(
                "audit_mode=True but libseccomp unavailable; "
                "skipping tracer (no filter would be installed)."
            )
            # F063b: same operator-visibility gap as F063a; the
            # tracer is correctly skipped, but the run dir contains
            # nothing to signal that fact.
            _summary_mod.record_audit_degraded(
                Path(audit_run_dir),
                reason="audit_mode=True but libseccomp is unavailable on this host",
                instructions=(
                    "install libseccomp (Debian/Ubuntu: apt install "
                    "libseccomp2; Alpine: apk add libseccomp), or run "
                    "without audit_mode on hosts where libseccomp is "
                    "intentionally absent"
                ),
            )
            if audit_required:
                _cleanup_stub(_root_dir)
                from .errors import SandboxSetupError
                msg = (
                    "audit_required=True but libseccomp is "
                    "unavailable on this host — the tracer would "
                    "receive no events; refusing to run the target "
                    "unaudited."
                )
                raise SandboxSetupError(
                    msg,
                    "install libseccomp (Debian/Ubuntu: apt install "
                    "libseccomp2), or drop audit_required= to accept "
                    "marker-recorded degradation.",
                )
        elif check_ptrace_available():
            _audit_engaged = True
            # Sweep stale config tempfiles from prior crashed runs
            # (SIGKILL'd parent leaves the mkstemp file behind) on
            # EVERY engaged-audit spawn. The sweep's age floor makes
            # per-spawn safe — files younger than an hour may belong
            # to a concurrent spawn and are left alone, so orphans
            # created after process start no longer outlive it (the
            # previous once-per-process guard missed them for the
            # rest of a long-lived session). Idempotent; no-op when
            # no stale files exist.
            _sweep_stale_audit_configs()
            # Build the tracer's filter config. Filtered mode (the
            # `audit` profile) drops openat/connect events that match
            # the Landlock allowlist; verbose mode (`audit-verbose`)
            # logs every traced syscall. The tracer reads this JSON
            # at startup and applies the filter per-event.
            #
            # System ro-allowlist mirrors core/sandbox/context.py's
            # restrict_reads default (the list passed to landlock as
            # readable_paths when restrict_reads=True). MUST stay in
            # sync — divergence means audit drops records for paths
            # Landlock would have blocked, OR over-reports paths
            # Landlock would have allowed.
            #
            # Kept as a literal (not imported) because the tracer
            # subprocess loads this list as JSON data via the audit
            # config file, not via the context module (which would
            # pull in the whole sandbox-context import graph).
            #
            # If the context.py list ever changes, this list MUST be
            # updated AND test_audit_system_ro_matches_context (in
            # test_audit_filter.py) verifies the parity.
            _system_ro = (
                "/usr", "/lib", "/lib64", "/bin", "/sbin",
                "/etc", "/proc", "/sys",
            )
            # Write-intent allowlist: writable_paths + /tmp + output.
            # Read-intent allowlist: writable_paths + /tmp + output +
            # readable_paths + system_ro + target.
            #
            # Use abspath (not just normpath) so caller-supplied relative
            # paths get resolved BEFORE the tracer sees them. The tracer
            # resolves tracee-paths via /proc/<pid>/cwd to absolute, so
            # relative paths in the allowlist would never match
            # (over-reporting every traced openat as would-be-blocked).
            # abspath uses the parent's cwd-at-spawn-time, matching what
            # Landlock effectively does via fd-based normalization.
            import os.path as _osp
            _writable = [_osp.abspath(p) for p in writable_paths or ()]
            if output:
                _writable.append(_osp.abspath(output))
            _read_allow = list(_writable)
            _read_allow.extend(_osp.abspath(p) for p in readable_paths or ())
            _read_allow.extend(_system_ro)
            if target:
                _read_allow.append(_osp.abspath(target))
            # Under restrict_reads=False, Landlock allows ALL reads.
            # Audit's filter must match: if not restricting, never
            # log read-intent events (they wouldn't be blocked).
            # We signal this by setting read_allowlist to None in
            # the config, which the tracer treats as "skip all
            # read-intent filtering" (every read passes the filter).
            # `audit_budget` propagates the parent's --audit-budget
            # CLI override into the tracer subprocess. The tracer
            # is a fresh Python interpreter so it doesn't inherit
            # state._cli_sandbox_audit_budget; we must serialise
            # the value through the same JSON channel as the
            # filter config. None = use the AuditBudget default.
            from . import evidence as _evidence_mod
            from . import state as _state
            from .tracer import _resolve_output_filename as _out_name
            # F11: create the evidence JSONL up-front in
            # <run_dir>/.audit/ — a directory excluded from the
            # target's writable view (mount-ns shadows it with a
            # read-only tmpfs; Landlock never grants it explicitly).
            # O_EXCL defeats a pre-created file/symlink; the tracer
            # inherits the held fd and appends through it, so a path-
            # level swap cannot redirect records; the inode recorded
            # here is verified when the file is closed at the end of
            # this call.
            try:
                _evidence_file = _evidence_mod.EvidenceFile.open(
                    audit_run_dir, _out_name(bool(observe_mode)),
                )
            except BaseException:
                # Same inline cleanup contract as the config-fd
                # failure below: the fork try/except that normally
                # owns stub cleanup hasn't been entered yet.
                _cleanup_stub(_root_dir)
                raise
            audit_config = {
                "verbose": bool(audit_verbose),
                "writable_paths": _writable,
                "read_allowlist": (_read_allow if restrict_reads
                                   else None),
                "allowed_tcp_ports": list(allowed_tcp_ports)
                    if allowed_tcp_ports else [],
                "audit_budget": getattr(
                    _state, "_cli_sandbox_audit_budget", None,
                ),
                # observe_mode flips the tracer's output filename to
                # .sandbox-observe.jsonl and the per-record stamp from
                # audit:True to observe:True (string literals in this
                # comment elided so the schema-parity regex does not
                # mistake them for config keys). Lets a downstream
                # parser tell observation runs apart from enforcement
                # runs without filename guessing.
                "observe_mode": bool(observe_mode),
                # Per-run provenance secret stamped on every record by
                # the tracer. Parser drops records lacking the
                # matching value, defeating spoofs by a target binary
                # that writes into the bind-mounted audit_run_dir.
                # Generated by context.py (which holds the value
                # locally so it can be returned to the operator via
                # sandbox_info["observe_nonce"]) and threaded through
                # the run_sandboxed kwarg. None when not in observe
                # mode (audit-mode JSONL is only written by the
                # tracer, never by sandboxed tools, so no nonce
                # needed).
                "observe_nonce": observe_nonce,
                # Held evidence fd the tracer inherits across its
                # exec (F11). The number is the parent-side fd value;
                # the tracer-child branch below clears CLOEXEC on it
                # so it survives the tracer's execvpe (never the
                # target's — the target's exec keeps default CLOEXEC).
                "evidence_fd": _evidence_file.fd,
            }
            # F31: the config (which carries the observe nonce) goes
            # into an ANONYMOUS fd — memfd on Linux — instead of a
            # /tmp tempfile a same-UID target could glob and read.
            # The tracer receives it as /proc/self/fd/N in argv; N is
            # meaningless to any process other than the tracer, and
            # the tracer closes it immediately after parsing. If the
            # write fails (memfd size limit, EIO), raise HERE so the
            # operator sees an error AT spawn-time rather than an
            # ambiguous "tracer attach failed" minutes later.
            import json as _json
            # sort_keys=True — same rationale as _landlock_audit.py:
            # the serialised audit config is hashed elsewhere for
            # cache lookups; stable ordering keeps the identity
            # contract intact across Python versions.
            _serialised = _json.dumps(audit_config, sort_keys=True).encode("utf-8")
            try:
                _audit_config_fd = _evidence_mod.anonymous_fd(_serialised)
                _audit_config_arg = _evidence_mod.fd_path(_audit_config_fd)
            except BaseException:
                # Failed to mint the config fd — close the evidence
                # file AND remove the mkdtemp stub created above, then
                # propagate so the operator sees the error immediately
                # rather than an ambiguous tracer timeout later. The
                # fork try/except below would re-cleanup if reached,
                # but it isn't reached when we raise here, so do both
                # cleanups inline.
                _evidence_file.close(verify=False)
                _evidence_file = None
                _cleanup_stub(_root_dir)
                _audit_engaged = False
                raise
        else:
            # Probe already logged the once-per-process warning with
            # workaround pointers; nothing more to say here. Workflow
            # continues, just without b2/b3 audit signal.
            # F063c: per-run marker so operators inspecting the
            # specific run dir see "audit didn't engage" rather than
            # an empty (and ambiguous) audit output. Distinct from the
            # process-wide warn-once; both are useful.
            _summary_mod.record_audit_degraded(
                Path(audit_run_dir),
                reason="audit_mode=True but ptrace is blocked on this host",
                instructions=(
                    "lower Yama scope (sysctl kernel.yama.ptrace_scope=1) "
                    "or run with CAP_SYS_PTRACE; on container hosts ensure "
                    "AppArmor / Yama policy permits PTRACE_SEIZE; or run "
                    "without audit_mode"
                ),
            )
            if audit_required:
                _cleanup_stub(_root_dir)
                from .errors import SandboxSetupError
                msg = (
                    "audit_required=True but ptrace is blocked on "
                    "this host — the tracer cannot attach; refusing "
                    "to run the target unaudited."
                )
                raise SandboxSetupError(
                    msg,
                    "lower Yama scope (sysctl kernel.yama."
                    "ptrace_scope=1) or grant CAP_SYS_PTRACE, or "
                    "drop audit_required= to accept marker-recorded "
                    "degradation.",
                )

    # Track every fd we hold in the parent so a failure ANYWHERE from
    # pipe()/fork() through the newuidmap handshake closes the lot.
    # Built before any pipe is opened so partial-open failures also get
    # cleaned up. Each successful transfer (dup/close/finished read)
    # pops from this set.
    _parent_fds: set = set()

    def _close_leftover() -> None:
        for fd in list(_parent_fds):
            try:
                os.close(fd)
            except OSError:
                pass
            _parent_fds.discard(fd)

    try:
        # Sync pipes: parent⇄child handshake for newuidmap timing.
        p_ready_r, p_ready_w = os.pipe()
        _parent_fds.update({p_ready_r, p_ready_w})
        p_go_r, p_go_w = os.pipe()
        _parent_fds.update({p_go_r, p_go_w})

        # Exec-status pipe. The child writes a typed status — which setup
        # step failed (mount/Landlock/seccomp/unshare) or that exec itself
        # failed — to status_w BEFORE exiting; on a SUCCESSFUL execvpe the
        # write end auto-closes (PEP 446 default O_CLOEXEC) and the parent
        # reads EOF. This is the unspoofable, unambiguous "did the target
        # exec, and if not exactly why" signal that replaces the brittle
        # exit-code + stderr-emptiness heuristics. The target cannot forge
        # it: status_w is close-on-exec, so it's gone before the target
        # runs. status_w is NOT marked inheritable-across-exec (unlike the
        # tracer's t_ready_w) precisely so the EOF-on-success contract holds.
        status_r, status_w = os.pipe()
        # SECURITY INVARIANT: status_w MUST stay close-on-exec (non-
        # inheritable). That is the ONE thing that makes the status
        # unspoofable — it guarantees the fd is gone from the target's fd
        # table before the target runs, so the target can neither forge a
        # setup status nor suppress a real one. os.pipe() sets CLOEXEC by
        # default (PEP 446) and we never flip it; this guard trips loudly
        # if a future change ever marks it inheritable, rather than
        # silently re-opening the spoofing hole. NOT a bare `assert`
        # (stripped under -O) — a real check for a security invariant.
        if os.get_inheritable(status_w):
            os.close(status_r)
            os.close(status_w)
            msg = (
                "sandbox exec-status pipe write-end is inheritable — the "
                "target could forge/suppress setup status; refusing to use "
                "the mount-ns spawn path (see core/sandbox/_spawn.py)."
            )
            raise RuntimeError(msg)
        # Parent reads status_r NON-BLOCKING (see _drain_status_pipe): under
        # concurrency a sibling fork can transiently hold our status_w open,
        # so a blocking read could hang a worker until the sibling's target
        # exits. Our child's status (if any) is written before it's reaped,
        # so it's already buffered when we read.
        os.set_blocking(status_r, False)
        _parent_fds.update({status_r, status_w})

        # Output capture pipes (optional).
        if capture_output:
            out_r, out_w = os.pipe()
            _parent_fds.update({out_r, out_w})
            err_r, err_w = os.pipe()
            _parent_fds.update({err_r, err_w})
        else:
            out_r = err_r = out_w = err_w = None

        # Death pipe: orphan-teardown signal. Parent holds death_w for
        # the duration of the sandbox call; intermediate child watches
        # death_r via select(). If the orchestrator is hard-killed
        # (SIGKILL/OOM/crash), death_w auto-closes → child reads EOF →
        # SIGKILLs the grandchild so the pid-namespace doesn't leak.
        death_r, death_w = os.pipe()
        _parent_fds.update({death_r, death_w})

        # Exec-pid pipe (optional): when exec_pid_callback is supplied,
        # the intermediate child writes the grandchild's pid here right
        # after forking it; the parent reads it post-go-signal and hands
        # it to the callback. Data (not EOF) is the success signal — a
        # child that dies before the fork closes its copies and the
        # parent reads EOF, degrading to "no callback".
        pid_r = pid_w = None
        if exec_pid_callback is not None:
            pid_r, pid_w = os.pipe()
            _parent_fds.update({pid_r, pid_w})

        # Precompute Landlock / seccomp preexec callables in parent so
        # import errors surface before fork. Each returns a callable we
        # can invoke in the child.
        # rw_submounts_ok: mount_ns may recursively bind an
        # extra_ro_paths tree whose locked submounts stay rw at the
        # mount layer — permitted only when Landlock's unconditional
        # write mask is there to enforce read-only anyway. Probe in
        # the parent (fork-safe: the child only closes over a bool).
        from .landlock import check_landlock_available as _ll_avail
        # ONLY the conditions that actually build landlock_fn below
        # count: readable_paths alone builds no write mask, so a
        # readable-only spawn claiming "Landlock enforces read-only
        # anyway" would leave the locked-submount rescue bind
        # writable with nothing masking it. Kernel availability is
        # necessary but not sufficient — the predicate must mirror
        # THIS spawn's actual Landlock engagement.
        _rw_submounts_ok = bool(
            (writable_paths or allowed_tcp_ports)
            and _ll_avail()
        )

        # Is the ro bind the ONLY read-only enforcement for the target
        # on this spawn? The remount-ro failure path says "relying on
        # Landlock" — that is vacuous when (a) Landlock doesn't engage
        # for this spawn at all, (b) the target sits UNDER a writable
        # grant (a /tmp-resident target under the /tmp baseline: the
        # per-ns tmpfs masks host /tmp but the target bind stacked on
        # top is covered by the grant), or (c) rootfs mode (the image
        # tree is granted wholesale). In those cases the mount flag
        # must fail CLOSED instead of warning.
        _target_under_writable = bool(target) and any(
            target == _w or target.startswith(_w.rstrip("/") + "/")
            for _w in (writable_paths or []) if _w
        )
        _require_target_ro = bool(
            target and output != target
            and (rootfs is not None
                 # a net-only ruleset (allowed_tcp_ports without
                 # writable_paths) handles no write accesses, so only
                 # an engaged WRITE mask counts as a backstop
                 or not (writable_paths and _ll_avail())
                 or _target_under_writable)
        )

        # All-or-nothing persona: without the mount-ns overlay step the
        # file half (/proc/cpuinfo, /etc/os-release, ...) never applies
        # while UTS + affinity still would — an inconsistent
        # half-persona is a fingerprint TELL, worse than none. The
        # construction-time gate in context.py rejects that
        # combination; the per-call skip_mount_ns path must not
        # sidestep it. Drop the persona for this spawn and say so.
        if persona is not None and (skip_mount_ns or not (target or output)):
            logger.warning(
                "sandbox: persona dropped for this spawn — mount-ns "
                "overlay unavailable (skip_mount_ns=%s, "
                "target/output present=%s); a UTS/affinity-only "
                "half-persona would be a fingerprint tell",
                skip_mount_ns, bool(target or output),
            )
            persona = None
        landlock_fn = None
        # readable_paths under restrict_reads is a POLICY too: a
        # read-restricted spawn with no writable paths and no TCP
        # ports (skip_mount_ns + exclude_tmp_baseline shapes) must
        # still build the Landlock read allowlist — the preexec-path
        # twin of this gate already includes it.
        if (writable_paths or allowed_tcp_ports
                or (readable_paths and restrict_reads)):
            effective_paths = list(writable_paths) if writable_paths else []
            if rootfs is not None:
                # Landlock rule paths are opened POST-pivot (the child
                # applies landlock_fn at step 10, after setup_mount_ns),
                # where the image rootfs IS "/". The image's own tree
                # must stay writable for the environment to function —
                # but a wholesale "/" grant is WRONG in rootfs mode:
                # /dev and /sys are recursive HOST binds there, so "/"
                # would hand the child Landlock write access to
                # same-UID host device nodes (the operator's other
                # ptys, most damningly — "host dirs are not bound in"
                # is false for exactly those two). Enumerate the
                # image's top-level entries instead, skipping
                # dev/sys/proc (device writes that tools legitimately
                # need — /dev/null, /dev/tty — are covered by the
                # file-scoped device rules landlock.py always adds;
                # /dev/shm and /tmp,/run are per-sandbox tmpfs served
                # via writable_paths). Symlinked entries are skipped:
                # rule opens follow symlinks post-pivot, so a hostile
                # image symlinking a top-level name into /dev would
                # re-open the hole — and Landlock resolves the REAL
                # path at access time anyway, so /bin -> usr/bin style
                # links are covered by their target's grant. The
                # target bind's MS_RDONLY remount still wins at the
                # VFS layer regardless of Landlock's grant.
                try:
                    _rootfs_entries = sorted(os.listdir(rootfs))
                except OSError:
                    _rootfs_entries = []
                for _ent in _rootfs_entries:
                    if _ent in ("dev", "sys", "proc"):
                        continue
                    try:
                        if os.path.islink(os.path.join(rootfs, _ent)):
                            continue
                    except OSError:
                        continue
                    effective_paths.append(f"/{_ent}")
                # The per-sandbox /dev/shm tmpfs must stay writable
                # even for direct callers whose writable_paths omit it.
                effective_paths.append("/dev/shm")
            # readable_paths serves two consumers with different
            # semantics: the mount-ns bind list (always) and Landlock's
            # read allowlist (ONLY under restrict_reads — Landlock
            # treats a non-None readable_paths as "deny reads
            # everywhere else", docstring in landlock.py). Passing it
            # unconditionally turned every tool_paths caller into an
            # accidental floor-less read restriction: the child could
            # not even read /bin/sh to exec it, failed with EACCES,
            # and the speculative-failure cache silently degraded the
            # binary to Landlock-only for the rest of the process.
            # The setup-report at the bottom of this function already
            # reported read_allowlist only when restrict_reads — the
            # enforcement now matches it.
            landlock_fn = _make_landlock_preexec(
                effective_paths,
                list(allowed_tcp_ports) if allowed_tcp_ports else None,
                readable_paths=(list(readable_paths)
                                if (readable_paths and restrict_reads)
                                else None),
            )
        # AF_UNIX is safe to allow exactly when this child gets the
        # mount-ns (fresh tmpfs masks /run's pathname sockets; the rest
        # of the host is read-only under pivot_root) on top of its
        # netns (abstract sockets are namespace-scoped). Mirrors the
        # child-side engagement condition at step 9; a mount failure
        # aborts the child before the payload runs, and the caller's
        # fallback re-runs through the preexec path where AF_UNIX
        # stays blocked. Needed for Python >= 3.14 multiprocessing
        # (forkserver listener) inside sandboxed tools.
        _allow_unix = bool((target or output) and not skip_mount_ns)
        # CONNECT SCOPING for the allowed AF_UNIX sockets (enforcement
        # mode). allow_unix's harmlessness rationale has one hole: the
        # OUTPUT dir is a READ-WRITE bind, so a host-side (or sibling-
        # sandbox) process can bind a pathname socket inside it and the
        # child can connect(2) — a live channel out of the sandbox.
        # Route connect(2) through a parent-side seccomp-user-notify
        # supervisor (core/sandbox/_unix_scope.py) that executes each
        # connect on the child's behalf: pathname targets are allowed
        # only on the sandbox's private tmpfs or the instance's own
        # lane sockets. Fail-closed: when the host cannot run the
        # supervisor (no user-notify / pidfd_getfd / openat2), AF_UNIX
        # stays in the seccomp blocklist — the pre-allow_unix
        # behaviour, trading Python 3.14 forkserver compatibility for
        # containment. Audit mode keeps the tracer's connect TRACE
        # path instead (mutually exclusive by construction).
        _unix_scope_parent_sock = None
        _unix_scope_child_sock = None
        if _allow_unix and seccomp_profile and not _audit_engaged:
            from ._unix_scope import probe_unix_scope
            if probe_unix_scope():
                import socket as _socket_mod
                (_unix_scope_parent_sock,
                 _unix_scope_child_sock) = _socket_mod.socketpair()
            else:
                _allow_unix = False
                if sys.platform != "linux":
                    # The supervisor is Linux plumbing; other platforms
                    # can never grow it, so Linux remediation guidance
                    # in an operator-facing WARNING is just noise.
                    logger.debug(
                        "Sandbox: AF_UNIX connect scoping is Linux-only"
                        " — socket(AF_UNIX) stays blocked for sandboxed"
                        " children on this platform.",
                    )
                elif state.warn_once("_unix_scope_unavailable_warned"):
                    logger.warning(
                        "Sandbox: AF_UNIX connect scoping unavailable "
                        "(needs seccomp user-notify + pidfd_getfd + "
                        "openat2, Linux >= 5.9 / libseccomp >= 2.5) — "
                        "socket(AF_UNIX) stays blocked for sandboxed "
                        "children (fail-closed; Python >= 3.14 "
                        "multiprocessing forkserver will not work "
                        "inside the sandbox on this host)."
                    )
        seccomp_fn = _make_seccomp_preexec(
            seccomp_profile, block_udp=seccomp_block_udp,
            audit_mode=_audit_engaged,
            observe_mode=bool(observe_mode) and _audit_engaged,
            allow_unix_sockets=_allow_unix,
            unix_scope_export_sock=_unix_scope_child_sock,
        ) if seccomp_profile else None

        # Tracer-ready pipe: the tracer subprocess writes a byte once
        # PTRACE_SEIZE + SETOPTIONS have succeeded; main parent reads it
        # before unblocking the target's exec via the existing p_go_w.
        # Only set up when audit is engaged.
        #
        # PEP 446: Python 3.4+ sets O_CLOEXEC on os.pipe() fds by
        # default, which closes them at the tracer's execvpe. Mark
        # the WRITE end inheritable so the tracer process can still
        # use it as sync_fd after exec. The READ end stays close-on-
        # exec (parent doesn't exec).
        t_ready_r = t_ready_w = None
        if _audit_engaged:
            t_ready_r, t_ready_w = os.pipe()
            os.set_inheritable(t_ready_w, True)
            _parent_fds.update({t_ready_r, t_ready_w})

        # Capture proxy bridge functions as local references BEFORE the
        # fork. After pivot_root the RAPTOR source tree is invisible in
        # the mount-ns, so `from core.sandbox._proxy_bridge import ...`
        # inside the child would fail with ModuleNotFoundError. Binding
        # the function objects here means the child only needs the
        # in-memory references, no filesystem import.
        _proxy_forwarder_fn = None
        # Loopback bring-up is bound unconditionally: EVERY fresh netns
        # needs lo up, not just the proxy-bridge variant. A new netns
        # has lo DOWN, so self-loopback connects fail ENETUNREACH —
        # which silently broke every loopback-IPC tool (gradle daemon,
        # language servers, self-connecting test suites) under
        # block_network profiles until 2026-08-15. The netns is per-run
        # and externally unreachable, so a working loopback adds no
        # exposure — it realises the isolated-loopback semantics the
        # netns_coordinator and proxy-bridge paths already had.
        from core.sandbox._proxy_bridge import (
            _bring_up_loopback as _loopback_up_fn,
        )
        # Bridge pairs (listen_port, unix_socket_path): the egress
        # proxy's relay plus any caller-declared extra loopback
        # services (LLM dispatcher for credential-proxy CLI children).
        # Materialised pre-fork so the child needs no filesystem
        # imports and no non-trivial object construction.
        _bridge_pairs: list[tuple[int, str]] = []
        if proxy_unix_socket and proxy_forwarder_port:
            _bridge_pairs.append((proxy_forwarder_port, proxy_unix_socket))
        if extra_unix_bridges:
            _bridge_pairs.extend(
                (int(port), str(path)) for port, path in extra_unix_bridges
            )
        if _bridge_pairs:
            from core.sandbox._proxy_bridge import (
                _run_bridges as _proxy_forwarder_fn,
            )

        # Suppress Python 3.12+ DeprecationWarning about multi-threaded
        # fork(). Our post-fork code does namespace setup via ctypes
        # syscalls + Landlock + seccomp + execvp — no Python objects,
        # no GIL acquisition, no malloc-arena access. posix_spawn()
        # can't do the bespoke namespace setup, so we need raw fork.
        # See module docstring for the fork-safety contract.
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            child_pid = os.fork()
    except BaseException:
        # Any failure before fork returns: close opened pipes, release
        # the audit-config fd and evidence file if created, and remove
        # the mkdtemp stub. Without this, a pipe-exhaustion OSError or
        # import-time failure in preexec construction would leak FDs
        # and a .raptor-sbx-* dir on every call.
        _close_leftover()
        if _audit_config_fd is not None:
            with contextlib.suppress(OSError):
                os.close(_audit_config_fd)
            _audit_config_fd = None
        if _evidence_file is not None:
            _evidence_file.close(verify=False)
            _evidence_file = None
        for _sk in (locals().get("_unix_scope_parent_sock"),
                    locals().get("_unix_scope_child_sock")):
            if _sk is not None:
                with contextlib.suppress(OSError):
                    _sk.close()
        _cleanup_stub(_root_dir)
        raise
    if child_pid == 0:
        # ================ CHILD ================
        # Close the ends of the pipes we don't use.
        os.close(p_ready_r)
        os.close(p_go_w)
        # Exec-status pipe: the child only WRITES (status_w); close the
        # read end. status_w is kept open through setup and auto-closes on
        # a successful execvpe (its default O_CLOEXEC) → parent reads EOF.
        os.close(status_r)
        # Death pipe: child watches death_r; close the write end so only
        # the parent holds it. Parent dying → death_w closes → EOF.
        os.close(death_w)
        # Exec-pid pipe: the child side only WRITES (pid_w, from the
        # intermediate after the grandchild fork); close the read end.
        if pid_r is not None:
            os.close(pid_r)
        # Unix-scope socketpair: the child only SENDS on the child end
        # (inside the seccomp preexec); close the parent end so the
        # parent's recvmsg sees EOF if the child dies before the
        # export.
        if _unix_scope_parent_sock is not None:
            _unix_scope_parent_sock.close()
        # Which setup step we're about to attempt — the BaseException
        # catch-all below writes this category to status_w so the parent
        # knows whether to degrade (mount) or fail loud (Landlock/seccomp/
        # unshare). Default 'U' (fail-loud) for any pre-mount step.
        _status_step = b"U"
        # Tracer-ready pipe: target child doesn't read from or write to
        # this pipe; the tracer subprocess writes one end and the main
        # parent reads the other. Close both inherited ends so the pipe
        # doesn't keep references to the target child's fd table.
        if _audit_engaged:
            os.close(t_ready_r)
            os.close(t_ready_w)
        if capture_output:
            os.close(out_r)
            os.close(err_r)
            os.dup2(out_w, 1)
            os.dup2(err_w, 2)
            os.close(out_w)
            os.close(err_w)
        else:
            # stdout=/stderr= redirects (int fd, file-like, DEVNULL,
            # STDOUT for stderr). Pre-fix these kwargs were silently
            # DROPPED on this path — the child inherited the parent's
            # fd 1/2 regardless, which also defeated run_untrusted's
            # write-only tty reopen (the child kept the O_RDWR pty
            # slave and could read() the operator's keystrokes
            # through its own stdout). PIPE is unsupported here, same
            # as stdin: fail closed to /dev/null with a stderr note.
            for _redir, _fdnum, _label in ((stdout, 1, b"stdout"),
                                           (stderr, 2, b"stderr")):
                if _redir is None:
                    continue
                if _redir == subprocess.PIPE:
                    try:
                        os.write(2, b"RAPTOR sandbox: %s=subprocess."
                                    b"PIPE not supported via the "
                                    b"mount-ns path; falling back to "
                                    b"/dev/null.\n" % _label)
                    except OSError:
                        pass
                    _redir = subprocess.DEVNULL
                if _redir == subprocess.DEVNULL:
                    _dn = os.open("/dev/null", os.O_WRONLY)
                    os.dup2(_dn, _fdnum)
                    os.close(_dn)
                    continue
                if _fdnum == 2 and _redir == subprocess.STDOUT:
                    os.dup2(1, 2)
                    continue
                _rfd = _redir if isinstance(_redir, int) else _redir.fileno()
                if _rfd != _fdnum:
                    os.dup2(_rfd, _fdnum)
        # stdin: caller-supplied fd/file if any, else /dev/null (defence
        # against tty-based escapes — a child with an inherited tty can
        # TIOCSTI-inject or ^Z into the parent's job control). The
        # Landlock-only path honours stdin=; the mount-ns path MUST do
        # the same or it silently drops input (bug previously hit by
        # packages/binary_analysis/debugger.py passing `stdin=open(...)`
        # for gdb's crash-replay input).
        # Map the caller's stdin= into fd 0. Handles the same cases
        # subprocess.Popen does:
        #   - None or subprocess.DEVNULL → /dev/null
        #   - subprocess.PIPE  → unsupported on this path (context.py
        #     already routes `input=` callers away from _spawn, so PIPE
        #     is always a caller mistake — fail closed with /dev/null
        #     and a stderr note rather than silently letting the child
        #     talk to whatever fd -1 resolves to).
        #   - int fd (real)    → dup2 onto 0
        #   - file-like object → dup2 on .fileno() onto 0
        _use_devnull = (
            stdin is None
            or stdin == subprocess.DEVNULL
            or stdin == subprocess.PIPE
        )
        if _use_devnull:
            if stdin == subprocess.PIPE:
                try:
                    os.write(2, b"RAPTOR sandbox: stdin=subprocess.PIPE "
                                b"not supported via the mount-ns path; "
                                b"use `input=` or an explicit fd. "
                                b"Falling back to /dev/null.\n")
                except OSError:
                    pass
            devnull = os.open("/dev/null", os.O_RDONLY)
            os.dup2(devnull, 0)
            os.close(devnull)
        else:
            try:
                stdin_fd = stdin if isinstance(stdin, int) else stdin.fileno()
                os.dup2(stdin_fd, 0)
                # Close the original fd so the child doesn't inherit a
                # duplicate (the caller's file object may not have
                # O_CLOEXEC, in which case execvpe would leave both
                # fds pointing at the same file). dup2 clears CLOEXEC
                # on fd 0, which is what we want — stdin stays open
                # across exec.
                if stdin_fd != 0:
                    try:
                        os.close(stdin_fd)
                    except OSError:
                        pass
            except (AttributeError, OSError):
                devnull = os.open("/dev/null", os.O_RDONLY)
                os.dup2(devnull, 0)
                os.close(devnull)
        # New session → no controlling tty. Honoured only when caller
        # explicitly or implicitly opts in — subprocess.run defaults to
        # start_new_session=False (session inherited) and callers relying
        # on a controlling tty (e.g. interactive gdb under /crash-analysis
        # via `sandbox(profile='debug')` + start_new_session=False) need
        # the same behaviour through this path. Previously _spawn
        # unconditionally setsid'd, silently defeating that escape
        # hatch on mount-ns-capable hosts.
        if start_new_session:
            try:
                os.setsid()
            except OSError:
                pass

        try:
            # Step 3: create namespaces. Leaves us as "nobody" in the
            # new user-ns until the parent runs newuidmap on us.
            ns_flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC
            if block_network and not inherit_netns:
                ns_flags |= CLONE_NEWNET
            if persona is not None:
                # Fresh UTS namespace so sethostname/setdomainname only
                # affect us, not the host. We have CAP_SYS_ADMIN in this
                # UTS-ns post-newuidmap (we own it as ns-uid-0) — the
                # actual sethostname call lives after step 7.
                ns_flags |= CLONE_NEWUTS
            os.unshare(ns_flags)

            # Step 3.5: bring lo up in the fresh netns. A new netns has
            # loopback DOWN — bind() works but self-connect fails
            # ENETUNREACH, breaking every loopback-IPC tool under
            # block_network. We own the netns (created by our user-ns)
            # so SIOCSIFFLAGS is permitted even pre-uidmap. Best-effort:
            # on failure the netns behaves exactly as before this fix.
            if ns_flags & CLONE_NEWNET:
                try:
                    _loopback_up_fn()
                except OSError as e:
                    warn_post_fork(
                        b"_spawn: netns loopback bringup failed "
                        b"(errno=%d); loopback IPC unavailable in "
                        b"this sandbox\n" % (e.errno or 0)
                    )

            # Step 4.5: declare PR_SET_PTRACER_ANY under Yama scope 1.
            #
            # Two cases need this:
            # - audit mode: the tracer (our sibling) must SEIZE us.
            # - debug profile: tools like frida/gdb use helper
            #   processes that ptrace across the ancestry boundary.
            #   The debug seccomp filter already allows the ptrace
            #   syscall; this makes Yama consistent with that.
            #
            # Must run BEFORE "R" — the parent may fork the tracer
            # right after newuidmap.
            #
            # The child here is uid 65534 ("nobody") after unshare but
            # before newuidmap — PR_SET_PTRACER doesn't require any
            # capability; it just declares permission to be traced.
            if _audit_engaged or seccomp_profile == "debug":
                # prctl failure isn't fatal — Yama may already be
                # permissive. Tracer's SEIZE is the actual gate.
                # Legitimate failures: ctypes absent on minimal Python
                # builds (ImportError), libc lookup/load failure
                # (OSError), prctl symbol missing on exotic libcs
                # (AttributeError — ctypes raises it on symbol access).
                with contextlib.suppress(
                    ImportError, OSError, AttributeError,
                ):
                    import ctypes as _c
                    import ctypes.util as _cu
                    _c_libc = _c.CDLL(_cu.find_library("c"),
                                      use_errno=True)
                    _PR_SET_PTRACER = 0x59616d61
                    # PR_SET_PTRACER_ANY is `(unsigned long)-1` in the
                    # kernel header. ctypes.c_ulong(-1) wraps to the
                    # platform's native max value: 2^64-1 on 64-bit
                    # systems, 2^32-1 on 32-bit. Computing the literal
                    # with `(1 << 64) - 1` would silently truncate
                    # under c_ulong on 32-bit, so use the -1-wrap form
                    # to be platform-portable.
                    _c_libc.prctl(_PR_SET_PTRACER,
                                  _c.c_ulong(-1),
                                  0, 0, 0)

            # Step 5: tell parent we're ready for newuidmap.
            os.write(p_ready_w, b"R")
            os.close(p_ready_w)

            # Step 7: wait for parent 'go' signal — parent has run
            # newuidmap by this point.
            try:
                if os.read(p_go_r, 1) != b"G":
                    # Parent failed before signalling go (it has already
                    # raised + killed us). Write a status anyway so the pipe
                    # is self-sufficient and never relies on caller ordering.
                    _write_setup_status(status_w, b"U", "no go signal")
                    os._exit(125)
            finally:
                os.close(p_go_r)

            # Child is now uid 0 in the new ns.
            if os.getuid() != 0:
                # newuidmap silently didn't map (parent wrote go but the
                # uid map didn't take). The parent IS waiting to reap and
                # WILL read the status pipe, so this 'U' makes it fail loud
                # rather than EOF-misread the 124 as a genuine result.
                _write_setup_status(status_w, b"U", "newuidmap did not map")
                os._exit(124)

            # rlimits as early as possible so later setup is constrained.
            _set_rlimits(limits)

            # Step 8.5 (fingerprint sanitisation): sethostname /
            # setdomainname inside our fresh UTS namespace. Done before
            # mount-ns so the persona's /etc/hostname (bind-mounted in
            # step 9) and uname()'s nodename agree (gethostname() reads
            # the UTS field, not /etc/hostname — both must be set
            # consistently or a cross-check is a sandbox tell).
            if persona is not None:
                from .fingerprint import set_uts
                try:
                    set_uts(persona.hostname, persona.domainname)
                except OSError as e:
                    # Degrade silently — caller (context.py) already
                    # gated on platform support; an unexpected runtime
                    # failure here shouldn't take down the whole
                    # sandbox, just leak hostname/domainname.
                    warn_post_fork(
                        b"sandbox: fingerprint set_uts failed (errno=%d)"
                        b"; hostname/domainname remain host-real\n"
                        % (e.errno or 0)
                    )

            # Step 8.7: proxy netns bridge. When the child is in an
            # empty netns with an egress proxy, fork a TCP-to-Unix
            # relay so the target can reach the proxy at
            # 127.0.0.1:<port> via HTTPS_PROXY. Ordering is
            # load-bearing twice over: BEFORE Landlock/seccomp so the
            # forwarder runs unrestricted (it needs AF_UNIX socket()
            # which seccomp blocks for the target), and BEFORE
            # setup_mount_ns so the forwarder keeps the HOST mount
            # view — after pivot_root the per-sandbox tmpfs replaces
            # /tmp and can shadow the unix socket path (observed with
            # output=/tmp), leaving the relay unable to reach the
            # proxy. The loopback bringup already happened at Step 3.5
            # for every fresh netns; the call here is a harmless
            # idempotent belt-and-braces retained for the proxy
            # error-handling contract (bridge is skipped, loudly, if
            # loopback cannot come up).
            _forwarder_pid = 0
            _forwarder_death_w = -1
            if _proxy_forwarder_fn is not None:
                try:
                    _loopback_up_fn()
                except OSError as e:
                    warn_post_fork(
                        b"_spawn: loopback bringup failed (errno=%d)"
                        b"; proxy bridge will not work\n"
                        % (e.errno or 0)
                    )
                else:
                    _fwd_death_r, _fwd_death_w = os.pipe()
                    _forwarder_death_w = _fwd_death_w
                    import warnings as _w2
                    with _w2.catch_warnings():
                        _w2.filterwarnings(
                            "ignore", category=DeprecationWarning,
                            message=r".*fork.*may lead to deadlocks.*",
                        )
                        _forwarder_pid = os.fork()
                    if _forwarder_pid == 0:
                        os.close(_fwd_death_w)
                        os.close(status_w)
                        # p_ready_w was closed at step 5 — do NOT close
                        # here; the fd number may have been reused by
                        # the death pipe allocated above.
                        #
                        # Detach into a PRIVATE COPY of the current
                        # (pre-pivot) mount tree. Fork order alone does
                        # not protect the forwarder's filesystem view:
                        # it shares the mount NAMESPACE entered at Step
                        # 3, so the target child's pivot_root at Step 9
                        # would swap the tree under it — the unix
                        # socket path then reads through the per-
                        # sandbox tmpfs and the relay dies with ENOENT
                        # (observed with output=/tmp). unshare(NEWNS)
                        # here snapshots the host view; capabilities
                        # are still intact (no exec has happened).
                        with contextlib.suppress(OSError):
                            os.unshare(CLONE_NEWNS)
                        # Broad by design: forked forwarder child must
                        # reach os._exit(0) on ANY failure — letting an
                        # exception propagate would run the parent's
                        # stack in the child.
                        with contextlib.suppress(BaseException):
                            _proxy_forwarder_fn(
                                _bridge_pairs,
                                _fwd_death_r,
                            )
                        os._exit(0)
                    os.close(_fwd_death_r)

            # Step 9: mount-ns pivot_root if target/output supplied.
            # readable_paths from the caller also get bind-mounted at
            # their original paths so they exist inside the pivoted
            # root — otherwise Landlock's allowlist would cover a path
            # the child can't reach (ENOENT before EACCES).
            if (target or output or rootfs) and not skip_mount_ns:
                _status_step = b"M"
                setup_mount_ns(target, output,
                               extra_ro_paths=readable_paths,
                               root_path=_root_dir,
                               persona=persona,
                               etc_overlay=etc_overlay,
                               rw_submounts_ok=_rw_submounts_ok,
                               rootfs=rootfs,
                               require_target_ro=_require_target_ro)

            # Step 9.5 (fingerprint sanitisation): pin sched_setaffinity
            # to a mask of size persona.cpu_count. The persona's
            # /proc/cpuinfo and /sys/devices/system/cpu/online already
            # claim cpu_count processors; pinning the affinity mask to
            # match means sched_getaffinity / os.cpu_count() /
            # nproc / Go GOMAXPROCS / Rust num_cpus all agree with the
            # cpuinfo view — no cross-check tell.
            #
            # Done AFTER mount_ns (no ordering dependency, but keeps the
            # fingerprint-related calls grouped) and BEFORE Landlock
            # (sched_setaffinity is allowed under seccomp/Landlock but
            # grouping makes the audit trail clearer).
            if persona is not None:
                from .fingerprint import set_cpu_affinity
                try:
                    set_cpu_affinity(persona.cpu_count)
                except (OSError, ValueError) as e:
                    warn_post_fork(
                        b"sandbox: fingerprint set_cpu_affinity failed "
                        b"(errno=%d); affinity unchanged\n"
                        % (getattr(e, "errno", 0) or 0)
                    )

            # cwd — only now, after pivot_root. Match subprocess.run
            # semantics: if the caller specified a cwd that doesn't
            # exist (or isn't executable), surface the error rather
            # than silently running from /. A silent fallback masks
            # genuine caller bugs (wrong repo_path, deleted target).
            # The stderr write lets the parent's observability layer
            # see what happened; the os._exit(127) code matches
            # subprocess's ENOENT-during-exec convention so callers
            # testing `result.returncode == 127` behave identically
            # across the two sandbox paths.
            if cwd:
                try:
                    os.chdir(cwd)
                except OSError as e:
                    try:
                        os.write(2,
                            f"RAPTOR sandbox: cwd={cwd!r} unusable inside "
                            f"sandbox ({e.__class__.__name__}: {e}); "
                            f"aborting.\n".encode())
                    except OSError:
                        pass
                    os._exit(127)

            # Step 10: Landlock. Must run BEFORE seccomp so seccomp
            # inherits PR_SET_NO_NEW_PRIVS.
            if landlock_fn:
                _status_step = b"L"
                landlock_fn()
            # Step 11: seccomp.
            if seccomp_fn:
                _status_step = b"S"
                seccomp_fn()
            # Step 12 (below): pid-ns unshare.
            _status_step = b"U"

            # Step 12: pid-ns via a second fork. NEWPID only takes
            # effect on a subsequent fork. This fork runs INSIDE the
            # already-forked child (single-threaded by then — no other
            # threads survived the parent fork) so the multi-threaded
            # warning shouldn't fire here, but suppress defensively
            # to match every other production fork() site.
            #
            # skip_pid_ns=True keeps the child in the parent's pid-ns
            # (still forks once for the exec-in-child pattern, but no
            # CLONE_NEWPID). This is the escape hatch for tools that
            # break inside a fresh pid-ns — chiefly gdb, whose host-
            # info probe reads /proc/1/* and gets EPERM when PID 1
            # resolves to systemd (in init_user_ns, where our user-ns
            # CAP_SYS_PTRACE doesn't apply). Found via bpftrace 2026-06-14:
            # __ptrace_may_access fires with target_pid=1 target_comm=systemd
            # then returns -EPERM, breaking gdb's bp insertion.
            import warnings as _warnings
            with _warnings.catch_warnings():
                _warnings.filterwarnings(
                    "ignore", category=DeprecationWarning,
                    message=r".*fork.*may lead to deadlocks.*",
                )
                if not skip_pid_ns:
                    os.unshare(CLONE_NEWPID)
                grand = os.fork()
            if grand == 0:
                # Grandchild runs as PID 1 in the new pid-ns.
                #
                # Tie our lifetime to the setup child (the sole
                # death-pipe watcher): a subprocess timeout SIGKILLs
                # that watcher FIRST, and pre-fix nothing then killed
                # this pid-ns init — the target tree survived the
                # timeout, still sandbox-confined but executing and
                # mutating output after the run "ended". PDEATHSIG
                # fires when our parent dies; as ns-init we cascade
                # SIGKILL through the whole namespace (kernel-
                # delivered SIGKILL from the ancestor ns reaches an
                # ns-init). Persists across the target execvpe
                # (no privilege change). The set-after-parent-died
                # race is microseconds wide and covered by the
                # parent-side backstop sweeps.
                try:
                    import ctypes as _ctypes
                    import ctypes.util as _ctypes_util
                    _libc_name = _ctypes_util.find_library("c") or "libc.so.6"
                    _libc = _ctypes.CDLL(_libc_name, use_errno=True)
                    _libc.prctl(1, int(signal.SIGKILL), 0, 0, 0)
                except Exception:  # noqa: BLE001
                    warn_post_fork(
                        b"_spawn: grandchild PR_SET_PDEATHSIG failed; "
                        b"a timeout that kills the setup child may "
                        b"leave the target running\n"
                    )
                    _libc = None
                # /proc was bind-mounted from HOST in setup_mount_ns
                # (step 6) before the pid-ns existed, so it exposes
                # host pids. Inside the new pid-ns the grandchild has
                # ns-local PIDs (1, 2, ...), and any tool that does
                # path lookups on /proc/<pid> (gdb's ptrace+POKE plumbing,
                # for instance) gets ENOENT — the host procfs doesn't
                # know about the ns-local pid. Remount a FRESH proc fs
                # in our newly-entered pid-ns so /proc/<ns-pid> resolves.
                # Best-effort, but the return code is CHECKED: rc=-1
                # used to pass silently, keeping the host-pid procfs
                # bind with no operator-visible signal — the warning
                # names both consequences (ns-pid lookups ENOENT AND
                # host process visibility through the retained bind).
                #
                # DELIBERATE warn-and-continue, not abort: the
                # credential contract does NOT rest on this mount.
                # Access to sensitive per-pid files (environ, mem,
                # fd/*) of host processes is refused by the kernel's
                # pid-ns/user-ns ptrace_may_access rule REGARDLESS of
                # which procfs instance is mounted — host tasks are
                # unmapped in our user namespace. What the retained
                # bind leaks is the world-readable listing surface
                # (pid dentries, cmdline, stat), the documented
                # in-policy /proc residual class. Aborting would turn
                # an environmental quirk (kernels that disallow the
                # second procfs mount in a nested user-ns) into a
                # hard run failure with no credential gain.
                _proc_rc = -1
                try:
                    if _libc is not None:
                        _proc_rc = int(_libc.mount(
                            b"proc", b"/proc", b"proc", 0, None))
                except Exception:  # noqa: BLE001
                    _proc_rc = -1
                if _proc_rc != 0:
                    warn_post_fork(
                        b"_spawn: grandchild fresh proc mount failed; "
                        b"/proc/<ns-pid>/* will ENOENT for gdb/ptrace "
                        b"and the HOST-pid procfs bind stays visible "
                        b"in the sandbox\n"
                    )
                if rootfs is not None and not skip_pid_ns:
                    # Rootfs mode: split so the image entrypoint is PID 2
                    # (a PID-1 entrypoint has kill(2)-delivered signals
                    # filtered — abort()/raise() deaths would vanish).
                    # Returns in the exec-path child; PID 1 stays behind
                    # as the in-process init mirroring exit statuses.
                    _pid1_split_for_waiter()
                if env is not None:
                    exec_env = env
                    # Defense-in-depth: context.py:run() already strips
                    # DANGEROUS_ENV_VARS from the caller env when
                    # strict_env=True, so this re-strip is a no-op on
                    # the standard call path. The kwarg lives here for
                    # parity with _macos_spawn.run_sandboxed and to
                    # protect direct callers of this function that
                    # bypass the run() wrapper (tests, future helpers).
                    if strict_env:
                        from core.config import RaptorConfig
                        _dangerous = set(RaptorConfig.DANGEROUS_ENV_VARS)
                        exec_env = {
                            k: v for k, v in exec_env.items()
                            if k not in _dangerous
                        }
                else:
                    # env=None → scrubbed allowlist env, NOT the full
                    # host environment. The public context.run() path
                    # always supplies an env; this default only serves
                    # direct callers of run_sandboxed, and a sandboxed
                    # child must not inherit ambient secrets because a
                    # caller skipped the wrapper. Allowlist filtering
                    # subsumes the DANGEROUS_ENV_VARS strip.
                    from core.config import RaptorConfig
                    exec_env = RaptorConfig.get_safe_env()
                # bounded fork count via RLIMIT_NPROC (prlimit).
                if nproc_limit and nproc_limit > 0:
                    import resource
                    try:
                        resource.setrlimit(resource.RLIMIT_NPROC,
                                           (nproc_limit, nproc_limit))
                    except (ValueError, OSError):
                        warn_post_fork(b"RAPTOR: _spawn grandchild RLIMIT_NPROC setrlimit failed -- fork-bomb bound not applied\n")
                import resource as _resource
                try:
                    _soft_nofile = _resource.getrlimit(_resource.RLIMIT_NOFILE)[0]
                except (ValueError, OSError):
                    _soft_nofile = 1024
                _keep_fds = {status_w}
                # Enumerate the ACTUALLY-open fds instead of assuming
                # they all sit below the RLIMIT_NOFILE soft limit:
                # _set_rlimits already LOWERED that limit earlier in
                # this child, and lowering NOFILE does not invalidate
                # existing descriptors — a pre-existing inheritable fd
                # numbered at/above the reduced limit survived the old
                # range()-based sweep and rode into the exec as an
                # out-of-policy capability. Fall back to the bounded
                # range only when /proc isn't listable.
                try:
                    _open_fds = [int(_n)
                                 for _n in os.listdir("/proc/self/fd")]
                except (OSError, ValueError):
                    _open_fds = list(range(3, min(_soft_nofile, 65536)))
                for _fd in _open_fds:
                    if _fd > 2 and _fd not in _keep_fds:
                        try:
                            os.close(_fd)
                        except OSError:
                            pass
                try:
                    # nosemgrep: python.lang.security.audit.dangerous-os-exec-tainted-env-args.dangerous-os-exec-tainted-env-args
                    os.execvpe(cmd[0], list(cmd), exec_env)
                except FileNotFoundError:
                    # Target (or a dep) not reachable in the sandboxed view
                    # — typically a mount-ns bind set too narrow. Signal
                    # 'X' so the parent retries Landlock-only (real result
                    # if it was a bind gap; same 127 if genuinely missing).
                    _write_setup_status(status_w, b"X", "exec: file not found")
                    os._exit(127)
                except PermissionError:
                    _write_setup_status(status_w, b"X", "exec: permission denied")
                    os._exit(126)
                os._exit(125)  # unreachable
            else:
                # Report the exec'ing grandchild's pid to the parent.
                # One short ASCII write is atomic (well under PIPE_BUF);
                # best-effort — if the parent went away the observation
                # is simply lost and the run proceeds normally.
                if pid_w is not None:
                    with contextlib.suppress(OSError):
                        os.write(pid_w, str(grand).encode("ascii"))
                    with contextlib.suppress(OSError):
                        os.close(pid_w)
                # Intermediate (pid 1's parent-in-parent-ns). Wait
                # for grandchild and mirror its exit status so the
                # top-level parent sees the same returncode shape
                # subprocess.run would produce:
                #   - normal exit → os._exit with the same code
                #   - signalled  → re-raise the same signal so the
                #     parent's waitpid reports WIFSIGNALED, which
                #     core.sandbox.observe._interpret_result decodes
                #     (rc < 0 → crash detection). A plain `os._exit(
                #     128 + sig)` would look like a normal non-zero
                #     exit to the parent and silently defeat the
                #     crash/sanitizer diagnostics.
                #
                # Death-pipe watch: if the orchestrator (parent) is
                # hard-killed (SIGKILL/OOM/crash), death_w closes →
                # select sees death_r readable (EOF) → we SIGKILL the
                # grandchild so the pid-ns doesn't orphan to init.
                import select as _sel
                while True:
                    try:
                        pid_, status = os.waitpid(grand, os.WNOHANG)
                    except ChildProcessError:
                        status = 9
                        break
                    if pid_ != 0:
                        break
                    try:
                        ready, _, _ = _sel.select([death_r], [], [], 0.05)
                    except (OSError, ValueError):
                        time.sleep(0.05)
                        continue
                    if ready:
                        try:
                            os.kill(grand, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitpid(grand, 0)
                        except ChildProcessError:
                            pass
                        if _forwarder_pid > 0:
                            try:
                                os.kill(_forwarder_pid, signal.SIGKILL)
                                os.waitpid(_forwarder_pid, 0)
                            except (ProcessLookupError,
                                    ChildProcessError, OSError):
                                pass
                        os._exit(137)
                try:
                    os.close(death_r)
                except OSError:
                    pass
                # Clean up the proxy bridge forwarder before
                # mirroring exit status.
                if _forwarder_pid > 0:
                    try:
                        os.kill(_forwarder_pid, 9)  # SIGKILL
                        os.waitpid(_forwarder_pid, 0)
                    except (ProcessLookupError, ChildProcessError,
                            OSError):
                        pass
                if _forwarder_death_w >= 0:
                    try:
                        os.close(_forwarder_death_w)
                    except OSError:
                        pass
                if os.WIFEXITED(status):
                    os._exit(os.WEXITSTATUS(status))
                if os.WIFSIGNALED(status):
                    sig = os.WTERMSIG(status)
                    import signal as _signal
                    try:
                        _signal.signal(sig, _signal.SIG_DFL)
                    except (OSError, ValueError):
                        pass
                    os.kill(os.getpid(), sig)
                    os._exit(128 + sig)
                os._exit(255)
        except BaseException:  # noqa: BLE001
            # Setup failed before exec. Signal WHICH step (status_w) so the
            # parent can degrade (mount) or fail loud (Landlock/seccomp/
            # unshare) deterministically — unspoofably, regardless of exit
            # code or stderr. Then the last-chance stderr diagnostic.
            _tb = traceback.format_exc().strip()
            _write_setup_status(
                status_w, _status_step,
                _tb.splitlines()[-1] if _tb else "",
            )
            # os.write to a possibly-closed/broken stderr → OSError.
            with contextlib.suppress(OSError):
                os.write(2, f"RAPTOR sandbox child failure:\n{traceback.format_exc()}\n".encode())
            os._exit(126)

    # ================ PARENT ================
    # Unix-scope supervisor: the parent owns the parent end of the
    # socketpair; the child ships the seccomp notify fd over it once
    # the filter is loaded. Receive + supervise on a daemon thread so
    # the handshake below is never blocked; the thread exits on EOF
    # (child died before the export) or when the run's finally closes
    # the supervisor.
    _unix_scope_supervisor: list = []
    if _unix_scope_parent_sock is not None:
        _unix_scope_child_sock.close()

        def _unix_scope_receiver() -> None:
            import array as _array
            import socket as _socket_mod2
            sp = _unix_scope_parent_sock
            try:
                sp.settimeout(120)
                fds = _array.array("i")
                try:
                    msg, ancdata, _fl, _ad = sp.recvmsg(
                        64, _socket_mod2.CMSG_SPACE(fds.itemsize))
                except (OSError, TimeoutError):
                    return
                if not msg:
                    return
                for _lvl, _typ, _data in ancdata:
                    if (_lvl == _socket_mod2.SOL_SOCKET
                            and _typ == _socket_mod2.SCM_RIGHTS):
                        fds.frombytes(
                            _data[:len(_data)
                                  - (len(_data) % fds.itemsize)])
                if not fds:
                    return
                notify_fd = fds[0]
                os.set_inheritable(notify_fd, False)
                # Private-tmpfs device ids pinned by the child AFTER
                # mount setup and BEFORE the target exec (payload:
                # b"F2" + count byte + count u64 LE device ids). This
                # pinned set is the supervisor's only private-tmpfs
                # identity evidence — a malformed/short payload yields
                # the EMPTY set (pathname connects then fail closed to
                # the allowlisted instance sockets), never a live
                # re-resolution of the child's rearrangeable view.
                _tmpfs_devs: frozenset[int] = frozenset()
                if len(msg) >= 3 and msg[:2] == b"F2":
                    _want = 3 + 8 * msg[2]
                    while len(msg) < _want:
                        try:
                            _more = sp.recv(_want - len(msg))
                        except (OSError, TimeoutError):
                            break
                        if not _more:
                            break
                        msg += _more
                    if len(msg) >= _want:
                        _tmpfs_devs = frozenset(
                            int.from_bytes(msg[i:i + 8], "little")
                            for i in range(3, _want, 8))
                if not _tmpfs_devs:
                    logger.warning(
                        "unix-scope: no private-tmpfs device pins "
                        "arrived with the notify fd — pathname "
                        "AF_UNIX connects will be limited to the "
                        "allowlisted instance sockets (fail closed).")
                from ._unix_scope import UnixScopeSupervisor
                _allowed = [p for p in ([proxy_unix_socket]
                                        + [b[1] for b in
                                           (extra_unix_bridges or [])])
                            if p]
                # The run's network policy travels WITH the supervisor:
                # Landlock CONNECT_TCP rules and the ABI-6 abstract
                # scope are task-scoped, so a connect the supervisor
                # executes never evaluates them — the supervisor must
                # re-apply the declared TCP port policy itself, and may
                # treat abstract names as netns-scoped only when this
                # run actually unshared a netns for the child.
                sup = UnixScopeSupervisor(
                    notify_fd, allowed_socket_paths=_allowed,
                    label=f"spawn-{child_pid}",
                    allowed_tcp_ports=(list(allowed_tcp_ports)
                                       if allowed_tcp_ports else None),
                    netns_isolated=bool(block_network
                                        and not inherit_netns),
                    private_tmpfs_devs=_tmpfs_devs)
                _unix_scope_supervisor.append(sup)
                sup.serve_forever()
            except Exception:  # noqa: BLE001 — supervisor thread must never propagate
                logger.debug("unix-scope receiver failed", exc_info=True)
            finally:
                with contextlib.suppress(OSError):
                    sp.close()

        threading.Thread(target=_unix_scope_receiver,
                         name=f"unix-scope-recv-{child_pid}",
                         daemon=True).start()
    if child_pid_callback is not None:
        try:
            child_pid_callback(child_pid)
        except Exception:
            logger.warning(
                "child_pid_callback raised; continuing with the run",
                exc_info=True,
            )
    # Initialised before the try so the outer finally can reference it
    # regardless of where in the parent flow we exit.
    tracer_pid: int | None = None
    try:
        # Close the ends the child owns — parent doesn't write to them.
        os.close(p_ready_w)
        _parent_fds.discard(p_ready_w)
        os.close(p_go_r)
        _parent_fds.discard(p_go_r)
        # Exec-status pipe: the parent only READS (status_r); close the
        # write end now (BEFORE the tracer fork below) so the tracer
        # subprocess can never inherit it and hold it open — otherwise the
        # parent's EOF-on-success read would block forever.
        os.close(status_w)
        _parent_fds.discard(status_w)
        # Death pipe: parent holds death_w only; close the read end now
        # (BEFORE the tracer fork) so the tracer can't inherit it.
        os.close(death_r)
        _parent_fds.discard(death_r)
        # Exec-pid pipe: the parent only READS (pid_r); close the write
        # end now (BEFORE the tracer fork) so only the children hold it
        # and EOF reaches the parent when they exit pre-fork.
        if pid_w is not None:
            os.close(pid_w)
            _parent_fds.discard(pid_w)
        if capture_output:
            os.close(out_w)
            _parent_fds.discard(out_w)
            os.close(err_w)
            _parent_fds.discard(err_w)

        # Step 4: wait for child to signal "unshare done, ready for newuidmap".
        try:
            if os.read(p_ready_r, 1) != b"R":
                _kill_and_reap(child_pid)
                msg = "sandbox child did not signal ready"
                raise RuntimeError(msg)
        finally:
            os.close(p_ready_r)
            _parent_fds.discard(p_ready_r)

        # Step 6: newuidmap / newgidmap.
        # Prefer raptor-gidmap-allow when available — it writes gid_map
        # WITHOUT denying setgroups, so targets that call setgroups(2)
        # during init can start.  Falls back to newgidmap silently.
        host_uid = os.getuid()
        host_gid = os.getgid()
        # Trusted-dirs resolution only: these setuid helpers execute
        # in the UNSANDBOXED parent, before any containment exists —
        # the one place a PATH-planted stub would run with the
        # operator's full ambient authority. Mirrors the module's own
        # _resolve_sandbox_binary doctrine (see probes.py).
        newuidmap = _find_sandbox_binary("newuidmap")
        gidmap_allow = _gidmap_allow_available()
        newgidmap = gidmap_allow or _find_sandbox_binary("newgidmap")
        if not newuidmap or not newgidmap:
            _kill_and_reap(child_pid)
            msg = (
                "newuidmap/newgidmap required for mount-ns sandbox — install "
                "the uidmap package"
            )
            raise FileNotFoundError(msg)
        uid_lines = ["0", str(host_uid), "1"]
        gid_lines = ["0", str(host_gid), "1"]
        gidmap_binary = newgidmap
        if rootfs is not None:
            # Rootfs mode wants a RANGE map: container-image entrypoints
            # chown to and setuid/initgroups as non-root uids (www-data,
            # postgres, uid 101, ...). A single-id map makes those fail
            # with EINVAL/EPERM. Map ns-ids 1..N onto the operator's
            # /etc/subuid+/etc/subgid allotment; ns-root stays mapped to
            # the caller so rootfs files created by ns-root remain
            # owned (and cleanable) by the operator on the host side.
            try:
                import pwd
                _user = pwd.getpwuid(host_uid).pw_name
            except (KeyError, OSError):
                _user = str(host_uid)
            _urange = _subid_range("/etc/subuid", _user, str(host_uid))
            _grange = _subid_range("/etc/subgid", _user, str(host_gid))
            # raptor-gidmap-allow accepts EXACTLY one triple by
            # contract; a range map must go through plain newgidmap
            # (setuid — no setgroups-deny involved, so setgroups to
            # mapped gids keeps working).
            _plain_newgidmap = _find_sandbox_binary("newgidmap")
            if _urange and _grange and _plain_newgidmap:
                _ucount = max(1, min(_urange[1], 65535))
                _gcount = max(1, min(_grange[1], 65535))
                uid_lines += ["1", str(_urange[0]), str(_ucount)]
                gid_lines += ["1", str(_grange[0]), str(_gcount)]
                gidmap_binary = _plain_newgidmap
            else:
                logger.warning(
                    "rootfs sandbox: no usable /etc/subuid+/etc/subgid "
                    "allotment (or plain newgidmap missing) — running "
                    "with the single-id map; image entrypoints that "
                    "chown/setuid to other uids will fail (EINVAL)"
                )
        try:
            _run_newuidmap(child_pid, newuidmap, uid_lines)
            # Argument contract with raptor-gidmap-allow (see the header
            # comment in helpers/raptor-gidmap-allow.c): exactly ONE
            # strictly-numeric triple mapping gid 0 inside the namespace
            # to the invoker's own gid, on a namespace the invoker just
            # created. The helper refuses foreign gids, namespaces owned
            # by other uids, and non-numeric or oversized mappings
            # (exit 3) — which is why the rootfs range map above swaps
            # to plain newgidmap.
            _run_newuidmap(child_pid, gidmap_binary, gid_lines)
        except Exception:
            _kill_and_reap(child_pid)
            raise

        # Step 7.5 (audit mode): fork the tracer subprocess and wait
        # for it to signal "attached and ready" before unblocking the
        # target's exec. The order matters: if we wrote "G" first, the
        # target would exec and start hitting traced syscalls before
        # the tracer was attached → SIGSYS-kill mid-startup.
        if _audit_engaged:
            # Important fd ordering: keep BOTH ends of the t_ready pipe
            # open in the parent until AFTER the tracer fork — the
            # tracer subprocess inherits the parent's open fd table and
            # needs t_ready_w as its sync_fd. If we closed t_ready_w in
            # the parent before fork, the tracer would inherit a closed
            # fd and its sync write would silently fail.
            #
            # Suppress Python 3.12+ multi-threaded-fork DeprecationWarning.
            # Tracer subprocess does only fd-close + execvpe in the
            # child path — no Python objects, no GIL. Same fork-safety
            # contract as the main child fork above.
            import warnings as _warnings
            with _warnings.catch_warnings():
                _warnings.filterwarnings(
                    "ignore", category=DeprecationWarning,
                    message=r".*fork.*may lead to deadlocks.*",
                )
                tracer_pid = os.fork()
            if tracer_pid == 0:
                # ===== TRACER SUBPROCESS =====
                # Own session: the tracer must NOT share the
                # orchestrator's process group. A hostile audited
                # target can keep the tracer alive past the reap
                # grace (a traced setsid descendant), and the
                # _kill_and_reap fallback then killpg's the tracer's
                # group — which, pre-setsid, WAS the orchestrator's
                # own (the killpg self-group guard is the second
                # layer; this makes the group correct to begin with).
                try:
                    os.setsid()
                except OSError:
                    pass
                # Close the read end — only the parent reads.
                os.close(t_ready_r)
                # Defence-in-depth: close all inherited fds except
                # stdio (0/1/2) and the sync write end. The tracer
                # subprocess has no legitimate need for the parent's
                # other open fds (proxy listener socket, prior
                # sandbox pipe ends, lifecycle file handles, etc.).
                # Without this close, those fds remain open across
                # the execvpe — they're not used by the tracer code,
                # but a future bug in the tracer that inadvertently
                # writes to fd N would corrupt whatever the parent
                # had open at N. Also defends against fd-table
                # exhaustion across many sandbox calls.
                #
                # Bound the close range to the actual RLIMIT_NOFILE
                # soft limit. A previous version hardcoded 1024,
                # which leaked any inherited fd >= 1024 on long-
                # running RAPTOR processes that had bumped their
                # NOFILE soft limit (multi-fuzzer setups, daemon
                # mode). Caps at 65536 to avoid pathological
                # 4G-iteration loops on systems with hard=infinity.
                #
                # Use os.closerange() in two split ranges around
                # the sync_fd we want to keep — single syscall per
                # range on Linux (close_range(2) on 5.9+) instead
                # of per-fd python-level close+EBADF-handling. ~1ms
                # → ~10us per tracer fork.
                import resource as _resource
                soft, _hard = _resource.getrlimit(
                    _resource.RLIMIT_NOFILE)
                upper = min(soft, 65536)
                # fds the tracer legitimately needs across its exec:
                # the sync write end, the audit-config anonymous fd,
                # and the held evidence fd. closerange over the gaps
                # between them — one close_range(2) syscall per gap
                # on Linux 5.9+.
                _keep = sorted(
                    fd for fd in (
                        t_ready_w,
                        _audit_config_fd,
                        _evidence_file.fd if _evidence_file is not None
                        else None,
                    )
                    if fd is not None and 3 <= fd < upper
                )
                _lo = 3
                for _k in _keep:
                    os.closerange(_lo, _k)
                    _lo = _k + 1
                os.closerange(_lo, upper)
                # The range ceiling derives from the CURRENT soft
                # limit; fds can legitimately exist at/above it (a
                # caller that lowered NOFILE after opening them, or
                # a >65536 table). Sweep the stragglers by
                # enumeration — cheap, and the keep-set fds are all
                # below `upper` by construction.
                try:
                    for _n in os.listdir("/proc/self/fd"):
                        _f = int(_n)
                        if _f >= upper:
                            try:
                                os.close(_f)
                            except OSError:
                                pass
                except (OSError, ValueError):
                    pass
                # Clear CLOEXEC on the config + evidence fds so THEY
                # survive the tracer's execvpe. Only ever done in
                # this post-fork tracer branch — the target child's
                # exec keeps the default close-on-exec, so the
                # nonce-carrying config and the evidence fd never
                # reach the target's fd table.
                for _fd in (_audit_config_fd,
                            _evidence_file.fd if _evidence_file is not None
                            else None):
                    if _fd is not None:
                        os.set_inheritable(_fd, True)
                # Replace argv via execvpe so the tracer runs as a
                # clean Python module without inheriting the parent's
                # complicated state. Pass the target_pid, audit_run_dir,
                # and the write end of t_ready as the sync_fd argument.
                #
                # Use the current Python interpreter for module loading
                # consistency. Interpreter lockdown comes from the
                # hand-crafted 2-key env below, not from `-I` — see
                # the note ahead of tracer_env for why isolated mode
                # is deliberately not used here (unlike
                # raptor-pid1-shim, which can afford it).
                try:
                    raptor_dir = os.environ.get("RAPTOR_DIR")
                    if raptor_dir is None:
                        # Last-resort: derive from this module's path.
                        raptor_dir = str(
                            Path(__file__).resolve().parent.parent.parent
                        )
                    # Tightly-controlled env: PYTHONPATH for module
                    # resolution, minimal PATH, nothing inherited.
                    # We do NOT use `-I` (isolated mode) because that
                    # ignores PYTHONPATH, leaving the tracer unable
                    # to import core.sandbox. The lockdown -I would
                    # provide is already covered: env is hand-crafted
                    # (no PYTHONHOME, PYTHONSTARTUP), no user site,
                    # no inherited dotfiles via fake_home elsewhere.
                    tracer_env = {
                        "PYTHONPATH": raptor_dir,
                        "PATH": "/usr/bin:/bin",
                    }
                    # Build tracer argv: pid, run_dir, sync_fd,
                    # optional config arg. The config arg is the
                    # /proc/self/fd/N spelling of the anonymous
                    # config fd — "self" resolves in the TRACER when
                    # it opens the path, so the argv value (visible
                    # in /proc/<pid>/cmdline) discloses nothing.
                    tracer_argv = [
                        sys.executable, "-m", "core.sandbox.tracer",
                        str(child_pid), str(audit_run_dir),
                        str(t_ready_w),
                    ]
                    if _audit_config_arg is not None:
                        tracer_argv.append(_audit_config_arg)
                    # nosemgrep: python.lang.security.audit.dangerous-os-exec-tainted-env-args.dangerous-os-exec-tainted-env-args
                    # tracer_env is hand-crafted: 2 keys
                    # (PYTHONPATH + PATH), no inheritance. Explicitly
                    # safer than os.environ-copy.
                    os.execvpe(
                        sys.executable, tracer_argv, tracer_env,
                    )
                except FileNotFoundError:
                    # sys.executable doesn't exist or PATH lookup
                    # failed. Distinct exit code (127, matches
                    # subprocess's ENOENT-during-exec convention)
                    # so the parent's diagnostic can name the
                    # actual cause instead of guessing PTRACE_SEIZE
                    # rejection.
                    os._exit(127)
                except PermissionError:
                    # sys.executable not executable. Distinct code
                    # 126 (matches subprocess convention).
                    os._exit(126)
                except Exception:  # noqa: BLE001
                    # Unknown execvpe failure (rare). 125 distinct
                    # from the documented codes so it's not
                    # confused with a successful run.
                    os._exit(125)

            # Parent: drop our copy of the anonymous config fd now —
            # the tracer holds its own inherited copy (and closes it
            # right after parsing). Closing here minimises the window
            # in which /proc/<parent-pid>/fd exposes the nonce-
            # carrying config to same-UID processes.
            if _audit_config_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(_audit_config_fd)
                _audit_config_fd = None

            # Parent: close the write end now (tracer has its own copy).
            # Without this close, the parent's `os.read(t_ready_r, ...)`
            # below would block FOREVER on tracer death, because the
            # parent's own t_ready_w would keep the pipe write end
            # alive and EOF would never be signalled to the read.
            os.close(t_ready_w)
            _parent_fds.discard(t_ready_w)

            # Parent: wait for tracer to signal ready. If tracer dies
            # before signalling, our read returns 0 bytes — treat as
            # "tracer failed" and abort the sandbox.
            try:
                ready = os.read(t_ready_r, 1)
            finally:
                os.close(t_ready_r)
                _parent_fds.discard(t_ready_r)
            if not ready:
                # Tracer failed to attach. Reap it (capture exit code
                # for diagnostics), kill the target child (still
                # blocked on go-pipe), abort.
                tracer_status: int | None = None
                try:
                    _, tracer_status = os.waitpid(tracer_pid, 0)
                except (ChildProcessError, OSError):
                    pass
                _kill_and_reap(child_pid)
                # Translate the tracer's exit code into an actionable
                # diagnostic. Default suspect is PTRACE_SEIZE rejection
                # (the most common cause), but specific exit codes
                # mean different things — operator gets the right
                # remediation hint.
                rc_hint = ""
                cause = ("PTRACE_SEIZE rejected (Yama scope, "
                         "container cap-drop, AppArmor, or user-ns "
                         "cred mismatch post-newuidmap)")
                if tracer_status is not None:
                    if os.WIFEXITED(tracer_status):
                        ec = os.WEXITSTATUS(tracer_status)
                        rc_hint = f" (tracer exit code {ec})"
                        if ec == 127:
                            cause = (f"tracer interpreter "
                                     f"{sys.executable!r} not found "
                                     f"or not executable — check "
                                     f"sys.executable resolves "
                                     f"correctly in this environment")
                        elif ec == 126:
                            cause = (f"tracer interpreter "
                                     f"{sys.executable!r} found but "
                                     f"not executable — check file "
                                     f"permissions / mount options")
                        elif ec == 125:
                            cause = ("tracer subprocess failed to "
                                     "exec for an unknown reason — "
                                     "see RAPTOR debug logs for the "
                                     "execvpe stack trace")
                        elif ec == 1:
                            cause = ("tracer rejected its CLI "
                                     "arguments — likely a bug in "
                                     "_spawn's tracer_argv "
                                     "construction; please report")
                        elif ec == 2:
                            cause = (f"tracer ran on an unsupported "
                                     f"CPU architecture (x86_64 / "
                                     f"aarch64 only); current "
                                     f"platform={platform.machine()}")
                        # ec == 3 is the documented PTRACE_SEIZE
                        # rejection — keep the default cause text.
                    elif os.WIFSIGNALED(tracer_status):
                        rc_hint = (f" (tracer killed by signal "
                                   f"{os.WTERMSIG(tracer_status)})")
                        cause = ("tracer killed by an external "
                                 "signal before it could attach — "
                                 "OOM-killer? operator's session "
                                 "terminated?")
                msg = (
                    f"audit-mode tracer failed to attach to sandboxed "
                    f"child{rc_hint} — {cause}"
                )
                raise RuntimeError(msg)

        # Step 8: tell child to proceed.
        try:
            os.write(p_go_w, b"G")
        finally:
            os.close(p_go_w)
            _parent_fds.discard(p_go_w)

        # Step 8.9: deliver the live grandchild pid to the caller.
        # Blocks (bounded) until the intermediate has forked the
        # grandchild and written its pid — i.e. after mount/Landlock/
        # seccomp setup completed. A select timeout (child wedged in
        # setup) or EOF-without-data (child failed pre-fork; the exec-
        # status pipe carries the real diagnostic) both degrade to
        # "callback not invoked".
        if pid_r is not None:
            _exec_pid = None
            try:
                import select as _pid_sel
                _pid_ready, _, _ = _pid_sel.select([pid_r], [], [], 15.0)
                if _pid_ready:
                    _pid_raw = os.read(pid_r, 64)
                    if _pid_raw:
                        try:
                            _exec_pid = int(_pid_raw)
                        except ValueError:
                            _exec_pid = None
            except OSError:
                _exec_pid = None
            finally:
                try:
                    os.close(pid_r)
                except OSError:
                    pass
                _parent_fds.discard(pid_r)
            if _exec_pid is not None and _exec_pid > 0:
                try:
                    exec_pid_callback(_exec_pid)
                except Exception:
                    logger.warning(
                        "exec_pid_callback raised; continuing with the "
                        "sandboxed run", exc_info=True,
                    )
    except BaseException:
        # Any failure above: kill+reap the target child if it's not
        # already dead, reap the audit tracer if forked, close
        # remaining pipe fds, remove the stub dir, then propagate.
        #
        # Most nested handlers DO call _kill_and_reap(child_pid)
        # before raising (the "child did not signal ready", uidmap
        # missing, _run_newuidmap fail, audit-fail branches all
        # do it). But some failure points don't — e.g., a
        # BrokenPipeError on `os.write(p_go_w, b"G")` if the child
        # died mid-startup, or any unexpected exception in the
        # post-newuidmap parent flow. Route through _teardown_target
        # (death-pipe EOF first — the go signal may already have been
        # written, meaning the grandchild can exist and may have
        # setsid'd out of the killable group). Both helpers are
        # idempotent (ProcessLookupError + ChildProcessError caught)
        # so re-reaping an already-dead child is harmless.
        if child_pid > 0:
            try:
                _teardown_target(child_pid, death_w, _parent_fds)
            except Exception:
                logger.debug("child reap during cleanup failed",
                             exc_info=True)
        # If the audit-mode tracer was forked but the parent-side flow
        # failed before reaching the final `finally:` (which has the
        # only other call to _reap_tracer), the tracer would otherwise
        # leak as a zombie. PTRACE_O_EXITKILL has already SIGKILL'd
        # any remaining tracees, so the tracer's loop should terminate
        # promptly — _reap_tracer waits 2s then SIGKILLs as backstop.
        if tracer_pid is not None:
            try:
                _reap_tracer(tracer_pid)
            except Exception:
                logger.debug("tracer reap during cleanup failed",
                             exc_info=True)
        if _audit_config_fd is not None:
            with contextlib.suppress(OSError):
                os.close(_audit_config_fd)
            # Mark closed so the final-finally below doesn't try to
            # close an already-released fd. Keeps the audit lifecycle
            # bookkeeping honest.
            _audit_config_fd = None
        if _evidence_file is not None:
            # Finalise the evidence file — the inode verification
            # inside close() fires its loud warning here too, so a
            # tamper attempt isn't masked by an unrelated failure.
            _evidence_file.close()
            _evidence_file = None
        _close_leftover()
        _cleanup_stub(_root_dir)
        raise

    # Step 14: collect output and wait. Everything from here down runs
    # under a try/finally so a TimeoutExpired (or any other unexpected
    # exception) still cleans up the mkdtemp stub — otherwise every
    # sandboxed command that exceeds `timeout` would leak a
    # .raptor-sbx-* dir under /tmp.
    stdout_buf = b"" if capture_output else None
    stderr_buf = b"" if capture_output else None
    # Per-stream capture ceiling: the child's RLIMIT_FSIZE/AS bound
    # its FILES, not its pipe writes — a hostile target streaming
    # gigabytes to stdout ballooned the TRUSTED PARENT's memory well
    # inside any timeout. Past the cap the stream is drained and
    # DISCARDED (the child never blocks) and a truncation marker is
    # appended so consumers can tell.
    _CAPTURE_CAP = 64 * 1024 * 1024
    _truncated = {1: False, 2: False}
    # time.monotonic() for deadline math — see _reap_tracer() above for the
    # NTP/wall-clock-jump rationale; same hazard applies here.
    deadline = time.monotonic() + timeout if timeout else None
    # Exec-status verdict — populated in the finally so the pipe is read and
    # status_r reclaimed on EVERY exit path (success, timeout, exception).
    setup_status = None
    try:
        if capture_output:
            import select
            fds = [out_r, err_r]
            try:
                while fds:
                    remaining = (deadline - time.monotonic()) if deadline else None
                    if remaining is not None and remaining <= 0:
                        # Death-pipe EOF BEFORE killing the
                        # intermediate — see _teardown_target: a
                        # setsid()'d target escapes the killpg sweep
                        # and only the (still-alive) watcher can
                        # reach it by pid.
                        _teardown_target(child_pid, death_w, _parent_fds)
                        out_str = stdout_buf.decode("utf-8", errors="replace") if text else stdout_buf
                        err_str = stderr_buf.decode("utf-8", errors="replace") if text else stderr_buf
                        raise subprocess.TimeoutExpired(
                            list(cmd), timeout, output=out_str, stderr=err_str
                        )
                    ready, _, _ = select.select(fds, [], [], remaining)
                    for fd in ready:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            os.close(fd)
                            _parent_fds.discard(fd)
                            fds.remove(fd)
                        elif fd == out_r:
                            if len(stdout_buf) < _CAPTURE_CAP:
                                stdout_buf += chunk
                            else:
                                _truncated[1] = True
                        else:
                            if len(stderr_buf) < _CAPTURE_CAP:
                                stderr_buf += chunk
                            else:
                                _truncated[2] = True
                if _truncated[1]:
                    stdout_buf += (b"\n[RAPTOR sandbox: stdout "
                                   b"capture truncated at 64 MiB]\n")
                if _truncated[2]:
                    stderr_buf += (b"\n[RAPTOR sandbox: stderr "
                                   b"capture truncated at 64 MiB]\n")
            finally:
                # Close any pipes we didn't drain (timeout, exception).
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    _parent_fds.discard(fd)

        try:
            # waitpid with a remaining timeout window.
            if deadline:
                while True:
                    pid_, status = os.waitpid(child_pid, os.WNOHANG)
                    if pid_ != 0:
                        break
                    if time.monotonic() > deadline:
                        # Death-pipe EOF first — same setsid-escape
                        # rationale as the capture_output branch above.
                        _teardown_target(child_pid, death_w, _parent_fds)
                        out_str = (stdout_buf or b"").decode("utf-8", errors="replace") if text else stdout_buf
                        err_str = (stderr_buf or b"").decode("utf-8", errors="replace") if text else stderr_buf
                        raise subprocess.TimeoutExpired(
                            list(cmd), timeout, output=out_str, stderr=err_str
                        )
                    time.sleep(0.01)
            else:
                _, status = os.waitpid(child_pid, 0)
        except ChildProcessError:
            # Child already reaped (ECHILD) — real exit status lost.
            # Synthesise SIGKILL (raw wait-status 9) so downstream
            # returncode is -9, not 0 (false success).
            logger.warning("waitpid: child %d already reaped (ECHILD); "
                           "exit status unknown", child_pid)
            status = 9
    finally:
        # Drain + close the exec-status pipe FIRST so status_r is reclaimed
        # even if a cleanup step below raises — an unclosed status_r leaks
        # one fd per timed-out call and eventually exhausts the table,
        # breaking all subsequent sandboxing. The child is reaped by now
        # (success: waitpid above; timeout: _kill_and_reap before the raise),
        # so any status byte is already buffered. On timeout the target had
        # execed (hence the timeout) → no status → None.
        setup_status = _drain_status_pipe(status_r, _parent_fds)
        # Death pipe write end: child has exited (or been killed), no
        # longer needed. Close it so the fd doesn't leak.
        if death_w in _parent_fds:
            try:
                os.close(death_w)
            except OSError:
                pass
            _parent_fds.discard(death_w)
        # Unix-scope supervisor: the run is over — close the notify fd
        # so any straggler's connect(2) gets ENOSYS from the kernel
        # (fail-closed) and the receiver thread exits.
        for _sup in _unix_scope_supervisor:
            _sup.close()
        if _unix_scope_parent_sock is not None:
            # shutdown() BEFORE close(): it wakes a receiver thread
            # still blocked in recvmsg (close alone does not).
            import socket as _socket_mod3
            with contextlib.suppress(OSError):
                _unix_scope_parent_sock.shutdown(_socket_mod3.SHUT_RDWR)
            with contextlib.suppress(OSError):
                _unix_scope_parent_sock.close()
        # Audit-mode tracer cleanup: target has exited (or been killed
        # via timeout), so the tracer's traced set will become empty
        # and it'll exit naturally. Wait for it to reap; if it doesn't
        # exit promptly, kill it (PTRACE_O_EXITKILL has already done
        # the right thing for any surviving tracees).
        if tracer_pid is not None:
            _reap_tracer(tracer_pid)
        # Release the anonymous config fd (normally already closed
        # right after the tracer fork; this covers early-exit paths).
        if _audit_config_fd is not None:
            with contextlib.suppress(OSError):
                os.close(_audit_config_fd)
        # Finalise the evidence file AFTER the tracer is reaped so no
        # writer shares the description any more: verify the on-disk
        # path still names the inode created at sandbox start (loud
        # warning on a swap), then close the held fd.
        if _evidence_file is not None:
            _evidence_file.close()
        _cleanup_stub(_root_dir)

    if os.WIFEXITED(status):
        returncode = os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        returncode = -os.WTERMSIG(status)
    else:
        returncode = -1

    # setup_status was drained from the exec-status pipe in the finally above
    # (on every exit path). Bytes ⇒ the child reported a setup failure BEFORE
    # exec (M/L/S/U/X); None ⇒ the target actually execed, so the
    # returncode/output are a genuine result. Unspoofable: status_w is
    # close-on-exec, gone before the target runs.
    stdout_out = stderr_out = None
    if capture_output:
        stdout_out = stdout_buf.decode("utf-8", errors="replace") if text else stdout_buf
        stderr_out = stderr_buf.decode("utf-8", errors="replace") if text else stderr_buf

    cp = subprocess.CompletedProcess(
        args=list(cmd),
        returncode=returncode,
        stdout=stdout_out,
        stderr=stderr_out,
    )
    # Authoritative setup-failure signal for context.py's decision table
    # (degrade on M/X, fail loud on L/S/U). None ⇒ target execed.
    cp._setup_status = setup_status
    return cp
