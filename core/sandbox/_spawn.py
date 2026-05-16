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

import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import state
from .landlock import _make_landlock_preexec
from .mount_ns import setup_mount_ns
from .seccomp import _make_seccomp_preexec

logger = logging.getLogger(__name__)

# CLONE flags from <linux/sched.h>. Python 3.12 exposes os.CLONE_* with the
# same values — we prefer the stdlib names when available so any future
# kernel-ABI churn surfaces via Python's own headers rather than our
# hardcoded copy. Requires Python 3.12+ (already enforced by the
# os.unshare() call below, which was also new in 3.12).
CLONE_NEWNS   = getattr(os, "CLONE_NEWNS",   0x00020000)
CLONE_NEWIPC  = getattr(os, "CLONE_NEWIPC",  0x08000000)
CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
CLONE_NEWPID  = getattr(os, "CLONE_NEWPID",  0x20000000)
CLONE_NEWNET  = getattr(os, "CLONE_NEWNET",  0x40000000)


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
        newuidmap = shutil.which("newuidmap")
        newgidmap = shutil.which("newgidmap")
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
                capture_output=True, timeout=2,
                env=RaptorConfig.get_safe_env(),
            )
            _ = r.returncode  # binary is callable
        except Exception:
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
        cmd, capture_output=True, text=True, timeout=5,
        env=RaptorConfig.get_safe_env(),
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"{binary} for child {child_pid} failed "
            f"(rc={r.returncode}, stderr={r.stderr.strip()!r})"
        )


def _set_rlimits(limits: dict) -> None:
    """Apply rlimits in the child. Mirrors preexec.py's _set_limits but
    designed to run before mount ops / Landlock / seccomp."""
    import resource
    from .preexec import _DEFAULT_LIMITS
    from ._fork_safe_warn import warn_post_fork
    mem = limits.get("memory_mb", _DEFAULT_LIMITS["memory_mb"])
    file_mb = limits.get("max_file_mb", _DEFAULT_LIMITS["max_file_mb"])
    cpu = limits.get("cpu_seconds", _DEFAULT_LIMITS["cpu_seconds"])
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
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        warn_post_fork(b"RAPTOR: _set_rlimits RLIMIT_CORE setrlimit failed -- coredump suppression relies on kernel core_pattern\n")


def _kill_and_reap(pid: int) -> None:
    """SIGKILL `pid` and reap it. Both ops are best-effort — if the
    child already exited (ProcessLookupError) or was reaped elsewhere
    (ChildProcessError), we just return. Used on every error path
    where the parent has to abandon the child mid-setup.

    On Linux 5.3+ uses pidfd_open + pidfd_send_signal so the SIGKILL
    cannot land on a reused PID if the original child is gone. Falls
    back to os.kill() on older kernels or when pidfd_open() is missing
    from this Python build (3.9+ has it stdlib).
    """
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
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
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
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
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            pid, _ = os.waitpid(tracer_pid, os.WNOHANG)
        except ChildProcessError:
            return  # already reaped by someone else
        if pid != 0:
            return
        time.sleep(0.02)
    # Tracer didn't exit; force.
    _kill_and_reap(tracer_pid)


def _sweep_stale_audit_configs() -> None:
    """Remove stale raptor-audit-cfg-* tempfiles in /tmp owned by
    the current UID, dating from prior crashed runs.

    Audit-config tempfiles get unlinked in the normal lifecycle path
    (BaseException + final finally in run_sandboxed). But if the
    parent process gets SIGKILL'd mid-audit (OOM, kernel panic,
    operator's session terminated externally), the tempfile leaks.
    Accumulation is slow but real on long-lived dev machines.

    Sweep on first engaged-audit per process (idempotent — no-op
    when no stale files exist). Same-UID-only — never touch other
    operators' files. Best-effort: any unlink failure is silently
    ignored (file may have been cleaned up by another process,
    or ownership changed).
    """
    import glob
    my_uid = os.getuid()
    for path in glob.glob("/tmp/raptor-audit-cfg-*.json"):
        try:
            st = os.lstat(path)
            if st.st_uid != my_uid:
                continue
            os.unlink(path)
        except OSError:
            continue


_audit_swept = False


def _cleanup_stub(root_dir: str) -> None:
    """Remove the mkdtemp sandbox-root stub after the child exits.

    lstat-check defeats TOCTOU: if a same-UID attacker raced to replace
    the random-name stub with a symlink between tmpdir creation and our
    cleanup, rmdir on the symlink would fail (ENOTDIR), and we
    deliberately do not fall back to a recursive remove — stale stubs
    are an acceptable leak, removing the wrong thing via symlink-follow
    is not.
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


def run_sandboxed(
    cmd: Sequence[str],
    *,
    target: Optional[str],
    output: Optional[str],
    block_network: bool,
    nproc_limit: int,
    limits: dict,
    writable_paths: Iterable[str],
    readable_paths: Optional[Iterable[str]],
    allowed_tcp_ports: Optional[Iterable[int]],
    seccomp_profile: Optional[str],
    seccomp_block_udp: bool,
    env: Optional[dict],
    cwd: Optional[str],
    timeout: Optional[float],
    capture_output: bool = True,
    text: bool = True,
    stdin=None,
    start_new_session: bool = True,
    audit_mode: bool = False,
    audit_run_dir: Optional[str] = None,
    audit_verbose: bool = False,
    observe_mode: bool = False,
    observe_nonce: Optional[str] = None,
    restrict_reads: bool = False,
) -> subprocess.CompletedProcess:
    """Run `cmd` inside a fully-isolated sandbox.

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
    """
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
    _audit_config_path: Optional[str] = None
    if audit_mode:
        if audit_run_dir is None:
            # Clean up the just-created mkdtemp stub before raising.
            # Pre-fix this raise leaked a `.raptor-sbx-*` directory on
            # every misuse of the API. The fork try/except below only
            # covers cleanup AFTER the audit-mode setup completes.
            _cleanup_stub(_root_dir)
            raise ValueError(
                "audit_mode=True requires audit_run_dir="
            )
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
        from .ptrace_probe import check_ptrace_available
        from .seccomp import check_seccomp_available
        if not seccomp_profile:
            logger.debug(
                "audit_mode=True but no seccomp filter active; "
                "skipping tracer (b2/b3 audit are no-ops without "
                "seccomp). Network audit (b1) is configured separately."
            )
        elif not check_seccomp_available():
            # libseccomp missing — tracer would attach but never
            # receive events (no filter installed). Skip the
            # ~200ms fork+SEIZE overhead.
            logger.debug(
                "audit_mode=True but libseccomp unavailable; "
                "skipping tracer (no filter would be installed)."
            )
        elif check_ptrace_available():
            _audit_engaged = True
            # First engaged-audit per process: sweep stale config
            # tempfiles from prior crashed runs (SIGKILL'd parent
            # leaves the mkstemp file behind). Idempotent; no-op
            # when no stale files exist.
            global _audit_swept
            if not _audit_swept:
                _sweep_stale_audit_configs()
                _audit_swept = True
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
            _writable = []
            for p in (writable_paths or ()):
                _writable.append(_osp.abspath(p))
            _writable.append("/tmp")
            if output:
                _writable.append(_osp.abspath(output))
            _read_allow = list(_writable)
            for p in (readable_paths or ()):
                _read_allow.append(_osp.abspath(p))
            for p in _system_ro:
                _read_allow.append(p)
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
            from . import state as _state
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
            }
            # mkstemp under /tmp; cleaned up after tracer exits.
            # If the write fails (disk full, EIO mid-flight), the
            # tracer would later read an empty/partial JSON file →
            # decode error → exit 1 → parent times out waiting for
            # ready → audit silently disabled. Better: catch the
            # write failure HERE, unlink the partial file, raise so
            # the operator sees an error AT spawn-time rather than
            # an ambiguous "tracer attach failed" minutes later.
            import tempfile as _tf
            import json as _json
            _cfd, _audit_config_path = _tf.mkstemp(
                prefix="raptor-audit-cfg-", suffix=".json",
            )
            _serialised = _json.dumps(audit_config).encode("utf-8")
            try:
                # os.write may write fewer bytes than requested
                # (rare on local fs, possible on network mounts).
                # Loop until done or error.
                _written = 0
                while _written < len(_serialised):
                    n = os.write(_cfd, _serialised[_written:])
                    if n <= 0:
                        raise OSError(
                            "audit-config write returned 0 bytes — "
                            "filesystem may be full or read-only"
                        )
                    _written += n
            except BaseException:
                # Partial / failed write — unlink the empty/partial
                # file AND the mkdtemp stub created above, then
                # propagate so the operator sees the error immediately
                # rather than an ambiguous tracer timeout later. The
                # fork try/except below would re-cleanup if reached,
                # but it isn't reached when we raise here, so do both
                # cleanups inline.
                try:
                    os.close(_cfd)
                except OSError:
                    pass
                try:
                    os.unlink(_audit_config_path)
                except OSError:
                    pass
                _cleanup_stub(_root_dir)
                _audit_config_path = None
                _audit_engaged = False
                raise
            finally:
                # Close the fd — only if not already closed by the
                # except branch above.
                try:
                    os.close(_cfd)
                except OSError:
                    pass
        else:
            # Probe already logged the once-per-process warning with
            # workaround pointers; nothing more to say here. Workflow
            # continues, just without b2/b3 audit signal.
            pass

    # Track every fd we hold in the parent so a failure ANYWHERE from
    # pipe()/fork() through the newuidmap handshake closes the lot.
    # Built before any pipe is opened so partial-open failures also get
    # cleaned up. Each successful transfer (dup/close/finished read)
    # pops from this set.
    _parent_fds: set = set()

    def _close_leftover():
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

        # Output capture pipes (optional).
        if capture_output:
            out_r, out_w = os.pipe()
            _parent_fds.update({out_r, out_w})
            err_r, err_w = os.pipe()
            _parent_fds.update({err_r, err_w})
        else:
            out_r = err_r = out_w = err_w = None

        # Precompute Landlock / seccomp preexec callables in parent so
        # import errors surface before fork. Each returns a callable we
        # can invoke in the child.
        landlock_fn = None
        if writable_paths or allowed_tcp_ports:
            effective_paths = list(writable_paths) if writable_paths else ["/tmp"]
            if "/tmp" not in effective_paths:
                effective_paths.append("/tmp")
            landlock_fn = _make_landlock_preexec(
                effective_paths,
                list(allowed_tcp_ports) if allowed_tcp_ports else None,
                readable_paths=list(readable_paths) if readable_paths else None,
            )
        seccomp_fn = _make_seccomp_preexec(
            seccomp_profile, block_udp=seccomp_block_udp,
            audit_mode=_audit_engaged,
            observe_mode=bool(observe_mode) and _audit_engaged,
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
        # Any failure before fork returns: close opened pipes, unlink
        # the audit-config tempfile if it was created, and remove the
        # mkdtemp stub. Without this, a pipe-exhaustion OSError or
        # import-time failure in preexec construction would leak FDs,
        # the audit-config file, and a .raptor-sbx-* dir on every call.
        _close_leftover()
        if _audit_config_path is not None:
            try:
                os.unlink(_audit_config_path)
            except OSError:
                pass
        _cleanup_stub(_root_dir)
        raise
    if child_pid == 0:
        # ================ CHILD ================
        # Close the ends of the pipes we don't use.
        os.close(p_ready_r)
        os.close(p_go_w)
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
            if block_network:
                ns_flags |= CLONE_NEWNET
            os.unshare(ns_flags)

            # Step 4.5 (audit mode): declare PR_SET_PTRACER_ANY so the
            # tracer subprocess (our sibling, not descendant) can SEIZE
            # us under Yama scope 1. Must run BEFORE we signal "R" to
            # the parent — the parent will fork the tracer right after
            # newuidmap, and the tracer attempts SEIZE while we're
            # blocked on the go-pipe. Without prctl in place by then,
            # the SEIZE returns EPERM under default Yama policy.
            #
            # The child here is uid 65534 ("nobody") after unshare but
            # before newuidmap — PR_SET_PTRACER doesn't require any
            # capability; it just declares permission to be traced.
            if _audit_engaged:
                try:
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
                except Exception:
                    # prctl failure isn't fatal — Yama may already be
                    # permissive. Tracer's SEIZE is the actual gate.
                    pass

            # Step 5: tell parent we're ready for newuidmap.
            os.write(p_ready_w, b"R")
            os.close(p_ready_w)

            # Step 7: wait for parent 'go' signal — parent has run
            # newuidmap by this point.
            try:
                if os.read(p_go_r, 1) != b"G":
                    os._exit(125)
            finally:
                os.close(p_go_r)

            # Child is now uid 0 in the new ns.
            if os.getuid() != 0:
                # newuidmap didn't take — parent must have failed.
                os._exit(124)

            # rlimits as early as possible so later setup is constrained.
            _set_rlimits(limits)

            # Step 9: mount-ns pivot_root if target/output supplied.
            # readable_paths from the caller also get bind-mounted at
            # their original paths so they exist inside the pivoted
            # root — otherwise Landlock's allowlist would cover a path
            # the child can't reach (ENOENT before EACCES).
            if target or output:
                setup_mount_ns(target, output,
                               extra_ro_paths=readable_paths,
                               root_path=_root_dir)

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
                landlock_fn()
            # Step 11: seccomp.
            if seccomp_fn:
                seccomp_fn()

            # Step 12: pid-ns via a second fork. NEWPID only takes
            # effect on a subsequent fork. This fork runs INSIDE the
            # already-forked child (single-threaded by then — no other
            # threads survived the parent fork) so the multi-threaded
            # warning shouldn't fire here, but suppress defensively
            # to match every other production fork() site.
            import warnings as _warnings
            with _warnings.catch_warnings():
                _warnings.filterwarnings(
                    "ignore", category=DeprecationWarning,
                    message=r".*fork.*may lead to deadlocks.*",
                )
                os.unshare(CLONE_NEWPID)
                grand = os.fork()
            if grand == 0:
                # Grandchild runs as PID 1 in the new pid-ns.
                if env is not None:
                    exec_env = env
                else:
                    exec_env = os.environ.copy()
                # bounded fork count via RLIMIT_NPROC (prlimit).
                if nproc_limit and nproc_limit > 0:
                    import resource
                    from ._fork_safe_warn import warn_post_fork
                    try:
                        resource.setrlimit(resource.RLIMIT_NPROC,
                                           (nproc_limit, nproc_limit))
                    except (ValueError, OSError):
                        warn_post_fork(b"RAPTOR: _spawn grandchild RLIMIT_NPROC setrlimit failed -- fork-bomb bound not applied\n")
                try:
                    os.execvpe(cmd[0], list(cmd), exec_env)
                except FileNotFoundError:
                    os._exit(127)
                except PermissionError:
                    os._exit(126)
                os._exit(125)  # unreachable
            else:
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
                _, status = os.waitpid(grand, 0)
                if os.WIFEXITED(status):
                    os._exit(os.WEXITSTATUS(status))
                if os.WIFSIGNALED(status):
                    sig = os.WTERMSIG(status)
                    import signal as _signal
                    # Clear any inherited handler/mask; re-raise by
                    # SIGDFL + kill(self).
                    try:
                        _signal.signal(sig, _signal.SIG_DFL)
                    except (OSError, ValueError):
                        pass
                    os.kill(os.getpid(), sig)
                    # Fallback if the signal was blocked/ignored.
                    os._exit(128 + sig)
                os._exit(255)
        except BaseException:
            # Last-chance diagnostic to stderr before aborting.
            try:
                os.write(2, f"RAPTOR sandbox child failure:\n{traceback.format_exc()}\n".encode())
            except Exception:
                pass
            os._exit(126)

    # ================ PARENT ================
    # Initialised before the try so the outer finally can reference it
    # regardless of where in the parent flow we exit.
    tracer_pid: Optional[int] = None
    try:
        # Close the ends the child owns — parent doesn't write to them.
        os.close(p_ready_w); _parent_fds.discard(p_ready_w)
        os.close(p_go_r);    _parent_fds.discard(p_go_r)
        if capture_output:
            os.close(out_w); _parent_fds.discard(out_w)
            os.close(err_w); _parent_fds.discard(err_w)

        # Step 4: wait for child to signal "unshare done, ready for newuidmap".
        try:
            if os.read(p_ready_r, 1) != b"R":
                _kill_and_reap(child_pid)
                raise RuntimeError("sandbox child did not signal ready")
        finally:
            os.close(p_ready_r); _parent_fds.discard(p_ready_r)

        # Step 6: newuidmap / newgidmap.
        host_uid = os.getuid()
        host_gid = os.getgid()
        newuidmap = shutil.which("newuidmap")
        newgidmap = shutil.which("newgidmap")
        if not newuidmap or not newgidmap:
            _kill_and_reap(child_pid)
            raise FileNotFoundError(
                "newuidmap/newgidmap required for mount-ns sandbox — install "
                "the uidmap package"
            )
        try:
            _run_newuidmap(child_pid, newuidmap, ["0", str(host_uid), "1"])
            _run_newuidmap(child_pid, newgidmap, ["0", str(host_gid), "1"])
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
                sync_fd = t_ready_w
                # Three cases, all handled by the split:
                #   sync_fd in [3, upper):  two ranges, gap at sync_fd
                #   sync_fd >= upper:       single range [3, upper)
                #   sync_fd < 3:            (impossible — pipe()
                #                            returns >=3 once stdio
                #                            is open) treat as
                #                            single range
                if 3 <= sync_fd < upper:
                    os.closerange(3, sync_fd)
                    os.closerange(sync_fd + 1, upper)
                else:
                    os.closerange(3, upper)
                # Replace argv via execvpe so the tracer runs as a
                # clean Python module without inheriting the parent's
                # complicated state. Pass the target_pid, audit_run_dir,
                # and the write end of t_ready as the sync_fd argument.
                #
                # Use the current Python interpreter for module loading
                # consistency. -I is isolated mode (ignore env vars,
                # don't add cwd to sys.path) — same hardening pattern
                # as raptor-pid1-shim.
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
                    # optional config_path. Config path tells the
                    # tracer which audit mode (filtered vs verbose)
                    # to run.
                    tracer_argv = [
                        sys.executable, "-m", "core.sandbox.tracer",
                        str(child_pid), str(audit_run_dir),
                        str(t_ready_w),
                    ]
                    if _audit_config_path is not None:
                        tracer_argv.append(_audit_config_path)
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
                except Exception:
                    # Unknown execvpe failure (rare). 125 distinct
                    # from the documented codes so it's not
                    # confused with a successful run.
                    os._exit(125)

            # Parent: close the write end now (tracer has its own copy).
            # Without this close, the parent's `os.read(t_ready_r, ...)`
            # below would block FOREVER on tracer death, because the
            # parent's own t_ready_w would keep the pipe write end
            # alive and EOF would never be signalled to the read.
            os.close(t_ready_w); _parent_fds.discard(t_ready_w)

            # Parent: wait for tracer to signal ready. If tracer dies
            # before signalling, our read returns 0 bytes — treat as
            # "tracer failed" and abort the sandbox.
            try:
                ready = os.read(t_ready_r, 1)
            finally:
                os.close(t_ready_r); _parent_fds.discard(t_ready_r)
            if not ready:
                # Tracer failed to attach. Reap it (capture exit code
                # for diagnostics), kill the target child (still
                # blocked on go-pipe), abort.
                tracer_status: Optional[int] = None
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
                raise RuntimeError(
                    f"audit-mode tracer failed to attach to sandboxed "
                    f"child{rc_hint} — {cause}"
                )

        # Step 8: tell child to proceed.
        try:
            os.write(p_go_w, b"G")
        finally:
            os.close(p_go_w); _parent_fds.discard(p_go_w)
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
        # post-newuidmap parent flow. _kill_and_reap is idempotent
        # (catches ProcessLookupError + ChildProcessError) so
        # re-reaping an already-dead child is harmless.
        if child_pid > 0:
            try:
                _kill_and_reap(child_pid)
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
        if _audit_config_path is not None:
            try:
                os.unlink(_audit_config_path)
            except OSError:
                pass
            # Mark unlinked so the final-finally below doesn't try
            # to unlink an already-removed file. Avoids the
            # silent-OSError swallowed-and-discarded path AND
            # keeps the audit lifecycle bookkeeping honest.
            _audit_config_path = None
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
    deadline = time.time() + timeout if timeout else None
    try:
        if capture_output:
            import select
            fds = [out_r, err_r]
            try:
                while fds:
                    remaining = (deadline - time.time()) if deadline else None
                    if remaining is not None and remaining <= 0:
                        _kill_and_reap(child_pid)
                        out_str = stdout_buf.decode() if text else stdout_buf
                        err_str = stderr_buf.decode() if text else stderr_buf
                        raise subprocess.TimeoutExpired(
                            list(cmd), timeout, output=out_str, stderr=err_str
                        )
                    ready, _, _ = select.select(fds, [], [], remaining)
                    for fd in ready:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            os.close(fd); _parent_fds.discard(fd)
                            fds.remove(fd)
                        elif fd == out_r:
                            stdout_buf += chunk
                        else:
                            stderr_buf += chunk
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
                    if time.time() > deadline:
                        _kill_and_reap(child_pid)
                        out_str = (stdout_buf or b"").decode() if text else stdout_buf
                        err_str = (stderr_buf or b"").decode() if text else stderr_buf
                        raise subprocess.TimeoutExpired(
                            list(cmd), timeout, output=out_str, stderr=err_str
                        )
                    time.sleep(0.01)
            else:
                _, status = os.waitpid(child_pid, 0)
        except ChildProcessError:
            status = 0
    finally:
        # Audit-mode tracer cleanup: target has exited (or been killed
        # via timeout), so the tracer's traced set will become empty
        # and it'll exit naturally. Wait for it to reap; if it doesn't
        # exit promptly, kill it (PTRACE_O_EXITKILL has already done
        # the right thing for any surviving tracees).
        if tracer_pid is not None:
            _reap_tracer(tracer_pid)
        # Clean up the audit-config file we wrote for the tracer.
        # The tracer has already read it and finished, so this is
        # safe even if the tracer is technically still in its post-
        # _reap_tracer cleanup phase.
        if _audit_config_path is not None:
            try:
                os.unlink(_audit_config_path)
            except OSError:
                pass
        _cleanup_stub(_root_dir)

    if os.WIFEXITED(status):
        returncode = os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        returncode = -os.WTERMSIG(status)
    else:
        returncode = -1

    stdout_out = stderr_out = None
    if capture_output:
        stdout_out = stdout_buf.decode() if text else stdout_buf
        stderr_out = stderr_buf.decode() if text else stderr_buf

    return subprocess.CompletedProcess(
        args=list(cmd),
        returncode=returncode,
        stdout=stdout_out,
        stderr=stderr_out,
    )
