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
import shutil
import signal
import subprocess
import time
import traceback
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
            r = _sp.run(
                [newuidmap, "--help"],
                capture_output=True, timeout=2,
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
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
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
    mem = limits.get("memory_mb", _DEFAULT_LIMITS["memory_mb"])
    file_mb = limits.get("max_file_mb", _DEFAULT_LIMITS["max_file_mb"])
    cpu = limits.get("cpu_seconds", _DEFAULT_LIMITS["cpu_seconds"])
    mem_bytes = mem * 1024 * 1024
    file_bytes = file_mb * 1024 * 1024
    try:
        if mem > 0:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        if file_mb > 0:
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        if cpu > 0:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


def _kill_and_reap(pid: int) -> None:
    """SIGKILL `pid` and reap it. Both ops are best-effort — if the
    child already exited (ProcessLookupError) or was reaped elsewhere
    (ChildProcessError), we just return. Used on every error path
    where the parent has to abandon the child mid-setup.
    """
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


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
) -> subprocess.CompletedProcess:
    """Run `cmd` inside a fully-isolated sandbox.

    Sets up (in order inside the forked child): user-ns + mount-ns + ipc-ns
    [+ net-ns], newuidmap/newgidmap applied from parent, mount pivot_root
    onto a fresh tmpfs, Landlock + seccomp, then pid-ns via a second fork.
    """
    # Sandbox root directory. Created by the parent via tempfile.mkdtemp
    # so the path is random-suffixed (mode 0700) — a same-UID attacker
    # can't pre-plant the stub as a symlink pointing at /etc or another
    # sensitive location. The child mounts tmpfs on this path; parent
    # rmdir's it after waitpid. We lstat-check before cleanup to defeat
    # TOCTOU substitution.
    import tempfile as _tempfile
    _root_dir = _tempfile.mkdtemp(prefix=".raptor-sbx-")

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
            seccomp_profile, block_udp=seccomp_block_udp
        ) if seccomp_profile else None

        child_pid = os.fork()
    except BaseException:
        # Any failure before fork returns: close opened pipes AND the
        # mkdtemp stub. Without this, a pipe-exhaustion OSError or
        # import-time failure in preexec construction would leak FDs
        # and leave a .raptor-sbx-* dir behind on every call.
        _close_leftover()
        _cleanup_stub(_root_dir)
        raise
    if child_pid == 0:
        # ================ CHILD ================
        # Close the ends of the pipes we don't use.
        os.close(p_ready_r)
        os.close(p_go_w)
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
            # effect on a subsequent fork.
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
                    try:
                        resource.setrlimit(resource.RLIMIT_NPROC,
                                           (nproc_limit, nproc_limit))
                    except (ValueError, OSError):
                        pass
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

        # Step 8: tell child to proceed.
        try:
            os.write(p_go_w, b"G")
        finally:
            os.close(p_go_w); _parent_fds.discard(p_go_w)
    except BaseException:
        # Any failure above: close remaining pipe fds, remove the stub
        # dir, and propagate. The child has already been SIGKILL'd +
        # reaped by the nested handlers that raised us here, so rmdir
        # now is safe.
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
