"""Persistent sandboxed Ghidra server.

Boots ONE pyghidra JVM inside ``core.sandbox.run`` (network denied,
reads restricted to the interpreter/pyghidra/Ghidra-install/work
scopes, writes scoped to the work dir) and serves decompile / apply /
export requests over a unix socket for the lifetime of a run. This is
the JVM-reuse the in-process pyghidra session offers, WITH the
sandbox the in-process path cannot have — many-request consumers
(audit loops decompiling function after function) pay one JVM boot
instead of one per subprocess invocation, on hostile projects.

Two transports, chosen by a boot-time pre-flight
(``check_child_unix_sockets_available``): a pathname unix socket the
worker binds itself (primary — keeps the namespace sandbox lane), or
an inherited socketpair half (``--socket-fd``) on hosts whose sandbox
lane denies ``socket(2)`` to the child (nested sandboxes: the worker
would otherwise die at bind with EPERM).

Usage::

    with GhidraServer(gpr_path) as srv:
        srv.open()
        code = srv.decompile("main")
        srv.apply_enrichments({...})

The working copy lives in the server's work dir (the original
project is never modified); ``enriched_gpr`` names the copy for
callers that persist results.
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from core.atomic_fs import open_exclusive_artifact
from core.sandbox import check_child_unix_sockets_available

from .detect import pyghidra_available
from .headless import _install_read_paths
from .project_util import prepare_working_copy

logger = logging.getLogger(__name__)

_BOOT_TIMEOUT_S = 60
_MAX_RESTARTS = 3
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_REQUEST_TIMEOUT_S = 300
_SHUTDOWN_GRACE_S = 5


class GhidraServerError(Exception):
    """Raised when the Ghidra server fails to boot or serve."""


class GhidraServerDied(GhidraServerError):
    """The worker process died mid-run (watchdog self-kill on a
    wedged JVM call, crash, sandbox reap). restart() recovers."""


class GhidraServer:
    """Long-lived sandboxed pyghidra worker behind a unix socket."""

    def __init__(
        self,
        gpr_path: Path,
        *,
        program_name: Optional[str] = None,
        lifetime_s: int = 3600,
    ) -> None:
        if not pyghidra_available():
            raise GhidraServerError(
                "pyghidra is not installed — the persistent server "
                "runs pyghidra in a sandboxed child; install via: "
                "pip install pyghidra"
            )
        self.gpr_path = Path(gpr_path)
        self.program_name = program_name
        self.lifetime_s = lifetime_s
        self._work_dir: Optional[Path] = None
        self._work_gpr: Optional[Path] = None
        self._sock: Optional[socket.socket] = None
        # Socketpair transport only: the parent's duplicate of the
        # CHILD half, OWNED by the boot's _serve thread — closed in
        # its finally, i.e. strictly after the sandbox call returns.
        # The sandbox spawn happens in that daemon thread with no
        # post-spawn hook, so any earlier close (boot timeout, boot
        # failure, stop()) races Popen inheriting the fd: the number
        # can be reused and pass_fds would export whatever descriptor
        # now wears it. Worker death still surfaces as EOF — the
        # sandbox call returns when the worker exits and the finally
        # drops the last open write end. This attribute is
        # observability only (cleared by the owning thread under
        # self._lock); nothing else may close it.
        self._child_sock: Optional[socket.socket] = None
        self._stream: Optional[io.BufferedRWPair] = None
        self._thread: Optional[threading.Thread] = None
        self._result: Dict[str, Any] = {}
        self._req_id = 0
        self._lock = threading.Lock()
        self._boot_seq = 0
        self._restarts = 0
        self._opened_program: Optional[str] = None

    # ── lifecycle ────────────────────────────────────────────────

    def start(self) -> None:
        """Prepare the working copy and boot the sandboxed worker."""
        if self._work_dir is not None:
            raise GhidraServerError(
                "server already started — one GhidraServer per "
                "lifecycle"
            )
        self._work_dir = Path(
            tempfile.mkdtemp(prefix="raptor-ghidra-server-")
        )
        work_gpr = prepare_working_copy(self.gpr_path, self._work_dir)
        self._work_gpr = work_gpr
        try:
            self._boot()
        except BaseException:
            # First-boot failure tears down (a raising __enter__
            # never reaches __exit__, so callers can't clean up).
            # restart() deliberately does NOT get this treatment —
            # a failed REBOOT must not destroy the working copy and
            # its saved enrichments.
            self.stop()
            raise

    def _boot(self) -> None:
        """Boot one sandboxed worker against the prepared work dir."""
        self._boot_seq += 1
        self._result = {}
        worker = Path(__file__).parent / "server_worker.py"

        # Transport pre-flight. The pathname unix socket stays PRIMARY:
        # an inherited-fd child forces the subprocess+preexec sandbox
        # lane (pass_fds is not plumbed through the namespace spawn
        # chain), which would downgrade healthy hosts from mount-ns
        # isolation. Hosts whose sandboxed child cannot CREATE AF_UNIX
        # sockets at all — nested sandboxes, where the namespace lane
        # cannot engage and the preexec seccomp lane denies
        # socket(AF_UNIX) unconditionally, killing the worker at bind
        # with EPERM — get the socketpair transport instead: the pair
        # is created HERE and inherited, so the worker never calls
        # socket(2).
        use_pathname = check_child_unix_sockets_available()
        socket_path: Optional[Path] = None
        parent_sock: Optional[socket.socket] = None
        child_sock: Optional[socket.socket] = None
        if use_pathname:
            socket_path = self._work_dir / f"worker-{self._boot_seq}.sock"
            # The work dir is worker-writable: a hostile worker from a
            # previous boot can squat the predictable next socket name
            # to make the replacement die at bind. Clear anything there.
            try:
                if socket_path.is_symlink() or socket_path.exists():
                    socket_path.unlink()
            except OSError:
                pass
            cmd = [
                sys.executable, "-u", str(worker),
                str(socket_path),
                "--idle-timeout", str(self.lifetime_s),
            ]
        else:
            logger.info(
                "ghidra server: sandboxed child cannot create AF_UNIX "
                "sockets on this host (namespace lane unavailable; the "
                "preexec seccomp lane denies socket creation) — using "
                "the inherited-socketpair transport on the "
                "Landlock-only lane"
            )
            parent_sock, child_sock = socket.socketpair()
            self._child_sock = child_sock
            cmd = [
                sys.executable, "-u", str(worker),
                "--socket-fd", str(child_sock.fileno()),
                "--idle-timeout", str(self.lifetime_s),
            ]

        import getpass
        import os
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self._work_dir),
            "XDG_CONFIG_HOME": str(self._work_dir / ".config"),
            "XDG_CACHE_HOME": str(self._work_dir / ".cache"),
            "JAVA_TOOL_OPTIONS": (
                f"-Duser.home={self._work_dir} "
                f"-Duser.name={getpass.getuser()}"
            ),
        }
        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if not install_dir:
            headless = shutil.which("analyzeHeadless")
            if headless:
                install_dir = str(Path(headless).resolve().parent.parent)
        if install_dir:
            env["GHIDRA_INSTALL_DIR"] = install_dir

        # The worker imports pyghidra from THIS interpreter's
        # environment — its prefix must be readable, alongside the
        # worker script's package and the Ghidra install.
        readable = [
            str(Path(sys.executable).resolve().parent.parent),
            str(Path(sys.prefix).resolve()),
            str(worker.parent),
        ]
        headless_path = shutil.which("analyzeHeadless")
        if headless_path:
            readable.extend(_install_read_paths(headless_path))
        elif install_dir:
            readable.append(install_dir)

        def _serve() -> None:
            from core.sandbox import run as _sandbox_run
            extra: Dict[str, Any] = {}
            if child_sock is not None:
                # Socketpair transport: the child half rides into the
                # sandboxed worker as an inherited descriptor. The
                # sandbox's pass_fds gate admits it (a connected
                # anonymous AF_UNIX socketpair half created by this
                # process — pipe-equivalent); pass_fds routes the call
                # onto the subprocess+preexec lane, which is exactly
                # the lane this transport exists for. fileno() is read
                # HERE, and the socket object is owned by this thread
                # (closed in the finally below, strictly after the
                # sandbox call returns) — no other close may race the
                # spawn, or the fd number could be reused and pass_fds
                # would export a different descriptor.
                extra["pass_fds"] = (child_sock.fileno(),)
            try:
                # The JVM parses attacker-controlled project data:
                # network denied, reads restricted, writes scoped to
                # the work dir (project lock + saves + socket).
                proc = _sandbox_run(
                    cmd,
                    block_network=True,
                    target=str(self._work_dir),
                    output=str(self._work_dir),
                    restrict_reads=True,
                    readable_paths=readable,
                    capture_output=True,
                    text=True,
                    timeout=self.lifetime_s + _SHUTDOWN_GRACE_S,
                    env=env,
                    env_caller_filtered=True,
                    **extra,
                )
                self._result["returncode"] = proc.returncode
                self._result["stderr"] = (proc.stderr or "")[-2000:]
            except BaseException as e:  # noqa: BLE001 — thread edge
                self._result["error"] = f"{type(e).__name__}: {e}"
            finally:
                # Owner-side close: the worker has exited (or the
                # spawn failed), so dropping the parent's duplicate
                # of the child half is now safe AND is what turns a
                # later worker death into EOF for the request path.
                if child_sock is not None:
                    try:
                        child_sock.close()
                    except OSError:
                        pass
                    with self._lock:
                        if self._child_sock is child_sock:
                            self._child_sock = None

        self._thread = threading.Thread(
            target=_serve, name="ghidra-server", daemon=True,
        )
        self._thread.start()

        deadline = time.monotonic() + _BOOT_TIMEOUT_S
        try:
            if parent_sock is not None:
                self._boot_wait_socketpair(parent_sock, deadline)
                return
            assert socket_path is not None  # pathname transport
            while time.monotonic() < deadline:
                if self._result:
                    raise self._boot_death_error(pathname=True)
                if socket_path.exists():
                    try:
                        self._connect(socket_path)
                        if self._request({"op": "ping"}).get("pong"):
                            logger.info(
                                "ghidra server up (work dir %s)",
                                self._work_dir,
                            )
                            return
                    except (OSError, GhidraServerError):
                        self._disconnect()
                time.sleep(0.2)
            raise GhidraServerError(
                f"worker did not come up within {_BOOT_TIMEOUT_S}s"
            )
        except BaseException:
            self._disconnect()
            if parent_sock is not None:
                # Not adopted as self._sock (or already closed by
                # _disconnect — socket close is idempotent).
                try:
                    parent_sock.close()
                except OSError:
                    pass
            # The child half is NOT closed here: the _serve thread
            # may still be pre-spawn (a boot timeout races the
            # sandbox layer's own setup), and closing would free the
            # fd number for reuse so pass_fds could export a
            # different descriptor. The owning thread's finally
            # closes it once the sandbox call returns.
            raise

    def _boot_death_error(self, *, pathname: bool) -> GhidraServerError:
        """Attributed boot-death error from the _serve thread result."""
        detail = str(
            self._result.get("error")
            or self._result.get("stderr", "")
        ).strip()
        msg = f"worker died during boot: {detail}"
        if pathname and "Operation not permitted" in detail:
            msg += (
                " — EPERM at worker socket setup: this host's sandbox "
                "lane denies AF_UNIX socket creation to the child "
                "(preexec seccomp policy), so the pathname transport "
                "cannot boot. The transport pre-flight "
                "(check_child_unix_sockets_available) should have "
                "selected the socketpair fallback here; its verdict "
                "was wrong for this host."
            )
        return GhidraServerError(msg)

    def _boot_wait_socketpair(
        self, parent_sock: socket.socket, deadline: float,
    ) -> None:
        """Wait for the worker over the socketpair transport.

        The connection exists from the start (no socket file to poll),
        so boot progress is: send ONE ping, then poll for the response
        with short read timeouts, checking the _serve thread's result
        box for worker death between reads. Raw recv (not makefile):
        a timeout mid-``readline`` on a buffered reader can drop
        already-buffered bytes; accumulating raw chunks is
        timeout-safe, and the accumulation is capped at
        ``_MAX_RESPONSE_BYTES`` — a worker that floods the pair
        without a newline fails the boot instead of growing the
        buffer without bound. On success the socket is adopted as
        the regular request transport; the child half stays with its
        owner (the _serve thread closes it when the sandbox call
        returns, which is what surfaces a later worker death as EOF).
        """
        self._req_id += 1
        ping_id = self._req_id
        try:
            parent_sock.sendall(
                (json.dumps({"id": ping_id, "op": "ping"}) + "\n")
                .encode())
        except OSError as e:
            # The peer is already gone: the worker (or its spawn)
            # died before boot-wait could ping, and the owning
            # _serve thread has closed the child half. _serve books
            # its result before that close, so the death is
            # attributable.
            raise self._boot_death_error(pathname=False) from e
        parent_sock.settimeout(0.2)
        buf = b""
        while time.monotonic() < deadline:
            if self._result:
                raise self._boot_death_error(pathname=False)
            try:
                chunk = parent_sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise self._boot_death_error(pathname=False)
            buf += chunk
            if len(buf) > _MAX_RESPONSE_BYTES:
                # Fail closed: the (sandboxed, untrusted) worker is
                # flooding the pair without ever completing a line.
                raise GhidraServerError(
                    f"worker boot response exceeded "
                    f"{_MAX_RESPONSE_BYTES >> 20} MiB before a "
                    f"newline — refusing to buffer further"
                )
            if b"\n" not in buf:
                continue
            line, _, rest = buf.partition(b"\n")
            try:
                resp = json.loads(line)
            except json.JSONDecodeError as e:
                raise GhidraServerError(
                    f"malformed worker boot response: {e}"
                ) from e
            if rest or resp.get("id") != ping_id or not resp.get("pong"):
                raise GhidraServerError(
                    "unexpected worker boot response — "
                    "desynchronized socketpair"
                )
            parent_sock.settimeout(_REQUEST_TIMEOUT_S)
            self._sock = parent_sock
            self._stream = parent_sock.makefile("rwb")
            logger.info(
                "ghidra server up over socketpair transport "
                "(work dir %s)", self._work_dir,
            )
            return
        raise GhidraServerError(
            f"worker did not come up within {_BOOT_TIMEOUT_S}s"
        )

    def stop(self) -> None:
        """Shut the worker down and remove the work dir.

        The socketpair child half is deliberately not closed here —
        its owning _serve thread closes it in its finally once the
        sandbox call returns (the join below waits for exactly that),
        so a stop() racing an in-flight spawn can never free the fd
        number out from under pass_fds.
        """
        try:
            if self._stream is not None:
                try:
                    self._request({"op": "shutdown"}, timeout=_SHUTDOWN_GRACE_S)
                except (OSError, GhidraServerError):
                    pass
            self._disconnect()
            if self._thread is not None:
                self._thread.join(timeout=_SHUTDOWN_GRACE_S * 2)
                if self._thread.is_alive():
                    logger.warning(
                        "ghidra server thread still alive after "
                        "shutdown grace — sandbox timeout will "
                        "reap it"
                    )
        finally:
            if self._work_dir is not None and not self._thread_alive():
                shutil.rmtree(self._work_dir, ignore_errors=True)
                # Consistent object protocol: a stopped server is
                # stopped — restart()/start() see the nulled state
                # instead of booting against a deleted dir.
                self._work_dir = None
                self._work_gpr = None

    def restart(self) -> None:
        """Boot a fresh worker after the previous one died mid-run.

        Recovers from a watchdog self-kill (a request wedged in native
        JVM code makes the worker answer with an error and exit) or
        any other worker death, without losing the working copy: the
        replacement opens the same on-disk project, so saved
        enrichments survive; unsaved ones from the dead worker are
        lost. Refuses while the old worker is still alive — its JVM
        holds the project lock, and a second opener on a live project
        risks corrupting the working copy; the sandbox lifetime cap
        remains the backstop for that case.
        """
        if self._work_dir is None or self._work_gpr is None:
            raise GhidraServerError(
                "server not started (or already stopped)"
            )
        if self._restarts >= _MAX_RESTARTS:
            raise GhidraServerError(
                f"restart budget ({_MAX_RESTARTS}) exhausted — a "
                "worker dying this often is a hostile or broken "
                "project; giving up for this run"
            )
        # Liveness check BEFORE touching the connection: refusing a
        # restart on a live worker must leave that worker usable.
        if self._thread is not None:
            self._thread.join(timeout=_SHUTDOWN_GRACE_S)
            if self._thread.is_alive():
                raise GhidraServerError(
                    "old worker still running — refusing to restart "
                    "over a live project lock"
                )
        self._restarts += 1
        self._disconnect()
        # The dead worker cannot release its Ghidra lock file.
        lock = self._work_gpr.parent / f"{self._work_gpr.stem}.lock"
        for stale in (lock, lock.with_suffix(".lock~")):
            try:
                if stale.is_file() or stale.is_symlink():
                    stale.unlink()
            except OSError:
                pass
        logger.info("ghidra server: restarting worker (boot %d)",
                    self._boot_seq + 1)
        self._boot()
        if self._opened_program is not None:
            self.open()

    def _thread_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def __enter__(self) -> "GhidraServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── transport ────────────────────────────────────────────────

    def _connect(self, socket_path: Path) -> None:
        import stat as _stat
        st = socket_path.lstat()
        if not _stat.S_ISSOCK(st.st_mode):
            # The worker owns the work dir — a symlink swap here
            # would point the unsandboxed parent at another socket.
            raise GhidraServerError(
                f"{socket_path} is not a unix socket — refusing"
            )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_REQUEST_TIMEOUT_S)
        sock.connect(str(socket_path))
        self._sock = sock
        self._stream = sock.makefile("rwb")

    def _disconnect(self) -> None:
        for closer in (self._stream, self._sock):
            if closer is not None:
                try:
                    closer.close()
                except OSError:
                    pass
        self._stream = None
        self._sock = None

    def _request(
        self, payload: Dict[str, Any], *, timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        if self._stream is None:
            raise GhidraServerError("server not connected")
        with self._lock:
            self._req_id += 1
            payload = {"id": self._req_id, **payload}
            if timeout is not None and self._sock is not None:
                self._sock.settimeout(timeout)
            try:
                self._stream.write(
                    (json.dumps(payload) + "\n").encode())
                self._stream.flush()
                # Bounded read: an unbounded readline() would buffer
                # a hostile newline-free response wholesale.
                line = self._stream.readline(_MAX_RESPONSE_BYTES + 1)
            except socket.timeout:
                # A half-read stream can never re-frame; the worker's
                # own watchdog is stricter than this socket timeout,
                # so reaching here means the worker died without
                # answering. restart() recovers.
                self._disconnect()
                raise GhidraServerDied(
                    "request timed out with the stream desynchronized "
                    "— call restart() to boot a fresh worker"
                ) from None
            except OSError as e:
                # Broken pipe / connection reset: the worker died
                # between requests (watchdog kill, crash, sandbox
                # reap) and the write or read surfaced it.
                self._disconnect()
                raise GhidraServerDied(
                    f"worker connection lost ({type(e).__name__}) — "
                    "call restart() to boot a fresh worker"
                ) from e
            finally:
                if timeout is not None and self._sock is not None:
                    self._sock.settimeout(_REQUEST_TIMEOUT_S)
        if not line:
            raise GhidraServerDied(
                "worker closed the connection (restart() boots a "
                "fresh worker): "
                f"{self._result.get('stderr', '')[-500:]}"
            )
        if len(line) > _MAX_RESPONSE_BYTES:
            raise GhidraServerError(
                f"worker response over {_MAX_RESPONSE_BYTES >> 20} "
                "MiB — refusing"
            )
        try:
            resp = json.loads(line)
        except json.JSONDecodeError as e:
            raise GhidraServerError(
                f"malformed worker response: {e}"
            ) from e
        if resp.get("id") != payload["id"]:
            raise GhidraServerError(
                "worker response id mismatch — desynchronized stream"
            )
        if not resp.get("ok"):
            if resp.get("worker_exiting"):
                raise GhidraServerDied(
                    resp.get("error", "worker watchdog kill"))
            raise GhidraServerError(
                resp.get("error", "unknown worker error"))
        return resp

    # ── API ──────────────────────────────────────────────────────

    def open(self) -> Dict[str, Any]:
        """Open the working copy in the worker's JVM."""
        program = self._opened_program or self.program_name
        if program is not None:
            # Program names originate in the hostile project's own
            # database — the same validation the headless -process
            # path applies (dash-leading names become switches there;
            # here they'd just misresolve, but stay consistent).
            parts = str(program).strip("/").split("/")
            if any(not p or p.startswith("-") or p == ".." for p in parts):
                raise GhidraServerError(
                    f"refusing suspicious program name: {program!r}"
                )
        resp = self._request({
            "op": "open",
            "gpr": str(self._work_gpr),
            "program": program,
        })
        # Remember what actually opened so a restarted worker reopens
        # the same program even when the caller passed none.
        opened = resp.get("opened")
        if isinstance(opened, str) and opened:
            self._opened_program = opened
        return resp

    def list_programs(self) -> list:
        return self._request({"op": "list"})["programs"]

    def decompile(self, function, *, timeout: int = 30) -> str:
        resp = self._request(
            {"op": "decompile", "function": function,
             "timeout": timeout},
            timeout=timeout + 30,
        )
        return resp["code"]

    def apply_enrichments(self, enrichments: Dict[str, Any]) -> Dict[str, int]:
        resp = self._request(
            {"op": "apply", "enrichments": enrichments})
        return {"comments": resp["comments"],
                "bookmarks": resp["bookmarks"]}

    def export(self, out_path: Path) -> int:
        """Export the program summary JSON to *out_path*.

        The worker writes only inside its own work dir (paths outside
        it would land in the sandbox's private mount namespace and
        silently vanish); the parent copies the result out.
        """
        if self._work_dir is None:
            raise GhidraServerError("server not started")
        worker_out = self._work_dir / "export.json"
        resp = self._request({
            "op": "export", "out": str(worker_out),
        })
        if worker_out.is_symlink() or not worker_out.is_file():
            raise GhidraServerError(
                "worker did not produce a regular export file"
            )
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive-create copy: follow_symlinks=False only covers
        # the SOURCE side of copy2 — the destination open is O_TRUNC
        # and follows whatever occupies out_path in the reused run
        # dir. Fresh O_EXCL|O_NOFOLLOW inode after an lstat-honest
        # unlink.
        out_path.unlink(missing_ok=True)
        with open(worker_out, "rb") as src_fh, os.fdopen(
            open_exclusive_artifact(out_path), "wb",
        ) as dst_fh:
            shutil.copyfileobj(src_fh, dst_fh)
        return resp["functions"]

    @property
    def enriched_gpr(self) -> Optional[Path]:
        """The working copy path (holds applied enrichments)."""
        return self._work_gpr

    def persist_enriched(self, dst_dir: Path) -> Path:
        """Copy the (possibly enriched) working copy out of the
        server's work dir — which is deleted on stop — into *dst_dir*.

        Call after apply_enrichments, before the context exits.

        The copy uses lstat semantics: the working copy was sanitized
        on the way IN, but the sandboxed worker has write access to
        the work dir and could plant symlinks afterwards — following
        them here (in the unsandboxed parent) would launder arbitrary
        same-user file reads into the persisted deliverable.
        """
        if self._work_gpr is None:
            raise GhidraServerError("server not started")
        from .project_util import _copy_rep_tree
        dst_dir = Path(dst_dir)
        dst_dir.mkdir(parents=True, exist_ok=True)
        if self._work_gpr.is_symlink():
            raise GhidraServerError(
                "working copy .gpr is a symlink — refusing to persist"
            )
        dst_gpr = dst_dir / self._work_gpr.name
        # Destination-side hardening (the docstring's lstat rationale
        # covered the source only): exclusive-create copy so a
        # symlink planted at the destination name is never followed.
        dst_gpr.unlink(missing_ok=True)
        with open(self._work_gpr, "rb") as src_fh, os.fdopen(
            open_exclusive_artifact(dst_gpr), "wb",
        ) as dst_fh:
            shutil.copyfileobj(src_fh, dst_fh)
        src_rep = self._work_gpr.with_suffix(".rep")
        dst_rep = dst_dir / src_rep.name
        if dst_rep.exists():
            shutil.rmtree(dst_rep)
        _copy_rep_tree(src_rep, dst_rep)
        lock = dst_dir / f"{self._work_gpr.stem}.lock"
        if lock.exists():
            lock.unlink()
        return dst_gpr
