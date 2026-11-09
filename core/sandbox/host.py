"""Persistent-sandbox host — parent-side handle.

Keeps a long-lived sandboxed daemon alive so multiple spawn/probe
calls share ONE sandbox + Python startup instead of paying it per
call.

Rendezvous: none — the RPC channel is a pair of inherited pipe fds.
The parent creates two pipe pairs (``os.pipe()``; CLOEXEC by default
per PEP 446) and hands the two DAEMON-side ends to the sandbox spawn
via ``pass_fds`` — subprocess clears CLOEXEC on exactly those fds in
the spawned child, so they survive the exec chain (unshare → pid-1
shim → daemon) while every other parent fd stays closed.  Their fd
numbers ride on the daemon's argv (``--rpc-in-fd N --rpc-out-fd M``);
the daemon opens nothing by path.  No filesystem name exists for the
channel, so a hostile target inside the sandbox has nothing to squat,
replace, symlink-swap, or open — the forged-verdict / injected-request
races that path-named FIFOs in the sandbox-writable target directory
allowed are impossible by construction.

Pipes (rather than AF_UNIX sockets) because seccomp:full blocks
``socket()`` — env parity with parse_result requires the daemon to
run under the same profile the target does.  The seccomp filter is a
blocklist that leaves ``pipe``/``pipe2`` alone, and the daemon's own
use of the channel needs only ``read``/``write``/``close`` at
runtime, all of which pass the filter.

Once the startup ping proves the daemon is alive, the parent closes
its copies of the daemon-side ends — from then on EOF on the read
end means the daemon (or its whole sandbox chain) died.  This
replaces the FIFO-open timeout dance the path-based rendezvous
needed.  ``pass_fds`` also routes the spawn down the
subprocess+preexec path (context.py's ``spawn_eligible`` gate —
the mount-ns fork chain doesn't plumb inherited fds); net-ns,
Landlock, seccomp and the pid-ns shim all still apply.

Threading: ``core.sandbox.run`` is blocking, so a background
thread holds the sandbox open.  The parent-side handle uses the
pipe fds for RPC while the thread parks in the sandbox call for
the host's lifetime.  ``close()`` terminates cleanly.

Wiring checklist — this docstring is the successor to the pre-wiring
design note; the module still has zero production callers.  Before
the first caller (the /exploit knowledge loop, which treats this
channel's verdicts as ground truth) wires in:

- Inherited-pipe-fd transport replacing the FIFO rendezvous — LANDED
  (this revision).
- ``_safe_eval`` node-allowlist trim in the daemon — LANDED.
- Hostile-peer e2e (``core/sandbox/tests/test_host_rpc.py``): no
  rendezvous path artifacts under the target dir, forged-verdict
  write and request-stream read from a daemon-spawned child both
  fail with EBADF, daemon death surfaces as EOF, ``close()`` leaks
  no fds.  These exist and must stay green.

The companion daemon script lives at ``core/sandbox/_daemon.py``
— pure stdlib, no external deps.
"""
from __future__ import annotations

import contextlib
import errno
import json
import logging
import math
import os
import select
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from core.atomic_fs import rmtree_hardened
from core.security.log_sanitisation import sanitise_exception_message, sanitise_for_terminal
from core.sandbox._daemon import (
    _MAX_REPLY_FRAME_BYTES,
    _MAX_FRAME_BYTES as _DAEMON_REQUEST_CAP,
)

log = logging.getLogger(__name__)


_DAEMON_SCRIPT = Path(__file__).resolve().parent / "_daemon.py"

def _rpc_deadline(timeout):
    try:
        seconds = float(timeout)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HostRPCError("RPC timeout must be finite and positive") from exc
    if not math.isfinite(seconds) or seconds <= 0:
        raise HostRPCError("RPC timeout must be finite and positive")
    return time.monotonic() + seconds


def _request_frame(payload):
    body = json.dumps(payload).encode("utf-8")
    if len(body) > _DAEMON_REQUEST_CAP:
        raise HostRPCError(f"request frame too large: {len(body)}")
    return struct.pack("!I", len(body)) + body


def _remove_owned_output(path: str) -> bool:
    """Best-effort removal with honest accounting and a retryable result."""
    try:
        if rmtree_hardened(path):
            return True
    except Exception as exc:
        log.warning(
            "Cannot remove sandbox host output %s: %s: %s",
            sanitise_for_terminal(path),
            sanitise_for_terminal(type(exc).__name__, max_len=64),
            sanitise_exception_message(exc),
        )
    else:
        log.warning("Sandbox host output retained after failed removal: %s",
                    sanitise_for_terminal(path))
    return False


def _resolve_output(target_path: Path, output: Path | None) -> tuple[str, str | None]:
    """Resolve the sandbox output directory; never the target itself.

    Returns ``(output_dir, owned_tmpdir)``. When ``output`` is omitted
    a private mkdtemp becomes the output dir (``owned_tmpdir`` is
    non-None and the caller removes it when the session ends).
    Pre-fix the default was the TARGET path, which made the untrusted
    target tree a writable bind — a hostile target could rewrite the
    scanned repo. An explicit ``output`` that resolves (realpath) to
    the target is refused for the same reason.

    The RESOLVED path is what gets returned: the guard compares
    realpaths, so the mount must consume exactly the path that was
    vetted — returning the raw argument would let a symlink swapped
    between check and use (or a dangling link) re-route the rw bind
    to a location the guard never saw.
    """
    if output is None:
        owned = tempfile.mkdtemp(prefix="raptor-host-out-")
        return owned, owned
    _out_real = os.path.realpath(os.fspath(output))
    _tgt_real = os.path.realpath(str(target_path))
    # Refuse BOTH nesting directions, not just equality — the path
    # relation enumeration is {equal, output-under-target,
    # target-under-output} and every element defeats the ro contract:
    # - output under target lands the rw output bind INSIDE the
    #   target tree, handing a spawned hostile target a writable
    #   window back into the scanned repo;
    # - target under output is subtler: the mount-ns setup binds the
    #   target ro FIRST, then binds the output rw ON TOP of it (the
    #   ancestor mount shadows the target's ro bind), and Landlock's
    #   writable grant on output is a subtree grant covering the
    #   target too — the ro remount succeeds and is then silently
    #   shadowed, so neither layer holds.
    if _out_real == _tgt_real or _out_real.startswith(
            _tgt_real.rstrip("/") + "/"):
        raise ValueError(
            f"output {str(output)!r} resolves into the target "
            f"directory {target_path} — the target tree must stay "
            f"read-only inside the sandbox; choose a distinct output "
            f"directory outside it"
        )
    if _tgt_real.startswith(_out_real.rstrip("/") + "/"):
        raise ValueError(
            f"output {str(output)!r} resolves to an ancestor of the "
            f"target directory {target_path} — its rw bind would "
            f"shadow the target's read-only bind and its Landlock "
            f"grant would cover the target subtree; the target tree "
            f"must stay read-only inside the sandbox; choose a "
            f"distinct output directory that does not contain it"
        )
    return _out_real, None


def _resolve_daemon_script() -> Path:
    """Locate the sandbox host daemon script (co-located sibling)."""
    if _DAEMON_SCRIPT.is_file():
        return _DAEMON_SCRIPT
    msg = f"sandbox daemon not found at {_DAEMON_SCRIPT}"
    raise RuntimeError(msg)


class HostRPCError(RuntimeError):
    """RPC channel failure or daemon-reported error."""


def _decode_response(body: bytes, *, source: str) -> dict:
    """Keep malformed replies on the channel-error and cleanup path."""
    try:
        response = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise HostRPCError(f"{source} response parse failed: {exc}") from exc
    if not isinstance(response, dict):
        raise HostRPCError(f"{source} response must contain a JSON object")
    return response


class SandboxHost:
    """Parent-side handle to a persistent sandboxed daemon.

    Public API: ``start`` (constructor), ``spawn``, ``probe``,
    ``conversation``, ``close``.
    """

    def __init__(
        self,
        *,
        _thread: threading.Thread,
        _write_fd: int,
        _read_fd: int,
        _daemon_fds: tuple[int, int] | None,
        _lock: threading.Lock,
        _owned_output: str | None = None,
    ) -> None:
        self._thread = _thread
        self._write_fd = _write_fd
        self._read_fd = _read_fd
        # Private mkdtemp used as the sandbox output dir when the
        # caller didn't pass one; removed in close().
        self._owned_output = _owned_output
        # Parent-held copies of the daemon-side pipe ends. Kept open
        # until the startup ping proves the daemon inherited its own
        # copies, or the backend exits. Release is shared with the
        # worker so failed startup also exposes EOF promptly.
        self._daemon_fds = _daemon_fds
        self._daemon_fds_lock = threading.Lock()
        # The fd numbers as they appear inside the daemon's fd table
        # (pass_fds preserves numbers). Retained after the parent
        # copies are closed — diagnostics and the hostile-peer tests
        # use them.
        self._daemon_fd_numbers = tuple(_daemon_fds or ())
        self._lock = _lock
        self._closed = False
        self._broken = False
        self._closing_transaction = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def start(
        cls,
        *,
        target: Path,
        output: Path | None = None,
        readable_paths: list[str] | None = None,
        writable_paths: list[str] | None = None,
        etc_overlay: dict | None = None,
        env: dict | None = None,
        startup_timeout: float = 30.0,
    ) -> SandboxHost:
        """Spawn the daemon inside a sandbox and connect via pipe fds.

        Callers are responsible for assembling ``readable_paths`` and
        ``env`` with any domain-specific paths (e.g. vendored
        libraries) BEFORE calling this method.  SandboxHost itself
        has no knowledge of what runs inside the sandbox.
        """
        from core.sandbox import run as sandbox_run
        from core.sandbox.context import _require_userns_or_optin

        # SandboxHost is an explicitly hostile-target facility; the
        # generic sandbox_run below carries none of run_untrusted's
        # fail-closed preflight, so on a namespace-less host it would
        # silently degrade to Landlock-only with the whole-/proc read
        # grant (same-UID environ readable). Apply the same gate: fail
        # closed unless the operator opted into degraded mode, and
        # withdraw the /proc read grant when they did.
        _omit_proc = _require_userns_or_optin("SandboxHost",
                                              restrict_reads=True)

        daemon = _resolve_daemon_script()
        target_path = Path(target).resolve()
        output_dir, owned_output = _resolve_output(target_path, output)

        setup_fds: list[int] = []
        launch_gate = None
        worker_enabled = False
        thread = None
        try:
            # Two pipe pairs. os.pipe() fds are CLOEXEC/non-inheritable by
            # default (PEP 446); pass_fds below clears CLOEXEC on the two
            # daemon-side ends in the spawned child ONLY, so the parent's
            # copies never leak into any other subprocess this process
            # spawns.
            in_r, in_w = os.pipe()      # rpc_in: parent writes → daemon reads
            setup_fds.extend((in_r, in_w))
            out_r, out_w = os.pipe()    # rpc_out: daemon writes → parent reads
            setup_fds.extend((out_r, out_w))

            readable = list(readable_paths or [])
            readable.append(str(daemon))
            from core.sandbox.python_paths import python_runtime_tool_paths
            readable.extend(python_runtime_tool_paths())

            result_holder: dict[str, Any] = {"error": None, "returncode": None}
            launch_gate = threading.Event()

            def _worker() -> None:
                launch_gate.wait()
                if not worker_enabled:
                    return
                try:
                    r = sandbox_run(
                        ["python3", "-S", str(daemon),
                         "--rpc-in-fd", str(in_r),
                         "--rpc-out-fd", str(out_w)],
                        target=str(target_path),
                        output=output_dir,
                        block_network=True,
                        restrict_reads=True,
                        omit_proc_reads=_omit_proc,
                        readable_paths=readable,
                        writable_paths=writable_paths,
                        etc_overlay=etc_overlay,
                        env=env or None,
                        env_caller_filtered=True,
                        # Declared intent for the PATH-divergence gate: the
                        # daemon is stdlib-only (-S, no site imports) and
                        # runs under WHATEVER python3 the sandbox view
                        # resolves — the caller's venv interpreter is
                        # deliberately not required, so a venv-active
                        # caller diverging from the child's system python3
                        # is fine here.
                        allow_path_divergence=True,
                        capture_output=True,
                        text=False,
                        timeout=None,
                        # Inherit exactly the daemon-side pipe ends across
                        # the sandbox spawn. sandbox().run() audits each
                        # entry (rejects sockets, allows pipes) and the
                        # subprocess backend keeps the fd NUMBERS stable,
                        # so the argv above stays valid inside the daemon.
                        pass_fds=(in_r, out_w),
                    )
                    result_holder["returncode"] = r.returncode
                    result_holder["stderr"] = (r.stderr or b"").decode(
                        "utf-8", errors="replace",
                    )[-4000:]
                except Exception as e:  # noqa: BLE001
                    result_holder["error"] = f"{type(e).__name__}: {e}"
                finally:
                    # A failed or cancelled startup may never receive a
                    # ping. Keep spawn fds valid until the backend exits,
                    # then release them so readers observe daemon EOF.
                    try:
                        host._release_daemon_fds()
                    finally:
                        if host._closed:
                            host._cleanup_owned_output()

            thread = threading.Thread(
                target=_worker, name="sandbox-host-daemon", daemon=True,
            )
            host = cls(
                _thread=thread,
                _write_fd=in_w,
                _read_fd=out_r,
                _daemon_fds=(in_r, out_w),
                _lock=threading.Lock(),
                _owned_output=owned_output,
            )
            thread.start()
        except BaseException as failure:
            # Register every owner before retirement can itself fail. The
            # disabled worker must be released and joined before its setup
            # endpoints are retired; private output is removed last.
            def close_setup_fd(fd):
                with contextlib.suppress(OSError):
                    os.close(fd)

            def join_disabled_worker():
                with contextlib.suppress(RuntimeError):
                    thread.join(timeout=5.0)

            try:
                with contextlib.ExitStack() as cleanup:
                    if owned_output:
                        cleanup.callback(_remove_owned_output, owned_output)
                    for fd in setup_fds:
                        cleanup.callback(close_setup_fd, fd)
                    if thread is not None:
                        cleanup.callback(join_disabled_worker)
                    if launch_gate is not None:
                        cleanup.callback(launch_gate.set)
            except BaseException as cleanup_error:
                failure.add_note(
                    "host preparation cleanup: " + type(cleanup_error).__name__)
            raise
        try:
            worker_enabled = True
            launch_gate.set()
            pong = host._rpc({"cmd": "ping"}, timeout=startup_timeout)
            if not pong.get("ok"):
                msg = f"daemon ping failed: {pong}"
                raise HostRPCError(msg)
        except BaseException as e:
            launch_gate.set()
            try:
                host.close()
            except BaseException as cleanup_error:
                e.add_note("host startup cleanup: " + type(cleanup_error).__name__)
            if not isinstance(e, Exception):
                raise
            if not thread.is_alive():
                msg = (
                    f"daemon died during startup: "
                    f"rc={result_holder.get('returncode')} "
                    f"err={result_holder.get('error')} "
                    f"stderr={result_holder.get('stderr', '')[-800:]!r}"
                )
                raise HostRPCError(msg) from e
            raise
        try:
            log.info("sandbox_host started (daemon pid=%s)", pong.get("pid"))
            # A successful ping proves inheritance. Drop the parent's
            # daemon-side copies so backend exit exposes EOF promptly.
            host._release_daemon_fds()
        except BaseException as failure:
            try:
                host.close()
            except BaseException as cleanup_error:
                failure.add_note("host acknowledgement cleanup: " + type(cleanup_error).__name__)
            raise
        return host

    def _release_daemon_fds(self) -> None:
        """Close the parent's copies of the daemon-side pipe ends."""
        with self._daemon_fds_lock:
            fds, self._daemon_fds = self._daemon_fds, None
        errors = []
        for fd in fds or ():
            try:
                os.close(fd)
            except OSError:
                pass
            except BaseException as exc:
                errors.append(exc)
        if errors:
            primary = errors.pop(0)
            for exc in errors:
                primary.add_note("daemon endpoint cleanup: " + type(exc).__name__)
            raise primary

    def _cleanup_owned_output(self) -> None:
        """Keep ownership until the backend's private scratch is removed."""
        with self._daemon_fds_lock:
            output = self._owned_output
            if output and _remove_owned_output(output):
                self._owned_output = None

    def _release_rpc_fds(self, failure=None) -> None:
        """Consume owned endpoint numbers before closing; caller owns _lock."""
        errors = []
        for name in ("_write_fd", "_read_fd"):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                except BaseException as exc:
                    errors.append(exc)
        if errors:
            primary = failure if failure is not None else errors.pop(0)
            for exc in errors:
                primary.add_note("RPC endpoint cleanup: " + type(exc).__name__)
            if failure is None:
                raise primary

    def close(self) -> None:
        """Close within one budget, without racing an active pipe operation.

        Active transactions observe the closing flag at bounded poll ticks;
        they retire their own channel before releasing the request lock.
        A backend still running retains its private output until it exits.
        """
        deadline = time.monotonic() + 5.0
        first = not self._closed
        self._closed = True
        failure = None
        try:
            if first:
                with contextlib.suppress(HostRPCError, ValueError):
                    self._rpc({"cmd": "close"}, timeout=max(0, deadline - time.monotonic()))
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                acquired = self._lock.acquire(timeout=max(0, deadline - time.monotonic()))
                if acquired:
                    try:
                        self._release_rpc_fds(failure)
                    finally:
                        self._lock.release()
                # The active I/O owner retires its endpoints after observing
                # close. Never close its numeric descriptors from this thread.
            except BaseException as exc:
                if failure is None:
                    failure = exc
                else:
                    failure.add_note("RPC close cleanup: " + type(exc).__name__)
            try:
                self._thread.join(timeout=max(0, deadline - time.monotonic()))
                if self._thread.is_alive():
                    log.warning("sandbox_host worker thread did not exit within 5s")
                else:
                    self._cleanup_owned_output()
            except BaseException as exc:
                if failure is None:
                    failure = exc
                else:
                    failure.add_note("RPC worker cleanup: " + type(exc).__name__)
            if failure is not None:
                raise failure

    # ------------------------------------------------------------------
    # RPC verbs
    # ------------------------------------------------------------------

    def spawn(
        self,
        argv: list[str],
        *,
        stdin_bytes: bytes = b"",
        timeout: float = 30.0,
    ) -> dict:
        """One-shot exec inside the sandbox."""
        response = self._rpc({
            "cmd": "spawn",
            "argv": argv,
            "stdin_hex": stdin_bytes.hex(),
            "timeout": timeout,
        }, timeout=timeout + 5.0)
        if not response.get("ok"):
            raise HostRPCError(response.get("error", "spawn failed"))
        return {
            "stdout": bytes.fromhex(response.get("stdout_hex", "")),
            "stderr": bytes.fromhex(response.get("stderr_hex", "")),
            "returncode": response.get("returncode"),
            "timed_out": response.get("timed_out", False),
            # Capture-cap markers: True when the daemon discarded
            # output beyond its per-stream retention ceiling.
            "stdout_truncated": response.get("stdout_truncated", False),
            "stderr_truncated": response.get("stderr_truncated", False),
            "wall_seconds": response.get("wall_seconds"),
        }

    def probe(
        self,
        *,
        target_argv: list[str],
        steps: list[dict],
        per_recv_timeout: float = 3.0,
        total_wait_seconds: float = 5.0,
        flag_string: str = "",
        timeout: float | None = None,
    ) -> dict:
        """Interactive step-driver probe."""
        rpc_timeout = timeout if timeout is not None else (
            per_recv_timeout * (len(steps) + 2) + total_wait_seconds + 10.0
        )
        return self._rpc({
            "cmd": "probe",
            "target_argv": target_argv,
            "steps": steps,
            "per_recv_timeout": per_recv_timeout,
            "total_wait_seconds": total_wait_seconds,
            "flag_string": flag_string,
        }, timeout=rpc_timeout)

    def conversation(
        self,
        *,
        target_argv: list[str],
        sends: list[dict],
        per_recv_timeout: float = 2.0,
        close_after: bool = True,
        total_wait_seconds: float = 3.0,
        timeout: float | None = None,
    ) -> dict:
        """stdin_conversation-shaped step-driver."""
        rpc_timeout = timeout if timeout is not None else (
            per_recv_timeout * (len(sends) + 2) + total_wait_seconds + 10.0
        )
        return self._rpc({
            "cmd": "conversation",
            "target_argv": target_argv,
            "sends": sends,
            "per_recv_timeout": per_recv_timeout,
            "total_wait_seconds": total_wait_seconds,
            "close_after": close_after,
        }, timeout=rpc_timeout)

    # ------------------------------------------------------------------
    # Framed RPC internals
    # ------------------------------------------------------------------

    def _rpc(self, payload: dict, *, timeout: float) -> dict:
        deadline = _rpc_deadline(timeout)
        closing = payload.get("cmd") == "close"
        if self._closed and not closing:
            raise HostRPCError("sandbox host is closed")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._lock.acquire(timeout=min(remaining, threading.TIMEOUT_MAX)):
            # A queued caller owns no transaction and cannot poison the
            # channel currently serving another caller.
            raise HostRPCError("RPC request queue deadline exceeded")
        started = False
        failure = None
        try:
            if self._broken:
                raise HostRPCError("RPC channel is retired after a failed transaction")
            if self._closed and not closing:
                raise HostRPCError("sandbox host is closed")
            rid = os.urandom(16).hex()
            frame = _request_frame({**payload, "rid": rid})
            if time.monotonic() >= deadline:
                raise HostRPCError("RPC request deadline exceeded before send")
            self._closing_transaction = closing
            started = True
            os.set_blocking(self._write_fd, False)
            os.set_blocking(self._read_fd, False)
            self._write_frame_bytes(frame, deadline=deadline)
            response = self._read_frame(deadline=deadline)
            if response.get("rid") != rid:
                raise HostRPCError(
                    f"reply not bound to request: expected rid={rid} "
                    f"got rid={response.get('rid')!r} — forged, stale, or "
                    f"misordered frame on the RPC channel"
                )
            response.pop("rid", None)
            return response
        except BaseException as exc:
            failure = exc
            if started:
                # A send/receive can fail at any byte boundary. Reusing
                # this stream would turn its residue into the next reply.
                self._broken = True
            raise
        finally:
            try:
                if self._broken or self._closed:
                    self._release_rpc_fds(failure)
            finally:
                self._closing_transaction = False
                self._lock.release()

    def _wait_rpc(self, fd, mask, deadline):
        poller = select.poll()
        poller.register(fd, mask)
        while True:
            if getattr(self, "_closed", False) and not getattr(self, "_closing_transaction", False):
                raise HostRPCError("sandbox host closed during request")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HostRPCError("RPC transaction deadline exceeded")
            # Close can interrupt an active transaction even if its caller
            # supplied a long request timeout and the peer stays silent.
            try:
                if poller.poll(math.ceil(min(remaining, 0.05) * 1000)):
                    return
            except InterruptedError:
                continue

    def _write_frame(self, payload: dict, *, deadline=None) -> None:
        self._write_frame_bytes(_request_frame(payload), deadline=deadline)

    def _write_frame_bytes(self, frame, *, deadline=None) -> None:
        view = memoryview(frame)
        try:
            while view:
                if deadline is not None:
                    self._wait_rpc(self._write_fd, select.POLLOUT, deadline)
                try:
                    n = os.write(self._write_fd, view[:65536])
                except (BlockingIOError, InterruptedError):
                    continue
                if n <= 0:
                    raise OSError(errno.EIO, "RPC frame write made no progress")
                view = view[n:]
        except OSError as exc:
            raise HostRPCError(f"write to daemon failed: {exc}") from exc

    def _read_frame(self, *, timeout=None, deadline=None) -> dict:
        if deadline is None:
            deadline = _rpc_deadline(timeout)
        try:
            hdr = self._read_exact(4, deadline)
        except (OSError, HostRPCError) as exc:
            raise HostRPCError(f"header read failed: {exc}") from exc
        (length,) = struct.unpack("!I", hdr)
        if length > _MAX_REPLY_FRAME_BYTES:
            raise HostRPCError(f"daemon frame too large: {length}")
        try:
            body = self._read_exact(length, deadline)
        except (OSError, HostRPCError) as exc:
            raise HostRPCError(f"body read failed: {exc}") from exc
        return _decode_response(body, source="daemon")

    def _read_exact(self, n: int, deadline: float) -> bytes:
        # bytearray accumulator: bounded reply frames can run to
        # hundreds of MiB (see _MAX_REPLY_FRAME_BYTES) and repeated
        # bytes concatenation is quadratic at that size.
        buf = bytearray()
        os.set_blocking(self._read_fd, False)
        while len(buf) < n:
            self._wait_rpc(self._read_fd, select.POLLIN, deadline)
            try:
                chunk = os.read(self._read_fd, min(n - len(buf), 65536))
            except (BlockingIOError, InterruptedError):
                continue
            if not chunk:
                raise HostRPCError("daemon EOF")
            buf.extend(chunk)
        return bytes(buf)


# ---------------------------------------------------------------------
# One-shot fallback substrate
# ---------------------------------------------------------------------


def one_shot_call(
    *,
    cmd: str,
    payload: dict,
    target: Path,
    output: Path | None = None,
    readable_paths: list[str] | None = None,
    writable_paths: list[str] | None = None,
    etc_overlay: dict | None = None,
    env: dict | None = None,
    timeout: float = 60.0,
) -> dict:
    """Spawn the daemon in ``--one-shot`` mode, execute exactly one
    verb, return the response.

    Used as the fallback substrate when the persistent SandboxHost
    can't start.  Same sandbox posture, same daemon code, same
    protocol — the only difference is the daemon reads one frame from
    stdin and exits instead of holding the inherited RPC fds.

    Callers must assemble ``readable_paths`` and ``env`` with any
    domain-specific paths BEFORE calling.
    """
    from core.sandbox import run as sandbox_run
    from core.sandbox.context import _require_userns_or_optin

    # Same fail-closed preflight as SandboxHost.start — see there.
    _omit_proc = _require_userns_or_optin("SandboxHost.one_shot_call",
                                          restrict_reads=True)

    daemon = _resolve_daemon_script()
    target_path = Path(target).resolve()
    output_dir, owned_output = _resolve_output(target_path, output)
    failure = None
    try:
        readable = list(readable_paths or [])
        readable.append(str(daemon))
        from core.sandbox.python_paths import python_runtime_tool_paths
        readable.extend(python_runtime_tool_paths())

        # Same request/response binding as SandboxHost._rpc: the daemon
        # echoes the parent-minted ``rid`` and the reply is rejected on a
        # mismatch (a target that reopened the daemon's stdout could
        # otherwise substitute the verdict frame).
        rid = os.urandom(16).hex()
        frame = _request_frame({"cmd": cmd, **payload, "rid": rid})

        try:
            r = sandbox_run(
                ["python3", "-S", str(daemon), "--one-shot"],
                target=str(target_path),
                output=output_dir,
                block_network=True,
                restrict_reads=True,
                omit_proc_reads=_omit_proc,
                readable_paths=readable,
                writable_paths=writable_paths,
                etc_overlay=etc_overlay,
                env=env or None,
                env_caller_filtered=True,
                # Same declared intent as the persistent-daemon spawn: the
                # stdlib-only daemon runs under the sandbox view's python3;
                # caller-venv divergence is fine here.
                allow_path_divergence=True,
                input=frame,
                capture_output=True,
                text=False,
                timeout=timeout,
            )
        except Exception as e:
            msg = f"one-shot daemon spawn failed: {type(e).__name__}: {e}"
            raise HostRPCError(msg) from e
        if not r.stdout:
            stderr_tail = (r.stderr or b"").decode(
                "utf-8", errors="replace",
            )[-800:]
            msg = (
                f"one-shot daemon produced no stdout (rc={r.returncode}, "
                f"stderr={stderr_tail!r})"
            )
            raise HostRPCError(msg)
        if len(r.stdout) < 4:
            msg = f"one-shot response too short: {len(r.stdout)} bytes"
            raise HostRPCError(msg)
        (length,) = struct.unpack("!I", r.stdout[:4])
        if length > _MAX_REPLY_FRAME_BYTES:
            raise HostRPCError(f"one-shot daemon frame too large: {length}")
        if length > len(r.stdout) - 4:
            msg = (
                f"one-shot response truncated: header={length} "
                f"body_bytes={len(r.stdout) - 4}"
            )
            raise HostRPCError(msg)
        if length != len(r.stdout) - 4:
            raise HostRPCError("trailing bytes after one-shot response frame")
        response = _decode_response(r.stdout[4:], source="one-shot")
        if response.get("rid") != rid:
            raise HostRPCError(
                f"one-shot reply not bound to request: expected rid={rid} "
                f"got rid={response.get('rid')!r}"
            )
        response.pop("rid", None)
        return response
    except BaseException as error:
        failure = error
        raise
    finally:
        if owned_output:
            try:
                _remove_owned_output(owned_output)
            except BaseException as cleanup_error:
                if failure is None:
                    raise
                failure.add_note(
                    "one-shot output cleanup: " + type(cleanup_error).__name__)
