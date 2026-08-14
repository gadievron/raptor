"""Persistent-sandbox host — parent-side handle.

Keeps a long-lived sandboxed daemon alive so multiple spawn/probe
calls share ONE sandbox + Python startup instead of paying it per
call.

Rendezvous: two FIFOs at ``<target>/rpc_in.fifo`` and
``<target>/rpc_out.fifo``.  Parent ``mkfifo``s them BEFORE
launching the sandbox; both sides open them by path.  Same
underlying inodes via the mount-ns bind of the target directory.
FIFOs (rather than AF_UNIX sockets) because seccomp:full blocks
``socket()`` — env parity with parse_result requires the daemon
to run under the same profile the target does.

Threading: ``core.sandbox.run`` is blocking, so a background
thread holds the sandbox open.  The parent-side handle uses the
FIFOs for RPC while the thread parks in the sandbox call for the
host's lifetime.  ``close()`` terminates cleanly.

The companion daemon script lives at ``core/sandbox/_daemon.py``
— pure stdlib, no external deps.
"""
from __future__ import annotations

import json
import logging
import os
import select
import struct
import threading
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


_DAEMON_SCRIPT = Path(__file__).resolve().parent / "_daemon.py"


def _resolve_daemon_script() -> Path:
    """Locate the sandbox host daemon script (co-located sibling)."""
    if _DAEMON_SCRIPT.is_file():
        return _DAEMON_SCRIPT
    raise RuntimeError(
        f"sandbox daemon not found at {_DAEMON_SCRIPT}"
    )


class HostRPCError(RuntimeError):
    """RPC channel failure or daemon-reported error."""


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
        _fifo_in: str,
        _fifo_out: str,
        _lock: threading.Lock,
    ) -> None:
        self._thread = _thread
        self._write_fd = _write_fd
        self._read_fd = _read_fd
        self._fifo_in = _fifo_in
        self._fifo_out = _fifo_out
        self._lock = _lock
        self._closed = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def start(
        cls,
        *,
        target: Path,
        output: Optional[Path] = None,
        readable_paths: Optional[list[str]] = None,
        writable_paths: Optional[list[str]] = None,
        etc_overlay: Optional[dict] = None,
        env: Optional[dict] = None,
        startup_timeout: float = 30.0,
    ) -> "SandboxHost":
        """Spawn the daemon inside a sandbox and connect via FIFOs.

        Callers are responsible for assembling ``readable_paths`` and
        ``env`` with any domain-specific paths (e.g. vendored
        libraries) BEFORE calling this method.  SandboxHost itself
        has no knowledge of what runs inside the sandbox.
        """
        from core.sandbox import run as sandbox_run

        daemon = _resolve_daemon_script()
        target_path = Path(target).resolve()
        fifo_in = str(target_path / "rpc_in.fifo")
        fifo_out = str(target_path / "rpc_out.fifo")
        for _p in (fifo_in, fifo_out):
            try:
                os.unlink(_p)
            except OSError:
                pass
            os.mkfifo(_p, 0o600)

        readable = list(readable_paths or [])
        readable.append(str(daemon))

        result_holder: dict[str, Any] = {"error": None, "returncode": None}

        def _worker() -> None:
            try:
                r = sandbox_run(
                    ["python3", "-S", str(daemon),
                     "--fifo-in", fifo_in,
                     "--fifo-out", fifo_out],
                    target=str(target_path),
                    output=str(output or target_path),
                    block_network=True,
                    restrict_reads=True,
                    readable_paths=readable,
                    writable_paths=writable_paths,
                    etc_overlay=etc_overlay,
                    env=env or None,
                    env_caller_filtered=True,
                    capture_output=True,
                    text=False,
                    timeout=None,
                )
                result_holder["returncode"] = r.returncode
                result_holder["stderr"] = (r.stderr or b"").decode(
                    "utf-8", errors="replace",
                )[-4000:]
            except Exception as e:  # noqa: BLE001
                result_holder["error"] = f"{type(e).__name__}: {e}"

        thread = threading.Thread(
            target=_worker, name="sandbox-host-daemon", daemon=True,
        )
        thread.start()

        _open_state: dict[str, Any] = {
            "write_fd": None, "read_fd": None, "error": None,
        }

        def _opener() -> None:
            try:
                _open_state["write_fd"] = os.open(fifo_in, os.O_WRONLY)
                _open_state["read_fd"] = os.open(fifo_out, os.O_RDONLY)
            except OSError as e:
                _open_state["error"] = e

        opener_thread = threading.Thread(
            target=_opener, name="sandbox-host-fifo-opener", daemon=True,
        )
        opener_thread.start()
        opener_thread.join(timeout=startup_timeout)
        if opener_thread.is_alive() or _open_state["error"] is not None:
            for _fd_key in ("write_fd", "read_fd"):
                _fd = _open_state[_fd_key]
                if _fd is not None:
                    try:
                        os.close(_fd)
                    except OSError:
                        pass
            if not thread.is_alive():
                raise HostRPCError(
                    f"daemon died before FIFO open: "
                    f"err={result_holder.get('error')} "
                    f"stderr={result_holder.get('stderr', '')[-800:]!r}"
                )
            raise HostRPCError(
                f"FIFO open timed out ({startup_timeout}s) — "
                f"opener_alive={opener_thread.is_alive()} "
                f"error={_open_state['error']}"
            )
        write_fd = _open_state["write_fd"]
        read_fd = _open_state["read_fd"]

        host = cls(
            _thread=thread,
            _write_fd=write_fd,
            _read_fd=read_fd,
            _fifo_in=fifo_in,
            _fifo_out=fifo_out,
            _lock=threading.Lock(),
        )
        try:
            pong = host._rpc({"cmd": "ping"}, timeout=10.0)
            if not pong.get("ok"):
                raise HostRPCError(f"daemon ping failed: {pong}")
            log.info("sandbox_host started (daemon pid=%s)", pong.get("pid"))
        except Exception:
            host.close()
            raise
        return host

    def close(self) -> None:
        """Terminate the daemon and clean up FIFOs."""
        if self._closed:
            return
        self._closed = True
        try:
            self._rpc({"cmd": "close"}, timeout=5.0)
        except Exception:  # noqa: BLE001
            pass
        for fd in (self._write_fd, self._read_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        self._thread.join(timeout=5.0)
        if self._thread.is_alive():
            log.warning("sandbox_host worker thread did not exit within 5s")
        for _p in (self._fifo_in, self._fifo_out):
            try:
                os.unlink(_p)
            except OSError:
                pass

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
        timeout: Optional[float] = None,
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
        timeout: Optional[float] = None,
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
        with self._lock:
            self._write_frame(payload)
            return self._read_frame(timeout=timeout)

    def _write_frame(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        hdr = struct.pack("!I", len(body))
        try:
            os.write(self._write_fd, hdr + body)
        except OSError as e:
            raise HostRPCError(f"write to daemon failed: {e}") from e

    def _read_frame(self, *, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        try:
            hdr = self._read_exact(4, deadline)
        except (OSError, HostRPCError) as e:
            raise HostRPCError(f"header read failed: {e}") from e
        (length,) = struct.unpack("!I", hdr)
        if length > 64 * 1024 * 1024:
            raise HostRPCError(f"daemon frame too large: {length}")
        try:
            body = self._read_exact(length, deadline)
        except (OSError, HostRPCError) as e:
            raise HostRPCError(f"body read failed: {e}") from e
        return json.loads(body.decode("utf-8"))

    def _read_exact(self, n: int, deadline: float) -> bytes:
        buf = b""
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HostRPCError(f"read timeout at {len(buf)}/{n}")
            r, _, _ = select.select([self._read_fd], [], [], remaining)
            if not r:
                raise HostRPCError(f"read select timeout at {len(buf)}/{n}")
            chunk = os.read(self._read_fd, n - len(buf))
            if not chunk:
                raise HostRPCError("daemon EOF")
            buf += chunk
        return buf


# ---------------------------------------------------------------------
# One-shot fallback substrate
# ---------------------------------------------------------------------


def one_shot_call(
    *,
    cmd: str,
    payload: dict,
    target: Path,
    output: Optional[Path] = None,
    readable_paths: Optional[list[str]] = None,
    writable_paths: Optional[list[str]] = None,
    etc_overlay: Optional[dict] = None,
    env: Optional[dict] = None,
    timeout: float = 60.0,
) -> dict:
    """Spawn the daemon in ``--one-shot`` mode, execute exactly one
    verb, return the response.

    Used as the fallback substrate when the persistent SandboxHost
    can't start.  Same sandbox posture, same daemon code, same
    protocol — the only difference is the daemon reads one frame from
    stdin and exits instead of holding open FIFOs.

    Callers must assemble ``readable_paths`` and ``env`` with any
    domain-specific paths BEFORE calling.
    """
    from core.sandbox import run as sandbox_run

    daemon = _resolve_daemon_script()
    target_path = Path(target).resolve()
    readable = list(readable_paths or [])
    readable.append(str(daemon))

    body = json.dumps({"cmd": cmd, **payload}).encode("utf-8")
    frame = struct.pack("!I", len(body)) + body

    try:
        r = sandbox_run(
            ["python3", "-S", str(daemon), "--one-shot"],
            target=str(target_path),
            output=str(output or target_path),
            block_network=True,
            restrict_reads=True,
            readable_paths=readable,
            writable_paths=writable_paths,
            etc_overlay=etc_overlay,
            env=env or None,
            env_caller_filtered=True,
            input=frame,
            capture_output=True,
            text=False,
            timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001
        raise HostRPCError(
            f"one-shot daemon spawn failed: {type(e).__name__}: {e}"
        ) from e

    if not r.stdout:
        stderr_tail = (r.stderr or b"").decode(
            "utf-8", errors="replace",
        )[-800:]
        raise HostRPCError(
            f"one-shot daemon produced no stdout (rc={r.returncode}, "
            f"stderr={stderr_tail!r})"
        )
    if len(r.stdout) < 4:
        raise HostRPCError(
            f"one-shot response too short: {len(r.stdout)} bytes"
        )
    (length,) = struct.unpack("!I", r.stdout[:4])
    if length > len(r.stdout) - 4:
        raise HostRPCError(
            f"one-shot response truncated: header={length} "
            f"body_bytes={len(r.stdout) - 4}"
        )
    try:
        return json.loads(r.stdout[4:4 + length].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise HostRPCError(f"one-shot response parse failed: {e}") from e
