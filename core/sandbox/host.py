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
import json
import logging
import os
import select
import shutil
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from core.sandbox._daemon import _MAX_CAPTURE_BYTES as _DAEMON_CAPTURE_CAP

log = logging.getLogger(__name__)


_DAEMON_SCRIPT = Path(__file__).resolve().parent / "_daemon.py"

# Ceiling on one daemon→parent reply frame. The daemon retains at
# most _MAX_CAPTURE_BYTES per stream and a reply carries at most two
# capped streams, each hex-doubled (spawn: stdout+stderr;
# conversation: recvs+stdout), so 4x the capture cap bounds the
# payload; 1 MiB covers JSON overhead. Sized from the daemon's cap so
# a maximal legitimate reply always fits — pre-fix the parent
# rejected frames over 64 MiB only AFTER the daemon had already built
# and half-sent them, wedging the persistent channel mid-frame.
_MAX_REPLY_FRAME_BYTES = 4 * _DAEMON_CAPTURE_CAP + 1024 * 1024


def _resolve_output(target_path: Path, output: Path | None) -> tuple[str, str | None]:
    """Resolve the sandbox output directory; never the target itself.

    Returns ``(output_dir, owned_tmpdir)``. When ``output`` is omitted
    a private mkdtemp becomes the output dir (``owned_tmpdir`` is
    non-None and the caller removes it when the session ends).
    Pre-fix the default was the TARGET path, which made the untrusted
    target tree a writable bind — a hostile target could rewrite the
    scanned repo. An explicit ``output`` that resolves (realpath) to
    the target is refused for the same reason.
    """
    if output is None:
        owned = tempfile.mkdtemp(prefix="raptor-host-out-")
        return owned, owned
    if os.path.realpath(os.fspath(output)) == os.path.realpath(
            str(target_path)):
        raise ValueError(
            f"output {str(output)!r} resolves to the target directory "
            f"{target_path} — the target tree must stay read-only "
            f"inside the sandbox; choose a distinct output directory"
        )
    return os.fspath(output), None


def _resolve_daemon_script() -> Path:
    """Locate the sandbox host daemon script (co-located sibling)."""
    if _DAEMON_SCRIPT.is_file():
        return _DAEMON_SCRIPT
    msg = f"sandbox daemon not found at {_DAEMON_SCRIPT}"
    raise RuntimeError(msg)


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
        # only until the startup ping proves the daemon inherited its
        # own copies, then closed so EOF tracks daemon death.
        self._daemon_fds = _daemon_fds
        # The fd numbers as they appear inside the daemon's fd table
        # (pass_fds preserves numbers). Retained after the parent
        # copies are closed — diagnostics and the hostile-peer tests
        # use them.
        self._daemon_fd_numbers = tuple(_daemon_fds or ())
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

        # Two pipe pairs. os.pipe() fds are CLOEXEC/non-inheritable by
        # default (PEP 446); pass_fds below clears CLOEXEC on the two
        # daemon-side ends in the spawned child ONLY, so the parent's
        # copies never leak into any other subprocess this process
        # spawns.
        in_r, in_w = os.pipe()      # rpc_in: parent writes → daemon reads
        out_r, out_w = os.pipe()    # rpc_out: daemon writes → parent reads

        readable = list(readable_paths or [])
        readable.append(str(daemon))

        result_holder: dict[str, Any] = {"error": None, "returncode": None}

        def _worker() -> None:
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

        try:
            thread = threading.Thread(
                target=_worker, name="sandbox-host-daemon", daemon=True,
            )
            thread.start()

            host = cls(
                _thread=thread,
                _write_fd=in_w,
                _read_fd=out_r,
                _daemon_fds=(in_r, out_w),
                _lock=threading.Lock(),
                _owned_output=owned_output,
            )
        except BaseException:
            # host.close() owns the cleanup from here on; before the
            # handle exists the mkdtemp must not leak.
            if owned_output:
                shutil.rmtree(owned_output, ignore_errors=True)
            raise
        try:
            pong = host._rpc({"cmd": "ping"}, timeout=startup_timeout)
            if not pong.get("ok"):
                msg = f"daemon ping failed: {pong}"
                raise HostRPCError(msg)
        except Exception as e:
            host.close()
            if not thread.is_alive():
                msg = (
                    f"daemon died during startup: "
                    f"rc={result_holder.get('returncode')} "
                    f"err={result_holder.get('error')} "
                    f"stderr={result_holder.get('stderr', '')[-800:]!r}"
                )
                raise HostRPCError(msg) from e
            raise
        log.info("sandbox_host started (daemon pid=%s)", pong.get("pid"))
        # The daemon answered, so the spawn happened and the daemon owns
        # its copies of the pipe ends. Drop the parent's copies now so
        # the read end delivers EOF the moment the daemon (or its
        # sandbox chain) exits.
        host._release_daemon_fds()
        return host

    def _release_daemon_fds(self) -> None:
        """Close the parent's copies of the daemon-side pipe ends."""
        fds, self._daemon_fds = self._daemon_fds, None
        for fd in fds or ():
            with contextlib.suppress(OSError):
                os.close(fd)

    def close(self) -> None:
        """Terminate the daemon and close the pipe fds."""
        if self._closed:
            return
        self._closed = True
        # Release the daemon-side copies first: if the daemon is
        # already dead, the close RPC below then fails fast with
        # EPIPE instead of waiting out its timeout.
        self._release_daemon_fds()
        # _rpc wraps channel failures in HostRPCError; a malformed
        # reply from a dying daemon surfaces as ValueError (json).
        with contextlib.suppress(HostRPCError, ValueError):
            self._rpc({"cmd": "close"}, timeout=5.0)
        for fd in (self._write_fd, self._read_fd):
            with contextlib.suppress(OSError):
                os.close(fd)
        self._thread.join(timeout=5.0)
        if self._thread.is_alive():
            log.warning("sandbox_host worker thread did not exit within 5s")
        if getattr(self, "_owned_output", None):
            # Default-output scratch dir this host created; removed
            # after the worker released the sandbox that bound it.
            shutil.rmtree(self._owned_output, ignore_errors=True)
            self._owned_output = None

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
        # Stamp every request with an unguessable parent-minted id and
        # require the reply to echo it: binds each response frame to
        # its request, so a forged / stale / misordered frame on the
        # persistent channel is rejected instead of silently answering
        # the wrong RPC. The daemon echoes ``rid`` verbatim; extra
        # response keys keep the wire format backward-compatible.
        rid = os.urandom(16).hex()
        with self._lock:
            self._write_frame({**payload, "rid": rid})
            response = self._read_frame(timeout=timeout)
        if response.get("rid") != rid:
            raise HostRPCError(
                f"reply not bound to request: expected rid={rid} "
                f"got rid={response.get('rid')!r} — forged, stale, or "
                f"misordered frame on the RPC channel"
            )
        response.pop("rid", None)
        return response

    def _write_frame(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        hdr = struct.pack("!I", len(body))
        try:
            os.write(self._write_fd, hdr + body)
        except OSError as e:
            msg = f"write to daemon failed: {e}"
            raise HostRPCError(msg) from e

    def _read_frame(self, *, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        try:
            hdr = self._read_exact(4, deadline)
        except (OSError, HostRPCError) as e:
            msg = f"header read failed: {e}"
            raise HostRPCError(msg) from e
        (length,) = struct.unpack("!I", hdr)
        if length > _MAX_REPLY_FRAME_BYTES:
            msg = f"daemon frame too large: {length}"
            raise HostRPCError(msg)
        try:
            body = self._read_exact(length, deadline)
        except (OSError, HostRPCError) as e:
            msg = f"body read failed: {e}"
            raise HostRPCError(msg) from e
        return json.loads(body.decode("utf-8"))

    def _read_exact(self, n: int, deadline: float) -> bytes:
        # bytearray accumulator: bounded reply frames can run to
        # hundreds of MiB (see _MAX_REPLY_FRAME_BYTES) and repeated
        # bytes concatenation is quadratic at that size.
        buf = bytearray()
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                msg = f"read timeout at {len(buf)}/{n}"
                raise HostRPCError(msg)
            r, _, _ = select.select([self._read_fd], [], [], remaining)
            if not r:
                msg = f"read select timeout at {len(buf)}/{n}"
                raise HostRPCError(msg)
            chunk = os.read(self._read_fd, n - len(buf))
            if not chunk:
                msg = "daemon EOF"
                raise HostRPCError(msg)
            buf += chunk
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
    readable = list(readable_paths or [])
    readable.append(str(daemon))

    # Same request/response binding as SandboxHost._rpc: the daemon
    # echoes the parent-minted ``rid`` and the reply is rejected on a
    # mismatch (a target that reopened the daemon's stdout could
    # otherwise substitute the verdict frame).
    rid = os.urandom(16).hex()
    body = json.dumps({"cmd": cmd, **payload, "rid": rid}).encode("utf-8")
    frame = struct.pack("!I", len(body)) + body

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
            input=frame,
            capture_output=True,
            text=False,
            timeout=timeout,
        )
    except Exception as e:
        msg = f"one-shot daemon spawn failed: {type(e).__name__}: {e}"
        raise HostRPCError(msg) from e
    finally:
        if owned_output:
            shutil.rmtree(owned_output, ignore_errors=True)

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
    if length > len(r.stdout) - 4:
        msg = (
            f"one-shot response truncated: header={length} "
            f"body_bytes={len(r.stdout) - 4}"
        )
        raise HostRPCError(msg)
    try:
        response = json.loads(r.stdout[4:4 + length].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        msg = f"one-shot response parse failed: {e}"
        raise HostRPCError(msg) from e
    if response.get("rid") != rid:
        raise HostRPCError(
            f"one-shot reply not bound to request: expected rid={rid} "
            f"got rid={response.get('rid')!r}"
        )
    response.pop("rid", None)
    return response
