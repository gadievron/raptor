"""RPC-channel hardening for the sandbox host daemon.

Two layers, both pinned here at the pipe level (real daemon process,
no sandbox — the transport is identical):

1. /proc fd reopen defence — the daemon sets PR_SET_DUMPABLE=0 before
   serving any request, so a same-UID non-root process (the position a
   daemon-spawned target runs in) cannot open
   ``/proc/<daemon>/fd/<n>`` to forge daemon→parent frames or steal
   parent→daemon requests. CLOEXEC alone did not cover this: the fds
   stay out of the target's fd table, but /proc lets a peer reopen
   them by number, and Yama ptrace_scope=1 does NOT block it (scope 1
   restricts ATTACH-mode access; /proc fd opens need only READ-mode —
   demonstrated live on a scope=1 host before the fix).

2. Request/response binding — the parent stamps every request with an
   unguessable ``rid`` which the daemon echoes in the reply frame; the
   parent rejects replies whose ``rid`` does not match, so a forged,
   stale, or misordered frame cannot silently answer the wrong RPC.
   Requests without a ``rid`` get an unchanged reply (wire format
   stays backward-compatible).
"""

from __future__ import annotations

import errno
import json
import os
import select
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from core.sandbox import _daemon
from core.sandbox.host import HostRPCError, SandboxHost

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only daemon internals (prctl, /proc)",
)

_DAEMON_PATH = Path(_daemon.__file__).resolve()
_FRAME_TIMEOUT = 30.0


def _frame(obj: dict) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("!I", len(body)) + body


def _read_frame(fd: int, timeout: float = _FRAME_TIMEOUT) -> dict:
    def _read_exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            r, _, _ = select.select([fd], [], [], timeout)
            if not r:
                raise TimeoutError(f"frame read stalled at {len(buf)}/{n}")
            chunk = os.read(fd, n - len(buf))
            if not chunk:
                raise EOFError("daemon EOF")
            buf += chunk
        return buf

    (length,) = struct.unpack("!I", _read_exact(4))
    return json.loads(_read_exact(length).decode("utf-8"))


class _PipeDaemon:
    """Real _daemon.py process on plain pipes (no sandbox)."""

    def __init__(self) -> None:
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        os.set_inheritable(in_r, True)
        os.set_inheritable(out_w, True)
        self.daemon_fd_numbers = (in_r, out_w)
        self.proc = subprocess.Popen(
            [sys.executable, "-S", str(_DAEMON_PATH),
             "--rpc-in-fd", str(in_r), "--rpc-out-fd", str(out_w)],
            pass_fds=(in_r, out_w),
            stderr=subprocess.DEVNULL,
        )
        os.close(in_r)
        os.close(out_w)
        self.write_fd = in_w
        self.read_fd = out_r

    def rpc(self, payload: dict) -> dict:
        os.write(self.write_fd, _frame(payload))
        return _read_frame(self.read_fd)

    def close(self) -> None:
        for fd in (self.write_fd, self.read_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        self.proc.kill()
        self.proc.wait(timeout=10)


@pytest.fixture
def pipe_daemon():
    d = _PipeDaemon()
    try:
        yield d
    finally:
        d.close()


class TestNonDumpable:

    def test_daemon_reports_dumpable_zero(self, pipe_daemon):
        """The daemon self-reports PR_GET_DUMPABLE == 0 via ping —
        the /proc reopen defence engaged before the first request."""
        pong = pipe_daemon.rpc({"cmd": "ping"})
        assert pong["ok"] is True
        assert pong["dumpable"] == 0

    @pytest.mark.skipif(os.geteuid() == 0,
                        reason="root's CAP_SYS_PTRACE bypasses the "
                               "dumpable gate by design")
    def test_proc_fd_reopen_denied_from_same_uid(self, pipe_daemon):
        """A same-UID process (here: the daemon's own ancestor, the
        access direction Yama is MOST permissive about) cannot reopen
        the daemon's RPC pipe ends via /proc/<pid>/fd/<n>. Pre-fix
        this open succeeded and a forged length-prefixed frame was
        accepted by the parent."""
        pong = pipe_daemon.rpc({"cmd": "ping"})
        assert pong["ok"] is True
        for fd_num in pipe_daemon.daemon_fd_numbers:
            path = f"/proc/{pipe_daemon.proc.pid}/fd/{fd_num}"
            with pytest.raises(OSError) as exc:
                os.open(path, os.O_WRONLY)
            assert exc.value.errno in (errno.EACCES, errno.EPERM), (
                f"{path} reopenable: {exc.value}"
            )

    @pytest.mark.skipif(os.geteuid() == 0,
                        reason="root's CAP_SYS_PTRACE bypasses the "
                               "dumpable gate by design")
    def test_proc_fd_reopen_denied_from_daemon_child(self, pipe_daemon):
        """From the hostile-target position — a child the daemon
        spawns — /proc/<ppid>/fd/<n> opens fail. This is the exact
        pre-fix breakage: with the daemon dumpable, the child's open
        succeeded even under Yama ptrace_scope=1."""
        _, out_w = pipe_daemon.daemon_fd_numbers
        child_code = (
            "import json, os\n"
            f"p = '/proc/' + str(os.getppid()) + '/fd/{out_w}'\n"
            "try:\n"
            "    os.open(p, os.O_WRONLY)\n"
            "    print(json.dumps({'opened': True}))\n"
            "except OSError as e:\n"
            "    print(json.dumps({'opened': False, 'errno': e.errno}))\n"
        )
        resp = pipe_daemon.rpc({
            "cmd": "spawn",
            "argv": [sys.executable, "-c", child_code],
            "timeout": 20.0,
        })
        assert resp["ok"] is True, resp
        report = json.loads(bytes.fromhex(resp["stdout_hex"]).decode())
        assert report["opened"] is False, (
            "daemon-spawned child reopened the RPC pipe via /proc"
        )
        assert report["errno"] in (errno.EACCES, errno.EPERM)


class TestRequestIdBinding:

    def test_rid_echoed_in_reply(self, pipe_daemon):
        pong = pipe_daemon.rpc({"cmd": "ping", "rid": "abc123"})
        assert pong["ok"] is True
        assert pong["rid"] == "abc123"

    def test_rid_echoed_on_error_replies(self, pipe_daemon):
        resp = pipe_daemon.rpc({"cmd": "no-such-verb", "rid": "err-1"})
        assert resp["ok"] is False
        assert resp["rid"] == "err-1"

    def test_rid_absent_stays_absent(self, pipe_daemon):
        """Backward compatibility: a request without a rid gets a
        reply without one — older frame producers keep working."""
        pong = pipe_daemon.rpc({"cmd": "ping"})
        assert pong["ok"] is True
        assert "rid" not in pong

    def test_close_reply_echoes_rid(self, pipe_daemon):
        resp = pipe_daemon.rpc({"cmd": "close", "rid": "bye"})
        assert resp == {"ok": True, "closed": True, "rid": "bye"}

    def test_one_shot_echoes_rid(self):
        proc = subprocess.run(
            [sys.executable, "-S", str(_DAEMON_PATH), "--one-shot"],
            input=_frame({"cmd": "ping", "rid": "os-1"}),
            capture_output=True, timeout=60, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        (length,) = struct.unpack("!I", proc.stdout[:4])
        pong = json.loads(proc.stdout[4:4 + length].decode())
        assert pong["ok"] is True
        assert pong["rid"] == "os-1"
        assert pong["dumpable"] == 0


class _FakeDaemonHost:
    """SandboxHost wired to an in-process fake daemon thread that
    replies to each frame via ``reply_fn`` — exercises the parent's
    rid verification without any real spawn."""

    def __init__(self, reply_fn) -> None:
        self._in_r, in_w = os.pipe()
        out_r, self._out_w = os.pipe()
        self.thread = threading.Thread(target=self._serve,
                                       args=(reply_fn,), daemon=True)
        self.thread.start()
        self.host = SandboxHost(
            _thread=self.thread,
            _write_fd=in_w,
            _read_fd=out_r,
            _daemon_fds=None,
            _lock=threading.Lock(),
        )

    def _serve(self, reply_fn) -> None:
        try:
            request = _read_frame(self._in_r, timeout=10.0)
            os.write(self._out_w, _frame(reply_fn(request)))
        except (OSError, EOFError, TimeoutError):
            pass
        finally:
            for fd in (self._in_r, self._out_w):
                try:
                    os.close(fd)
                except OSError:
                    pass


class TestParentRejectsUnboundReplies:

    def test_mismatched_rid_rejected(self):
        fake = _FakeDaemonHost(
            lambda req: {"ok": True, "pong": True, "rid": "forged"},
        )
        with pytest.raises(HostRPCError, match="not bound to request"):
            fake.host._rpc({"cmd": "ping"}, timeout=10.0)

    def test_missing_rid_rejected(self):
        fake = _FakeDaemonHost(lambda req: {"ok": True, "pong": True})
        with pytest.raises(HostRPCError, match="not bound to request"):
            fake.host._rpc({"cmd": "ping"}, timeout=10.0)

    def test_matching_rid_accepted_and_stripped(self):
        fake = _FakeDaemonHost(
            lambda req: {"ok": True, "pong": True, "rid": req["rid"]},
        )
        response = fake.host._rpc({"cmd": "ping"}, timeout=10.0)
        assert response == {"ok": True, "pong": True}
