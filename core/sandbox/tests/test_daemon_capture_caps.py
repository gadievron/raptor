"""Captured-child-output ceilings in the sandbox host daemon.

The spawn/probe/conversation handlers used to retain the target's
complete stdout/stderr in memory — plus a 2x hex expansion in the
reply frame — with no byte ceiling (demonstrated live: a 512 MiB
stdout burst grew the handler's process by ~2 GiB). Retention is now
capped at ``_MAX_CAPTURE_BYTES`` per stream (spawn) / per request
(probe and conversation cumulative stdout); output beyond the cap is
still read, so the child never blocks on a full pipe, but discarded
and reported via ``*_truncated`` flags and ``*_bytes_kept`` counts in
the result payload. The parent's reply-frame ceiling is sized off the
same constant so a maximal bounded reply always fits — an oversized
frame used to be rejected only after the daemon had built and
half-sent it, wedging the persistent channel.

Pipe-level tests; the cap is monkeypatched small so they stay fast.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import threading

import pytest

from core.sandbox import _daemon
from core.sandbox import host as host_mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="handlers spawn real subprocesses",
)

_CAP = 8192  # small stand-in ceiling for fast tests


@pytest.fixture
def small_cap(monkeypatch):
    monkeypatch.setattr(_daemon, "_MAX_CAPTURE_BYTES", _CAP)
    return _CAP


def _burst_argv(n_out: int, n_err: int = 0, linger: float = 0.0) -> list[str]:
    code = (
        "import sys, time\n"
        f"sys.stdout.buffer.write(b'O' * {n_out}); sys.stdout.flush()\n"
        f"sys.stderr.buffer.write(b'E' * {n_err}); sys.stderr.flush()\n"
        f"time.sleep({linger})\n"
    )
    return [sys.executable, "-c", code]


class TestSpawnCaps:

    def test_oversized_streams_truncated_with_marker(self, small_cap):
        resp = _daemon._handle_spawn({
            "argv": _burst_argv(10 * _CAP, 5 * _CAP),
            "timeout": 30.0,
        })
        assert resp["ok"] is True, resp
        assert len(bytes.fromhex(resp["stdout_hex"])) == _CAP
        assert resp["stdout_truncated"] is True
        assert resp["stdout_bytes_kept"] == _CAP
        assert len(bytes.fromhex(resp["stderr_hex"])) == _CAP
        assert resp["stderr_truncated"] is True
        assert resp["stderr_bytes_kept"] == _CAP
        assert resp["timed_out"] is False

    def test_under_cap_streams_untouched(self, small_cap):
        resp = _daemon._handle_spawn({
            "argv": _burst_argv(100, 50),
            "timeout": 30.0,
        })
        assert resp["ok"] is True, resp
        assert bytes.fromhex(resp["stdout_hex"]) == b"O" * 100
        assert resp["stdout_truncated"] is False
        assert resp["stdout_bytes_kept"] == 100
        assert bytes.fromhex(resp["stderr_hex"]) == b"E" * 50
        assert resp["stderr_truncated"] is False
        assert resp["stderr_bytes_kept"] == 50

    def test_timeout_path_stays_capped(self, small_cap):
        resp = _daemon._handle_spawn({
            "argv": _burst_argv(10 * _CAP, linger=60.0),
            "timeout": 1.0,
        })
        assert resp["ok"] is True, resp
        assert resp["timed_out"] is True
        assert len(bytes.fromhex(resp["stdout_hex"])) <= _CAP
        assert resp["stdout_truncated"] is True

    def test_stdin_still_delivered_in_full(self, small_cap):
        # The bounded communicate must not clip the request's stdin —
        # only captured OUTPUT is capped.
        payload = os.urandom(4 * _CAP)
        resp = _daemon._handle_spawn({
            "argv": [sys.executable, "-c",
                     "import hashlib, sys\n"
                     "data = sys.stdin.buffer.read()\n"
                     "print(len(data), hashlib.sha256(data).hexdigest())"],
            "stdin_hex": payload.hex(),
            "timeout": 30.0,
        })
        assert resp["ok"] is True, resp
        import hashlib
        out = bytes.fromhex(resp["stdout_hex"]).decode().split()
        assert int(out[0]) == len(payload)
        assert out[1] == hashlib.sha256(payload).hexdigest()


class TestProbeCaps:

    def test_cumulative_stdout_capped(self, small_cap):
        resp = _daemon._handle_probe({
            "target_argv": _burst_argv(10 * _CAP),
            "steps": [{"recv_until": "timeout"}],
            "per_recv_timeout": 2.0,
            "total_wait_seconds": 5.0,
        })
        assert resp["ok"] is True, resp
        assert resp["stdout_bytes_kept"] <= _CAP
        assert resp["stdout_truncated"] is True
        assert resp["stderr_truncated"] is False

    def test_under_cap_not_flagged(self, small_cap):
        resp = _daemon._handle_probe({
            "target_argv": _burst_argv(64),
            "steps": [{"recv_until": 64}],
            "per_recv_timeout": 5.0,
            "total_wait_seconds": 5.0,
        })
        assert resp["ok"] is True, resp
        assert resp["stdout_truncated"] is False
        assert resp["stdout_bytes_kept"] == 64


class TestConversationCaps:

    def test_cumulative_stdout_capped(self, small_cap):
        resp = _daemon._handle_conversation({
            "target_argv": _burst_argv(10 * _CAP),
            "sends": [{"bytes_hex": b"x".hex(),
                       "then_recv_until": "timeout"}],
            "per_recv_timeout": 2.0,
            "total_wait_seconds": 5.0,
        })
        assert resp["ok"] is True, resp
        total = len(bytes.fromhex(resp["target_stdout_hex"]))
        assert total <= _CAP
        assert resp["stdout_bytes_kept"] == total
        assert resp["stdout_truncated"] is True
        # recvs are slices of the same capped capture.
        assert sum(len(bytes.fromhex(r)) for r in resp["recvs_hex"]) <= _CAP

    def test_under_cap_round_trip_unchanged(self, small_cap):
        resp = _daemon._handle_conversation({
            "target_argv": ["/bin/cat"],
            "sends": [{"bytes_hex": b"pong\n".hex(),
                       "then_recv_until": "newline"}],
            "per_recv_timeout": 5.0,
            "total_wait_seconds": 5.0,
        })
        assert resp["ok"] is True, resp
        assert resp["recvs_hex"] == [b"pong\n".hex()]
        assert resp["stdout_truncated"] is False
        assert resp["target_exit"] == "clean"


def _frame(obj: dict) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("!I", len(body)) + body


class TestParentReplyCeiling:

    def test_ceiling_admits_maximal_bounded_reply(self):
        """The parent's reply-frame cap must cover the daemon's
        bounded worst case (two capped streams, hex-doubled) — else a
        maximal legitimate reply wedges the channel again."""
        assert host_mod._MAX_REPLY_FRAME_BYTES >= (
            4 * _daemon._MAX_CAPTURE_BYTES
        )

    def test_parent_reads_frame_beyond_legacy_64mib(self):
        """A reply between the old 64 MiB ceiling and the new bounded
        one is read intact — pre-fix _read_frame raised mid-stream
        and desynced the channel."""
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        blob = "x" * (65 * 1024 * 1024)

        def _serve():
            try:
                # Consume the request to learn the rid, then reply big.
                hdr = b""
                while len(hdr) < 4:
                    hdr += os.read(in_r, 4 - len(hdr))
                (length,) = struct.unpack("!I", hdr)
                body = b""
                while len(body) < length:
                    body += os.read(in_r, length - len(body))
                rid = json.loads(body)["rid"]
                data = _frame({"ok": True, "blob": blob, "rid": rid})
                view = memoryview(data)
                while view:
                    n = os.write(out_w, view)
                    view = view[n:]
            finally:
                for fd in (in_r, out_w):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        host = host_mod.SandboxHost(
            _thread=thread,
            _write_fd=in_w,
            _read_fd=out_r,
            _daemon_fds=None,
            _lock=threading.Lock(),
        )
        try:
            response = host._rpc({"cmd": "ping"}, timeout=60.0)
            assert response["ok"] is True
            assert len(response["blob"]) == len(blob)
        finally:
            for fd in (in_w, out_r):
                try:
                    os.close(fd)
                except OSError:
                    pass
            thread.join(timeout=10)


class TestSpawnWrapperPassthrough:

    def test_truncation_markers_surface_to_callers(self, monkeypatch):
        def _fake_rpc(self, payload, *, timeout):
            return {
                "ok": True,
                "stdout_hex": (b"O" * 8).hex(),
                "stderr_hex": "",
                "stdout_truncated": True,
                "stderr_truncated": False,
                "stdout_bytes_kept": 8,
                "stderr_bytes_kept": 0,
                "returncode": 0,
                "timed_out": False,
                "wall_seconds": 0.1,
            }

        monkeypatch.setattr(host_mod.SandboxHost, "_rpc", _fake_rpc)
        host = host_mod.SandboxHost(
            _thread=threading.Thread(target=lambda: None, daemon=True),
            _write_fd=-1,
            _read_fd=-1,
            _daemon_fds=None,
            _lock=threading.Lock(),
        )
        res = host.spawn(["/bin/true"])
        assert res["stdout"] == b"O" * 8
        assert res["stdout_truncated"] is True
        assert res["stderr_truncated"] is False
