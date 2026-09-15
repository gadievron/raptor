"""Probe/conversation sends must not block the single-threaded daemon.

A target that stops reading stdin while its own stdout pipe is full
used to park ``_handle_probe`` / ``_handle_conversation`` in a plain
blocking ``proc.stdin.write`` — the mutual-blocking deadlock
``_communicate_capped`` closes for the spawn verb. Sends now route
through ``_send_capped``: select-driven, non-blocking, draining the
target's stdout concurrently (returned as pushback so no recv bytes
are lost) and bounded by the per-step deadline.
"""

from __future__ import annotations

import shutil
import subprocess
import sys as _sys
import threading
import time

import pytest

from core.sandbox import _daemon as daemon

pytestmark = pytest.mark.skipif(
    _sys.platform != "linux" or shutil.which("sh") is None,
    reason="handlers spawn real target subprocesses via sh",
)

_SH = shutil.which("sh") or "/bin/sh"

# Well over the 64 KiB pipe buffer in both directions.
_STDOUT_FLOOD = 128 * 1024
_SEND_BYTES = 256 * 1024

# A target that floods stdout BEFORE reading any stdin (dd blocks on
# the full stdout pipe), then echoes stdin. Forces the historic
# deadlock: daemon blocked in write(2), target blocked in write(2).
_FLOOD_THEN_CAT = (
    f"dd if=/dev/zero bs=4096 count={_STDOUT_FLOOD // 4096} "
    f"2>/dev/null; exec cat"
)


def _run_handler_bounded(fn, payload, timeout_s: float = 30.0):
    """Run a daemon handler with a hard wall-clock bound.

    Pre-fix the handler deadlocks in write(2) with no deadline, so a
    plain call would hang the suite. The target proc is captured via
    the spawn seam and group-killed if the bound trips.
    """
    procs: list[subprocess.Popen] = []
    real_spawn = daemon._spawn_request_target

    def _capturing_spawn(argv):
        p = real_spawn(argv)
        procs.append(p)
        return p

    daemon._spawn_request_target = _capturing_spawn
    result: dict = {}
    try:
        def _call():
            result["resp"] = fn(payload)

        t = threading.Thread(target=_call, daemon=True)
        t.start()
        t.join(timeout_s)
        if t.is_alive():
            for p in procs:
                daemon._kill_request_group(p)
            t.join(10.0)
            pytest.fail(
                "handler exceeded the wall-clock bound — blocking "
                "send deadlock"
            )
    finally:
        daemon._spawn_request_target = real_spawn
        for p in procs:
            daemon._kill_request_group(p)
    return result["resp"]


class TestConversationSendDeadlock:

    def test_large_send_to_flooding_target_completes(self):
        resp = _run_handler_bounded(daemon._handle_conversation, {
            "target_argv": [_SH, "-c", _FLOOD_THEN_CAT],
            "sends": [{
                "bytes_hex": "41" * _SEND_BYTES,
                "then_recv_until": _STDOUT_FLOOD,
            }],
            "per_recv_timeout": 15.0,
            "total_wait_seconds": 10.0,
        })
        assert resp["ok"] is True
        # The flood bytes drained during the send must be consumed by
        # the recv, in order, with nothing lost.
        assert resp["recvs_hex"][0] == "00" * _STDOUT_FLOOD
        # The echoed send arrives after the flood.
        all_out = bytes.fromhex(resp["target_stdout_hex"])
        assert all_out.startswith(b"\x00" * _STDOUT_FLOOD)
        assert all_out.count(b"A") == _SEND_BYTES
        assert resp["target_exit"] == "clean"


class TestProbeSendDeadlock:

    def test_large_send_to_flooding_target_completes(self):
        resp = _run_handler_bounded(daemon._handle_probe, {
            "target_argv": [_SH, "-c", _FLOOD_THEN_CAT],
            "steps": [{
                "send_hex": "41" * _SEND_BYTES,
                "recv_until": _STDOUT_FLOOD,
            }],
            "per_recv_timeout": 15.0,
            "total_wait_seconds": 10.0,
        })
        assert resp["ok"] is True
        assert resp["steps_completed"] == 1
        # Flood + echoed send are all retained (well under the cap).
        assert resp["stdout_bytes_kept"] == _STDOUT_FLOOD + _SEND_BYTES
        assert resp["stdout_truncated"] is False
        assert resp["target_exit"] == "clean"


class TestSendCappedBounds:

    def test_nonreading_target_bounded_by_deadline(self):
        # Target neither reads stdin nor writes stdout: the send can
        # only place ~one pipe buffer, then must give up at the
        # deadline instead of blocking forever.
        proc = daemon._spawn_request_target([_SH, "-c", "sleep 30"])
        try:
            t0 = time.monotonic()
            drained, trunc, undelivered = daemon._send_capped(
                proc, b"B" * _SEND_BYTES, 1.0, daemon._MAX_CAPTURE_BYTES,
            )
            wall = time.monotonic() - t0
            assert wall < 5.0
            assert drained == b""
            assert trunc is False
            # Only ~one pipe buffer fits; the rest must be REPORTED
            # undelivered, never silently dropped.
            assert 0 < undelivered < _SEND_BYTES
        finally:
            daemon._kill_request_group(proc)

    def test_exited_target_returns_without_raising(self):
        proc = daemon._spawn_request_target([_SH, "-c", "exit 0"])
        try:
            proc.wait(timeout=10.0)
            drained, trunc, undelivered = daemon._send_capped(
                proc, b"C" * _SEND_BYTES, 2.0, daemon._MAX_CAPTURE_BYTES,
            )
            assert trunc is False
            assert drained == b""
            assert undelivered > 0
        finally:
            daemon._kill_request_group(proc)

    def test_drain_cap_reports_truncation(self):
        # Flooding target, tiny retention cap: bytes beyond the cap
        # are read (target unblocked) but dropped with the flag set.
        proc = daemon._spawn_request_target([_SH, "-c", _FLOOD_THEN_CAT])
        try:
            drained, trunc, undelivered = daemon._send_capped(
                proc, b"D" * _SEND_BYTES, 15.0, 1024,
            )
            assert len(drained) == 1024
            assert trunc is True
            assert undelivered == 0
        finally:
            daemon._kill_request_group(proc)


class TestSendTruncationReported:
    """A partially delivered stimulus must be flagged in the reply.

    Deadline truncation against a LIVE slow reader is not the
    BrokenPipeError shape (target exited) — the target keeps running
    on partial input and the verdict machinery reading the reply must
    be able to see that the stimulus was incomplete.
    """

    # Reads stdin only after the send deadline has long expired, then
    # reports how many bytes actually arrived.
    _SLOW_READER = "sleep 2; wc -c"

    def test_probe_reply_flags_partial_send(self):
        resp = _run_handler_bounded(daemon._handle_probe, {
            "target_argv": [_SH, "-c", self._SLOW_READER],
            "steps": [{"send_hex": "41" * _SEND_BYTES}],
            "per_recv_timeout": 0.5,
            "total_wait_seconds": 10.0,
        })
        assert resp["ok"] is True
        assert resp["sends_truncated"] is True
        assert 0 < resp["stdin_bytes_dropped"] < _SEND_BYTES
        # wc -c saw exactly the delivered bytes — the reply's
        # arithmetic matches what the target really received.
        delivered = _SEND_BYTES - resp["stdin_bytes_dropped"]
        assert str(delivered) in resp["target_stdout_tail"]

    def test_conversation_reply_flags_partial_send(self):
        resp = _run_handler_bounded(daemon._handle_conversation, {
            "target_argv": [_SH, "-c", self._SLOW_READER],
            "sends": [{"bytes_hex": "42" * _SEND_BYTES,
                       "then_recv_until": "timeout"}],
            "per_recv_timeout": 0.5,
            "total_wait_seconds": 10.0,
        })
        assert resp["ok"] is True
        assert resp["sends_truncated"] is True
        assert 0 < resp["stdin_bytes_dropped"] < _SEND_BYTES
        delivered = _SEND_BYTES - resp["stdin_bytes_dropped"]
        assert str(delivered).encode().hex() in resp["target_stdout_hex"]

    def test_fully_delivered_send_not_flagged(self):
        resp = _run_handler_bounded(daemon._handle_conversation, {
            "target_argv": [_SH, "-c", "exec cat"],
            "sends": [{"bytes_hex": "43" * _SEND_BYTES,
                       "then_recv_until": _SEND_BYTES}],
            "per_recv_timeout": 15.0,
            "total_wait_seconds": 10.0,
        })
        assert resp["ok"] is True
        assert resp["sends_truncated"] is False
        assert resp["stdin_bytes_dropped"] == 0
