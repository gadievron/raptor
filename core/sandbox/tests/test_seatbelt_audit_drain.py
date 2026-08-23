"""Shutdown tail-drain tests for the macOS seatbelt log streamer.

The kernel→log-subsystem→`log stream` pipeline has visible latency
(~1.5s for a cold first event), so at stop() time the last records of
a short workload are typically still buffered in the subprocess pipe.
Pre-fix, ``stop()`` set the ``_stopped`` flag BEFORE terminating the
producer while ``_read_loop`` broke on that flag before parsing
already-buffered lines — the tail was silently lost, yet a healthy
audit_summary was appended. The fixed ordering is: terminate the
producer, drain the reader to EOF (bounded join), THEN set the flag
and append the summary.

Hermetic: a fake producer gates its buffered lines on terminate() —
exactly the pipe-buffer shape — so the tests run on any host.
"""

from __future__ import annotations

import json
import threading
import time

from core.sandbox import evidence as evidence_mod
from core.sandbox import seatbelt_audit
from core.sandbox.seatbelt import SANDBOX_KEXT_SENDER


def _kext_line(pid: int, path: str) -> str:
    return json.dumps({
        "senderImagePath": SANDBOX_KEXT_SENDER,
        "eventMessage": f"Sandbox: proc({pid}) deny file-write-data {path}",
        "timestamp": "2026-05-03 10:00:00.000000+0000",
    }) + "\n"


class _GatedTailStdout:
    """Iterable stdout whose lines only become readable once the
    producer is terminated — models bytes sitting in the subprocess
    pipe buffer at stop() time. Before release(), iteration blocks
    (a live pipe with nothing to read); after, the buffered tail
    drains and EOF follows."""

    def __init__(self, lines):
        self._lines = list(lines)
        self._gate = threading.Event()
        self._idx = 0

    def release(self):
        self._gate.set()

    def __iter__(self):
        return self

    def __next__(self):
        # Bounded wait so a regression can never hang the suite.
        if not self._gate.wait(timeout=10.0):
            raise StopIteration
        if self._idx >= len(self._lines):
            raise StopIteration
        line = self._lines[self._idx]
        self._idx += 1
        return line


class _TailProc:
    """Fake `log stream` Popen: terminate() flushes the pipe buffer
    (release the gated stdout), wait()/kill() are no-ops."""

    def __init__(self, stdout: _GatedTailStdout):
        self.stdout = stdout
        self.terminated = False

    def terminate(self):
        self.terminated = True
        self.stdout.release()

    def kill(self):
        self.stdout.release()

    def wait(self, timeout=None):
        return 0


def _read_jsonl(tmp_path):
    p = (tmp_path / evidence_mod.AUDIT_SUBDIR
         / seatbelt_audit.DENIALS_FILE)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines()
            if line.strip()]


def _start_reader(streamer, proc):
    """Wire a fake proc and start the real reader thread, then give
    it a moment to block on the (still-gated) stdout — the state a
    live streamer is in when stop() fires."""
    streamer._proc = proc
    streamer._reader = threading.Thread(
        target=streamer._read_loop, daemon=True,
    )
    streamer._reader.start()
    time.sleep(0.05)


def test_stop_drains_buffered_tail_into_jsonl(tmp_path):
    """Lines buffered in the producer's pipe at stop() time must be
    parsed into records — pre-fix the reader broke on the stop flag
    before parsing them and the tail was silently lost."""
    tail_paths = [f"/tmp/tail-{i}" for i in range(5)]
    proc = _TailProc(_GatedTailStdout(
        [_kext_line(4242, p) for p in tail_paths]
    ))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    _start_reader(streamer, proc)

    streamer.stop()

    records = _read_jsonl(tmp_path)
    got_paths = [r.get("path") for r in records if "path" in r]
    assert got_paths == tail_paths, (
        f"buffered tail lines lost at stop(): expected {tail_paths}, "
        f"JSONL has {got_paths}"
    )
    assert proc.terminated is True


def test_summary_is_last_record_after_tail_drain(tmp_path):
    """The audit_summary must be appended AFTER the drained tail
    records — a summary written before the drain asserts a
    completeness the JSONL doesn't have."""
    proc = _TailProc(_GatedTailStdout(
        [_kext_line(4242, "/tmp/tail-final")]
    ))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    _start_reader(streamer, proc)

    streamer.stop()

    records = _read_jsonl(tmp_path)
    assert records, "no records written at all"
    assert records[-1].get("type") == "audit_summary"
    data_idx = [i for i, r in enumerate(records)
                if r.get("path") == "/tmp/tail-final"]
    assert data_idx, "tail record missing from JSONL"
    assert data_idx[0] < len(records) - 1


def test_summary_counts_include_drained_tail(tmp_path):
    """The budget summary must account for the drained tail records —
    the 'N records, 0 drops' operator signal is only honest when the
    tail was counted before the summary snapshot."""
    n = 4
    proc = _TailProc(_GatedTailStdout(
        [_kext_line(4242, f"/tmp/t{i}") for i in range(n)]
    ))
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    _start_reader(streamer, proc)

    streamer.stop()

    records = _read_jsonl(tmp_path)
    summary = next(r for r in records if r.get("type") == "audit_summary")
    assert summary["total_records"] == n
