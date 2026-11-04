"""Shutdown closes evidence once and contains abandoned readers."""

from concurrent.futures import ThreadPoolExecutor
import errno
import io
import json
import os
import subprocess
import threading
from unittest.mock import Mock

import pytest

from core.sandbox import evidence, seatbelt_audit


def records(tmp_path):
    path = tmp_path / evidence.AUDIT_SUBDIR / seatbelt_audit.DENIALS_FILE
    return path.read_bytes(), [json.loads(line) for line in path.read_bytes().splitlines()]


def test_concurrent_and_repeated_stops_finalise_only_once(tmp_path):
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: streamer.stop(), range(8)))
    before, parsed = records(tmp_path)
    assert len(parsed) == 1
    assert parsed[0]["type"] == "audit_summary"
    assert parsed[0]["reader_drained"] is True
    streamer.stop()
    assert records(tmp_path)[0] == before
    assert streamer._evidence is None
    with pytest.raises(RuntimeError, match="stopped"):
        streamer.start()


@pytest.mark.parametrize("signal", ["terminate", "kill"])
def test_signal_errors_do_not_skip_finalisation(tmp_path, signal):
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    proc = Mock(stdout=io.StringIO())
    getattr(proc, signal).side_effect = ProcessLookupError()
    proc.wait.side_effect = (
        [subprocess.TimeoutExpired("log", 1), 0] if signal == "kill" else [0]
    )
    streamer._proc = proc
    streamer.stop()
    assert proc.stdout.closed
    assert records(tmp_path)[1][-1]["type"] == "audit_summary"
    waits = proc.wait.call_count
    streamer.stop()
    assert proc.wait.call_count == waits


def test_summary_failure_still_closes_evidence(tmp_path, monkeypatch):
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer._append_record({"type": "test"})
    fd = streamer._evidence.fd
    with monkeypatch.context() as patch:
        patch.setattr(
            streamer, "_append_record_locked", Mock(side_effect=OSError("write failed")),
        )
        streamer.stop()
    assert streamer._evidence is None
    with pytest.raises(OSError) as exc:
        os.fstat(fd)
    assert exc.value.errno == errno.EBADF
    before, _ = records(tmp_path)
    streamer._append_record({"type": "late"})
    streamer.stop()
    assert records(tmp_path)[0] == before


def test_abandoned_reader_cannot_append_after_summary(tmp_path, monkeypatch, caplog):
    entered, release = threading.Event(), threading.Event()

    class DelayedStream:
        closed = False
        emitted = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.emitted:
                raise StopIteration
            entered.set()
            assert release.wait(5)
            self.emitted = True
            return json.dumps({
                "senderImagePath": seatbelt_audit.SANDBOX_KEXT_SENDER,
                "eventMessage": "Sandbox: Python(4242) deny file-read-data /tmp/late",
            })

        def close(self):
            self.closed = True

    stream = DelayedStream()
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    streamer._proc = Mock(stdout=stream)
    reader = threading.Thread(target=streamer._read_loop, daemon=True)
    streamer._reader = reader
    real_join = reader.join
    reader.start()
    try:
        assert entered.wait(5)
        # Simulate expiry of the bounded join without a three-second test.
        monkeypatch.setattr(reader, "join", lambda timeout: None)
        streamer.stop()
        before, parsed = records(tmp_path)
        assert parsed[-1]["reader_drained"] is False
        assert "capture is incomplete" in caplog.text
        assert stream.closed is False
        release.set()
        real_join(5)
        assert not reader.is_alive()
        assert stream.closed is True
        assert records(tmp_path)[0] == before
        assert streamer._budget.total_records_emitted == 0
        assert streamer._evidence is None
    finally:
        release.set()
        real_join(5)
