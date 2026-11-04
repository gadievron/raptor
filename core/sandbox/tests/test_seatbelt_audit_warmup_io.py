"""Warm-up log framing must respect deadlines and bounded line storage."""

import json
import os
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import probes, seatbelt_audit as audit


@pytest.fixture
def gate(tmp_path, monkeypatch):
    streamer = audit.LogStreamer(tmp_path)
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "r")
    streamer._proc = SimpleNamespace(stdout=stream)
    warmup = Mock(pid=4242)
    warmup.wait.return_value = 0
    monkeypatch.setattr(probes, "_find_sandbox_binary", lambda name: sys.executable)
    monkeypatch.setattr(audit.subprocess, "Popen", Mock(return_value=warmup))
    try:
        yield streamer, stream, write_fd, warmup
    finally:
        stream.close()
        os.close(write_fd)


def message():
    return json.dumps({
        "senderImagePath": audit.SANDBOX_KEXT_SENDER,
        "eventMessage": "Sandbox: Python(4242) deny file-read-data /tmp/example",
    }).encode()


def test_partial_line_cannot_park_warmup_past_deadline(gate, monkeypatch):
    streamer, stream, writer, warmup = gate
    os.write(writer, b'{"eventMessage":')
    monkeypatch.setattr(audit, "_WARM_UP_TIMEOUT_S", 0.05)
    done = threading.Event()
    outcomes, errors = [], []

    def run():
        try:
            outcomes.append(streamer._warm_up_until_attached())
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    finished_on_time = done.wait(1)
    if not finished_on_time:
        # Release a regressed blocking readline before failing the test.
        os.write(writer, b"null}\n")
    thread.join(5)
    assert not thread.is_alive()
    assert finished_on_time
    assert not errors
    assert outcomes == [False]
    assert os.get_blocking(stream.fileno()) is True
    warmup.wait.assert_called_once()


def test_split_utf8_and_json_line_is_reassembled(gate, monkeypatch):
    streamer, stream, writer, _ = gate
    raw = json.dumps({
        "senderImagePath": audit.SANDBOX_KEXT_SENDER,
        "eventMessage": "Sandbox: Pythön(4242) deny file-read-data /tmp/example",
    }, ensure_ascii=False).encode()
    monkeypatch.setattr(audit, "_WARM_UP_READ_CHUNK", 1)
    os.write(writer, raw + b"\n")
    assert streamer._warm_up_until_attached() is True
    assert os.get_blocking(stream.fileno()) is True


def test_oversized_line_resynchronizes_at_next_newline(gate, monkeypatch):
    streamer, stream, writer, _ = gate
    monkeypatch.setattr(audit, "_MAX_WARM_UP_LINE_BYTES", 256)
    monkeypatch.setattr(audit, "_WARM_UP_READ_CHUNK", 31)
    os.write(writer, b"x" * 1000 + b"\n" + message() + b"\n")
    assert streamer._warm_up_until_attached() is True
    assert os.get_blocking(stream.fileno()) is True


@pytest.mark.parametrize("blocking", [False, True])
def test_early_generator_close_restores_original_mode(gate, blocking):
    _, stream, writer, _ = gate
    os.set_blocking(stream.fileno(), blocking)
    os.write(writer, message() + b"\n")
    lines = audit._warm_up_log_lines(stream, time.monotonic() + 1)
    try:
        assert next(lines) == message().decode()
    finally:
        lines.close()
    assert os.get_blocking(stream.fileno()) is blocking


def test_final_unterminated_line_is_preserved(tmp_path):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, message())
    os.close(write_fd)
    with os.fdopen(read_fd, "r") as stream:
        assert list(audit._warm_up_log_lines(stream, time.monotonic() + 1)) == [
            message().decode(),
        ]
        assert os.get_blocking(stream.fileno()) is True
