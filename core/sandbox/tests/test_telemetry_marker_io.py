"""Damaged marker logs cannot block re-keying or hide later records."""

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import telemetry_mac as tmac


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    tmac.tamper_marker_path().parent.mkdir(mode=0o700, parents=True)


@pytest.fixture
def warning(monkeypatch):
    capture = Mock()
    monkeypatch.setattr(tmac.logger, "warning", capture)
    return capture


def test_reader_continues_after_damaged_records():
    before = {"reason": "first"}
    after = {"reason": "last"}
    tmac.tamper_marker_path().write_bytes(
        json.dumps(before).encode() + b"\n"
        + b'{"reason":"\xff"}\n'
        + b"[" * 2000 + b"]" * 2000 + b"\n"
        + b"null\n[]\n{bad json\n"
        + json.dumps(after).encode() + b"\n"
    )
    assert tmac.tamper_events() == [before, after]


@pytest.mark.parametrize("operation", ["read", "write"])
def test_marker_symlink_is_refused(operation, tmp_path, warning):
    destination = tmp_path / "original"
    data = b'{"reason":"outside marker log"}\n'
    destination.write_bytes(data)
    tmac.tamper_marker_path().symlink_to(destination)
    if operation == "read":
        assert tmac.tamper_events() == []
    else:
        tmac._record_tamper_event("reason", "quarantined")
        assert "could not append the key tamper marker" in warning.call_args.args[0]
    assert destination.read_bytes() == data


@pytest.mark.parametrize("written", [0, 5])
def test_short_append_warns_without_retrying_fragments(monkeypatch, warning, written):
    real_write, real_close = os.write, os.close
    calls, closed = [], []

    def partial(fd, data):
        calls.append(fd)
        return real_write(fd, data[:written])

    def close(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(tmac.os, "write", partial)
    monkeypatch.setattr(tmac.os, "close", close)
    tmac._record_tamper_event("reason", "quarantined")
    assert len(calls) == 1
    assert closed.count(calls[0]) == 1
    assert "could not append the key tamper marker" in warning.call_args.args[0]
    with pytest.raises(OSError) as exc:
        os.fstat(calls[0])
    assert exc.value.errno == errno.EBADF


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
@pytest.mark.parametrize("operation", ["read", "rekey"])
def test_fifo_marker_does_not_block(operation):
    os.mkfifo(tmac.tamper_marker_path(), 0o600)
    if operation == "rekey":
        # A malformed key invokes the marker writer during recovery.
        tmac._key_path().write_bytes(b"x" * 64)
        tmac._key_path().chmod(0o600)
    script = """
import runpy, sys
module = runpy.run_path(sys.argv[1])
if sys.argv[2] == "read":
    assert module["tamper_events"]() == []
else:
    fields = {"kind": "proxy-event"}
    token = module["mint"](fields)
    assert token is not None
    assert module["verify"](fields, token)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(tmac.__file__).resolve()), operation],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    if operation == "rekey":
        assert "could not append the key tamper marker" in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
def test_writer_rejects_fifo_even_when_a_reader_is_present(warning):
    path = tmac.tamper_marker_path()
    os.mkfifo(path, 0o600)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        tmac._record_tamper_event("reason", "quarantined")
        assert "could not append the key tamper marker" in warning.call_args.args[0]
        assert os.read(fd, 4096) == b""
    finally:
        os.close(fd)
