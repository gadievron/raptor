"""Calibration fingerprints regular files without special-file hangs."""

import errno
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import calibrate as cal, calibrate_cli as cli


@pytest.fixture
def cache(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    root.mkdir()
    monkeypatch.setattr(cal, "_CACHE_DIR", root)
    return root


@pytest.mark.parametrize("payload", [b"", b"binary-data" * 100])
def test_digest_matches_streaming_sha256(tmp_path, payload):
    path = tmp_path / "tool"
    path.write_bytes(payload)
    assert cal._sha256_file(path) == hashlib.sha256(payload).hexdigest()


def test_operator_symlink_and_partial_reads_remain_supported(tmp_path, monkeypatch):
    path = tmp_path / "tool"
    payload = b"binary-data" * 100
    path.write_bytes(payload)
    link = tmp_path / "linked-tool"
    link.symlink_to(path)
    real_read = os.read
    monkeypatch.setattr(cal.os, "read", lambda fd, size: real_read(fd, min(size, 3)))
    assert cal._sha256_file(link) == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("change", ["grow", "shrink"])
def test_size_changes_after_stat_are_refused(tmp_path, monkeypatch, change):
    path = tmp_path / "tool"
    path.write_bytes(b"binary-data")
    real_fstat = os.fstat
    calls = []

    def fstat(fd):
        metadata = real_fstat(fd)
        calls.append(fd)
        if len(calls) == 1:
            path.write_bytes(b"binary-data-extra" if change == "grow" else b"b")
        return metadata

    monkeypatch.setattr(cal.os, "fstat", fstat)
    with pytest.raises(OSError) as raised:
        cal._sha256_file(path)
    assert raised.value.errno == errno.EIO


def test_same_size_metadata_change_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "tool"
    path.write_bytes(b"binary-data")
    real_fstat = os.fstat
    calls = []

    def fstat(fd):
        metadata = real_fstat(fd)
        calls.append(fd)
        if len(calls) == 2:
            return SimpleNamespace(
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns + 1,
                st_ctime_ns=metadata.st_ctime_ns,
            )
        return metadata

    monkeypatch.setattr(cal.os, "fstat", fstat)
    with pytest.raises(OSError, match="changed while hashing"):
        cal._sha256_file(path)


@pytest.mark.parametrize("stage", ["fstat", "read"])
@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
def test_hash_failure_releases_descriptor(tmp_path, monkeypatch, stage, failure_type):
    path = tmp_path / "tool"
    path.write_bytes(b"binary-data")
    real_open, real_close = os.open, os.close
    opened, closed = [], []
    failure = failure_type("hash failed")

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def close_fd(fd):
        closed.append(fd)
        return real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(cal.os, "open", open_fd)
        patch.setattr(cal.os, "close", close_fd)
        patch.setattr(cal.os, stage, Mock(side_effect=failure))
        with pytest.raises(failure_type) as raised:
            cal._sha256_file(path)
    assert raised.value is failure
    assert len(opened) == 1
    assert closed == opened
    with pytest.raises(OSError) as invalid:
        os.fstat(opened[0])
    assert invalid.value.errno == errno.EBADF


@pytest.mark.parametrize("mode", [[], ["--show"], ["--clear"]])
def test_cli_reports_invalid_binary_without_traceback(tmp_path, cache, monkeypatch, capsys, mode):
    binary = tmp_path / "directory"
    binary.mkdir()
    monkeypatch.setattr(cal, "_spawn_probe", Mock(side_effect=AssertionError("must not execute")))
    assert cli._cli_main(["--bin", str(binary), *mode]) == cli._SOFTWARE_EX
    captured = capsys.readouterr()
    assert "not a regular file" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
@pytest.mark.parametrize("operation", ["hash", "calibrate", "load", "clear"])
def test_fifo_binary_is_refused_without_blocking(tmp_path, cache, operation):
    fifo = tmp_path / "tool"
    os.mkfifo(fifo, 0o600)
    script = """
import importlib.util, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("binary_io_test", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module._CACHE_DIR = Path(sys.argv[2])
signal.alarm(3)
path = Path(sys.argv[3])
operation = sys.argv[4]
try:
    if operation == "hash":
        module._sha256_file(path)
    elif operation == "calibrate":
        module.calibrate_binary(path)
    elif operation == "load":
        module.load_or_calibrate(path)
    else:
        module.clear_cache(path)
except OSError:
    pass
else:
    raise AssertionError("nonregular binary was accepted")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(cal.__file__).resolve()),
         str(cache), str(fifo), operation],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
