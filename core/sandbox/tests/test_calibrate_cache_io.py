"""Cache artifacts must not block calibration or targeted clearing."""

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import calibrate as cal


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cal, "_CACHE_DIR", tmp_path / "cache")
    cal._CACHE_DIR.mkdir()
    return cal._CACHE_DIR


def profile(**fields):
    return {
        "binary_path": "/tool", "binary_sha256": "hash",
        "env_signature": "env", "captured_at": "timestamp", **fields,
    }


def test_chunked_reads_round_trip(cache, monkeypatch):
    path = cache / "entry.json"
    path.write_text(json.dumps(profile(proxy_hosts=["example.test"])))
    real_read = os.read
    monkeypatch.setattr(cal.os, "read", lambda fd, size: real_read(fd, min(size, 5)))
    loaded = cal._load_from_cache("entry")
    assert loaded is not None
    assert loaded.proxy_hosts == ["example.test"]


def test_oversized_entry_is_rejected_before_read(cache, monkeypatch):
    monkeypatch.setattr(cal, "_MAX_CACHE_BYTES", 64)
    (cache / "entry.json").write_bytes(b"x" * 65)
    read = Mock(side_effect=AssertionError("oversized file must not be read"))
    monkeypatch.setattr(cal.os, "read", read)
    assert cal._load_from_cache("entry") is None
    read.assert_not_called()


def test_growth_after_stat_is_bounded(cache, monkeypatch):
    monkeypatch.setattr(cal, "_MAX_CACHE_BYTES", 64)
    (cache / "entry.json").write_bytes(b"{}")
    reads = []

    def growing_read(fd, size):
        reads.append(size)
        return b"x" * size

    monkeypatch.setattr(cal.os, "read", growing_read)
    assert cal._load_from_cache("entry") is None
    assert reads == [65]


@pytest.mark.parametrize("operation", ["load", "clear"])
def test_symlink_is_not_followed(cache, tmp_path, operation):
    binary = tmp_path / "tool"
    binary.write_bytes(b"tool")
    original = tmp_path / "original.json"
    data = json.dumps(profile(binary_sha256=cal._sha256_file(binary)))
    original.write_text(data)
    link = cache / "entry.json"
    link.symlink_to(original)
    if operation == "load":
        assert cal._load_from_cache("entry") is None
    else:
        assert cal.clear_cache(binary) == 0
    assert link.is_symlink()
    assert original.read_text() == data


@pytest.mark.parametrize("stage", ["fstat", "read"])
def test_read_failure_releases_descriptor(cache, monkeypatch, stage):
    (cache / "entry.json").write_text(json.dumps(profile()))
    real_open = os.open
    opened = []

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(cal.os, "open", open_fd)
        patch.setattr(cal.os, stage, Mock(side_effect=OSError("I/O failure")))
        assert cal._load_from_cache("entry") is None
    assert len(opened) == 1
    with pytest.raises(OSError) as exc:
        os.fstat(opened[0])
    assert exc.value.errno == errno.EBADF


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
@pytest.mark.parametrize("operation", ["load", "clear"])
def test_fifo_does_not_block(cache, tmp_path, operation):
    os.mkfifo(cache / "blocked.json", 0o600)
    binary = tmp_path / "tool"
    binary.write_bytes(b"tool")
    (cache / "valid.json").write_text(json.dumps(
        profile(binary_sha256=cal._sha256_file(binary)),
    ))
    script = """
import importlib.util, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("cache_io_test", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module._CACHE_DIR = Path(sys.argv[2])
# Bound the operation separately from application import overhead.
signal.alarm(3)
if sys.argv[3] == "load":
    assert module._load_from_cache("blocked") is None
else:
    assert module.clear_cache(sys.argv[4]) == 1
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(cal.__file__).resolve()),
         str(cache), operation, str(binary)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert (cache / "blocked.json").exists()
    assert (cache / "valid.json").exists() is (operation == "load")
