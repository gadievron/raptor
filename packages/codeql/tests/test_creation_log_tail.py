"""Failure diagnostics must not buffer whole extraction logs or block on pipes."""
import os
from pathlib import Path

import pytest

from packages.codeql.database_manager import DatabaseManager


def write_log(tmp_path, name, data):
    path = tmp_path / "log" / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("limit", [1, 16, 8192])
def test_only_requested_tail_is_read(tmp_path, monkeypatch, limit):
    import packages.codeql.database_manager as manager
    path = write_log(tmp_path, "database-create-001.log", b"x" * 100_000 + b"failure\n")
    original = manager.open_regular_gated
    reads = []

    class MeasuredLog:
        def __enter__(self):
            self.log = original(path, follow_symlinks=False)
            return self

        def __exit__(self, *args):
            self.log.close()

        def seek(self, *args):
            return self.log.seek(*args)

        def read(self, size=-1):
            reads.append((self.log.tell(), size))
            assert size == limit
            return self.log.read(size)

    monkeypatch.setattr(manager, "open_regular_gated", lambda *a, **kw: MeasuredLog())
    assert DatabaseManager._salvage_creation_log(tmp_path, limit) == (b"x" * 100_000 + b"failure\n")[-limit:].decode()
    assert reads == [(path.stat().st_size - limit, limit)]


def test_latest_log_and_replacement_decoding(tmp_path):
    write_log(tmp_path, "database-create-001.log", b"old")
    write_log(tmp_path, "database-create-002.log", b"failed: \xff")
    write_log(tmp_path, "other.log", b"unrelated")
    assert DatabaseManager._salvage_creation_log(tmp_path) == "failed: \ufffd"


@pytest.mark.parametrize("kind", ["missing", "empty", "directory", "fifo", "symlink"])
def test_unavailable_or_nonregular_log_is_empty(tmp_path, monkeypatch, kind):
    path = tmp_path / "log" / "database-create-001.log"
    path.parent.mkdir()
    if kind == "empty":
        path.touch()
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        target = tmp_path / "external"
        target.write_text("outside log")
        path.symlink_to(target)

    def unbounded_read(*args, **kwargs):
        pytest.fail("must use nonblocking regular-file tail reader")

    monkeypatch.setattr(Path, "read_bytes", unbounded_read)
    assert DatabaseManager._salvage_creation_log(tmp_path) == ""


@pytest.mark.parametrize("limit", [0, -1])
def test_nonpositive_tail_does_not_read(tmp_path, monkeypatch, limit):
    import packages.codeql.database_manager as manager
    write_log(tmp_path, "database-create-001.log", b"failure")

    def unexpected_open(*args, **kwargs):
        pytest.fail("empty tail must not open the log")

    monkeypatch.setattr(manager, "open_regular_gated", unexpected_open)
    assert DatabaseManager._salvage_creation_log(tmp_path, limit) == ""
