"""Passive session-log descriptor ownership; no instrumentation is invoked."""
import os
from types import SimpleNamespace

import pytest

from core.audit import frida_observe as consumer


@pytest.mark.parametrize("primary_type", [MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_interrupted_seek_retires_duplicate_and_preserves_caller(
        tmp_path, monkeypatch, primary_type, close_type):
    path = tmp_path / "passive.jsonl"
    path.write_bytes(b"{}\n")
    original = os.open(path, os.O_RDONLY)
    duplicates = set()
    primary = primary_type("after native seek")

    def duplicate(fd):
        result = os.dup(fd)
        duplicates.add(result)
        return result

    def seek(*args):
        os.lseek(*args)
        raise primary

    def close(fd):
        os.close(fd)
        duplicates.remove(fd)
        if close_type is not None:
            raise close_type("after native close")

    monkeypatch.setattr(consumer, "os", SimpleNamespace(
        **{**vars(os), "dup": duplicate, "lseek": seek, "close": close}))
    try:
        with pytest.raises(primary_type) as raised:
            consumer._parse_observations(path, log_fd=original)
        assert raised.value is primary
        os.fstat(original)
        assert not duplicates
    finally:
        for fd in duplicates:
            os.close(fd)
        os.close(original)
