"""Telemetry tokens must use complete persisted keys without FIFO hangs."""

import errno
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from core.sandbox import telemetry_mac as tmac
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def test_partial_creation_writes_produce_a_verifiable_key(monkeypatch):
    real_write = os.write
    writes = []

    def partial_write(fd, data):
        written = real_write(fd, data[:5])
        writes.append(written)
        return written

    patch_module_attribute(monkeypatch, tmac, "os", "write", partial_write)
    fields = {"kind": "proxy-event", "host": "example"}
    token = tmac.mint(fields)
    assert token is not None
    assert len(writes) > 1
    assert sum(writes) == tmac._KEY_LEN
    assert len(tmac._key_path().read_bytes()) == tmac._KEY_LEN
    assert tmac.verify(fields, token) is True


@pytest.mark.parametrize("failure", ["zero", "error"])
def test_failed_creation_never_returns_an_unpersisted_key(monkeypatch, request, failure):
    real_write, real_close, real_open = os.write, os.close, os.open
    calls, closed, active = [], [], set()

    def release_if_owned(fd):
        if fd in active:
            active.remove(fd)
            real_close(fd)

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        active.add(fd)
        request.addfinalizer(lambda: release_if_owned(fd))
        return fd

    def fail_write(fd, data):
        calls.append(fd)
        if len(calls) == 1:
            return real_write(fd, data[:5])
        if failure == "zero":
            return 0
        raise OSError(errno.ENOSPC, "no space")

    def close(fd):
        active.discard(fd)  # Never retry a descriptor after a close attempt.
        closed.append(fd)
        return real_close(fd)

    patch_module_attribute(monkeypatch, tmac, "os", "open", open_fd)
    patch_module_attribute(monkeypatch, tmac, "os", "write", fail_write)
    patch_module_attribute(monkeypatch, tmac, "os", "close", close)
    assert tmac.mint({"kind": "proxy-event"}) is None
    assert len(calls) == 2
    assert closed.count(calls[0]) == 1
    with pytest.raises(OSError) as exc:
        os.fstat(calls[0])
    assert exc.value.errno == errno.EBADF
    # Failed exclusive creation removes only its own incomplete inode.
    # A later healthy call can create a usable key instead of refusing forever.
    assert not tmac._key_path().exists()
    patch_module_attribute(monkeypatch, tmac, "os", "write", real_write)
    token = tmac.mint({"kind": "proxy-event"})
    assert token
    assert tmac.verify({"kind": "proxy-event"}, token)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
def test_fifo_key_is_quarantined_without_waiting_for_a_writer():
    key = tmac._key_path()
    key.parent.mkdir(mode=0o700, parents=True)
    os.mkfifo(key, 0o600)
    script = """
import runpy, sys
from pathlib import Path
module = runpy.run_path(sys.argv[1])
fields = {"kind": "proxy-event"}
token = module["mint"](fields)
assert token is not None
assert module["verify"](fields, token)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(tmac.__file__).resolve())],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert key.is_file()
    assert len(key.read_bytes()) == tmac._KEY_LEN
    quarantined = list(key.parent.glob(key.name + ".tampered-*"))
    assert len(quarantined) == 1
    assert stat.S_ISFIFO(quarantined[0].lstat().st_mode)
    assert len(tmac.tamper_events()) == 1
