"""Fake-HOME descriptors remain owned when close or acquisition fails."""
import errno
import os
import stat

import pytest

from core.sandbox import _fake_home as home
from core.testing.module_bindings import patch_module_attribute


class _OwnedOps:
    def __init__(self):
        self.native_open = os.open
        self.native_close = os.close
        self.native_dup = os.dup
        self.live = set()
        self.duplicates = []
        self.action = None
        self.mode = "success"
        self.close_fd = None
        self.close_error = OSError(errno.EIO, "owned close failed after release")
        self.primary = PermissionError(errno.EACCES, "owned acquisition failed")
        self.close_fired = False
        self.observed = None
        self.home_fd = None

    def open(self, path, flags, *args, **kwargs):
        assert flags == home._DIR_FLAGS
        target = (self.action == "walk" and "dir_fd" in kwargs) or (
            self.action in ("open_home", "prepare_output") and path == ".home"
        ) or (self.action == "prepare_nested" and path == ".config")
        if target and self.mode in ("handoff", "primary") and self.close_fd is None and not self.close_fired:
            self.close_fd = kwargs["dir_fd"]
            if self.mode == "primary":
                raise self.primary
        fd = self.native_open(path, flags, *args, **kwargs)
        self.live.add(fd)
        if path == ".home":
            self.home_fd = fd
        return fd

    def dup(self, fd):
        duplicate = self.native_dup(fd)
        self.live.add(duplicate)
        return duplicate

    def close(self, fd):
        if fd not in self.live:
            # Never let a duplicate attempt reach a possibly recycled fd.
            self.duplicates.append(fd)
            raise OSError(errno.EBADF, "close of an already released owned fd")
        self.live.remove(fd)
        self.native_close(fd)
        if fd == self.close_fd or (self.mode == "final" and fd == self.home_fd):
            self.close_fd = None
            self.close_fired = True
            raise self.close_error

    def finish(self):
        # Reclaim baseline leaks too, even when a regression assertion fails.
        for fd in list(self.live):
            self.native_close(fd)
            self.live.remove(fd)


@pytest.fixture
def ops(monkeypatch, request):
    ledger = _OwnedOps()
    request.addfinalizer(ledger.finish)
    patch_module_attribute(monkeypatch, home, "os", "open", ledger.open)
    patch_module_attribute(monkeypatch, home, "os", "close", ledger.close)
    patch_module_attribute(monkeypatch, home, "os", "dup", ledger.dup)
    return ledger


def _invoke(tmp_path, ledger, action):
    ledger.action = action
    output = tmp_path / "output"
    output.mkdir()
    if action == "walk":
        return home._open_directory(str(output.resolve()))
    if action == "open_home":
        (output / ".home").mkdir()
        return home.open_home(str(output / ".home"))
    return home.prepare_home(str(output))


_ACTIONS = ["walk", "open_home", "prepare_output", "prepare_nested"]


@pytest.mark.parametrize("action", _ACTIONS)
def test_close_handoff_reclaims_new_descriptor(tmp_path, ops, action):
    ops.mode = "handoff"
    with pytest.raises(OSError) as caught:
        _invoke(tmp_path, ops, action)
    ops.observed = caught.value
    assert ops.close_fired
    assert not ops.live, "new descriptor escaped ownership after parent close failed"
    assert ops.duplicates == []
    assert caught.value is ops.close_error


@pytest.mark.parametrize("action", _ACTIONS)
@pytest.mark.parametrize("failure", ["permission", "interrupt"])
def test_acquisition_failure_survives_close_failure(tmp_path, ops, action, failure):
    ops.mode = "primary"
    if failure == "interrupt":
        ops.primary = KeyboardInterrupt("owned acquisition interrupted")
    with pytest.raises(type(ops.primary)) as caught:
        try:
            _invoke(tmp_path, ops, action)
        except BaseException as error:
            ops.observed = error
            raise
    assert caught.value is ops.primary
    assert ops.close_fired
    assert not ops.live
    assert ops.duplicates == []


@pytest.mark.parametrize("action", _ACTIONS)
def test_acquisition_failure_survives_interrupted_close(tmp_path, ops, action):
    ops.mode = "primary"
    ops.close_error = KeyboardInterrupt("owned cleanup interrupted after release")
    with pytest.raises(BaseException) as caught:
        _invoke(tmp_path, ops, action)
    assert caught.value is ops.primary
    assert ops.close_fired
    assert not ops.live
    assert ops.duplicates == []


@pytest.mark.parametrize("action", _ACTIONS)
def test_success_retains_only_the_returned_descriptor(tmp_path, ops, action):
    result = _invoke(tmp_path, ops, action)
    if action in ("walk", "open_home"):
        assert ops.live == {result}
        assert stat.S_ISDIR(os.fstat(result).st_mode)
        ops.close(result)
    else:
        assert result is None
        base = tmp_path / "output" / ".home"
        for relative in (".config", ".cache", ".local/share", ".local/state"):
            assert (base / relative).is_dir()
    assert not ops.live
    assert ops.duplicates == []


def test_final_close_failure_still_propagates(tmp_path, ops):
    ops.mode = "final"
    with pytest.raises(OSError) as caught:
        _invoke(tmp_path, ops, "prepare_output")
    assert caught.value is ops.close_error
    assert ops.close_fired
    assert not ops.live
    assert ops.duplicates == []
