"""Fake-HOME intake keeps cleanup errors soft and cancellation primary."""
import errno
import os

import pytest

from core.sandbox import context
from core.testing.module_bindings import patch_module_attribute


class _IntakeOps:
    def __init__(self):
        self.native_home = context._open_fake_home
        self.native_open = os.open
        self.native_read = os.read
        self.native_close = os.close
        self.live = set()
        self.home_fd = None
        self.open_error = None
        self.read_error = None
        self.close_errors = set()
        self.close_faults = []
        self.duplicates = []
        self.observed = None
        self.cancel = None

    def open_home(self, path):
        fd = self.native_home(path)
        self.home_fd = fd
        self.live.add(fd)
        return fd

    def open(self, *args, **kwargs):
        if self.open_error is not None:
            raise self.open_error
        fd = self.native_open(*args, **kwargs)
        self.live.add(fd)
        return fd

    def read(self, *args):
        if self.read_error is not None:
            raise self.read_error
        return self.native_read(*args)

    def close(self, fd):
        if fd not in self.live:
            self.duplicates.append(fd)
            raise OSError(errno.EBADF, "owned descriptor already released")
        self.live.remove(fd)
        self.native_close(fd)
        kind = "home" if fd == self.home_fd else "file"
        if kind in self.close_errors:
            self.close_faults.append(kind)
            raise OSError(errno.EIO, "owned close failed after release")

    def finish(self):
        for fd in list(self.live):
            self.native_close(fd)
            self.live.remove(fd)


@pytest.fixture
def intake_ops(monkeypatch, request):
    ops = _IntakeOps()
    request.addfinalizer(ops.finish)
    monkeypatch.setattr(context, "_open_fake_home", ops.open_home)
    patch_module_attribute(monkeypatch, context, "os", "open", ops.open)
    patch_module_attribute(monkeypatch, context, "os", "read", ops.read)
    patch_module_attribute(monkeypatch, context, "os", "close", ops.close)
    return ops


def _intake(tmp_path):
    path = tmp_path / ".home"
    path.mkdir()
    (path / ".config").mkdir()
    (path / "settings").write_bytes(b"owned settings")
    return path


def _configure(monkeypatch, ops, scenario):
    if scenario == "budget":
        monkeypatch.setattr(context, "_FAKE_HOME_INGEST_MAX_FILES", 0)
    elif scenario == "open-error":
        ops.open_error = PermissionError(errno.EACCES, "owned file open failed")
    elif scenario == "read-error":
        ops.read_error = OSError(errno.EIO, "owned file read failed")
    elif scenario == "file-close":
        ops.close_errors.add("file")


@pytest.mark.parametrize("scenario", ["success", "budget", "open-error", "read-error"])
def test_home_close_error_uses_intake_fallback(tmp_path, monkeypatch, intake_ops, scenario):
    intake = _intake(tmp_path)
    _configure(monkeypatch, intake_ops, scenario)
    intake_ops.close_errors.add("home")
    assert context._stage_fake_home_intake(str(intake)) is None
    assert "home" in intake_ops.close_faults
    assert not intake_ops.live
    assert intake_ops.duplicates == []


@pytest.mark.parametrize("cancel_kind", ["interrupt", "exit"])
@pytest.mark.parametrize("close_kind", ["file", "home", "both"])
def test_cancellation_survives_intake_close_errors(tmp_path, intake_ops, cancel_kind, close_kind):
    intake = _intake(tmp_path)
    cancel = KeyboardInterrupt("owned read cancelled") if cancel_kind == "interrupt" else SystemExit(17)
    intake_ops.cancel = cancel
    intake_ops.read_error = cancel
    intake_ops.close_errors.update({"file", "home"} if close_kind == "both" else {close_kind})
    with pytest.raises(type(cancel)) as caught:
        try:
            context._stage_fake_home_intake(str(intake))
        except BaseException as error:
            intake_ops.observed = error
            raise
    assert caught.value is cancel
    assert intake_ops.close_faults
    assert not intake_ops.live
    assert intake_ops.duplicates == []


@pytest.mark.parametrize("scenario", ["success", "budget", "open-error", "read-error", "file-close"])
def test_intake_outcomes_without_home_close_error(tmp_path, monkeypatch, intake_ops, scenario):
    intake = _intake(tmp_path)
    _configure(monkeypatch, intake_ops, scenario)
    staged = context._stage_fake_home_intake(str(intake))
    if scenario == "success":
        assert staged == ({context._TMP_FAKE_HOME + "/settings": b"owned settings"},
                          [context._TMP_FAKE_HOME, context._TMP_FAKE_HOME + "/.config"])
    else:
        assert staged is None
    assert not intake_ops.live
    assert intake_ops.duplicates == []


@pytest.mark.parametrize("cancel_kind", ["interrupt", "exit"])
def test_cancellation_without_close_errors(tmp_path, intake_ops, cancel_kind):
    intake = _intake(tmp_path)
    cancel = KeyboardInterrupt("owned read cancelled") if cancel_kind == "interrupt" else SystemExit(17)
    intake_ops.cancel = cancel
    intake_ops.read_error = cancel
    with pytest.raises(type(cancel)) as caught:
        context._stage_fake_home_intake(str(intake))
    assert caught.value is cancel
    assert not intake_ops.live
    assert intake_ops.duplicates == []
