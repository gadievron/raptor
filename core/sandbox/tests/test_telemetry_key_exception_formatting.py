"""Telemetry key cleanup diagnostics preserve primary failures and descriptors."""

import errno
import os
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


class Cancelled(BaseException):
    pass


@pytest.fixture
def owned(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(mac, "_warned_paths", set())
    private = ModuleType("owned_telemetry_os")
    vars(private).update(vars(os))
    monkeypatch.setattr(mac, "os", private)
    return mac._key_path(), private


def broken_error(formatting, attempts):
    class BrokenError(OSError):
        def __str__(self):
            attempts.append("str")
            if formatting == "non-string":
                return None
            if formatting == "type":
                raise TypeError("message unavailable")
            raise RuntimeError("message unavailable")

        def __repr__(self):
            raise AssertionError("diagnostics must not attempt repr")
    return BrokenError()


def install_faults(monkeypatch, request, owned, original, secondary, route):
    path, private = owned
    opened, closed, active = [], [], set()
    writes = []

    def finish():
        while active:
            fd = active.pop()  # Release ownership before attempting close.
            os.close(fd)

    request.addfinalizer(finish)

    def open_fd(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        active.add(fd)
        opened.append(fd)
        return fd

    def write(fd, data):
        writes.append(fd)
        if len(writes) == 1:
            return os.write(fd, data[:3])
        raise original

    def close(fd):
        active.remove(fd)
        os.close(fd)
        closed.append(fd)
        if route in {"close", "both", "close-only"}:
            raise secondary

    if route in {"unlink", "both"}:
        class RefusedPath(type(path)):
            def unlink(self, *args, **kwargs):
                raise secondary
        monkeypatch.setattr(mac, "_key_path", lambda: RefusedPath(path))
    # Only this test's private OS view changes; the shared os stays native.
    private.open, private.close = open_fd, close
    if route != "close-only":
        private.write = write
    return opened, closed, active


@pytest.mark.parametrize("route", ["unlink", "close", "both"])
@pytest.mark.parametrize("formatting", ["runtime", "type", "non-string"])
@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt, SystemExit, Cancelled],
                         ids=["io", "interrupt", "exit", "cancel"])
def test_cleanup_formatting_keeps_primary(owned, monkeypatch, request, caplog,
                                         route, formatting, kind):
    path, _private = owned
    original = kind("original write failure")
    attempts = []
    secondary = broken_error(formatting, attempts)
    with monkeypatch.context() as patch:
        opened, closed, active = install_faults(
            patch, request, owned, original, secondary, route,
        )
        with pytest.raises(kind) as caught:
            mac._load_or_create_key()
        assert caught.value is original
    assert len(opened) == 1
    assert closed == opened
    assert not active
    with pytest.raises(OSError) as released:
        os.fstat(opened[0])
    assert released.value.errno == errno.EBADF
    count = 2 if route == "both" else 1
    assert attempts == ["str"] * count
    assert caplog.text.count("exception message unavailable") == count
    if route in {"unlink", "both"}:
        assert path.stat().st_size == 3
        # Preserve evidence of the failed cleanup until explicit owned removal.
        path.unlink()
    else:
        assert not path.exists()
    # Remove the private faults before a real mint/verify recovery cycle.
    private = owned[1]
    private.open, private.write, private.close = os.open, os.write, os.close
    fields = {"kind": "owned-recovery"}
    token = mac.mint(fields)
    assert token is not None
    assert mac.verify(fields, token)
    assert not mac.verify({"kind": "changed"}, token)
    assert len(path.read_bytes()) == mac._KEY_LEN
    assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("formatting", ["runtime", "type", "non-string"])
def test_close_only_failure_retains_original_identity(owned, monkeypatch, request,
                                                     caplog, formatting):
    path, private = owned
    attempts = []
    secondary = broken_error(formatting, attempts)
    opened, closed, active = install_faults(
        monkeypatch, request, owned, None, secondary, "close-only",
    )
    with pytest.raises(OSError) as caught:
        mac._load_or_create_key()
    assert caught.value is secondary
    assert attempts == []  # A sole close failure must propagate, not be rendered.
    assert len(opened) == 1 and opened == closed and not active
    assert len(path.read_bytes()) == mac._KEY_LEN
    assert not caplog.records
    private.open, private.close = os.open, os.close
    assert mac.key_usable()
    fields = {"kind": "complete-key"}
    token = mac.mint(fields)
    assert token and mac.verify(fields, token)
