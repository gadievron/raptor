"""Protection-marker preparation owns both native metadata descriptors."""
import errno
import json
import os

import pytest

from core.security import launch_scratch as launch
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(os.open not in os.supports_dir_fd, reason="requires directory descriptors")


def _identity(fd):
    info = os.fstat(fd)
    return fd, info.st_dev, info.st_ino


def _is_live(identity):
    try:
        return _identity(identity[0]) == identity
    except OSError as error:
        assert error.errno == errno.EBADF
        return False


def _prepare_cleanup(tmp_path, monkeypatch, close_type=None, *, close_role="target", read_type=None):
    base = tmp_path / "sessions"
    base.mkdir(mode=0o700)
    metadata = launch.allocate(base, os.getpid())
    before = json.loads(metadata.read_bytes())
    native_open, native_read, native_close = os.open, os.read, os.close
    opened, retired = {}, []
    cleanup = close_type("prepare cleanup failed") if close_type is not None else None
    primary = read_type("prepare read failed") if read_type is not None else None
    cleanup_started = False

    def opened_file(path, flags, *args, **kwargs):
        fd = native_open(path, flags, *args, **kwargs)
        if path == metadata.name and flags & os.O_ACCMODE == os.O_RDWR:
            assert not opened
            opened["target"] = _identity(fd)
            opened["directory"] = _identity(kwargs["dir_fd"])
        return fd

    def read(fd, count):
        if primary is not None and opened.get("target") == _identity(fd):
            raise primary
        return native_read(fd, count)

    def close(fd):
        nonlocal cleanup_started
        identity = _identity(fd)
        native_close(fd)
        role = next((name for name, own in opened.items() if own == identity), None)
        if role is not None:
            retired.append(role)
            if cleanup is not None and role == close_role:
                cleanup_started = True
                raise cleanup
            if cleanup_started:
                raise SystemExit("secondary metadata parent cleanup failed")

    with monkeypatch.context() as fault:
        patch_module_attribute(fault, launch, "os", "open", opened_file)
        patch_module_attribute(fault, launch, "os", "read", read)
        patch_module_attribute(fault, launch, "os", "close", close)
        try:
            if primary is not None or cleanup is not None:
                expected = read_type if primary is not None else close_type
                with pytest.raises(expected) as caught:
                    launch.prepare_protection(metadata)
                assert caught.value is (primary if primary is not None else cleanup)
            else:
                assert launch.prepare_protection(metadata) is None
            assert set(opened) == {"target", "directory"}
            live = {role: _is_live(identity) for role, identity in opened.items()}
            assert not any(live.values()), live
            assert retired == ["target", "directory"]
            expected_data = dict(before, protected=primary is None)
            assert json.loads(metadata.read_bytes()) == expected_data
        finally:
            for identity in opened.values():
                if _is_live(identity):
                    native_close(identity[0])
    if primary is None:
        # Writing the request does not make a writable directory sealed.
        with pytest.raises(PermissionError, match="not read-only"):
            launch.read(metadata, require_protected=True)
    else:
        assert launch.read(metadata) == str(metadata.parent.parent / "tmp")


def test_metadata_close_failure_still_retires_parent(tmp_path, monkeypatch):
    _prepare_cleanup(tmp_path, monkeypatch, OSError)


@pytest.mark.parametrize("read_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_read_failure_remains_primary_during_both_closes(tmp_path, monkeypatch, read_type, close_type):
    _prepare_cleanup(tmp_path, monkeypatch, close_type, read_type=read_type)


@pytest.mark.parametrize("close_role", ["target", "directory"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_preserves_written_marker_and_sealed_floor(tmp_path, monkeypatch, close_role, close_type):
    _prepare_cleanup(tmp_path, monkeypatch, close_type, close_role=close_role)


def test_success_prepares_marker_without_claiming_sealed_metadata(tmp_path, monkeypatch):
    _prepare_cleanup(tmp_path, monkeypatch)
