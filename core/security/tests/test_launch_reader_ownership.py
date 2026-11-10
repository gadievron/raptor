"""Launcher metadata reads retire independently owned native descriptors."""
import errno
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


def _read_cleanup(tmp_path, monkeypatch, close_type, *, close_role="scratch", read_type=None, protection=None):
    base = tmp_path / "sessions"
    base.mkdir(mode=0o700)
    metadata = launch.allocate(base, os.getpid(), protected=protection == "unsealed")
    root = metadata.parent.parent
    before = metadata.read_bytes()
    paths = {"root": root, "metadata": metadata.parent, "target": metadata, "scratch": root / "tmp"}
    identities = {(path.stat().st_dev, path.stat().st_ino): role for role, path in paths.items()}
    native_open, native_read, native_close = os.open, os.read, os.close
    opened, retired = {}, []
    cleanup = close_type("reader cleanup failed") if close_type is not None else None
    primary = read_type("metadata read failed") if read_type is not None else None
    cleanup_started = False

    def open_file(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        identity = _identity(fd)
        role = identities.get(identity[1:])
        if role is not None:
            assert role not in opened
            opened[role] = identity
        return fd

    def read(fd, count):
        if primary is not None:
            assert _identity(fd) == opened["target"]
            raise primary
        return native_read(fd, count)

    def close(fd):
        nonlocal cleanup_started
        identity = _identity(fd)
        role = identities.get(identity[1:])
        native_close(fd)
        if role is not None:
            retired.append(role)
            if cleanup is not None and role == close_role:
                cleanup_started = True
                raise cleanup
            if cleanup_started:
                raise SystemExit("secondary cleanup failed")

    with monkeypatch.context() as fault:
        patch_module_attribute(fault, launch, "os", "open", open_file)
        patch_module_attribute(fault, launch, "os", "read", read)
        patch_module_attribute(fault, launch, "os", "close", close)
        try:
            if protection is not None:
                with pytest.raises(PermissionError, match="protec") as caught:
                    launch.read(metadata, require_protected=protection == "missing")
                assert cleanup is not caught.value
            elif primary is not None or cleanup is not None:
                expected = read_type if primary is not None else close_type
                with pytest.raises(expected) as caught:
                    launch.read(metadata)
                assert caught.value is (primary if primary is not None else cleanup)
            else:
                assert launch.read(metadata) == str(root / "tmp")
            expected_roles = [role for role in ("scratch", "target", "metadata", "root") if role in opened]
            live = {role: _is_live(identity) for role, identity in opened.items()}
            assert not any(live.values()), live
            assert retired == expected_roles
            assert metadata.read_bytes() == before
        finally:
            for identity in opened.values():
                if _is_live(identity):
                    native_close(identity[0])


def test_failed_first_close_retires_all_metadata_descriptors(tmp_path, monkeypatch):
    _read_cleanup(tmp_path, monkeypatch, OSError)


@pytest.mark.parametrize("close_role", ["scratch", "target", "metadata", "root"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_error_keeps_first_error_and_retires_all(tmp_path, monkeypatch, close_role, close_type):
    _read_cleanup(tmp_path, monkeypatch, close_type, close_role=close_role)


@pytest.mark.parametrize("read_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_read_error_remains_primary_after_independent_cleanup(tmp_path, monkeypatch, read_type, close_type):
    _read_cleanup(tmp_path, monkeypatch, close_type, close_role="target", read_type=read_type)


@pytest.mark.parametrize("protection", ["missing", "unsealed"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_native_protection_refusal_remains_primary(tmp_path, monkeypatch, protection, close_type):
    _read_cleanup(tmp_path, monkeypatch, close_type, close_role="target", protection=protection)


def test_successful_native_metadata_read_closes_all(tmp_path, monkeypatch):
    _read_cleanup(tmp_path, monkeypatch, None)
