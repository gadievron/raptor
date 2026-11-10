"""Native descriptor ownership during write-side directory traversal."""
import errno
import os
from pathlib import Path

import pytest

from core.source import beneath
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


def _failed_handoff(tmp_path, monkeypatch, primary_type, cleanup_type):
    root = tmp_path / "owned"
    (root / "child").mkdir(parents=True)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"separate owned descriptor")
    native_open, native_close = os.open, os.close
    foreign_fd = native_open(foreign, os.O_RDONLY)
    foreign_identity = _identity(foreign_fd)
    primary = primary_type("parent retirement failed")
    opened, retired, aliases = [], [], []

    def opened_directory(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        opened.append(_identity(fd))
        return fd

    def close(fd):
        identity = _identity(fd)
        retired.append(identity)
        native_close(fd)
        if identity == opened[0]:
            os.dup2(foreign_fd, fd)
            aliases.append((fd, foreign_identity[1], foreign_identity[2]))
            raise primary
        if len(opened) > 1 and identity == opened[1] and cleanup_type is not None:
            raise cleanup_type("child cleanup failed")

    patch_module_attribute(monkeypatch, beneath, "os", "open", opened_directory)
    patch_module_attribute(monkeypatch, beneath, "os", "close", close)
    try:
        with pytest.raises(primary_type) as caught:
            beneath.open_dir_beneath(root, Path("child"))
        assert caught.value is primary
        assert len(opened) == 2 and len(aliases) == 1
        child_live, foreign_live = _is_live(opened[1]), _is_live(aliases[0])
        assert not child_live and foreign_live, (child_live, foreign_live, retired, opened)
        assert retired == opened
    finally:
        for identity in opened + aliases + [foreign_identity]:
            if _is_live(identity):
                native_close(identity[0])


def test_parent_retirement_does_not_retry_consumed_descriptor(tmp_path, monkeypatch):
    _failed_handoff(tmp_path, monkeypatch, OSError, None)


@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_child_cleanup_preserves_parent_failure(tmp_path, monkeypatch, primary_type, cleanup_type):
    _failed_handoff(tmp_path, monkeypatch, primary_type, cleanup_type)


@pytest.mark.parametrize("create", [False, True])
def test_successful_walk_transfers_final_directory_once(tmp_path, create):
    root = tmp_path / "owned"
    root.mkdir()
    if not create:
        (root / "a" / "b").mkdir(parents=True)
    fd = beneath.open_dir_beneath(root, Path("a/b"), create=create)
    try:
        info = os.fstat(fd)
        expected = (root / "a" / "b").stat()
        assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
    finally:
        os.close(fd)
