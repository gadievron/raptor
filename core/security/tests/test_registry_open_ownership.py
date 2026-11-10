"""Registry descriptors stay owned until validation and parent retirement."""
import errno
import os

import pytest

from core.security import scratch_lifecycle as lifecycle
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state

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


def _failed_return(tmp_path, monkeypatch, primary_type, cleanup_type=None, *, invalid=False):
    home = (tmp_path / "registry-home").resolve()
    home.mkdir(mode=0o700)
    registry = home / ".scratch-lifecycle"
    registry.mkdir(mode=0o755 if invalid else 0o700)
    registry.chmod(0o755 if invalid else 0o700)
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(home))
    primary = primary_type("parent close failed")
    native_open, native_close = os.open, os.close
    parents, children, retired, validation_errors = [], [], [], []
    with isolated_module_state(lifecycle, {"_scratch_module": None}):
        scratch = lifecycle.scratch()
        native_parent, native_private = scratch._open_directory, scratch._private

        def open_parent(*args, **kwargs):
            fd = native_parent(*args, **kwargs)
            parents.append(_identity(fd))
            return fd

        def open_child(*args, **kwargs):
            fd = native_open(*args, **kwargs)
            children.append(_identity(fd))
            return fd

        def private(*args):
            try:
                native_private(*args)
            except PermissionError as error:
                validation_errors.append(error)
                raise

        def close(fd):
            identity = _identity(fd)
            retired.append(identity)
            native_close(fd)
            if identity in parents and not invalid:
                raise primary
            if cleanup_type is not None:
                raise cleanup_type("secondary cleanup failed")

        monkeypatch.setattr(scratch, "_open_directory", open_parent)
        monkeypatch.setattr(scratch, "_private", private)
        patch_module_attribute(monkeypatch, lifecycle, "os", "open", open_child)
        patch_module_attribute(monkeypatch, lifecycle, "os", "close", close)
        try:
            with pytest.raises(PermissionError if invalid else primary_type) as caught:
                lifecycle._open_registry()
            assert len(parents) == len(children) == 1
            assert caught.value is (validation_errors[0] if invalid else primary)
            assert not _is_live(children[0])
            assert not _is_live(parents[0])
            assert retired.count(parents[0]) == retired.count(children[0]) == 1
            assert registry.is_dir()
        finally:
            for identity in parents + children:
                if _is_live(identity):
                    native_close(identity[0])


def test_parent_close_failure_retires_unreturned_registry(tmp_path, monkeypatch):
    _failed_return(tmp_path, monkeypatch, OSError)


@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_registry_child_cleanup_preserves_parent_failure(tmp_path, monkeypatch, primary_type, cleanup_type):
    _failed_return(tmp_path, monkeypatch, primary_type, cleanup_type)


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_native_private_refusal_survives_cleanup_failure(tmp_path, monkeypatch, cleanup_type):
    _failed_return(tmp_path, monkeypatch, PermissionError, cleanup_type, invalid=True)


@pytest.mark.parametrize("create", [False, True])
def test_registry_success_returns_owned_private_directory(tmp_path, monkeypatch, create):
    home = (tmp_path / "registry-home").resolve()
    home.mkdir(mode=0o700)
    registry = home / ".scratch-lifecycle"
    if not create:
        registry.mkdir(mode=0o700)
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(home))
    with isolated_module_state(lifecycle, {"_scratch_module": None}):
        fd = lifecycle._open_registry(create=create)
        try:
            info, expected = os.fstat(fd), registry.stat()
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            assert info.st_mode & 0o077 == 0
        finally:
            os.close(fd)
