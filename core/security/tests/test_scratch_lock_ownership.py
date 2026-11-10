"""Scratch lock owners retire every descriptor without changing lock policy."""
import errno
import fcntl
import os

import pytest

from core.security import launch_scratch
from core.security import scratch_lifecycle as lifecycle
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state

pytestmark = pytest.mark.skipif(os.open not in os.supports_dir_fd, reason="requires directory descriptors")


@pytest.fixture
def session(tmp_path, monkeypatch):
    home = (tmp_path / "registry-home").resolve()
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(home))
    base = tmp_path / "sessions"
    base.mkdir(mode=0o700)
    with isolated_module_state(lifecycle, {"_scratch_module": None}):
        metadata = launch_scratch.allocate(base, os.getpid())
        identifier = lifecycle.register(metadata, os.getpid())
        yield identifier, home / ".scratch-lifecycle"


def _identity(fd):
    info = os.fstat(fd)
    return fd, info.st_dev, info.st_ino


def _is_live(identity):
    try:
        return _identity(identity[0]) == identity
    except OSError as error:
        assert error.errno == errno.EBADF
        return False


def _failed_cleanup(session, monkeypatch, close_type, body_type=None, *, parent_only=False):
    identifier, root = session
    before = (root / (identifier + ".json")).read_bytes()
    native_open, native_close = os.open, os.close
    lock, node, retired = [], [], []
    armed = False
    cleanup = close_type("descriptor cleanup failed")
    body = body_type("body failed") if body_type is not None else None

    def opened(path, *args, **kwargs):
        fd = native_open(path, *args, **kwargs)
        if path == identifier + ".lock":
            lock.append(_identity(fd))
        return fd

    def close(fd):
        identity = _identity(fd)
        native_close(fd)
        if armed and identity in lock + node:
            retired.append(identity)
            should_fail = identity in (node if parent_only else lock)
            if should_fail:
                raise cleanup
            if body is not None:
                raise SystemExit("secondary parent cleanup failed")

    with monkeypatch.context() as fault:
        patch_module_attribute(fault, lifecycle, "os", "open", opened)
        patch_module_attribute(fault, lifecycle, "os", "close", close)
        try:
            with pytest.raises(body_type if body_type is not None else close_type) as caught:
                with lifecycle.locked(identifier) as (fd, value):
                    node.append(_identity(fd))
                    assert value["id"] == identifier and value["state"] == "retained"
                    armed = True
                    if body is not None:
                        raise body
            assert caught.value is (body if body is not None else cleanup)
            assert len(lock) == len(node) == 1
            assert not _is_live(node[0]) and not _is_live(lock[0])
            assert retired == [lock[0], node[0]]
            assert (root / (identifier + ".json")).read_bytes() == before
        finally:
            for identity in lock + node:
                if _is_live(identity):
                    native_close(identity[0])
    with lifecycle.locked(identifier) as (_, value):
        assert value["id"] == identifier


def test_lock_close_failure_still_retires_registry(session, monkeypatch):
    _failed_cleanup(session, monkeypatch, OSError)


@pytest.mark.parametrize("body_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_body_failure_preserves_primary_while_both_closes_fail(session, monkeypatch, body_type, close_type):
    _failed_cleanup(session, monkeypatch, close_type, body_type)


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_lock_close_error_propagates_after_successful_body(session, monkeypatch, close_type):
    _failed_cleanup(session, monkeypatch, close_type)


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_registry_close_error_propagates_after_successful_body(session, monkeypatch, close_type):
    _failed_cleanup(session, monkeypatch, close_type, parent_only=True)


def test_native_lock_excludes_contender_then_releases(session):
    identifier, root = session
    with lifecycle.locked(identifier) as (_, value):
        assert value["id"] == identifier
        contender = os.open(root / (identifier + ".lock"), os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
    with lifecycle.locked(identifier) as (_, value):
        assert value["state"] == "retained"
