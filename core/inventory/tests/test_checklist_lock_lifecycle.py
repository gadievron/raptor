"""Checklist lock ownership across acquisition and teardown failures."""

import errno
import os

import pytest

import core.inventory as inventory
from core.atomic_fs import fs_lock
from core.testing.module_bindings import patch_module_attribute


def still_owned(fd, identity):
    try:
        info = os.fstat(fd)
    except OSError as error:
        if error.errno == errno.EBADF:
            return False
        raise
    return (info.st_dev, info.st_ino) == identity


@pytest.fixture
def lock_case(tmp_path, monkeypatch):
    locks, descriptors = [], []
    validate = fs_lock.validate_lock_fd
    acquire = fs_lock.acquire_flock_bounded

    def make(*, stage=None, error=None, create=True):
        def checked(fd, path):
            info = os.fstat(fd)
            descriptors.append((fd, (info.st_dev, info.st_ino)))
            if stage == "validate":
                raise error
            return validate(fd, path)

        def locked(fd, path, **kwargs):
            if stage == "acquire":
                raise error
            return acquire(fd, path, **kwargs)

        monkeypatch.setattr(fs_lock, "validate_lock_fd", checked)
        monkeypatch.setattr(fs_lock, "acquire_flock_bounded", locked)
        lock = inventory._checklist_lock(tmp_path / "checklist.json", create=create)
        locks.append(lock)
        return lock, descriptors

    yield make
    # The negative baseline keeps its TextIOWrapper on the lock object.
    # Reclaim it explicitly after the assertion without relying on GC.
    for lock in locks:
        stream = getattr(lock, "_lock_file", None)
        if stream is not None:
            stream.close()
    for fd, identity in descriptors:
        if still_owned(fd, identity):
            os.close(fd)


@pytest.mark.parametrize("stage", ["validate", "acquire"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_entry_releases_owned_lock(lock_case, stage, error_type):
    error = error_type("lock setup failed")
    lock, descriptors = lock_case(stage=stage, error=error)
    with pytest.raises(error_type) as caught:
        with lock:
            pytest.fail("failed acquisition must not enter the body")
    assert caught.value is error
    assert descriptors
    assert not any(still_owned(fd, identity) for fd, identity in descriptors)


@pytest.mark.parametrize("body_type", [None, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("unlock_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_unlock_failure_still_closes_and_preserves_active_body(
    lock_case, monkeypatch, body_type, unlock_type,
):
    lock, descriptors = lock_case()
    body = body_type("body failed") if body_type is not None else None
    unlock = unlock_type("unlock failed")
    original_flock = fs_lock.fcntl.flock
    reached = []

    def flock(fd, operation):
        if operation == fs_lock.fcntl.LOCK_UN:
            reached.append(fd)
            raise unlock
        return original_flock(fd, operation)

    patch_module_attribute(monkeypatch, fs_lock, "fcntl", "flock", flock)

    def invoke():
        with lock:
            if body is not None:
                raise body

    expected = body if body is not None else (None if unlock_type is OSError else unlock)
    if expected is None:
        invoke()
    else:
        with pytest.raises(type(expected)) as caught:
            invoke()
        assert caught.value is expected
    assert reached and descriptors
    assert not any(still_owned(fd, identity) for fd, identity in descriptors)
    lock.__exit__(None, None, None)  # Released contexts do not retry uncertain closes.


def test_read_without_existing_lock_creates_no_artifact(lock_case, tmp_path):
    lock, descriptors = lock_case(create=False)
    with lock:
        assert not list(tmp_path.iterdir())
    assert descriptors == []


def test_lock_context_can_be_reused_after_release(lock_case):
    lock, descriptors = lock_case()
    for _ in range(2):
        with lock:
            assert still_owned(*descriptors[-1])
        assert not any(still_owned(fd, identity) for fd, identity in descriptors)
    assert len(descriptors) == 2


def test_reentry_keeps_original_lease(lock_case, monkeypatch):
    lock, descriptors = lock_case()
    with lock:
        original = descriptors[-1]

        def forbidden(*args, **kwargs):
            pytest.fail("reentry must be refused before another acquisition")

        monkeypatch.setattr(fs_lock, "acquire_flock_bounded", forbidden)
        with pytest.raises(RuntimeError, match="already entered"):
            lock.__enter__()
        assert still_owned(*original)
        assert len(descriptors) == 1
    assert not still_owned(*original)
