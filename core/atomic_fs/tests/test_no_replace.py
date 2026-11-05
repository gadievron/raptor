"""Exclusive publication never exposes partial records or replaces a winner."""

import json
import os
import threading
import types

import pytest

from core import atomic_fs as fs
from core.run import tmp_ownership as owners
from core.trajectories import store as trajectories


@pytest.fixture
def local_os(monkeypatch):
    proxy = types.ModuleType("atomic_writer_os")
    proxy.__dict__.update(vars(os))
    monkeypatch.setattr(fs, "os", proxy)
    return proxy


@pytest.mark.parametrize("kind", ["file", "symlink", "dangling", "directory", "fifo"])
def test_occupied_destination_is_unchanged(tmp_path, kind):
    path = tmp_path / "record"
    other = tmp_path / "other"
    other.write_text("keep")
    if kind == "file":
        path.write_text("winner")
    elif kind == "symlink":
        path.symlink_to(other)
    elif kind == "dangling":
        path.symlink_to(tmp_path / "missing")
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    before = path.lstat()
    with pytest.raises(FileExistsError):
        fs.write_text_atomically(path, "loser", replace=False, mode=0o600)
    assert path.lstat().st_ino == before.st_ino
    assert other.read_text() == "keep"
    assert not list(tmp_path.glob(".atomic-*"))


@pytest.mark.parametrize("text", [False, True])
def test_short_writes_are_completed_before_publication(tmp_path, local_os, text):
    path = tmp_path / "record"
    payload = "unicode \N{SNOWMAN}" * 20

    def short_write(fd, data):
        assert not path.exists()
        return os.write(fd, data[:3])

    local_os.write = short_write
    if text:
        fs.write_text_atomically(path, payload, replace=False, mode=0o600)
    else:
        fs.write_bytes_atomically(path, [payload.encode()[:7], payload.encode()[7:]], replace=False, mode=0o600)
    assert path.read_text() == payload
    assert path.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("phase", ["write", "fsync", "close", "link"])
@pytest.mark.parametrize("cancel", [False, True], ids=["io-error", "cancel"])
def test_failed_publication_removes_staging_and_closes_descriptor(tmp_path, local_os, phase, cancel):
    path = tmp_path / "record"
    descriptors = []
    original_open = os.open
    original_close = os.close

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        descriptors.append(fd)
        return fd

    error = KeyboardInterrupt if cancel else OSError

    def fail(*args, **kwargs):
        if phase == "close":
            original_close(args[0])
        raise error("injected publication failure")

    local_os.open = opened
    setattr(local_os, phase, fail)
    with pytest.raises(error, match="injected publication failure"):
        fs.write_text_atomically(path, "payload", replace=False, mode=0o600)
    assert not list(tmp_path.iterdir())
    assert descriptors
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_zero_progress_refuses_to_publish(tmp_path, local_os):
    local_os.write = lambda fd, data: 0
    with pytest.raises(OSError, match="short write"):
        fs.write_bytes_atomically(tmp_path / "record", b"payload", replace=False)
    assert not list(tmp_path.iterdir())


def test_racing_writers_publish_exactly_one_complete_record(tmp_path):
    path = tmp_path / "record"
    winners, collisions, errors = [], [], []
    barrier = threading.Barrier(4)

    def write(index):
        try:
            barrier.wait(timeout=3)
            fs.write_bytes_atomically(path, bytes([index]) * 4096, replace=False)
            winners.append(index)
        except FileExistsError:
            collisions.append(index)
        except BaseException as exc:
            errors.append(exc)

    workers = [threading.Thread(target=write, args=(index,)) for index in range(4)]
    try:
        for worker in workers:
            worker.start()
    finally:
        for worker in workers:
            if worker.ident is not None:
                worker.join(timeout=5)
    assert not any(worker.is_alive() for worker in workers)
    assert not errors
    assert len(winners) == 1 and len(collisions) == 3
    assert path.read_bytes() == bytes([winners[0]]) * 4096
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("consumer", ["trajectory", "owner"])
@pytest.mark.parametrize("cancel", [False, True], ids=["disk-full", "cancel"])
def test_consumers_leave_no_partial_and_allow_retry(tmp_path, local_os, consumer, cancel):
    def fail(fd, data):
        os.write(fd, data[:2])
        if cancel:
            raise KeyboardInterrupt("cancelled")
        raise OSError("disk full")

    local_os.write = fail
    if consumer == "trajectory":
        with pytest.raises(KeyboardInterrupt if cancel else OSError):
            trajectories._write_atomic(tmp_path / "trajectory.json", '{"record": true}')
    elif cancel:
        with pytest.raises(KeyboardInterrupt):
            owners.write_owner_marker(tmp_path)
    else:
        owners.write_owner_marker(tmp_path)  # best effort remains best effort
    assert not list(tmp_path.iterdir())
    local_os.write = os.write
    if consumer == "trajectory":
        path = trajectories._write_atomic(tmp_path / "trajectory.json", '{"record": true}')
        assert json.loads(path.read_text()) == {"record": True}
    else:
        owners.write_owner_marker(tmp_path)
        assert owners._owner_pid(tmp_path / owners.OWNER_MARKER_NAME) == os.getpid()


def test_trajectory_collision_keeps_original_record(tmp_path):
    path = tmp_path / "trajectory.json"
    path.write_text("original")
    written = trajectories._write_atomic(path, "replacement")
    assert written != path
    assert path.read_text() == "original"
    assert written.read_text() == "replacement"
    assert len(list(tmp_path.iterdir())) == 2


def test_owner_marker_never_replaces_existing_owner(tmp_path):
    path = tmp_path / owners.OWNER_MARKER_NAME
    path.write_text('{"pid": 123}')
    before = path.stat().st_ino
    owners.write_owner_marker(tmp_path)
    assert path.read_text() == '{"pid": 123}'
    assert path.stat().st_ino == before
    assert list(tmp_path.iterdir()) == [path]


def test_owner_marker_does_not_recreate_removed_owner(tmp_path):
    root = tmp_path / "gone"
    owners.write_owner_marker(root)
    assert not root.exists()
