"""Native exclusive rename moves inode identity without adopting contenders."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from core.atomic_fs import rename_without_replace
from core.atomic_fs.tests.test_directory_publication import native_only


def entry(path, kind, target):
    if kind == "directory":
        path.mkdir()
        (path / "data").write_bytes(b"entry")
    elif kind == "file":
        path.write_bytes(b"entry")
    elif kind in {"symlink", "dangling"}:
        path.symlink_to(target if kind == "symlink" else path.parent / "missing")
    else:
        os.mkfifo(path)


@pytest.fixture(params=["file", "directory", "symlink", "dangling", "fifo"])
def source(request, tmp_path):
    native_only()
    victim = tmp_path / "victim"
    victim.write_bytes(b"preserve")
    path = tmp_path / "source"
    entry(path, request.param, victim)
    return path, victim


def test_native_moves_entry_without_copy(source, tmp_path):
    path, victim = source
    before = path.lstat()
    destination = tmp_path / "destination"
    rename_without_replace(path, destination)
    assert not os.path.lexists(path)
    after = destination.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
    assert victim.read_bytes() == b"preserve"


@pytest.mark.parametrize("occupied", ["file", "directory", "symlink", "dangling", "fifo"])
def test_native_refuses_every_occupied_entry(source, tmp_path, occupied):
    path, victim = source
    destination = tmp_path / "destination"
    entry(destination, occupied, victim)
    original, contender = path.lstat(), destination.lstat()
    with pytest.raises(OSError):
        rename_without_replace(path, destination)
    assert path.lstat().st_ino == original.st_ino
    assert destination.lstat().st_ino == contender.st_ino
    assert victim.read_bytes() == b"preserve"


def test_same_entry_is_refused(source):
    path, victim = source
    before = path.lstat().st_ino
    with pytest.raises(FileExistsError):
        rename_without_replace(path, path)
    assert path.lstat().st_ino == before


def test_missing_same_path_reports_missing_source(tmp_path):
    path = tmp_path / "missing"
    with pytest.raises(FileNotFoundError):
        rename_without_replace(path, path)


def test_competing_entry_moves_have_one_winner(tmp_path):
    native_only()
    sources = [tmp_path / "first", tmp_path / "second"]
    for index, path in enumerate(sources):
        path.write_bytes(bytes([index]))
    barrier = Barrier(2)
    target = tmp_path / "published"

    def move(path):
        barrier.wait(timeout=5)
        try:
            rename_without_replace(path, target)
            return path
        except FileExistsError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = list(pool.map(move, sources))
    assert len([winner for winner in winners if winner is not None]) == 1
    assert len([path for path in sources if path.exists()]) == 1
    assert target.read_bytes() in {b"\0", b"\1"}
