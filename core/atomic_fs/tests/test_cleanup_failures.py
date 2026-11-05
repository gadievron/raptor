"""Cleanup refuses wrong targets and preserves the primary I/O failure."""

import os
import socket
from pathlib import Path

import pytest

from core import atomic_fs as fs


@pytest.mark.parametrize("kind", ["file", "fifo", "socket"])
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o444])
def test_non_directory_roots_are_not_removed_or_chmodded(tmp_path, short_socket_dir, kind, mode):
    root = (short_socket_dir if kind == "socket" else tmp_path) / "node"
    sock = None
    if kind == "file":
        root.write_text("keep")
    elif kind == "fifo":
        os.mkfifo(root)
    else:
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(root))
    root.chmod(mode)
    try:
        assert fs.rmtree_hardened(root) is False
        assert root.lstat().st_mode & 0o777 == mode
    finally:
        if sock:
            sock.close()


@pytest.mark.parametrize("suffix", ["", "/", "/."])
def test_symlink_root_spelling_cannot_change_cleanup_scope(tmp_path, suffix):
    outside = tmp_path / "operator-data"
    outside.mkdir()
    payload = outside / "payload"
    payload.write_text("keep")
    link = tmp_path / "scratch"
    link.symlink_to(outside, target_is_directory=True)
    assert fs.rmtree_hardened(str(link) + suffix) is False
    assert payload.read_text() == "keep"
    assert link.is_symlink()


@pytest.mark.parametrize("value", [None, 123, True, {}, [], "", "bad\x00name"])
def test_invalid_cleanup_targets_are_not_reported_as_removed(
    value, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    assert fs.rmtree_hardened(value) is False


def test_filesystem_root_is_refused_before_any_mutation(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected filesystem mutation")

    monkeypatch.setattr(fs.shutil, "rmtree", forbidden)
    monkeypatch.setattr(os, "chmod", forbidden)
    assert fs.rmtree_hardened(Path("/")) is False


@pytest.mark.parametrize("failure", [PermissionError, OSError])
def test_uninspectable_root_is_not_reported_gone(tmp_path, monkeypatch, failure):
    root = tmp_path / "scratch"
    root.mkdir()
    lstat = os.lstat

    def fail(path, *args, **kwargs):
        if str(path) == str(root):
            raise failure("cannot inspect")
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fail)
    assert fs.rmtree_hardened(root) is False
    assert root.exists()


def test_removal_error_is_a_failed_receipt(tmp_path, monkeypatch):
    root = tmp_path / "scratch"
    root.mkdir()

    def fail(*args, **kwargs):
        raise OSError("removal unavailable")

    monkeypatch.setattr(fs.shutil, "rmtree", fail)
    assert fs.rmtree_hardened(root) is False
    assert root.exists()


def test_replaced_root_is_not_permission_restored(tmp_path, monkeypatch):
    root = tmp_path / "scratch"
    root.mkdir()
    calls = []

    def replace(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            root.rename(tmp_path / "original")
            root.mkdir(mode=0o750)
            (root / "operator-data").write_text("keep")

    monkeypatch.setattr(fs.shutil, "rmtree", replace)
    assert fs.rmtree_hardened(root) is False
    assert root.stat().st_mode & 0o777 == 0o750
    assert (root / "operator-data").read_text() == "keep"
    assert len(calls) == 1


@pytest.mark.parametrize("phase", ["write", "fsync", "replace"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_unlink_failure_does_not_mask_original_write_failure(
    tmp_path, monkeypatch, phase, error
):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    original = error("primary failure")
    unlink = Path.unlink

    def fail(*args, **kwargs):
        raise original

    def cannot_unlink(path, *args, **kwargs):
        if path != target:
            raise PermissionError("secondary cleanup failure")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, phase, fail)
    with monkeypatch.context() as fault:
        fault.setattr(Path, "unlink", cannot_unlink)
        with pytest.raises(error) as caught:
            fs.write_bytes_atomically(target, b"new")
    assert caught.value is original
    assert target.read_bytes() == b"old"
    assert len(list(tmp_path.glob(".atomic-*"))) == 1


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_close_error_does_not_mask_failed_write(tmp_path, monkeypatch, error):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    original = error("primary failure")
    close = os.close

    def fail_write(*args, **kwargs):
        raise original

    def fail_close(fd):
        close(fd)
        raise OSError("secondary close failure")

    monkeypatch.setattr(os, "write", fail_write)
    monkeypatch.setattr(os, "close", fail_close)
    with pytest.raises(error) as caught:
        fs.write_bytes_atomically(target, b"new")
    assert caught.value is original
    assert target.read_bytes() == b"old"
    assert list(tmp_path.glob(".atomic-*")) == []


@pytest.mark.parametrize("marker", [".", "..", "../child/.."])
def test_relative_current_and_parent_markers_are_refused(tmp_path, monkeypatch, marker):
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    payload = child / "payload"
    payload.write_text("keep")
    with monkeypatch.context() as scope:
        scope.chdir(child)
        assert fs.rmtree_hardened(marker) is False
    assert payload.read_text() == "keep"


@pytest.mark.parametrize("failed_stat", [2, 3])
def test_inspection_failure_after_removal_attempt_is_not_a_success(
    tmp_path, monkeypatch, failed_stat
):
    root = tmp_path / "scratch"
    root.mkdir()
    lstat = os.lstat
    calls = []

    def inspect(path, *args, **kwargs):
        if str(path) == str(root):
            calls.append(path)
            if len(calls) == failed_stat:
                raise PermissionError("cannot confirm removal")
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", inspect)
    monkeypatch.setattr(fs.shutil, "rmtree", lambda *a, **kw: None)
    assert fs.rmtree_hardened(root) is False
    assert root.exists()


@pytest.mark.parametrize("ambient_error", [False, True])
def test_close_failure_without_failed_write_aborts_publication(
    tmp_path, monkeypatch, ambient_error
):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    close = os.close

    def fail_close(fd):
        close(fd)
        raise OSError("close failed")

    monkeypatch.setattr(os, "close", fail_close)

    def attempt():
        with pytest.raises(OSError, match="close failed"):
            fs.write_bytes_atomically(target, b"new")

    if ambient_error:
        try:
            raise LookupError("unrelated exception handled by caller")
        except LookupError:
            attempt()
    else:
        attempt()
    assert target.read_bytes() == b"old"
    assert list(tmp_path.glob(".atomic-*")) == []


def test_directory_cleanup_does_not_swallow_cancellation(tmp_path, monkeypatch):
    root = tmp_path / "scratch"
    root.mkdir()

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(fs.shutil, "rmtree", interrupt)
    with pytest.raises(KeyboardInterrupt):
        fs.rmtree_hardened(root)
    assert root.exists()
