"""Atomic reporting writes stay on pinned directory inodes during swaps."""
import os
from pathlib import Path

import pytest

from core.atomic_fs import write_bytes_atomically
from core.source.beneath import open_dir_beneath


import core.atomic_fs as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def _isolate_delegated_os_faults(monkeypatch):
    """Forward delegated syscalls while preserving each borrowed OS view."""
    import core.atomic_fs as primary0
    import core.source.beneath as delegated0
    patch_module_attribute(monkeypatch, delegated0, "os", "open",
                           lambda *args, **kwargs: primary0.os.open(*args, **kwargs))


def test_directory_walk_rejects_parent_traversal_and_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        open_dir_beneath(root, root / "absolute", create=True)
    with pytest.raises(ValueError):
        open_dir_beneath(root, Path("../outside"), create=True)
    with pytest.raises(OSError):
        open_dir_beneath(root, Path("link/new"), create=True)
    assert not list(outside.iterdir())


def test_rename_cannot_redirect_an_already_pinned_atomic_write(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    parent = root / "nested"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.json").write_bytes(b"outside evidence")
    original = os.replace
    def swap(source, destination, **kwargs):
        parent.rename(root / "held")
        parent.symlink_to(outside, target_is_directory=True)
        return original(source, destination, **kwargs)
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "replace", swap)
    write_bytes_atomically(parent / "report.json", b"new report", root=root)
    assert (outside / "report.json").read_bytes() == b"outside evidence"
    assert (root / "held" / "report.json").read_bytes() == b"new report"
    assert not list((root / "held").glob(".atomic-*"))


def test_swap_before_directory_open_is_refused(tmp_path, monkeypatch):
    parent = tmp_path / "nested"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original = os.open
    swapped = False
    def swap(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "nested" and not swapped:
            parent.rename(tmp_path / "held")
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original(path, flags, *args, **kwargs)
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "open", swap)
    with pytest.raises(OSError):
        write_bytes_atomically(parent / "report.json", b"new report", root=tmp_path)
    assert not list(outside.iterdir())


def test_anchored_atomic_short_writes_are_completed(tmp_path, monkeypatch):
    original = os.write
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "write", lambda fd, data: original(fd, data[:3]))
    destination = tmp_path / "nested/report.json"
    write_bytes_atomically(destination, b"complete report content", root=tmp_path)
    assert destination.read_bytes() == b"complete report content"


@pytest.mark.parametrize("interrupted", [False, True])
def test_failure_preserves_original_and_cleans_temporary(tmp_path, monkeypatch, interrupted):
    destination = tmp_path / "report.json"
    destination.write_bytes(b"old report")
    destination.chmod(0o600)
    def fail(fd, data):
        if interrupted:
            raise KeyboardInterrupt
        return 0
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "write", fail)
    with pytest.raises(KeyboardInterrupt if interrupted else OSError):
        write_bytes_atomically(destination, b"new report", root=tmp_path)
    assert destination.read_bytes() == b"old report"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".atomic-*"))


def test_anchored_streaming_supports_non_byte_buffers(tmp_path):
    from array import array
    chunks = [memoryview(array("H", [1, 2])), b"tail"]
    destination = tmp_path / "nested/report.bin"
    write_bytes_atomically(destination, iter(chunks), root=tmp_path)
    assert destination.read_bytes() == chunks[0].cast("B").tobytes() + b"tail"


def test_anchored_no_clobber_preserves_existing_destination(tmp_path):
    destination = tmp_path / "report.json"
    destination.write_bytes(b"existing report")
    with pytest.raises(FileExistsError):
        write_bytes_atomically(destination, iter([b"new", b" report"]), root=tmp_path, replace=False)
    assert destination.read_bytes() == b"existing report"
    assert not list(tmp_path.glob(".atomic-*"))


def test_anchored_no_clobber_publishes_complete_stream(tmp_path):
    destination = tmp_path / "report.json"
    write_bytes_atomically(destination, iter([b"complete", b" report"]), root=tmp_path, replace=False)
    assert destination.read_bytes() == b"complete report"
    assert not list(tmp_path.glob(".atomic-*"))


def test_failed_stream_iteration_keeps_original(tmp_path):
    destination = tmp_path / "report.json"
    destination.write_bytes(b"existing report")
    def chunks():
        yield b"partial"
        raise ValueError("fixture stream failure")
    with pytest.raises(ValueError, match="stream failure"):
        write_bytes_atomically(destination, chunks(), root=tmp_path)
    assert destination.read_bytes() == b"existing report"
    assert not list(tmp_path.glob(".atomic-*"))


def test_text_writer_forwards_anchor_and_no_clobber(tmp_path):
    from core.atomic_fs import write_text_atomically
    destination = tmp_path / "report.txt"
    write_text_atomically(destination, "report", root=tmp_path, replace=False)
    with pytest.raises(FileExistsError):
        write_text_atomically(destination, "replacement", root=tmp_path, replace=False)
    assert destination.read_text() == "report"
