"""Owned metadata fixtures for ordered C-level source discovery."""

import importlib
import os
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

analyze = importlib.import_module("packages.source_intel.analyze")


def test_source_cap_does_not_open_later_subtree(tmp_path, monkeypatch):
    first, later = tmp_path / "a", tmp_path / "z"
    first.mkdir()
    later.mkdir()
    for index in range(501):
        (first / f"owned{index:04}.c").touch()
    (later / "later.c").touch()
    actual = os.scandir
    reads = []

    def guarded(path):
        if not isinstance(path, int) and Path(path) == later:
            raise AssertionError("selected source prefix must not enumerate later subtree")
        return actual(path)

    def read(path, *, newline):
        assert newline == ""
        reads.append(path)
        return None

    monkeypatch.setattr(os, "scandir", guarded)
    monkeypatch.setattr(analyze, "read_text_capped", read)
    assert analyze._scan_c_level_source_inputs(tmp_path) == []
    assert reads == [first / f"owned{index:04}.c" for index in range(500)]


def test_ordered_paths_preserve_path_order_and_leaf_links(tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / ".hidden").mkdir()
    for path in (root / "a.c", root / "a" / "nested.HXX", root / "b.cpp",
                 root / ".hidden" / "x.cc", root / "notes.txt"):
        path.touch()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "excluded.c").touch()
    (root / "dir-link").symlink_to(outside, target_is_directory=True)
    (root / "file-link.h").symlink_to(root / "a.c")
    (root / "broken-link").symlink_to(root / "missing")
    expected = sorted(root.rglob("*"))
    actual = list(analyze._iter_sorted_paths(root))
    assert actual == expected
    assert root / "file-link.h" in actual
    assert root / "dir-link" / "excluded.c" not in actual


def test_scandir_is_closed_before_first_yield(tmp_path, monkeypatch):
    (tmp_path / "owned.c").touch()
    events = []

    class Listing:
        def __init__(self, path):
            self.inner = os.scandir(path)

        def __enter__(self):
            events.append("open")
            return self.inner.__enter__()

        def __exit__(self, *args):
            events.append("close")
            return self.inner.__exit__(*args)

    monkeypatch.setattr(analyze, "os", SimpleNamespace(scandir=Listing, name="posix"))
    paths = analyze._iter_sorted_paths(tmp_path)
    assert next(paths) == tmp_path / "owned.c"
    assert events == ["open", "close"]
    paths.close()


def test_refused_subdirectory_retains_available_sibling(tmp_path, monkeypatch):
    blocked = tmp_path / "a-blocked"
    blocked.mkdir()
    sibling = tmp_path / "b.c"
    sibling.touch()
    actual = os.scandir

    def guarded(path):
        if Path(path) == blocked:
            raise PermissionError("owned refusal")
        return actual(path)

    monkeypatch.setattr(analyze, "os", SimpleNamespace(scandir=guarded, name="posix"))
    assert list(analyze._iter_sorted_paths(tmp_path)) == [blocked, sibling]


def test_nonposix_fallback_preserves_global_casefold_path_order(tmp_path, monkeypatch):
    root = PureWindowsPath("C:/owned")
    entries = [root / "A", root / "a", root / "A" / "z.c", root / "a" / "a.c"]

    class OwnedRoot(type(tmp_path)):
        def rglob(self, pattern):
            assert pattern == "*"
            return iter(entries)

    def forbidden(*_):
        raise AssertionError("non-POSIX fallback must not use streaming adapter")

    monkeypatch.setattr(analyze, "os", SimpleNamespace(name="nt", scandir=forbidden))
    assert list(analyze._iter_sorted_paths(OwnedRoot(tmp_path))) == sorted(entries)
