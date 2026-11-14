"""Owned file material controls; no compiler or complete namespace claim."""

from dataclasses import FrozenInstanceError
import hashlib

import pytest

from core.audit import prepared_dependency_material as material
from core.audit.prepared_dependency_material import (
    DependencyMaterialUnavailable, DependencyReference,
    capture_dependency_materials, dependency_materials_current,
)


@pytest.fixture
def owned(tmp_path):
    (tmp_path / "include").mkdir()
    (tmp_path / "unit.c").write_bytes(b"unit")
    (tmp_path / "include/owned.h").write_bytes(b"header")
    refs = (DependencyReference("target", "unit.c"), DependencyReference("target", "include/owned.h"))
    return tmp_path, refs


def capture(root, refs, **caps):
    return capture_dependency_materials(refs, roots={"target": root}, **{
        "max_files": 8, "max_file_bytes": 16, "max_total_bytes": 32, **caps})


def test_complete_raw_files_keep_order_identity_and_exact_duplicate_deduplication(owned):
    root, refs = owned
    result = capture(root, refs + refs[:1])
    assert isinstance(result, tuple)
    assert tuple(item.reference for item in result) == refs
    assert tuple(item.content for item in result) == (b"unit", b"header")
    assert result[0].identity.sha256 == hashlib.sha256(b"unit").hexdigest()
    assert len(result[0].identity.version) == 5
    with pytest.raises(FrozenInstanceError):
        result[0].content = b"changed"
    assert dependency_materials_current(result, references=refs, roots={"target": root},
                                       max_files=8, max_file_bytes=16, max_total_bytes=32)


@pytest.mark.parametrize("path", ["", "/absolute", "../unit.c", "include/../unit.c", "./unit.c",
                                  "include//owned.h", "unit.c/", "C:unit.c", "a\\b", "a\0b"])
def test_ambiguous_or_outside_spellings_refuse_without_a_partial_result(owned, path):
    root, refs = owned
    result = capture(root, refs[:1] + (DependencyReference("target", path),))
    assert isinstance(result, DependencyMaterialUnavailable)
    assert result.reason == "invalid_dependency_reference"


def test_missing_and_unknown_root_refuse_the_whole_group(owned):
    root, refs = owned
    assert capture(root, refs + (DependencyReference("other", "unit.c"),)).reason == "unknown_dependency_root"
    assert capture(root, refs + (DependencyReference("target", "missing.h"),)).reason == "dependency_material_unavailable"


def test_exact_limits_and_limits_before_deduplication(owned):
    root, refs = owned
    assert isinstance(capture(root, refs, max_files=2, max_file_bytes=6, max_total_bytes=10), tuple)
    assert capture(root, refs, max_file_bytes=5).reason == "dependency_file_byte_budget"
    assert capture(root, refs, max_total_bytes=9).reason == "dependency_total_byte_budget"
    assert capture(root, refs[:1] * 3, max_files=2).reason == "dependency_material_count_budget"


@pytest.mark.parametrize("cap", [True, None, 0, -1, 1.5])
def test_caps_are_explicit_positive_integers(owned, cap):
    root, refs = owned
    for name in ("max_files", "max_file_bytes", "max_total_bytes"):
        assert capture(root, refs, **{name: cap}).reason == "invalid_dependency_material_budget"


def test_symlinks_and_directories_are_not_dependency_material(owned):
    root, refs = owned
    (root / "alias.h").symlink_to(root / "include/owned.h")
    for path in ("alias.h", "include"):
        result = capture(root, refs[:1] + (DependencyReference("target", path),))
        assert result.reason == "dependency_material_unavailable"


class _ReadHook:
    def __init__(self, stream, hook):
        self.stream, self.hook = stream, hook

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def fileno(self):
        return self.stream.fileno()

    def read(self, size):
        data = self.stream.read(size)
        return self.hook(data)


@pytest.mark.parametrize("change", ["partial", "growth", "earlier-file"])
def test_partial_growth_or_across_capture_change_never_returns_a_prefix(owned, monkeypatch, change):
    root, refs = owned
    original = material.open_regular_beneath
    reached, streams = [], []

    def open_selected(base, path, mode):
        stream = original(base, path, mode)
        if stream is None:
            return None
        streams.append(stream)

        def hook(data):
            reached.append(str(path))
            if change == "partial" and str(path) == "unit.c":
                return data[:1]
            if change == "growth" and str(path) == "unit.c":
                (root / "unit.c").write_bytes(b"growing unit")
            if change == "earlier-file" and str(path) == "include/owned.h":
                (root / "unit.c").write_bytes(b"new!")
            return data

        return _ReadHook(stream, hook)

    monkeypatch.setattr(material, "open_regular_beneath", open_selected)
    result = capture(root, refs)
    assert reached
    assert isinstance(result, DependencyMaterialUnavailable)
    assert result.reason == ("dependency_capture_changed" if change == "earlier-file"
                             else "dependency_changed_during_read")
    assert all(stream.closed for stream in streams)


def test_currentness_compares_refs_and_bytes_but_not_new_header_discovery(owned):
    root, refs = owned
    result = capture(root, refs)
    assert isinstance(result, tuple)
    kwargs = dict(roots={"target": root}, max_files=8, max_file_bytes=16, max_total_bytes=32)
    assert not dependency_materials_current(result, references=refs[:1], **kwargs)
    (root / "new-header.h").write_bytes(b"not in old declarations")
    assert dependency_materials_current(result, references=refs, **kwargs)
    (root / "unit.c").write_bytes(b"edit")
    assert not dependency_materials_current(result, references=refs, **kwargs)
