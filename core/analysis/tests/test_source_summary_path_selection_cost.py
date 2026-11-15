"""Parser-free source-summary input selection and retained-candidate bounds."""

from pathlib import Path

import pytest

from core.analysis import java_source_summaries as stage


class LegacyInt(int):
    def __add__(self, other):
        raise AssertionError("legacy caps must not acquire arithmetic")


@pytest.mark.parametrize("cap,count,hit", [
    (-2, 0, True), (0, 0, True), (1, 1, True), (2, 2, True),
    (3, 3, True), (4, 4, False), (8, 4, False),
    (False, 0, True), (True, 1, True), (1.5, 2, True),
    (LegacyInt(2), 2, True),
])
def test_selection_retains_sorted_eligible_prefix(tmp_path, monkeypatch, cap, count, hit):
    root = tmp_path / "out" / "checkout"
    expected = ["a.java", "src/b.java", "src/c.java", "z.java"]
    for name in ["z.java", "src/c.java", "src/b.java", "a.java",
                 "test/skip.java", ".hidden/skip.java", "out/skip.java", ".Skip.java"]:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("class Owned {}\n")
    reads, selections = [], []
    read = stage.read_contained_bytes
    select = stage.nsmallest

    def observed_read(base, path, limit):
        reads.append(path.relative_to(root).as_posix())
        return read(base, path, limit)

    def observed_select(limit, paths):
        assert iter(paths) is paths  # Selection consumes an iterator, not a retained full list.
        chosen = select(limit, paths)
        selections.append((limit, len(chosen)))
        return chosen

    def forbidden_parse(source):
        pytest.fail("owned non-request inputs must not enter the Java parser")

    monkeypatch.setattr(stage, "read_contained_bytes", observed_read)
    monkeypatch.setattr(stage, "nsmallest", observed_select)
    monkeypatch.setattr(stage, "derive_source_summaries", forbidden_parse)
    summaries, refusals, scanned = stage.scan_tree(root, max_files=cap)
    assert summaries == [] and scanned == count
    assert reads == expected[:count]
    assert refusals == ({"file_cap_hit": 1} if hit else {})
    if type(cap) is int:
        limit = max(1, cap + 1)
        assert selections == [(limit, min(limit, 4))]
    else:
        assert selections == []  # Keep legacy comparison semantics for other cap values.


def test_selection_keeps_contained_read_and_source_cap_refusals(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "A.java").write_text("class Owned {}" + " " * 100)
    outside = tmp_path / "outside.java"
    outside.write_text("class Outside {}")
    (root / "B.java").symlink_to(outside)
    monkeypatch.setattr(stage, "DEFAULT_MAX_SOURCE_CHARS", 32)

    def forbidden_parse(source):
        pytest.fail("oversized and outside-root inputs must not enter the Java parser")

    monkeypatch.setattr(stage, "derive_source_summaries", forbidden_parse)
    summaries, refusals, scanned = stage.scan_tree(root, max_files=2)
    assert summaries == [] and scanned == 2
    assert refusals == {"source_cap_hit": 1, "unreadable": 1}
    assert outside.read_text() == "class Outside {}"


@pytest.mark.parametrize("cap", [None, "1"])
def test_empty_tree_preserves_legacy_noninteger_caps(tmp_path, cap):
    assert stage.scan_tree(Path(tmp_path), max_files=cap) == ([], {}, 0)
