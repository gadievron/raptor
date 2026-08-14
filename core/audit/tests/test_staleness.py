"""Tests for core.audit.staleness — stale annotation detection."""

from __future__ import annotations

from pathlib import Path

from core.audit.staleness import (
    StaleItem,
    find_stale_annotations,
    stale_as_gaps,
)


def _gap(file, name, priority=0):
    return {
        "file": file,
        "name": name,
        "line_start": 1,
        "line_end": 10,
        "priority": priority,
        "strategies": [],
        "is_stale": False,
        "sloc": 10,
    }


class TestFindStaleAnnotations:
    def test_no_annotations_dir(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        ann_dir = tmp_path / "annotations"
        result = find_stale_annotations(ann_dir, target)
        assert result == []

    def test_annotation_without_hash(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "auth.c").write_text("int f() { return 0; }\n")

        ann_dir = tmp_path / "annotations"
        (ann_dir / "src").mkdir(parents=True)
        (ann_dir / "src" / "auth.c.md").write_text(
            "## f\n"
            "<!-- meta: status=clean source=llm -->\n\n"
            "Looks safe.\n"
        )

        result = find_stale_annotations(ann_dir, target)
        assert result == []

    def test_deleted_source_file(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()

        ann_dir = tmp_path / "annotations"
        (ann_dir / "src").mkdir(parents=True)
        (ann_dir / "src" / "gone.c.md").write_text(
            "## old_func\n"
            "<!-- meta: status=clean hash=abc123 -->\n\n"
            "Was here.\n"
        )

        result = find_stale_annotations(ann_dir, target)
        assert len(result) == 1
        assert result[0].reason == "deleted"
        assert result[0].file == "src/gone.c"

    def test_modified_source(self, tmp_path: Path):
        from core.annotations.storage import compute_function_hash

        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        src_file = target / "src" / "auth.c"
        src_file.write_text("int check_pw() { return 1; }\n")

        old_hash = compute_function_hash(src_file, 1, 1)

        src_file.write_text("int check_pw() { return validate(); }\n")

        ann_dir = tmp_path / "annotations"
        (ann_dir / "src").mkdir(parents=True)
        (ann_dir / "src" / "auth.c.md").write_text(
            "## check_pw\n"
            f"<!-- meta: status=clean hash={old_hash} line_start=1 line_end=1 -->\n\n"
            "Was safe.\n"
        )

        result = find_stale_annotations(ann_dir, target)
        assert len(result) == 1
        assert result[0].reason == "modified"
        assert result[0].old_hash == old_hash

    def test_unchanged_source(self, tmp_path: Path):
        from core.annotations.storage import compute_function_hash

        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        src_file = target / "src" / "auth.c"
        src_file.write_text("int check_pw() { return 1; }\n")

        current_hash = compute_function_hash(src_file, 1, 1)

        ann_dir = tmp_path / "annotations"
        (ann_dir / "src").mkdir(parents=True)
        (ann_dir / "src" / "auth.c.md").write_text(
            "## check_pw\n"
            f"<!-- meta: status=clean hash={current_hash} line_start=1 line_end=1 -->\n\n"
            "Still safe.\n"
        )

        result = find_stale_annotations(ann_dir, target)
        assert result == []


class TestStaleAsGaps:
    def test_empty_stale(self):
        gaps = [_gap("a.c", "f")]
        result = stale_as_gaps([], gaps)
        assert len(result) == 1

    def test_new_stale_added(self):
        gaps = [_gap("a.c", "f")]
        stale = [StaleItem("b.c", "g", "old", "new", "modified")]
        result = stale_as_gaps(stale, gaps)
        assert len(result) == 2
        stale_gap = next(g for g in result if g["name"] == "g")
        assert stale_gap["is_stale"] is True
        assert stale_gap["priority"] == 0

    def test_existing_gap_marked_stale(self):
        gaps = [_gap("a.c", "f", priority=5)]
        stale = [StaleItem("a.c", "f", "old", "new", "modified")]
        result = stale_as_gaps(stale, gaps)
        assert len(result) == 1
        assert result[0]["is_stale"] is True
        assert result[0]["priority"] == 0

    def test_deleted_skipped(self):
        gaps = [_gap("a.c", "f")]
        stale = [StaleItem("gone.c", "g", "old", "", "deleted")]
        result = stale_as_gaps(stale, gaps)
        assert len(result) == 1

    def test_no_existing_gaps(self):
        stale = [StaleItem("a.c", "f", "old", "new", "modified")]
        result = stale_as_gaps(stale)
        assert len(result) == 1
        assert result[0]["is_stale"] is True
