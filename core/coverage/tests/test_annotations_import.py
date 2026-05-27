"""Tests for importing durable annotations as llm-category coverage."""

from __future__ import annotations

from core.annotations.models import Annotation
from core.annotations.storage import write_annotation
from core.coverage.importer import import_annotations
from core.coverage.store import CoverageStore

_CHECKLIST = {
    "files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]},
        {"path": "b.c", "total_lines": 50, "functions": [
            {"name": "g1", "line_start": 0, "line_end": 10},
        ]},
    ],
}


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def _ann(base, file, function, status, source="llm"):
    write_annotation(
        base,
        Annotation(file=file, function=function, body="note",
                   metadata={"status": status, "source": source}),
    )


def test_clean_annotation_becomes_llm_coverage(tmp_path):
    base = tmp_path / "annotations"
    _ann(base, "a.c", "f1", "clean")
    s = _store(tmp_path)
    n = import_annotations(s, base, _CHECKLIST)
    assert n == 1
    # f1 now llm-examined over its inventory range, verdict clean.
    assert "annotations" in s.tool_coverage_of_range("a.c", 0, 20)
    assert s.function_verdict("a.c", 0, 20) == "clean"


def test_finding_annotation_links_finding_open(tmp_path):
    base = tmp_path / "annotations"
    _ann(base, "a.c", "f2", "finding")
    _ann(base, "b.c", "g1", "suspicious")
    s = _store(tmp_path)
    import_annotations(s, base, _CHECKLIST)
    assert s.function_verdict("a.c", 30, 60) == "open"
    assert s.function_verdict("b.c", 0, 10) == "open"


def test_annotation_for_unknown_function_is_skipped(tmp_path):
    base = tmp_path / "annotations"
    _ann(base, "a.c", "nonexistent", "clean")
    s = _store(tmp_path)
    # No inventory range and no lines metadata -> skipped.
    assert import_annotations(s, base, _CHECKLIST) == 0


def test_lines_metadata_fallback(tmp_path):
    base = tmp_path / "annotations"
    write_annotation(
        base,
        Annotation(file="c.c", function="h", body="",
                   metadata={"status": "clean", "source": "llm", "lines": "5-9"}),
    )
    s = _store(tmp_path)
    # c.c not in the checklist -> falls back to the lines metadata.
    assert import_annotations(s, base, _CHECKLIST) == 1
    assert "annotations" in s.tool_coverage_of_range("c.c", 5, 9)


def test_missing_base_dir_is_noop(tmp_path):
    s = _store(tmp_path)
    assert import_annotations(s, tmp_path / "nope", _CHECKLIST) == 0
