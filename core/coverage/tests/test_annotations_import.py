"""Tests for importing durable human-authored annotations as coverage."""

from __future__ import annotations

from core.annotations.models import Annotation
from core.annotations.storage import write_annotation
from core.coverage.importer import import_annotations
from core.coverage.store import CoverageStore

_CHECKLIST = {
    "files": [
        {"path": "a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]},
        {"path": "b.c", "lines": 50, "functions": [
            {"name": "g1", "line_start": 0, "line_end": 10},
        ]},
    ],
}


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def _ann(base, file, function, status, source="human"):
    write_annotation(
        base,
        Annotation(file=file, function=function, body="note",
                   metadata={"status": status, "source": source}),
    )


def test_human_clean_annotation_becomes_coverage(tmp_path):
    base = tmp_path / "annotations"
    _ann(base, "a.c", "f1", "clean")
    s = _store(tmp_path)
    n = import_annotations(s, base, _CHECKLIST)
    assert n == 1
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
    assert import_annotations(s, base, _CHECKLIST) == 0


def test_lines_metadata_fallback(tmp_path):
    base = tmp_path / "annotations"
    write_annotation(
        base,
        Annotation(file="c.c", function="h", body="",
                   metadata={"status": "clean", "source": "human", "lines": "5-9"}),
    )
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 1
    assert "annotations" in s.tool_coverage_of_range("c.c", 5, 9)


def test_missing_base_dir_is_noop(tmp_path):
    s = _store(tmp_path)
    assert import_annotations(s, tmp_path / "nope", _CHECKLIST) == 0


# ── source=human guard (Phase 0c) ────────────────────────────────────

def test_llm_annotation_is_skipped(tmp_path):
    """LLM-authored annotations must not count as coverage evidence."""
    base = tmp_path / "annotations"
    _ann(base, "a.c", "f1", "clean", source="llm")
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 0


def test_no_source_annotation_is_skipped(tmp_path):
    """Annotations without a source field are treated as non-human."""
    base = tmp_path / "annotations"
    write_annotation(
        base,
        Annotation(file="a.c", function="f1", body="note",
                   metadata={"status": "clean"}),
    )
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 0


def test_mixed_source_only_human_imported(tmp_path):
    """When human and LLM annotations coexist, only human ones count."""
    base = tmp_path / "annotations"
    _ann(base, "a.c", "f1", "clean", source="human")
    _ann(base, "a.c", "f2", "finding", source="llm")
    _ann(base, "b.c", "g1", "clean", source="human")
    s = _store(tmp_path)
    n = import_annotations(s, base, _CHECKLIST)
    assert n == 2
    assert s.function_verdict("a.c", 0, 20) == "clean"
    assert s.function_verdict("b.c", 0, 10) == "clean"
    assert s.function_verdict("a.c", 30, 60) == "unexamined"


# ── provenance-grade tiering ─────────────────────────────────────────

def _ann_meta(base, file, function, status, meta):
    write_annotation(
        base,
        Annotation(file=file, function=function, body="note",
                   metadata={"status": status, **meta}),
    )


def test_stamped_interactive_human_is_operator_evidence(tmp_path):
    base = tmp_path / "annotations"
    _ann_meta(base, "a.c", "f2", "finding", {
        "source": "human", "provenance": "interactive-tty",
        "tty": "stdin",
    })
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 1
    assert "annotations" in s.tool_coverage_of_range("a.c", 30, 60)
    # Operator finding links retained.
    assert s.function_verdict("a.c", 30, 60) == "open"


def test_agent_annotation_marks_machine_tier(tmp_path):
    base = tmp_path / "annotations"
    _ann_meta(base, "a.c", "f1", "clean", {
        "source": "agent", "provenance": "non-tty", "tty": "none",
    })
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 1
    tools = s.tool_coverage_of_range("a.c", 0, 20)
    assert "annotations:machine" in tools
    assert "annotations" not in tools
    # Still examination coverage — the function leaves the gap list.
    assert s.function_verdict("a.c", 0, 20) == "clean"


def test_agent_finding_does_not_link_operator_finding(tmp_path):
    base = tmp_path / "annotations"
    _ann_meta(base, "a.c", "f2", "finding", {
        "source": "agent", "provenance": "non-tty", "tty": "none",
    })
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 1
    # Machine tier: coverage marked, but no linked operator finding.
    assert s.function_verdict("a.c", 30, 60) == "clean"


def test_forged_human_non_tty_demotes_to_machine_tier(tmp_path):
    base = tmp_path / "annotations"
    _ann_meta(base, "a.c", "f2", "finding", {
        "source": "human", "provenance": "non-tty", "tty": "none",
    })
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 1
    tools = s.tool_coverage_of_range("a.c", 30, 60)
    assert "annotations:machine" in tools
    assert "annotations" not in tools
    assert s.function_verdict("a.c", 30, 60) == "clean"


def test_legacy_human_no_stamp_keeps_operator_grade(tmp_path):
    base = tmp_path / "annotations"
    _ann_meta(base, "a.c", "f2", "suspicious", {"source": "human"})
    s = _store(tmp_path)
    assert import_annotations(s, base, _CHECKLIST) == 1
    assert "annotations" in s.tool_coverage_of_range("a.c", 30, 60)
    assert s.function_verdict("a.c", 30, 60) == "open"
