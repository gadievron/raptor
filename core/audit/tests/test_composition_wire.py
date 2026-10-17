"""Tests for composition → orchestrator wiring (Phase C → D)."""

from __future__ import annotations

from core.audit.composition import ComposedHypothesis, UnguardedPath, WeaknessRecord
from core.audit.orchestrator import (
    _build_reverse_edges,
    _composed_hypotheses_to_gaps,
    _MAX_COMPOSITION_REVIEWS,
)


def _w(
    func: str = "parse_input",
    file: str = "src/parse.c",
    guard_type: str = "bounds",
    confidence: str = "medium",
) -> WeaknessRecord:
    return WeaknessRecord(
        function=func,
        file=file,
        guard_type=guard_type,
        assumed_property="length <= 256",
        mechanism="CWE-120 buffer overflow",
        guarded_by=("validate_input",),
        confidence=confidence,
    )


def _ch(
    w: WeaknessRecord | None = None,
    path: list[tuple[str, str]] | None = None,
    verifiable: bool = True,
) -> ComposedHypothesis:
    if w is None:
        w = _w()
    if path is None:
        path = [("src/main.c", "main"), ("src/parse.c", "parse_input")]
    return ComposedHypothesis(
        weakness=w,
        unguarded_path=UnguardedPath(chain=path),
        hypothesis_text="test hypothesis",
        fids=[f"{f}:{fn}" for f, fn in path],
        verifiable=verifiable,
    )


def _checklist(*functions: tuple[str, str, int]) -> dict:
    """Build a minimal checklist from (file, name, line_start) tuples."""
    files_dict: dict[str, list] = {}
    for file, name, line in functions:
        files_dict.setdefault(file, []).append({
            "name": name,
            "line_start": line,
            "line_end": line + 20,
            "kind": "function",
        })
    return {
        "files": [
            {"path": f, "items": items}
            for f, items in files_dict.items()
        ],
    }


class TestBuildReverseEdges:
    def test_basic(self):
        edges = [
            {
                "caller_file": "a.c", "caller": "main",
                "callee_file": "b.c", "callee": "parse",
            },
        ]
        rev = _build_reverse_edges(edges)
        assert ("b.c", "parse") in rev
        assert ("a.c", "main") in rev[("b.c", "parse")]

    def test_multiple_callers(self):
        edges = [
            {
                "caller_file": "a.c", "caller": "f1",
                "callee_file": "b.c", "callee": "g",
            },
            {
                "caller_file": "a.c", "caller": "f2",
                "callee_file": "b.c", "callee": "g",
            },
        ]
        rev = _build_reverse_edges(edges)
        assert len(rev[("b.c", "g")]) == 2

    def test_skips_incomplete_edges(self):
        edges = [
            {"caller_file": "a.c", "caller": "", "callee_file": "b.c", "callee": "g"},
            {"caller_file": "a.c", "callee_file": "b.c", "callee": "g"},
        ]
        rev = _build_reverse_edges(edges)
        assert len(rev) == 0

    def test_empty(self):
        assert _build_reverse_edges([]) == {}


class TestComposedHypothesesToGaps:
    def test_basic_resolution(self):
        ch = _ch()
        checklist = _checklist(("src/parse.c", "parse_input", 10))
        gaps = _composed_hypotheses_to_gaps([ch], checklist)
        assert len(gaps) == 1
        assert gaps[0]["from_composition"] is True
        assert gaps[0]["injected_hypotheses"][0]["source"] == "composition"

    def test_skips_already_reviewed(self):
        ch = _ch()
        checklist = _checklist(("src/parse.c", "parse_input", 10))
        reviewed = {"src/parse.c:parse_input"}
        gaps = _composed_hypotheses_to_gaps(
            [ch], checklist, reviewed_set=reviewed,
        )
        assert len(gaps) == 0

    def test_deduplicates_by_function(self):
        w1 = _w(guard_type="bounds")
        w2 = _w(guard_type="null_safety")
        ch1 = _ch(w=w1)
        ch2 = _ch(w=w2)
        checklist = _checklist(("src/parse.c", "parse_input", 10))
        gaps = _composed_hypotheses_to_gaps([ch1, ch2], checklist)
        assert len(gaps) == 1

    def test_cap_limits_output(self):
        composed = []
        funcs = []
        for i in range(30):
            w = _w(func=f"f{i}", file="src/x.c")
            ch = _ch(
                w=w,
                path=[("src/main.c", "main"), ("src/x.c", f"f{i}")],
            )
            composed.append(ch)
            funcs.append(("src/x.c", f"f{i}", i * 30 + 10))
        checklist = _checklist(*funcs)
        gaps = _composed_hypotheses_to_gaps(composed, checklist)
        assert len(gaps) == _MAX_COMPOSITION_REVIEWS

    def test_unresolvable_function_skipped(self):
        ch = _ch()
        checklist = _checklist(("src/other.c", "other_func", 10))
        gaps = _composed_hypotheses_to_gaps([ch], checklist)
        assert len(gaps) == 0

    def test_confidence_propagated(self):
        ch = _ch(w=_w(confidence="high"))
        checklist = _checklist(("src/parse.c", "parse_input", 10))
        gaps = _composed_hypotheses_to_gaps([ch], checklist)
        assert gaps[0]["injected_hypotheses"][0]["confidence"] == "high"

    def test_priority_floor(self):
        ch = _ch()
        checklist = _checklist(("src/parse.c", "parse_input", 10))
        gaps = _composed_hypotheses_to_gaps([ch], checklist)
        assert gaps[0]["priority_score"] >= 0.85
