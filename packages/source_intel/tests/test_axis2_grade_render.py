"""Tests for axis-2 abort-grade caveats in render output.

Phase C PR1: each grade carries the correct strength prose:
  * dominates    — strong, no caveat needed
  * same_path    — mid-strength, explicit "other branches bypass" caveat
  * same_function — weak, explicit "may be unrelated path" caveat
"""

from __future__ import annotations

from packages.source_intel.analyze import (
    AbortEvidence,
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    SourceIntelResult,
)
from packages.source_intel.render import derive_evidence_strings


def _result_with_abort(grade):
    return SourceIntelResult(
        target="/tmp/x",
        aborts=(
            AbortEvidence(
                macro="panic",
                location=("/tmp/x/f.c", 50),
                enclosing_function="do_thing",
                grade=grade,
            ),
        ),
    )


def _render(grade):
    result = _result_with_abort(grade)
    return "\n".join(
        derive_evidence_strings(
            result,
            finding_function="do_thing",
            style="stage_d",
        )
    )


class TestDominatesGrade:
    def test_no_strength_caveat_on_dominates(self):
        """dominates is the strongest grade — no 'mid-strength' or
        'weak' caveats should appear."""
        text = _render(GRADE_DOMINATES)
        assert "DOMINATES" in text
        assert "mid-strength" not in text
        assert "weak:" not in text

    def test_dominates_describes_depth1(self):
        """The prose should explain WHAT dominates means at code level."""
        text = _render(GRADE_DOMINATES)
        assert "depth-1" in text or "function body" in text


class TestSamePathGrade:
    def test_same_path_carries_caveat(self):
        text = _render(GRADE_SAME_PATH)
        assert "same_path" in text
        assert "mid-strength" in text

    def test_same_path_explains_bypass(self):
        """Caveat should call out that other branches bypass the abort."""
        text = _render(GRADE_SAME_PATH)
        assert "bypass" in text or "branches" in text

    def test_same_path_mentions_stronger_grade(self):
        """Caveat should point the LLM at what stronger evidence looks like."""
        text = _render(GRADE_SAME_PATH)
        assert "dominates" in text

    def test_same_path_describes_nested_branch(self):
        """The grade phrase itself should describe what same_path means."""
        text = _render(GRADE_SAME_PATH)
        assert "nested" in text or "depth>1" in text

    def test_same_path_does_not_carry_same_function_caveat(self):
        """Specifically the same_function caveat ('unrelated path')
        must NOT appear on a same_path observation."""
        text = _render(GRADE_SAME_PATH)
        assert "unrelated path" not in text


class TestSameFunctionGrade:
    def test_same_function_carries_caveat(self):
        text = _render(GRADE_SAME_FUNCTION)
        assert "same_function" in text
        assert "weak" in text

    def test_same_function_does_not_carry_same_path_caveat(self):
        """Specifically the same_path caveat should NOT appear on a
        same_function observation."""
        text = _render(GRADE_SAME_FUNCTION)
        assert "mid-strength" not in text


class TestGradeProseAccuracy:
    """Validates the corrected prose: same_path no longer claims
    'appears on the SmPL path between entry and sink' which overstated
    what the grade proves."""

    def test_same_path_does_not_overstate_provenance(self):
        text = _render(GRADE_SAME_PATH)
        # Old wording asserted "on the path between entry and sink"
        # which the grade does NOT actually prove (it only sees depth).
        assert "between entry and sink" not in text
