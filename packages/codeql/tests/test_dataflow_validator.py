"""Tests for packages.codeql.dataflow_validator.

Scoped to the pure helpers — profile inference, hint normalisation —
not to the LLM-driven ``validate_dataflow_path`` flow (which needs a
mock LLM client and is exercised end-to-end elsewhere).
"""

import sys
from pathlib import Path

import pytest

# packages/codeql/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.dataflow_validator import _infer_bv_profile


class TestInferBVProfileHeuristic:
    """When the LLM hint is absent the rule_id heuristic picks a profile.

    CodeQL rule names that mention overflow / wraparound / CWE-190 family
    get 32-bit unsigned; everything else defaults to 64-bit unsigned."""

    def test_non_overflow_rule_defaults_to_64_bit(self):
        p = _infer_bv_profile("java/sql-injection", {})
        assert p.width == 64
        assert p.signed is False

    def test_no_rule_id_defaults_to_64_bit(self):
        p = _infer_bv_profile(None, {})
        assert p.width == 64

    def test_empty_rule_id_defaults_to_64_bit(self):
        p = _infer_bv_profile("", {})
        assert p.width == 64

    @pytest.mark.parametrize("rule_id", [
        "cpp/cwe-190-integer-overflow",
        "CPP/CWE-190/ArithmeticOverflow",
        # batch 394 — `cpp/overflow-check-missing` removed: bare
        # "overflow" alone no longer signals integer-overflow
        # (false-positive driver — matched buffer-overflow,
        # stack-overflow, heap-overflow, all NON-integer cases).
        "cpp/integer-overflow",
        "java/IntegerOverflow",
        "cpp/integeroverflow-in-loop",
        "cpp/unsigned-wraparound",
        "cpp/wrap-around-bug",
        "cpp/CWE-191-underflow",
        "cpp/CWE-680-int-to-buf",
    ])
    def test_overflow_markers_trigger_32_bit(self, rule_id):
        p = _infer_bv_profile(rule_id, {})
        assert p.width == 32
        assert p.signed is False

    def test_matching_is_case_insensitive(self):
        p = _infer_bv_profile("CPP/Cwe-190-overflow", {})
        assert p.width == 32


class TestInferBVProfileHint:
    """LLM-emitted hints take precedence over the heuristic when valid."""

    def test_hint_width_only_combines_with_heuristic_signed(self):
        # LLM says width=32; rule isn't overflow, so heuristic signed=False.
        p = _infer_bv_profile("java/sql-injection", {"width": 32})
        assert p.width == 32
        assert p.signed is False

    def test_hint_signed_only_combines_with_heuristic_width(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"signed": True})
        assert p.width == 32   # from heuristic (overflow rule)
        assert p.signed is True  # from hint

    def test_hint_beats_heuristic_when_both_supplied(self):
        # LLM says 64-bit signed even though rule would default to 32-bit unsigned.
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"width": 64, "signed": True})
        assert p.width == 64
        assert p.signed is True


class TestInferBVProfileInvalidHints:
    """Garbage values in the hint dict must be ignored, not crash."""

    def test_string_width_ignored(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"width": "not-an-int"})
        assert p.width == 32  # heuristic fallback, not ValueError

    def test_negative_width_ignored(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"width": -1})
        assert p.width == 32

    def test_zero_width_ignored(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"width": 0})
        assert p.width == 32

    def test_string_signed_ignored(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"signed": "yes"})
        assert p.signed is False

    def test_none_values_ignored(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {"width": None, "signed": None})
        assert p.width == 32

    def test_missing_keys_tolerated(self):
        p = _infer_bv_profile("cpp/integer-overflow-bug", {})
        assert p.width == 32


# ---------------------------------------------------------------------
# Sanitizer-evidence integration (PR1c-2)
# ---------------------------------------------------------------------


from pathlib import Path as _Path
from unittest.mock import MagicMock

from core.dataflow.sanitizer_evidence import (
    PROVENANCE_LLM,
    SEMANTICS_SQL_ESCAPE,
    CandidateValidator,
    SanitizerEvidence,
    StepAnnotation,
)
from core.security.prompt_envelope import UntrustedBlock
from packages.codeql.dataflow_validator import (
    DataflowPath,
    DataflowStep,
    SANITIZER_EVIDENCE_INSTRUCTIONS,
    _build_sanitizer_evidence_block,
)


def _dp() -> DataflowPath:
    return DataflowPath(
        source=DataflowStep(file_path="a.py", line=1, column=0, snippet="x", label="source"),
        sink=DataflowStep(file_path="a.py", line=2, column=0, snippet="y", label="sink"),
        intermediate_steps=[],
        sanitizers=[],
        rule_id="py/x",
        message="m",
    )


def _evidence_with_one_candidate() -> SanitizerEvidence:
    return SanitizerEvidence(
        candidate_pool=(
            CandidateValidator(
                name="escape_sql",
                qualified_name="db.escape_sql",
                semantics_tag=SEMANTICS_SQL_ESCAPE,
                semantics_text="doubles single quotes",
                confidence=0.9,
                source_file="db/helpers.py",
                source_line=18,
                extraction_provenance=PROVENANCE_LLM,
            ),
        ),
        step_annotations=(
            StepAnnotation(step_index=0, on_path_validators=("db.escape_sql",)),
        ),
        pool_completeness="scoped_to_2_files",
    )


class TestBuildSanitizerEvidenceBlock:
    """The helper that turns SanitizerEvidence into an UntrustedBlock for
    injection into the validate_path prompt. Free function — testable
    without instantiating DataflowValidator (which needs a full
    LLM-client mock)."""

    def test_no_collector_returns_none(self):
        result = _build_sanitizer_evidence_block(
            None, _dp(), _Path("/tmp"), MagicMock()
        )
        assert result is None

    def test_collector_returning_none_returns_none(self):
        def _collector(_dp, _path):
            return None

        result = _build_sanitizer_evidence_block(
            _collector, _dp(), _Path("/tmp"), MagicMock()
        )
        assert result is None

    def test_collector_returning_evidence_produces_untrusted_block(self):
        def _collector(_dp, _path):
            return _evidence_with_one_candidate()

        result = _build_sanitizer_evidence_block(
            _collector, _dp(), _Path("/tmp"), MagicMock()
        )
        assert isinstance(result, UntrustedBlock)
        assert result.kind == "sanitizer-evidence"
        assert result.origin == "project-source-extracted"
        assert "escape_sql" in result.content
        assert "db.escape_sql" in result.content

    def test_collector_exception_logged_and_returns_none(self):
        def _collector(_dp, _path):
            raise RuntimeError("boom")

        log = MagicMock()
        result = _build_sanitizer_evidence_block(
            _collector, _dp(), _Path("/tmp"), log
        )
        assert result is None
        assert log.warning.called
        # The first positional arg of warning() is the format string;
        # check the boom mention appears in the formatted message.
        call_args = log.warning.call_args
        rendered = call_args.args[0] % tuple(call_args.args[1:])
        assert "boom" in rendered

    def test_collector_passed_dataflow_and_repo_root(self):
        captured = {}

        def _collector(dp, path):
            captured["dp"] = dp
            captured["path"] = path
            return None

        repo = _Path("/some/repo")
        _build_sanitizer_evidence_block(_collector, _dp(), repo, MagicMock())
        assert captured["path"] == repo
        assert captured["dp"].rule_id == "py/x"


class TestSanitizerEvidenceInstructions:
    """The system-prompt addendum applied only when an evidence block is
    built. Tested as a string so an accidental rename / removal in a
    refactor surfaces as a test failure."""

    def test_instructions_constant_is_non_empty(self):
        assert SANITIZER_EVIDENCE_INSTRUCTIONS.strip() != ""

    def test_instructions_mention_semantic_judgement_requirement(self):
        """Regression guard: the LLM must be told that pattern matchers
        don't model semantics — that's the whole point of the evidence
        pipeline."""
        assert "semantics" in SANITIZER_EVIDENCE_INSTRUCTIONS.lower()
        assert "do not model semantics" in SANITIZER_EVIDENCE_INSTRUCTIONS.lower() or \
               "not model semantics" in SANITIZER_EVIDENCE_INSTRUCTIONS.lower()

    def test_instructions_warn_about_inlined_helpers_gap(self):
        """The inlined_helpers field is the honest 'we didn't follow
        these' caveat. The LLM must know to weigh that gap."""
        assert "inlined helpers" in SANITIZER_EVIDENCE_INSTRUCTIONS.lower()
