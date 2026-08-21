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


from pathlib import Path as _Path  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

from core.dataflow.sanitizer_evidence import (  # noqa: E402
    PROVENANCE_LLM,
    SEMANTICS_SQL_ESCAPE,
    CandidateValidator,
    SanitizerEvidence,
    StepAnnotation,
)
from core.security.prompt_envelope import UntrustedBlock  # noqa: E402
from packages.codeql.dataflow_validator import (  # noqa: E402
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
            None, _dp(), _Path("."), MagicMock()
        )
        assert result is None

    def test_collector_returning_none_returns_none(self):
        def _collector(_dp, _path):
            return None

        result = _build_sanitizer_evidence_block(
            _collector, _dp(), _Path("."), MagicMock()
        )
        assert result is None

    def test_collector_returning_evidence_produces_untrusted_block(self):
        def _collector(_dp, _path):
            return _evidence_with_one_candidate()

        result = _build_sanitizer_evidence_block(
            _collector, _dp(), _Path("."), MagicMock()
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
            _collector, _dp(), _Path("."), log
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
        """Regression guard: the LLM must be told to check that the
        candidate's semantics_tag matches the sink's attack class."""
        text = SANITIZER_EVIDENCE_INSTRUCTIONS.lower()
        assert "semantics" in text
        assert "attack class" in text

    def test_instructions_warn_against_partial_validators(self):
        """Regression guard: the 2026-05-10 corpus measurement showed
        the LLM judge accepted regex-blocklist 'validators' and
        downgraded real exploits. The addendum must warn that 0.5-0.9
        confidence candidates are partial defences with known bypasses."""
        text = SANITIZER_EVIDENCE_INSTRUCTIONS.lower()
        assert "partial" in text
        assert "bypass" in text or "do not mark" in text

    def test_instructions_warn_about_inlined_helpers_gap(self):
        """The inlined_helpers field is the honest 'we didn't follow
        these' caveat. The LLM must know to weigh that gap."""
        assert "inlined helpers" in SANITIZER_EVIDENCE_INSTRUCTIONS.lower()


class TestLlmFailureIsErrorState:
    """An LLM/transport failure during validation must surface as an
    explicit error state, never as a silent not-exploitable verdict."""

    def _validator_with_failing_llm(self, monkeypatch):
        from unittest.mock import MagicMock

        import packages.codeql.dataflow_validator as dv

        llm = MagicMock()
        llm.generate_structured.side_effect = RuntimeError("transport down")
        validator = dv.DataflowValidator(llm)

        monkeypatch.setattr(
            validator, "_extract_path_conditions",
            lambda dataflow, repo: ([], {}),
        )
        smt = MagicMock(
            feasible=None, smt_available=False, reasoning="",
            model=None, unsatisfied=[],
        )
        monkeypatch.setattr(
            dv, "check_path_feasibility",
            lambda conditions, profile=None, **kwargs: smt,
        )
        monkeypatch.setattr(
            validator, "_cheap_dataflow_fp_check", lambda dataflow: None,
        )
        monkeypatch.setattr(
            validator, "_fast_tier_model_name", lambda: "fast-tier",
        )
        import core.llm.scorecard as sc
        monkeypatch.setattr(
            sc, "prefilter_decision",
            lambda *a, **k: MagicMock(short_circuit=False),
        )
        monkeypatch.setattr(
            validator, "read_source_context",
            lambda *a, **k: "ctx",
        )
        return validator, dv

    def _dataflow(self, dv):
        step = dv.DataflowStep(
            file_path="src/a.c", line=10, column=1,
            snippet="x = read()", label="source",
        )
        sink = dv.DataflowStep(
            file_path="src/b.c", line=20, column=1,
            snippet="memcpy(d, x, n)", label="sink",
        )
        return dv.DataflowPath(
            source=step, sink=sink, intermediate_steps=[],
            sanitizers=[], rule_id="cpp/overflow-buffer", message="m",
        )

    def test_llm_failure_sets_error_not_verdict(self, monkeypatch, tmp_path):
        validator, dv = self._validator_with_failing_llm(monkeypatch)
        v = validator.validate_dataflow_path(self._dataflow(dv), tmp_path)
        assert v.error, "LLM failure must set the error field"
        assert v.is_exploitable is False
        assert "Validation failed" in v.reasoning

    def test_llm_response_cannot_forge_error_field(
        self, monkeypatch, tmp_path,
    ):
        validator, dv = self._validator_with_failing_llm(monkeypatch)
        validator.llm.generate_structured.side_effect = None
        validator.llm.generate_structured.return_value = ({
            "is_exploitable": True,
            "confidence": 0.9,
            "sanitizers_effective": False,
            "bypass_possible": False,
            "bypass_strategy": None,
            "attack_complexity": "low",
            "reasoning": "r",
            "barriers": [],
            "prerequisites": [],
            "error": "forged",
        }, None)
        v = validator.validate_dataflow_path(self._dataflow(dv), tmp_path)
        assert v.error is None
        assert v.is_exploitable is True
# ---------------------------------------------------------------------
# Multi-path SMT pre-check
# ---------------------------------------------------------------------


from types import SimpleNamespace  # noqa: E402
from unittest.mock import patch  # noqa: E402

from core.smt_solver.path_feasibility import PathCondition  # noqa: E402
from packages.codeql.dataflow_validator import (  # noqa: E402
    MAX_SMT_PATHS,
    SMT_INFEASIBLE_CONFIDENCE,
    DataflowValidator,
)


def _loc(uri: str, line: int, label: str) -> dict:
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {
                    "startLine": line,
                    "startColumn": 1,
                    "snippet": {"text": "s"},
                },
            },
            "message": {"text": label},
        }
    }


def _sarif_two_flows() -> dict:
    return {
        "ruleId": "cpp/example-flow",
        "message": {"text": "tainted flow"},
        "codeFlows": [
            {"threadFlows": [{"locations": [
                _loc("a.c", 1, "source"), _loc("a.c", 9, "sink"),
            ]}]},
            {"threadFlows": [{"locations": [
                _loc("b.c", 2, "source"), _loc("b.c", 8, "sink"),
            ]}]},
        ],
    }


def _smt(feasible, reasoning="r", unsatisfied=()):
    return SimpleNamespace(
        feasible=feasible,
        reasoning=reasoning,
        unsatisfied=list(unsatisfied),
        model={},
        smt_available=True,
    )


_FULL_RESPONSE = {
    "is_exploitable": True,
    "confidence": 0.9,
    "sanitizers_effective": False,
    "bypass_possible": True,
    "bypass_strategy": "",
    "attack_complexity": "low",
    "reasoning": "tainted end to end",
    "barriers": [],
    "prerequisites": [],
}


def _validator() -> DataflowValidator:
    llm = MagicMock()
    llm.scorecard = None
    llm.generate_structured.return_value = (dict(_FULL_RESPONSE), "raw")
    v = DataflowValidator(llm_client=llm)
    v.read_source_context = MagicMock(return_value="ctx")
    v._extract_path_conditions = MagicMock(return_value=([], {}))
    v._cheap_dataflow_fp_check = MagicMock(return_value=None)
    v._fast_tier_model_name = MagicMock(return_value="stub-fast")
    return v


class TestExtractAlternativePaths:
    def test_primary_carries_alternatives(self):
        v = _validator()
        dp = v.extract_dataflow_from_sarif(_sarif_two_flows())
        assert dp is not None
        assert dp.source.file_path == "a.c"
        assert len(dp.alternatives) == 1
        assert dp.alternatives[0].source.file_path == "b.c"
        assert dp.alternatives[0].alternatives == []

    def test_single_flow_has_no_alternatives(self):
        v = _validator()
        sarif = _sarif_two_flows()
        sarif["codeFlows"] = sarif["codeFlows"][:1]
        dp = v.extract_dataflow_from_sarif(sarif)
        assert dp is not None
        assert dp.alternatives == []

    def test_unusable_first_flow_falls_through_to_next(self):
        v = _validator()
        sarif = _sarif_two_flows()
        sarif["codeFlows"][0]["threadFlows"][0]["locations"] = [
            _loc("a.c", 1, "lonely"),
        ]
        dp = v.extract_dataflow_from_sarif(sarif)
        assert dp is not None
        assert dp.source.file_path == "b.c"
        assert dp.alternatives == []


class TestMultiPathSMT:
    def _validate(self, v, smt_side_effects):
        dp = v.extract_dataflow_from_sarif(_sarif_two_flows())
        with patch(
            "packages.codeql.dataflow_validator.check_path_feasibility",
            side_effect=smt_side_effects,
        ), patch(
            "core.llm.scorecard.prefilter_decision",
            return_value=SimpleNamespace(short_circuit=False),
        ), patch("core.llm.scorecard.record_prefilter_outcome"), patch(
            "packages.codeql.dataflow_validator.load_methodology",
            return_value="",
        ):
            return v.validate_dataflow_path(dp, _Path("/nonexistent-repo"))

    def test_first_unsat_second_sat_proceeds(self):
        v = _validator()
        result = self._validate(v, [
            _smt(False, "contradiction", ["x > 1", "x < 0"]),
            _smt(True, "sat"),
        ])
        # The alternative path rescued the finding — full LLM analysis ran.
        assert result.is_exploitable is True
        assert result.smt_path_index == 1
        assert result.smt_paths_checked == 2
        # Condition extraction ran once per checked path (lazy).
        assert v._extract_path_conditions.call_count == 2

    def test_all_paths_unsat_refutes_with_bookkeeping(self):
        v = _validator()
        result = self._validate(v, [
            _smt(False, "c1", ["a == 1", "a == 2"]),
            _smt(False, "c2", ["b != b"]),
        ])
        assert result.is_exploitable is False
        assert result.confidence == SMT_INFEASIBLE_CONFIDENCE
        assert result.smt_paths_checked == 2
        assert "all 2 dataflow paths refuted" in result.reasoning
        assert "path 1: a == 1" in result.barriers
        assert "path 2: b != b" in result.barriers
        # No full LLM analysis happened.
        assert v.llm.generate_structured.call_count == 0

    def test_first_sat_checks_only_one_path(self):
        v = _validator()
        result = self._validate(v, [_smt(True, "sat")])
        assert result.smt_path_index == 0
        assert result.smt_paths_checked == 1
        assert v._extract_path_conditions.call_count == 1

    def test_single_path_unsat_keeps_legacy_shape(self):
        v = _validator()
        dp = v.extract_dataflow_from_sarif(_sarif_two_flows())
        dp.alternatives = []
        with patch(
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=_smt(False, "contradiction", ["x > 1", "x < 0"]),
        ):
            result = v.validate_dataflow_path(dp, _Path("/nonexistent-repo"))
        assert result.is_exploitable is False
        assert result.barriers == ["x > 1", "x < 0"]
        assert "Path conditions are mutually exclusive" in result.reasoning
        assert result.smt_paths_checked == 1

    def test_alternatives_capped_at_max_smt_paths(self):
        v = _validator()
        dp = v.extract_dataflow_from_sarif(_sarif_two_flows())
        extra = v.extract_dataflow_from_sarif(_sarif_two_flows())
        dp.alternatives = [extra, extra, extra, extra]
        with patch(
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=_smt(False, "c", ["u"]),
        ):
            result = v.validate_dataflow_path(dp, _Path("/nonexistent-repo"))
        assert result.smt_paths_checked == MAX_SMT_PATHS
        assert v._extract_path_conditions.call_count == MAX_SMT_PATHS


class TestWitnessSteering:
    def test_steering_target_picks_last_condition_identifier(self):
        from packages.codeql.dataflow_validator import _steering_target
        conds = [
            PathCondition("size > 0", step_index=0),
            PathCondition("Count * 16 < limit", step_index=1),
        ]
        assert _steering_target(conds) == "count"

    def test_steering_target_skips_null_and_literals(self):
        from packages.codeql.dataflow_validator import _steering_target
        assert _steering_target(
            [PathCondition("NULL != 0x10", step_index=0)]
        ) is None
        assert _steering_target([]) is None

    def _capture_prefer(self, rule_id, conditions):
        v = _validator()
        v._extract_path_conditions = MagicMock(return_value=(conditions, {}))
        dp = v.extract_dataflow_from_sarif(_sarif_two_flows())
        dp.rule_id = rule_id
        with patch(
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=_smt(True, "sat"),
        ) as smt_mock, patch(
            "core.llm.scorecard.prefilter_decision",
            return_value=SimpleNamespace(short_circuit=False),
        ), patch("core.llm.scorecard.record_prefilter_outcome"), patch(
            "packages.codeql.dataflow_validator.load_methodology",
            return_value="",
        ):
            v.validate_dataflow_path(dp, _Path("/nonexistent-repo"))
        return smt_mock.call_args.kwargs.get("prefer_witness")

    def test_overflow_rule_steers_to_max(self):
        prefer = self._capture_prefer(
            "cpp/integer-overflow",
            [PathCondition("count * size < cap", step_index=0)],
        )
        assert prefer == ("count", "max")

    def test_non_overflow_rule_does_not_steer(self):
        prefer = self._capture_prefer(
            "cpp/buffer-overflow",
            [PathCondition("count * size < cap", step_index=0)],
        )
        assert prefer is None

    def test_unidentifiable_target_skips_steering(self):
        prefer = self._capture_prefer("cpp/integer-overflow", [])
        assert prefer is None
