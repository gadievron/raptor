"""Tests for ``packages.codeql.evidence_validator``."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parents[3]))

from core.dataflow import Finding, Step
from core.dataflow.validator import Validator, ValidatorVerdict
from packages.codeql.dataflow_validator import (
    DataflowPath,
    DataflowStep,
    DataflowValidation,
)
from packages.codeql.evidence_validator import (
    CodeQLEvidenceValidator,
    _finding_to_dataflow_path,
    _step_to_dataflow_step,
)


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------


def _step(file_path: str = "a.py", line: int = 1, label: str = "x") -> Step:
    return Step(file_path=file_path, line=line, column=0, snippet="snip", label=label)


def _finding() -> Finding:
    return Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="py/x",
        message="m",
        source=_step("a.py", line=1, label="source"),
        sink=_step("a.py", line=2, label="sink"),
        intermediate_steps=(_step("a.py", line=3),),
    )


def _validation(is_exploitable: bool = True) -> DataflowValidation:
    return DataflowValidation(
        is_exploitable=is_exploitable,
        confidence=0.9,
        sanitizers_effective=False,
        bypass_possible=True,
        bypass_strategy=None,
        attack_complexity="low",
        reasoning="r",
        barriers=[],
        prerequisites=[],
    )


# ---------------------------------------------------------------------
# Step / DataflowPath conversion
# ---------------------------------------------------------------------


def test_step_to_dataflow_step_preserves_all_fields():
    s = Step(file_path="x.py", line=42, column=8, snippet="snippet", label="role")
    out = _step_to_dataflow_step(s)
    assert out.file_path == "x.py"
    assert out.line == 42
    assert out.column == 8
    assert out.snippet == "snippet"
    assert out.label == "role"


def test_step_to_dataflow_step_handles_none_label():
    """Step.label is Optional[str]; DataflowStep.label is str. The
    conversion coerces None to empty string so DataflowValidator's
    f-string formatters don't see literal 'None'."""
    s = Step(file_path="x.py", line=1, column=0, snippet="s", label=None)
    out = _step_to_dataflow_step(s)
    assert out.label == ""


def test_finding_to_dataflow_path_preserves_topology():
    f = _finding()
    dp = _finding_to_dataflow_path(f)
    assert isinstance(dp, DataflowPath)
    assert dp.rule_id == "py/x"
    assert dp.message == "m"
    assert dp.source.line == 1
    assert dp.sink.line == 2
    assert len(dp.intermediate_steps) == 1
    assert dp.intermediate_steps[0].line == 3


def test_finding_to_dataflow_path_leaves_sanitizers_empty():
    """The legacy sanitizers field is replaced by SanitizerEvidence;
    this conversion deliberately leaves it empty."""
    dp = _finding_to_dataflow_path(_finding())
    assert dp.sanitizers == []


# ---------------------------------------------------------------------
# Constructor + lazy init
# ---------------------------------------------------------------------


def test_zero_arg_constructor_does_not_construct_llm_client(monkeypatch):
    """The constructor must not trigger LLMClient construction —
    importing the validator module + instantiating the class should
    be free of side effects (no egress-proxy bring-up, no config
    reads)."""
    sentinel = MagicMock(side_effect=AssertionError("LLMClient must NOT be constructed at __init__"))
    monkeypatch.setattr(
        "packages.codeql.evidence_validator._construct_default_llm_client",
        sentinel,
    )
    validator = CodeQLEvidenceValidator()
    sentinel.assert_not_called()
    assert validator._validator is None


def test_constructor_accepts_injected_llm_client():
    mock_llm = MagicMock()
    v = CodeQLEvidenceValidator(llm_client=mock_llm)
    assert v._injected_llm_client is mock_llm


def test_constructor_accepts_injected_repo_root(tmp_path: Path):
    v = CodeQLEvidenceValidator(repo_root=tmp_path)
    assert v._repo_root == tmp_path


def test_constructor_accepts_injected_cache():
    cache = {"some_key": ()}
    v = CodeQLEvidenceValidator(cache=cache)
    assert v._cache is cache


def test_default_repo_root_resolves_to_raptor_repo_root():
    """Without --repo-root, fixtures referenced as
    ``packages/llm_analysis/tests/fixtures/iris_e2e/...`` must
    resolve to actual files in the repo."""
    v = CodeQLEvidenceValidator()
    # The marker is a file we know exists in the repo root.
    assert (v._repo_root / "core" / "dataflow" / "finding.py").exists()


# ---------------------------------------------------------------------
# Validator protocol conformance
# ---------------------------------------------------------------------


def test_satisfies_validator_protocol():
    """The corpus runner's ``load_validator`` checks
    ``isinstance(instance, Validator)`` — break this and the
    libexec --validator route stops working."""
    assert isinstance(CodeQLEvidenceValidator(), Validator)


# ---------------------------------------------------------------------
# validate() routing
# ---------------------------------------------------------------------


def test_validate_routes_through_dataflow_validator():
    v = CodeQLEvidenceValidator()
    # Bypass lazy init by setting the cached DataflowValidator directly
    mock_dv = MagicMock()
    mock_dv.validate_dataflow_path.return_value = _validation(is_exploitable=True)
    v._validator = mock_dv

    v.validate(_finding())

    assert mock_dv.validate_dataflow_path.called
    call_args = mock_dv.validate_dataflow_path.call_args
    dp_arg, repo_arg = call_args.args
    assert isinstance(dp_arg, DataflowPath)
    assert repo_arg == v._repo_root


def test_validate_maps_is_exploitable_true_to_exploitable():
    v = CodeQLEvidenceValidator()
    mock_dv = MagicMock()
    mock_dv.validate_dataflow_path.return_value = _validation(is_exploitable=True)
    v._validator = mock_dv
    assert v.validate(_finding()) == ValidatorVerdict.EXPLOITABLE


def test_validate_maps_is_exploitable_false_to_not_exploitable():
    v = CodeQLEvidenceValidator()
    mock_dv = MagicMock()
    mock_dv.validate_dataflow_path.return_value = _validation(is_exploitable=False)
    v._validator = mock_dv
    assert v.validate(_finding()) == ValidatorVerdict.NOT_EXPLOITABLE


def test_validate_returns_uncertain_on_dataflow_validator_exception():
    """LLM transport errors / budget exhaustion / parse errors must
    not bubble up — the corpus runner records UNCERTAIN, which
    contributes to neither precision nor recall."""
    v = CodeQLEvidenceValidator()
    mock_dv = MagicMock()
    mock_dv.validate_dataflow_path.side_effect = RuntimeError("boom")
    v._validator = mock_dv
    assert v.validate(_finding()) == ValidatorVerdict.UNCERTAIN


def test_validate_does_not_swallow_keyboard_interrupt():
    """Exception-swallowing must not catch BaseException — operator
    Ctrl-C should still kill the run cleanly."""
    v = CodeQLEvidenceValidator()
    mock_dv = MagicMock()
    mock_dv.validate_dataflow_path.side_effect = KeyboardInterrupt()
    v._validator = mock_dv
    with pytest.raises(KeyboardInterrupt):
        v.validate(_finding())


def test_validate_constructs_dataflow_validator_lazily(monkeypatch):
    """First validate() call constructs the DataflowValidator;
    second call reuses it (cache amortisation)."""
    constructed = []

    class _MockDV:
        def __init__(self, llm, evidence_collector=None):
            constructed.append(self)
            self.evidence_collector = evidence_collector

        def validate_dataflow_path(self, dp, repo):
            return _validation(is_exploitable=False)

    monkeypatch.setattr(
        "packages.codeql.evidence_validator.DataflowValidator", _MockDV
    )
    monkeypatch.setattr(
        "packages.codeql.evidence_validator._construct_default_llm_client",
        lambda: MagicMock(),
    )

    v = CodeQLEvidenceValidator()
    assert v._validator is None
    v.validate(_finding())
    assert len(constructed) == 1
    v.validate(_finding())
    assert len(constructed) == 1  # reused, not re-constructed


def test_evidence_collector_wired_into_dataflow_validator(monkeypatch):
    """The DataflowValidator must be constructed with an
    evidence_collector — that's the whole point of this adapter."""
    captured_kwargs = {}

    class _SpyDV:
        def __init__(self, llm, evidence_collector=None):
            captured_kwargs["evidence_collector"] = evidence_collector

        def validate_dataflow_path(self, dp, repo):
            return _validation(is_exploitable=False)

    monkeypatch.setattr(
        "packages.codeql.evidence_validator.DataflowValidator", _SpyDV
    )
    monkeypatch.setattr(
        "packages.codeql.evidence_validator._construct_default_llm_client",
        lambda: MagicMock(),
    )

    v = CodeQLEvidenceValidator()
    v.validate(_finding())

    assert captured_kwargs["evidence_collector"] is not None
