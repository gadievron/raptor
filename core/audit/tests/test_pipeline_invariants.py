"""Tests for pipeline_invariants — the post-pipeline invariant oracle."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from core.audit.pipeline_invariants import (
    InvariantViolation,
    assert_pipeline_invariants,
    check_pipeline_invariants,
)


@dataclass
class _Outcome:
    file: str = "test.c"
    function: str = "foo"
    status: str = "clean"
    body: str = ""
    evidence_tool: str = ""
    review_result: dict[str, Any] | None = None


@dataclass
class _Result:
    clean: int = 0
    suspicious: int = 0
    findings: int = 0
    ondemand_synthesized: int = 0
    outcomes: list = field(default_factory=list)


class TestCounterConsistency:
    def test_consistent_counters_pass(self):
        r = _Result(clean=2, suspicious=1, findings=0, outcomes=[
            _Outcome(status="clean"),
            _Outcome(status="clean", function="bar"),
            _Outcome(status="suspicious", function="baz"),
        ])
        assert check_pipeline_invariants(r) == []

    def test_drifted_clean_counter(self):
        r = _Result(clean=5, suspicious=0, findings=0, outcomes=[
            _Outcome(status="clean"),
        ])
        vs = check_pipeline_invariants(r)
        assert len(vs) == 1
        assert "counter drift" in vs[0]
        assert "result.clean=5" in vs[0]

    def test_drifted_suspicious_counter(self):
        r = _Result(clean=0, suspicious=3, findings=0, outcomes=[
            _Outcome(status="suspicious"),
        ])
        vs = check_pipeline_invariants(r)
        assert any("result.suspicious=3" in v for v in vs)

    def test_drifted_findings_counter(self):
        r = _Result(clean=0, suspicious=0, findings=2, outcomes=[])
        vs = check_pipeline_invariants(r)
        assert any("result.findings=2" in v for v in vs)


class TestNoDoubleDispatch:
    def test_no_immediate_verified_passes(self):
        r = _Result(clean=1, outcomes=[
            _Outcome(status="clean", review_result={}),
        ])
        assert check_pipeline_invariants(r) == []

    def test_immediate_verified_without_sweep_passes(self):
        r = _Result(findings=1, outcomes=[
            _Outcome(
                status="finding",
                review_result={"immediate_verified": True},
            ),
        ])
        assert check_pipeline_invariants(r) == []

    def test_immediate_verified_with_sweep_marker_fails(self):
        r = _Result(findings=1, outcomes=[
            _Outcome(
                status="finding",
                body="[sweep-promotion: confirmed]",
                review_result={"immediate_verified": True},
            ),
        ])
        vs = check_pipeline_invariants(r)
        assert any("double-dispatch" in v for v in vs)

    def test_immediate_verified_with_secondary_dispatch_fails(self):
        r = _Result(suspicious=1, outcomes=[
            _Outcome(
                status="suspicious",
                body="[secondary-dispatch: routed]",
                review_result={"immediate_verified": True},
            ),
        ])
        vs = check_pipeline_invariants(r)
        assert any("double-dispatch" in v for v in vs)


class TestExhaustionFinality:
    def test_exhausted_without_sweep_passes(self):
        r = _Result(suspicious=1, outcomes=[
            _Outcome(
                status="suspicious",
                review_result={"chain_exhausted": True},
            ),
        ])
        assert check_pipeline_invariants(r) == []

    def test_exhausted_with_sweep_promotion_fails(self):
        r = _Result(findings=1, outcomes=[
            _Outcome(
                status="finding",
                body="[sweep-promotion: confirmed by semgrep]",
                review_result={"chain_exhausted": True},
            ),
        ])
        vs = check_pipeline_invariants(r)
        assert any("exhaustion re-attempt" in v for v in vs)


class TestToolEvidencePreservation:
    def test_confirmed_with_evidence_passes(self):
        r = _Result(findings=1, outcomes=[
            _Outcome(
                status="finding",
                evidence_tool="semgrep:rule-123",
                review_result={"tools_confirmed": ["semgrep"]},
            ),
        ])
        assert check_pipeline_invariants(r) == []

    def test_confirmed_without_evidence_fails(self):
        r = _Result(findings=1, outcomes=[
            _Outcome(
                status="finding",
                evidence_tool="",
                review_result={"tools_confirmed": ["semgrep"]},
            ),
        ])
        vs = check_pipeline_invariants(r)
        assert any("evidence stripped" in v for v in vs)


class TestSynthesisCap:
    def test_within_cap_passes(self):
        r = _Result(ondemand_synthesized=3)
        assert check_pipeline_invariants(r) == []

    def test_exceeds_cap_fails(self):
        r = _Result(ondemand_synthesized=999)
        vs = check_pipeline_invariants(r)
        assert any("synthesis cap exceeded" in v for v in vs)


class TestAssertRaises:
    def test_assert_raises_on_violation(self):
        r = _Result(clean=99, outcomes=[])
        with pytest.raises(InvariantViolation, match="counter drift"):
            assert_pipeline_invariants(r)

    def test_assert_passes_clean_result(self):
        r = _Result(clean=1, outcomes=[_Outcome(status="clean")])
        assert_pipeline_invariants(r)
