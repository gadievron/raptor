"""Tests for core.audit.evidence_grade."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.audit.evidence_grade import (
    VALID_EVIDENCE_TOOLS,
    Confidence,
    EvidenceSource,
    default_confidence,
    finding_confidence,
    format_evidence_chain,
    grade_evidence,
    grade_evidence_record,
    grade_review_result,
    is_tool_evidence,
)


class TestEvidenceSource:
    def test_mechanical_sources_are_high(self):
        mechanical = [
            EvidenceSource.TREE_SITTER,
            EvidenceSource.TAINT_APPROX,
            EvidenceSource.CALL_GRAPH,
            EvidenceSource.JOERN,
            EvidenceSource.SEMGREP,
            EvidenceSource.CODEQL,
        ]
        for src in mechanical:
            assert default_confidence(src) == Confidence.HIGH

    def test_llm_sources_are_low(self):
        assert default_confidence(EvidenceSource.LLM_INFERRED) == Confidence.LOW
        assert default_confidence(EvidenceSource.LLM_SPEC) == Confidence.LOW

    def test_dynamic_sources_are_high(self):
        assert default_confidence(EvidenceSource.DYNAMIC_SANITIZER) == Confidence.HIGH
        assert default_confidence(EvidenceSource.DYNAMIC_FRIDA) == Confidence.HIGH

    def test_dynamic_crash_is_medium(self):
        assert default_confidence(EvidenceSource.DYNAMIC_CRASH) == Confidence.MEDIUM

    def test_corroborated_llm_is_medium(self):
        assert default_confidence(EvidenceSource.LLM_CORROBORATED) == Confidence.MEDIUM


class TestGradeEvidence:
    def test_creates_graded_evidence(self):
        ge = grade_evidence(EvidenceSource.JOERN, "3 flows found")
        assert ge.source == EvidenceSource.JOERN
        assert ge.confidence == Confidence.HIGH
        assert ge.description == "3 flows found"

    def test_confidence_override(self):
        ge = grade_evidence(
            EvidenceSource.LLM_INFERRED, "hypothesis",
            confidence_override=Confidence.HIGH,
        )
        assert ge.confidence == Confidence.HIGH

    def test_to_dict(self):
        ge = grade_evidence(
            EvidenceSource.SEMGREP, "match",
            detail="rule: tainted-format-string",
        )
        d = ge.to_dict()
        assert d["source"] == "mechanical:semgrep"
        assert d["confidence"] == "high"
        assert d["description"] == "match"
        assert d["detail"] == "rule: tainted-format-string"

    def test_to_dict_no_detail(self):
        ge = grade_evidence(EvidenceSource.JOERN, "flow")
        d = ge.to_dict()
        assert "detail" not in d

    def test_priority_ordering(self):
        high = grade_evidence(EvidenceSource.JOERN, "x")
        med = grade_evidence(EvidenceSource.NEGATIVE_SPACE, "y")
        low = grade_evidence(EvidenceSource.LLM_INFERRED, "z")
        assert high.priority < med.priority < low.priority


class TestFindingConfidence:
    def test_empty_chain_is_low(self):
        assert finding_confidence([]) == Confidence.LOW

    def test_single_high(self):
        chain = [grade_evidence(EvidenceSource.JOERN, "flow")]
        assert finding_confidence(chain) == Confidence.HIGH

    def test_single_low(self):
        chain = [grade_evidence(EvidenceSource.LLM_INFERRED, "guess")]
        assert finding_confidence(chain) == Confidence.LOW

    def test_mechanical_plus_llm_upgrades(self):
        chain = [
            grade_evidence(EvidenceSource.JOERN, "flow"),
            grade_evidence(EvidenceSource.LLM_INFERRED, "hypothesis"),
        ]
        conf = finding_confidence(chain)
        assert conf == Confidence.HIGH

    def test_multiple_low_stays_low(self):
        chain = [
            grade_evidence(EvidenceSource.LLM_INFERRED, "a"),
            grade_evidence(EvidenceSource.LLM_SPEC, "b"),
        ]
        assert finding_confidence(chain) == Confidence.LOW

    def test_dynamic_is_high(self):
        chain = [grade_evidence(EvidenceSource.DYNAMIC_SANITIZER, "crash")]
        assert finding_confidence(chain) == Confidence.HIGH


@dataclass
class FakeEvidenceRecord:
    file: str = "a.c"
    function: str = "f"
    sink_unreachable: bool = False
    taint_approx: Optional[Any] = None
    taint_summary: Optional[Any] = None
    joern_flows: List[Any] = field(default_factory=list)
    imported_joern_flows: List[Any] = field(default_factory=list)
    joern_unguarded_sinks: List[Any] = field(default_factory=list)
    codeql_alerts: List[Any] = field(default_factory=list)
    semgrep_hits: List[Any] = field(default_factory=list)
    negative_space: List[Any] = field(default_factory=list)
    binary_sink_edges: List[Any] = field(default_factory=list)


@dataclass
class FakeTaintApprox:
    dangerous_flows: Dict[int, list] = field(default_factory=dict)
    has_opaque_flow: bool = False
    params: list = field(default_factory=list)


class TestGradeEvidenceRecord:
    def test_empty_record(self):
        rec = FakeEvidenceRecord()
        items = grade_evidence_record(rec)
        assert items == []

    def test_taint_approx(self):
        rec = FakeEvidenceRecord(
            taint_approx=FakeTaintApprox(
                dangerous_flows={0: [("sink", 0)]},
                params=["buf"],
            ),
        )
        items = grade_evidence_record(rec)
        assert len(items) == 1
        assert items[0].source == EvidenceSource.TAINT_APPROX

    def test_joern_flows(self):
        rec = FakeEvidenceRecord(joern_flows=[{"flow": 1}, {"flow": 2}])
        items = grade_evidence_record(rec)
        assert any(e.source == EvidenceSource.JOERN for e in items)
        assert "2 Joern CPG flows" in items[0].description

    def test_multiple_sources(self):
        rec = FakeEvidenceRecord(
            joern_flows=[{"f": 1}],
            semgrep_hits=[{"h": 1}],
            negative_space=[{"n": 1}],
        )
        items = grade_evidence_record(rec)
        sources = {e.source for e in items}
        assert EvidenceSource.JOERN in sources
        assert EvidenceSource.SEMGREP in sources
        assert EvidenceSource.NEGATIVE_SPACE in sources

    def test_sink_unreachable(self):
        rec = FakeEvidenceRecord(sink_unreachable=True)
        items = grade_evidence_record(rec)
        assert len(items) == 1
        assert items[0].source == EvidenceSource.CALL_GRAPH

    def test_binary_edges(self):
        rec = FakeEvidenceRecord(
            binary_sink_edges=[{"edge": 1}],
        )
        items = grade_evidence_record(rec)
        assert items[0].source == EvidenceSource.BINARY_ORACLE


class TestGradeReviewResult:
    def test_empty_result(self):
        assert grade_review_result(None) == []
        assert grade_review_result({}) == []

    def test_hypothesis(self):
        items = grade_review_result({"hypothesis": "buffer overflow"})
        assert len(items) == 1
        assert items[0].source == EvidenceSource.LLM_INFERRED

    def test_spec_deviation(self):
        items = grade_review_result({
            "spec_deviation": {
                "deviation": "missing length check",
                "expected": "check len",
                "actual": "no check",
            },
        })
        assert any(e.source == EvidenceSource.LLM_SPEC for e in items)

    def test_typestate_confirmed(self):
        items = grade_review_result({
            "typestate_violation": {
                "confirmed": True,
                "violation_kind": "double_free",
                "type_name": "malloc/free",
            },
        })
        ts = [e for e in items if e.source == EvidenceSource.TYPESTATE]
        assert len(ts) == 1
        assert ts[0].confidence == Confidence.HIGH

    def test_typestate_unconfirmed_skipped(self):
        items = grade_review_result({
            "typestate_violation": {
                "confirmed": False,
                "violation_kind": "double_free",
            },
        })
        ts = [e for e in items if e.source == EvidenceSource.TYPESTATE]
        assert len(ts) == 0

    def test_evidence_tool_dynamic(self):
        items = grade_review_result({}, evidence_tool="dynamic")
        assert any(e.source == EvidenceSource.DYNAMIC_SANITIZER for e in items)

    def test_evidence_tool_dynamic_crash(self):
        items = grade_review_result({}, evidence_tool="dynamic:crash")
        crash = [e for e in items if e.source == EvidenceSource.DYNAMIC_CRASH]
        assert len(crash) == 1
        assert crash[0].confidence == Confidence.MEDIUM

    def test_evidence_tool_joern(self):
        items = grade_review_result({}, evidence_tool="joern:live")
        assert any(e.source == EvidenceSource.JOERN for e in items)

    def test_evidence_tool_semgrep(self):
        items = grade_review_result({}, evidence_tool="semgrep:rule_7")
        assert any(e.source == EvidenceSource.SEMGREP for e in items)

    def test_evidence_tool_codeql(self):
        items = grade_review_result({}, evidence_tool="codeql:dataflow")
        assert any(e.source == EvidenceSource.CODEQL for e in items)

    def test_evidence_tool_coccinelle(self):
        items = grade_review_result({}, evidence_tool="coccinelle:bounds")
        assert any(e.source == EvidenceSource.COCCINELLE for e in items)

    def test_evidence_tool_smt(self):
        items = grade_review_result({}, evidence_tool="smt:check-oob")
        assert any(e.source == EvidenceSource.SMT for e in items)

    def test_composite_receipt_grades_every_component(self):
        items = grade_review_result(
            {}, evidence_tool="smt:check-oob+coccinelle:bounds",
        )
        sources = {e.source for e in items}
        assert EvidenceSource.SMT in sources
        assert EvidenceSource.COCCINELLE in sources

    def test_critique_receipt_grades_the_wrapped_tool(self):
        items = grade_review_result({}, evidence_tool="critique:semgrep:r1")
        assert any(e.source == EvidenceSource.SEMGREP for e in items)

    def test_bare_tool_name_is_not_a_receipt(self):
        """A bare name is what a model types, not what a tool run stamps."""
        for bare in ("joern", "semgrep", "codeql", "coccinelle", "smt"):
            items = grade_review_result({}, evidence_tool=bare)
            assert not any(
                e.confidence == Confidence.HIGH for e in items
            ), bare

    def test_model_claim_earns_no_tool_grade(self):
        items = grade_review_result({}, evidence_tool="llm-claimed:joern")
        assert not any(e.source == EvidenceSource.JOERN for e in items)


class TestFormatEvidenceChain:
    def test_empty_chain(self):
        assert format_evidence_chain([]) == ""

    def test_renders_sorted_by_priority(self):
        chain = [
            grade_evidence(EvidenceSource.LLM_INFERRED, "guess"),
            grade_evidence(EvidenceSource.JOERN, "flow"),
        ]
        text = format_evidence_chain(chain)
        joern_pos = text.index("joern")
        llm_pos = text.index("inferred")
        assert joern_pos < llm_pos

    def test_includes_confidence_tag(self):
        chain = [grade_evidence(EvidenceSource.SEMGREP, "match")]
        text = format_evidence_chain(chain)
        assert "[HIGH]" in text
        assert "semgrep" in text


class TestIsToolEvidence:
    """is_tool_evidence rejects LLM-hallucinated stamps."""

    def test_canonical_stamps_accepted(self):
        for stamp in VALID_EVIDENCE_TOOLS:
            assert is_tool_evidence(stamp), stamp

    def test_namespaced_composites_accepted(self):
        assert is_tool_evidence("semgrep:rule-123")
        assert is_tool_evidence("critique:prefilter:rule-id")
        assert is_tool_evidence("smt:path_feasibility")
        assert is_tool_evidence("sarif_cache:hit")

    def test_llm_hallucinations_rejected(self):
        assert not is_tool_evidence("Semgrep")
        assert not is_tool_evidence("CodeQL")
        assert not is_tool_evidence("llm")
        assert not is_tool_evidence("llm-claimed:codeql")

    def test_empty_and_none_rejected(self):
        assert not is_tool_evidence("")
        assert not is_tool_evidence("none")
