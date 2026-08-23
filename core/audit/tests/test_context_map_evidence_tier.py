"""Context-map sinks grade as LLM claims, never mechanical evidence.

context-map.json ``sink_details`` are raw LLM output from /understand
over the untrusted repo. Pre-fix they attached as ``context_map_sink``
graded ``EvidenceSource.CALL_GRAPH`` → ``Confidence.HIGH`` with
structured ``evidence_tier="header_backed"`` — a rank-2 mechanical
tier a hostile repo could steer (THREAT_MODEL I2(b) violation),
feeding prioritisation, review prompts, and evidence fusion as if a
deterministic tool had produced it. These tests are the inverted PoC
for the promotion path.
"""

from __future__ import annotations

from core.audit.evidence_grade import (
    Confidence,
    EvidenceSource,
    grade_evidence_record,
)
from core.evidence import (
    ContextMapSink,
    EvidenceRecord,
    EvidenceTier,
    format_evidence_prose,
    format_evidence_structured,
    strongest_evidence_tier,
)


def _record(**kw) -> EvidenceRecord:
    rec = EvidenceRecord(file="a.c", function="f", line_start=1, line_end=9)
    for k, v in kw.items():
        setattr(rec, k, v)
    return rec


def _context_map_grades(rec):
    return [g for g in grade_evidence_record(rec)
            if "context-map" in g.description]


def test_uncorroborated_sink_grades_llm_inferred_low() -> None:
    rec = _record(context_map_sink=ContextMapSink(
        sink_type="command_injection", notes="the LLM said so"))
    grades = _context_map_grades(rec)
    assert len(grades) == 1
    assert grades[0].source == EvidenceSource.LLM_INFERRED
    assert grades[0].confidence == Confidence.LOW
    # And never the mechanical call-graph source it used to claim.
    assert grades[0].source != EvidenceSource.CALL_GRAPH


def test_tool_corroborated_sink_grades_medium_not_high() -> None:
    """A deterministic receipt for the same function upgrades the
    claim to LLM_CORROBORATED/MEDIUM — still never HIGH."""
    rec = _record(
        context_map_sink=ContextMapSink(sink_type="cmd", notes=""),
        semgrep_hits=[{"rule_id": "r1", "line": 3}],
    )
    grades = _context_map_grades(rec)
    assert grades[0].source == EvidenceSource.LLM_CORROBORATED
    assert grades[0].confidence == Confidence.MEDIUM


def test_structured_tier_is_llm_claimed_and_outside_the_enum() -> None:
    """The structured entry's evidence_tier must not parse as any
    EvidenceTier member — it can never satisfy
    strongest_evidence_tier or a tool-evidence gate."""
    rec = _record(context_map_sink=ContextMapSink(
        sink_type="cmd", notes=""))
    entries = [e for e in format_evidence_structured(rec)
               if e["tier"] == "context_map_sink"]
    assert entries and entries[0]["evidence_tier"] == "llm_claimed"
    assert all(
        entries[0]["evidence_tier"] != t.value for t in EvidenceTier
    )
    # A record whose ONLY evidence is the context-map claim
    # contributes nothing above HEURISTIC.
    assert strongest_evidence_tier(entries) == EvidenceTier.HEURISTIC


def test_prose_labels_the_claim_as_llm_derived() -> None:
    rec = _record(context_map_sink=ContextMapSink(
        sink_type="cmd", notes="notes"))
    prose = format_evidence_prose(rec)
    line = next(ln for ln in prose.splitlines()
                if "context-map sink" in ln)
    assert "LLM-derived" in line
    assert "not tool evidence" in line
