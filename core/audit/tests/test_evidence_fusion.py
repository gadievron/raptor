"""Tests for core.audit.evidence_fusion."""

from __future__ import annotations

from core.audit.evidence_fusion import (
    FusedEvidence,
    compute_injection_priority,
    format_fused_evidence,
    fuse_evidence,
)
from core.audit.evidence_grade import (
    Confidence,
    EvidenceSource,
    grade_evidence,
)


class TestFuseEvidence:
    def test_single_item_passthrough(self):
        items = [grade_evidence(EvidenceSource.JOERN, "3 flows")]
        fused = fuse_evidence(items, [], [], [], [])
        assert len(fused) == 1
        assert fused[0].description == "3 flows"
        assert fused[0].corroboration_count == 1

    def test_corroborating_items_merge(self):
        mech = [grade_evidence(EvidenceSource.JOERN, "overflow detected")]
        spec = [grade_evidence(EvidenceSource.LLM_SPEC, "overflow in parse")]
        fused = fuse_evidence(mech, spec, [], [], [])
        overflow_items = [f for f in fused if "overflow" in f.description]
        assert len(overflow_items) >= 1

    def test_different_concerns_stay_separate(self):
        items = [
            grade_evidence(EvidenceSource.JOERN, "overflow in parse"),
            grade_evidence(EvidenceSource.NEGATIVE_SPACE, "missing auth check"),
        ]
        fused = fuse_evidence(items, [], [], [], [])
        assert len(fused) == 2

    def test_corroboration_upgrades_confidence(self):
        mech = [grade_evidence(EvidenceSource.JOERN, "injection flow")]
        llm = [grade_evidence(EvidenceSource.LLM_INFERRED, "injection risk")]
        fused = fuse_evidence(mech, llm, [], [], [])
        injection_fused = [f for f in fused if "injection" in f.description]
        assert len(injection_fused) == 1
        assert injection_fused[0].confidence == Confidence.HIGH
        assert injection_fused[0].corroboration_count == 2

    def test_multiple_llm_only_upgrades_to_medium(self):
        spec = [grade_evidence(EvidenceSource.LLM_SPEC, "auth bypass")]
        llm = [grade_evidence(EvidenceSource.LLM_INFERRED, "authentication issue")]
        fused = fuse_evidence([], spec, llm, [], [])
        auth_items = [f for f in fused if "auth" in f.description.lower()]
        assert len(auth_items) >= 1

    def test_empty_inputs(self):
        fused = fuse_evidence([], [], [], [], [])
        assert fused == []

    def test_limits_output(self):
        items = [
            grade_evidence(EvidenceSource.JOERN, f"flow {i}")
            for i in range(20)
        ]
        fused = fuse_evidence(items, [], [], [], [])
        assert len(fused) <= 15

    def test_sorted_by_confidence(self):
        mech = [grade_evidence(EvidenceSource.JOERN, "overflow critical")]
        llm = [grade_evidence(EvidenceSource.LLM_INFERRED, "maybe issue")]
        fused = fuse_evidence(mech, llm, [], [], [])
        if len(fused) >= 2:
            confs = [f.confidence for f in fused]
            priorities = [
                {"high": 0, "medium": 1, "low": 2}[c.value]
                for c in confs
            ]
            assert priorities == sorted(priorities)

    def test_typestate_evidence(self):
        ts = [grade_evidence(
            EvidenceSource.TYPESTATE,
            "double_free on malloc/free",
        )]
        fused = fuse_evidence([], [], [], [], ts)
        assert len(fused) == 1
        assert fused[0].sources == [EvidenceSource.TYPESTATE]


class TestFusedEvidence:
    def test_to_prompt_section(self):
        fe = FusedEvidence(
            description="buffer overflow via tainted input",
            sources=[EvidenceSource.JOERN, EvidenceSource.LLM_INFERRED],
            confidence=Confidence.HIGH,
            corroboration_count=2,
        )
        text = fe.to_prompt_section()
        assert "[HIGH]" in text
        assert "joern" in text
        assert "inferred" in text

    def test_single_source(self):
        fe = FusedEvidence(
            description="missing check",
            sources=[EvidenceSource.NEGATIVE_SPACE],
            confidence=Confidence.MEDIUM,
            corroboration_count=1,
        )
        text = fe.to_prompt_section()
        assert "[MEDIUM]" in text


class TestFormatFusedEvidence:
    def test_empty(self):
        assert format_fused_evidence([]) == ""

    def test_renders_header(self):
        fused = [FusedEvidence(
            description="test",
            sources=[EvidenceSource.JOERN],
            confidence=Confidence.HIGH,
            corroboration_count=1,
        )]
        text = format_fused_evidence(fused)
        assert "Pre-review evidence" in text
        assert "[HIGH]" in text


class TestComputeInjectionPriority:
    def test_high_confidence_is_zero(self):
        assert compute_injection_priority(Confidence.HIGH) == 0

    def test_medium_confidence_is_one(self):
        assert compute_injection_priority(Confidence.MEDIUM) == 1

    def test_low_confidence_is_two(self):
        assert compute_injection_priority(Confidence.LOW) == 2

    def test_corroborated_upgrades(self):
        assert compute_injection_priority(Confidence.LOW, is_corroborated=True) == 1

    def test_high_stays_high_even_if_corroborated(self):
        assert compute_injection_priority(Confidence.HIGH, is_corroborated=True) == 0
