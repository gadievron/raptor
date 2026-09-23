"""Tests for evidence tier vocabulary (formerly core.evidence)."""

from core.evidence import (
    EvidenceTier,
    TIER_RANK,
    make_evidence,
    stronger,
)


class TestEvidenceTierOrdering:
    """The tier ordering is a design constraint, not an implementation detail.

    OBSERVED_RUNTIME > REPLAYED_CRASH > SMT_PROVED >
    CORPUS_CORROBORATED > DECODED_INSTRUCTION > XREF_BACKED >
    HEADER_BACKED > DECOMPILER_INFERRED > HEURISTIC
    """

    def test_ordering(self):
        ordered = [
            EvidenceTier.OBSERVED_RUNTIME,
            EvidenceTier.REPLAYED_CRASH,
            EvidenceTier.SMT_PROVED,
            EvidenceTier.CORPUS_CORROBORATED,
            EvidenceTier.DECODED_INSTRUCTION,
            EvidenceTier.XREF_BACKED,
            EvidenceTier.HEADER_BACKED,
            EvidenceTier.DECOMPILER_INFERRED,
            EvidenceTier.HEURISTIC,
        ]
        for i in range(len(ordered) - 1):
            assert TIER_RANK[ordered[i]] > TIER_RANK[ordered[i + 1]], (
                f"{ordered[i]} should rank above {ordered[i + 1]}"
            )

    def test_all_tiers_ranked(self):
        for tier in EvidenceTier:
            assert tier in TIER_RANK


class TestCorroboratedSpecTiersDerivation:
    """fail_open_roles' registry-grade set means "rank >=
    HEADER_BACKED" — pinned as a DERIVATION from the canonical
    ladder so new tiers can never be silently excluded (an ordering
    inversion once they are minted)."""

    def test_derived_from_ladder(self):
        from core.audit.fail_open_roles import _CORROBORATED_SPEC_TIERS
        floor = TIER_RANK[EvidenceTier.HEADER_BACKED]
        expected = frozenset(
            tier.value
            for tier, rank in TIER_RANK.items() if rank >= floor
        )
        assert _CORROBORATED_SPEC_TIERS == expected

    def test_new_tiers_are_registry_grade(self):
        from core.audit.fail_open_roles import _CORROBORATED_SPEC_TIERS
        assert "decoded_instruction" in _CORROBORATED_SPEC_TIERS
        assert "corpus_corroborated" in _CORROBORATED_SPEC_TIERS
        assert "decompiler_inferred" not in _CORROBORATED_SPEC_TIERS
        assert "heuristic" not in _CORROBORATED_SPEC_TIERS


class TestStronger:
    def test_same_tier(self):
        assert stronger(EvidenceTier.HEURISTIC, EvidenceTier.HEURISTIC) == EvidenceTier.HEURISTIC

    def test_left_stronger(self):
        assert stronger(EvidenceTier.OBSERVED_RUNTIME, EvidenceTier.HEURISTIC) == EvidenceTier.OBSERVED_RUNTIME

    def test_right_stronger(self):
        assert stronger(EvidenceTier.HEURISTIC, EvidenceTier.XREF_BACKED) == EvidenceTier.XREF_BACKED


class TestMakeEvidence:
    def test_basic(self):
        rec = make_evidence(
            "abc123",
            kind="sink_call",
            source="readelf",
            summary="imports memcpy",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            reproducible=True,
            tool="readelf",
        )
        assert rec.tier == EvidenceTier.HEADER_BACKED
        assert rec.id.startswith("evidence:")

    def test_to_dict(self):
        rec = make_evidence(
            "abc",
            kind="test",
            source="test",
            summary="test",
            tier=EvidenceTier.HEURISTIC,
            confidence="low",
            reproducible=False,
            tool="test",
        )
        d = rec.to_dict()
        assert d["tier"] == "heuristic"
        assert isinstance(d["data"], dict)
