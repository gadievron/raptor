"""Tests for packages.osv.verdicts — Verdict enum + OracleVerdict."""
from __future__ import annotations

from packages.osv.verdicts import OracleVerdict, Verdict


def test_is_pass_on_passing_verdicts() -> None:
    assert Verdict.MATCH_EXACT.is_pass
    assert Verdict.MATCH_RANGE.is_pass
    assert Verdict.MIRROR_DIFFERENT_SLUG.is_pass


def test_is_pass_on_failing_verdicts() -> None:
    assert not Verdict.DISPUTE.is_pass
    assert not Verdict.ORPHAN.is_pass
    assert not Verdict.LIKELY_HALLUCINATION.is_pass


def test_verdict_is_str_enum() -> None:
    assert str(Verdict.MATCH_EXACT) == "Verdict.MATCH_EXACT"
    assert Verdict.MATCH_EXACT.value == "match_exact"


def test_oracle_verdict_to_dict() -> None:
    v = OracleVerdict(
        cve_id="CVE-2023-38545",
        picked_slug="curl/curl",
        picked_sha="fb4415d8",
        verdict=Verdict.MATCH_EXACT,
        source="osv",
        expected_slugs=("curl/curl",),
        expected_shas=("fb4415d8",),
        notes="",
    )
    d = v.to_dict()
    assert d["cve_id"] == "CVE-2023-38545"
    assert d["verdict"] == "match_exact"
    assert d["is_pass"] is True
    assert d["expected_slugs"] == ["curl/curl"]


def test_oracle_verdict_frozen() -> None:
    v = OracleVerdict(
        cve_id="CVE-TEST", picked_slug="a/b", picked_sha="abc",
        verdict=Verdict.ORPHAN, source="none",
    )
    try:
        v.cve_id = "CVE-OTHER"  # type: ignore[misc]
        assert False, "should have raised"
    except AttributeError:
        pass
