"""Tests for ``packages.sca.supply_chain.composite``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import (
    Confidence, Dependency, PinStyle, Severity, SupplyChainFinding,
    SupplyChainKind,
)
from packages.sca.supply_chain.composite import apply


def _dep(name: str = "pkg", version: str = "1.0.0",
         ecosystem: str = "npm") -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path("package.json"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _finding(kind: SupplyChainKind, dep: Dependency,
             severity: Severity = "low") -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=f"sca:supply_chain:{kind}:{dep.name}",
        kind=kind, dependency=dep, detail="t",
        evidence={}, severity=severity,
        confidence=Confidence("medium", reason="t"),
    )


# ---------------------------------------------------------------------------
# Single-family — no promotion
# ---------------------------------------------------------------------------

def test_single_family_passes_through_unchanged() -> None:
    """One detector firing on a dep is normal; composite is a no-op."""
    d = _dep()
    f = _finding("install_hook_suspicious", d, severity="low")
    out = apply([f])
    assert len(out) == 1
    assert out[0].severity == "low"
    assert "composite_score" not in out[0].evidence


def test_multiple_same_family_findings_do_not_promote() -> None:
    """Two BINARY-family findings count as ONE family — no composite."""
    d = _dep()
    fs = [
        _finding("disguised_filename", d, severity="medium"),
        _finding("large_obfuscated_artefact", d, severity="medium"),
    ]
    out = apply(fs)
    assert all("composite_score" not in f.evidence for f in out)
    assert [f.severity for f in out] == ["medium", "medium"]


# ---------------------------------------------------------------------------
# Multi-family — composite promotes
# ---------------------------------------------------------------------------

def test_two_families_floor_medium() -> None:
    """HOOK + SQUAT on the same dep → at least medium."""
    d = _dep()
    fs = [
        _finding("install_hook_suspicious", d, severity="low"),
        _finding("typosquat_candidate", d, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "medium" for f in out)
    for f in out:
        assert sorted(f.evidence["composite_score"]["families"]) == [
            "HOOK", "SQUAT",
        ]


def test_three_families_floor_high() -> None:
    d = _dep()
    fs = [
        _finding("install_hook_suspicious", d, severity="low"),
        _finding("typosquat_candidate", d, severity="low"),
        _finding("recent_publish", d, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "high" for f in out)


def test_four_families_floor_critical() -> None:
    d = _dep()
    fs = [
        _finding("install_hook_suspicious", d, severity="low"),
        _finding("typosquat_candidate", d, severity="low"),
        _finding("recent_publish", d, severity="low"),
        _finding("git_tag_drift", d, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "critical" for f in out)


# ---------------------------------------------------------------------------
# Hard pairs — critical regardless of base
# ---------------------------------------------------------------------------

def test_hook_plus_binary_is_critical_iron_worm_shape() -> None:
    """HOOK ∧ BINARY = Iron Worm signature → critical regardless of
    individual severities."""
    d = _dep()
    fs = [
        _finding("install_hook_suspicious", d, severity="low"),
        _finding("disguised_filename", d, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "critical" for f in out)
    for f in out:
        # The promotion stamp explains WHY:
        assert "hard-pair" in f.evidence["composite_score"]["promotion"]


def test_hook_plus_egress_is_critical_generic_worm_shape() -> None:
    d = _dep()
    fs = [
        _finding("install_hook_suspicious", d, severity="low"),
        _finding("known_exfil_destination", d, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "critical" for f in out)


def test_gha_plus_sentinel_is_critical() -> None:
    d = _dep()
    fs = [
        _finding("gha_action_ref_drift", d, severity="low"),
        _finding("sentinel_match", d, severity="medium"),
    ]
    out = apply(fs)
    assert all(f.severity == "critical" for f in out)


# ---------------------------------------------------------------------------
# Soundness invariants — composite as a one-way ratchet
# ---------------------------------------------------------------------------

def test_composite_never_demotes() -> None:
    """A finding that's already higher than the composite floor must
    NOT be lowered."""
    d = _dep()
    fs = [
        _finding("install_hook_suspicious", d, severity="critical"),
        _finding("typosquat_candidate", d, severity="low"),
    ]
    out = apply(fs)
    severities = sorted(f.severity for f in out)
    # The critical row stays critical (not demoted to medium floor);
    # the low row is promoted to medium floor.
    assert severities == ["critical", "medium"]


def test_findings_on_different_deps_do_not_combine() -> None:
    """Per-dep grouping: two findings on UNRELATED packages don't
    earn a composite even if they're from different families."""
    a = _dep(name="a")
    b = _dep(name="b")
    fs = [
        _finding("install_hook_suspicious", a, severity="low"),
        _finding("disguised_filename", b, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "low" for f in out)
    assert all("composite_score" not in f.evidence for f in out)


def test_findings_on_different_versions_do_not_combine() -> None:
    """Per-version grouping: same package at v1 and v2 are separate
    groups — an attacker who spreads payload across versions gains
    nothing from us combining them either."""
    v1 = _dep(version="1.0.0")
    v2 = _dep(version="2.0.0")
    fs = [
        _finding("install_hook_suspicious", v1, severity="low"),
        _finding("disguised_filename", v2, severity="low"),
    ]
    out = apply(fs)
    assert all(f.severity == "low" for f in out)


def test_unknown_kind_is_skipped_not_lost() -> None:
    """A finding whose kind has no family mapping contributes nothing
    to composite scoring, but is NOT dropped from the output."""
    d = _dep()
    # Use a real kind for the known-family row + craft a finding with
    # a kind we haven't mapped (we use a typed cast via dataclasses
    # for this safety belt — runtime check, not type check).
    known = _finding("install_hook_suspicious", d, severity="low")
    unknown = _finding("disguised_filename", d, severity="low")
    # Force-mutate to a not-yet-mapped kind for the test (string
    # literal type cast is fine at runtime).
    unknown.kind = "xxx_unmapped_test_kind"      # type: ignore[assignment]
    out = apply([known, unknown])
    # Both findings present; only the "known" row sees a single-
    # family bucket → no composite; unknown is passed through.
    assert len(out) == 2
    assert all(f.severity == "low" for f in out)


# ---------------------------------------------------------------------------
# Order-independence & purity
# ---------------------------------------------------------------------------

def test_result_is_order_independent() -> None:
    d = _dep()
    a = _finding("install_hook_suspicious", d, severity="low")
    b = _finding("disguised_filename", d, severity="low")
    out_ab = apply([a, b])
    out_ba = apply([b, a])
    sev_ab = sorted(f.severity for f in out_ab)
    sev_ba = sorted(f.severity for f in out_ba)
    assert sev_ab == sev_ba


def test_input_list_is_not_mutated() -> None:
    d = _dep()
    inputs = [
        _finding("install_hook_suspicious", d, severity="low"),
        _finding("disguised_filename", d, severity="low"),
    ]
    snapshot_sev = [f.severity for f in inputs]
    apply(inputs)
    assert [f.severity for f in inputs] == snapshot_sev
