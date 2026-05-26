"""Tests for the cross-detector severity escalation on slopsquat
findings.

The mechanical heuristic in ``slopsquat.py`` produces a baseline
severity (info / low / medium / high) from the shape of the
package name alone. The orchestrator's
``_escalate_cross_detector`` lifts that severity when registry-
side findings co-occur for the same dep — the conjunction is
the actionable signal.

This file exercises the lift rules without invoking the live LLM
or the registry-metadata HTTP path; we hand-build the
SupplyChainFinding list and run the escalation directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from packages.sca.models import (
    Confidence, Dependency, PinStyle, SupplyChainFinding,
)
from packages.sca.supply_chain import _escalate_cross_detector


def _dep(name: str = "lodash-pro") -> Dependency:
    return Dependency(
        ecosystem="npm", name=name, version="1.0",
        declared_in=Path("/p"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:npm/{name}@1.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def _slop_finding(dep: Dependency, severity: str = "medium") -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=f"slop:{dep.key()}",
        kind="slopsquat_suspect",
        dependency=dep, detail="",
        evidence={"score": 0.6, "reasons": ["popular_prefix_generic_suffix"]},
        severity=severity,                        # type: ignore[arg-type]
        confidence=Confidence("medium", reason="t"),
    )


def _registry_finding(
    dep: Dependency, kind: str,
) -> SupplyChainFinding:
    return SupplyChainFinding(
        finding_id=f"{kind}:{dep.key()}",
        kind=kind,                                 # type: ignore[arg-type]
        dependency=dep, detail="",
        evidence={},
        severity="info",
        confidence=Confidence("high", reason="t"),
    )


# ---------------------------------------------------------------------------
# Solo slopsquat — no escalation.
# ---------------------------------------------------------------------------

def test_slopsquat_alone_stays_at_heuristic_severity() -> None:
    """No co-occurring registry findings → severity untouched."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [_slop_finding(dep, "medium")]
    _escalate_cross_detector(findings)
    assert findings[0].severity == "medium"
    # No escalation_reasons key added.
    assert "escalation_reasons" not in findings[0].evidence


# ---------------------------------------------------------------------------
# +recent_publish only → high.
# ---------------------------------------------------------------------------

def test_slopsquat_plus_recent_publish_escalates_to_high() -> None:
    """Slopsquat-shape + registry says "first published < 30
    days ago" is the new-package risk shape."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep, "medium"),
        _registry_finding(dep, "recent_publish"),
    ]
    _escalate_cross_detector(findings)
    slop = next(f for f in findings if f.kind == "slopsquat_suspect")
    assert slop.severity == "high"
    assert "escalation_reasons" in slop.evidence
    assert any("recent_publish" in r for r in slop.evidence["escalation_reasons"])


def test_slopsquat_plus_version_publish_also_escalates() -> None:
    """``version_publish`` (latest version published on a
    dormant package) is the freshly-revived signal — same
    risk shape as recent_publish, so the same lift applies."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep, "medium"),
        _registry_finding(dep, "version_publish"),
    ]
    _escalate_cross_detector(findings)
    slop = next(f for f in findings if f.kind == "slopsquat_suspect")
    assert slop.severity == "high"


# ---------------------------------------------------------------------------
# +recent_publish + low_bus_factor → critical.
# ---------------------------------------------------------------------------

def test_slopsquat_plus_recent_and_low_bus_escalates_to_critical() -> None:
    """The full bait shape — slopsquat-shape + just-registered
    + single-anonymous-publisher — escalates to critical so it
    can't be hidden by severity filters."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep, "medium"),
        _registry_finding(dep, "recent_publish"),
        _registry_finding(dep, "low_bus_factor"),
    ]
    _escalate_cross_detector(findings)
    slop = next(f for f in findings if f.kind == "slopsquat_suspect")
    assert slop.severity == "critical"
    assert "LLM-hallucination-bait archetype" in (
        " ".join(slop.evidence["escalation_reasons"])
    )


# ---------------------------------------------------------------------------
# +low_bus_factor only → medium (no upgrade from medium).
# ---------------------------------------------------------------------------

def test_low_bus_factor_alone_lifts_to_medium() -> None:
    """A low-baseline slopsquat finding combined with single-
    maintainer signal lifts to medium even without recent
    publishing — many bait packages WILL have low_bus_factor
    without yet having the recent_publish signal (e.g.
    package was registered weeks ago, sitting dormant)."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep, "low"),
        _registry_finding(dep, "low_bus_factor"),
    ]
    _escalate_cross_detector(findings)
    slop = next(f for f in findings if f.kind == "slopsquat_suspect")
    assert slop.severity == "medium"


# ---------------------------------------------------------------------------
# +maintainer_change → high (account takeover on existing name).
# ---------------------------------------------------------------------------

def test_maintainer_change_lifts_to_high() -> None:
    """If a package matching slopsquat shape ALSO has a fresh
    maintainer-list change, that's the account-takeover variant
    of the same attack. Same severity ceiling as
    recent_publish."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep, "medium"),
        _registry_finding(dep, "maintainer_change"),
    ]
    _escalate_cross_detector(findings)
    slop = next(f for f in findings if f.kind == "slopsquat_suspect")
    assert slop.severity == "high"


# ---------------------------------------------------------------------------
# Cross-dep: registry signals from OTHER deps don't escalate this one.
# ---------------------------------------------------------------------------

def test_registry_signals_on_other_dep_do_not_escalate() -> None:
    """``recent_publish`` on dep A must NOT escalate
    ``slopsquat_suspect`` on dep B. The escalation is per-dep,
    keyed on ``(ecosystem, name)``."""
    dep_a = _dep("lodash-pro")
    dep_b = _dep("requests-utils")
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep_a, "medium"),
        _registry_finding(dep_b, "recent_publish"),
        _registry_finding(dep_b, "low_bus_factor"),
    ]
    _escalate_cross_detector(findings)
    slop_a = next(
        f for f in findings
        if f.kind == "slopsquat_suspect" and f.dependency.name == "lodash-pro"
    )
    # dep_a's slopsquat severity untouched — dep_b's registry
    # signals don't carry over.
    assert slop_a.severity == "medium"


# ---------------------------------------------------------------------------
# Severity floor: never downgrade.
# ---------------------------------------------------------------------------

def test_high_severity_slopsquat_not_downgraded() -> None:
    """A slopsquat finding that started at ``high`` (because the
    heuristic itself scored above 0.7) must NOT be downgraded
    by an escalation pass that nominally only lifts to "high"
    or below. Severity is monotone."""
    dep = _dep()
    findings: List[SupplyChainFinding] = [
        _slop_finding(dep, "high"),
        _registry_finding(dep, "low_bus_factor"),
    ]
    _escalate_cross_detector(findings)
    slop = next(f for f in findings if f.kind == "slopsquat_suspect")
    # low_bus_factor alone targets ``medium`` — but the finding's
    # current severity is already ``high``, so the max(target,
    # current) keeps it at ``high``.
    assert slop.severity == "high"
