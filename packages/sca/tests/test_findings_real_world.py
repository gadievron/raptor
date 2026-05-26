"""Regressions for issues surfaced by the live raptor-repo run."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    AffectedRange,
    Advisory,
    CVSSScore,
    Confidence,
    Dependency,
    PinStyle,
)
from packages.sca.osv import OsvResult


def _dep(version: str = "2.0.0", name: str = "pydantic",
         ecosystem: str = "PyPI") -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path("/repo/x"), scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(
    osv_id: str,
    fixed: List[str],
    aliases: List[str] | None = None,
) -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=aliases or [],
        summary="t",
        details="",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, *[{"fixed": v} for v in fixed]],
        )],
        severity=CVSSScore(
            score=5.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            severity="medium",
        ),
        fixed_versions=fixed,
        references=[],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# _smallest_applicable_fix
# ---------------------------------------------------------------------------

def test_fix_picks_upgrade_above_installed_version() -> None:
    """Pydantic 2.0.0 with two non-overlapping fix versions (1.10.13 +
    2.4.0): the right upgrade is 2.4.0, not the global minimum 1.10.13."""
    dep = _dep(version="2.0.0", name="pydantic")
    adv = _adv("GHSA-x", fixed=["1.10.13", "2.4.0"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [adv])],
    )
    assert findings[0].fixed_version == "2.4.0"


def test_fix_falls_back_when_installed_above_all_fixes() -> None:
    """Operator already runs past every published fix — emit the global
    minimum so the report still has *something*."""
    dep = _dep(version="9.99.0", name="pydantic")
    adv = _adv("GHSA-x", fixed=["1.10.13", "2.4.0"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [adv])],
    )
    assert findings[0].fixed_version == "1.10.13"


def test_fix_single_value_used_directly() -> None:
    dep = _dep(version="1.0", name="x")
    adv = _adv("GHSA-x", fixed=["2.0"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [adv])],
    )
    assert findings[0].fixed_version == "2.0"


def test_fix_handles_unknown_ecosystem_comparator() -> None:
    """For an ecosystem we don't know how to order, fall back to OSV order."""
    dep = _dep(version="1.0", name="x", ecosystem="Hex")
    adv = _adv("GHSA-x", fixed=["2.5", "2.0"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [adv])],
    )
    assert findings[0].fixed_version in ("2.0", "2.5")


# ---------------------------------------------------------------------------
# Alias dedup
# ---------------------------------------------------------------------------

def test_ghsa_and_pysec_with_same_cve_collapse_to_one_finding() -> None:
    """OSV returns CVE-2023-32681 under both GHSA-j8r2-6x86-q33q AND
    PYSEC-2023-74. Emit one finding, not two."""
    dep = _dep(version="2.28.0", name="requests")
    ghsa = _adv("GHSA-j8r2-6x86-q33q", fixed=["2.31.0"],
                aliases=["CVE-2023-32681", "PYSEC-2023-74"])
    pysec = _adv("PYSEC-2023-74", fixed=["2.31.0"],
                 aliases=["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [ghsa, pysec])],
    )
    assert len(findings) == 1
    # GHSA preferred over PYSEC.
    assert findings[0].advisories[0].osv_id.startswith("GHSA-")


def test_distinct_cves_keep_separate_findings() -> None:
    dep = _dep(version="2.28.0", name="requests")
    a = _adv("GHSA-1", fixed=["2.31.0"], aliases=["CVE-A"])
    b = _adv("GHSA-2", fixed=["2.32.0"], aliases=["CVE-B"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [a, b])],
    )
    ids = sorted(f.advisories[0].osv_id for f in findings)
    assert ids == ["GHSA-1", "GHSA-2"]


def test_advisory_without_cve_alias_kept_as_unique() -> None:
    """A pure GHSA without a CVE alias keys on its own ID, so it doesn't
    accidentally collapse into another."""
    dep = _dep(version="1.0", name="x")
    a = _adv("GHSA-no-cve", fixed=["2.0"], aliases=[])
    b = _adv("GHSA-also-no-cve", fixed=["2.0"], aliases=[])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [a, b])],
    )
    assert len(findings) == 2


def test_preference_order_prefers_ghsa_over_cve_over_pysec() -> None:
    dep = _dep(version="1.0", name="x")
    cve_first = _adv("CVE-2023-X", fixed=["2.0"], aliases=["CVE-2023-X"])
    pysec = _adv("PYSEC-2023-X", fixed=["2.0"], aliases=["CVE-2023-X"])
    ghsa = _adv("GHSA-X", fixed=["2.0"], aliases=["CVE-2023-X"])
    # Order in OSV response varies; result must be deterministic.
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [cve_first, pysec, ghsa])],
    )
    assert len(findings) == 1
    assert findings[0].advisories[0].osv_id == "GHSA-X"
