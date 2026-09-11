"""Tests for ``packages.sca.findings``."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from packages.sca.findings import (
    build_vuln_findings,
    severity_rank,
    write_findings_json,
)
from packages.sca.models import (
    Advisory,
    AffectedRange,
    Confidence,
    CVSSScore,
    Dependency,
    HygieneFinding,
    PinStyle,
    Reachability,
)
from packages.sca.osv import OsvResult

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _dep(name: str = "lodash", version: str = "4.17.20",
         path: Path = Path("/repo/package.json"),
         ecosystem: str = "npm",
         direct: bool = True) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(
    osv_id: str = "GHSA-x",
    aliases: list[str] | None = None,
    fixed: list[str] | None = None,
    severity_score: float = 9.8,
    severity_label: str = "critical",
    summary: str = "Test advisory",
) -> Advisory:
    cvss = CVSSScore(
        score=severity_score,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=severity_label,        # type: ignore[arg-type]
    )
    return Advisory(
        osv_id=osv_id,
        aliases=aliases if aliases is not None else ["CVE-2099-9999"],
        summary=summary,
        details="Details.",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "5.0.0"}],
        )],
        severity=cvss,
        fixed_versions=fixed or ["5.0.0"],
        references=["https://example.com"],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


class FakeKev:
    def __init__(self, hits: list[str] | None = None) -> None:
        self.hits = {h.upper() for h in (hits or [])}

    def contains(self, cve: str) -> bool:
        return cve.upper() in self.hits


class FakeEpss:
    def __init__(self, scores: dict[str, float] | None = None) -> None:
        self.s = {k.upper(): v for k, v in (scores or {}).items()}

    def scores(self, cves):
        return {c: self.s[c] for c in cves if c in self.s}

    def score(self, cve):
        return self.s.get(cve.upper())


# ---------------------------------------------------------------------------
# build_vuln_findings
# ---------------------------------------------------------------------------

def test_one_finding_per_advisory() -> None:
    d = _dep()
    adv1 = _adv(osv_id="GHSA-1", aliases=["CVE-A"])
    adv2 = _adv(osv_id="GHSA-2", aliases=["CVE-B"])
    osv_results = [OsvResult(dep_key=d.key(), advisories=[adv1, adv2])]
    findings = build_vuln_findings([d], osv_results)
    assert len(findings) == 2
    ids = {f.finding_id for f in findings}
    assert any("GHSA-1" in i for i in ids)
    assert any("GHSA-2" in i for i in ids)


def test_kev_and_epss_enrichment() -> None:
    d = _dep()
    adv = _adv(aliases=["CVE-2021-44228"])
    osv = [OsvResult(dep_key=d.key(), advisories=[adv])]
    kev = FakeKev(hits=["CVE-2021-44228"])
    epss = FakeEpss(scores={"CVE-2021-44228": 0.97})
    findings = build_vuln_findings([d], osv, kev=kev, epss=epss)
    assert findings[0].in_kev is True
    assert findings[0].epss == 0.97


def test_no_advisories_no_findings() -> None:
    d = _dep()
    osv = [OsvResult(dep_key=d.key(), advisories=[])]
    assert build_vuln_findings([d], osv) == []


def test_finding_for_dep_with_no_osv_result() -> None:
    """If osv_results is missing the dep entirely, no findings emit."""
    d = _dep()
    assert build_vuln_findings([d], []) == []


def test_smallest_fix_picked_via_ecosystem_comparator() -> None:
    d = _dep()
    adv = _adv(fixed=["5.0.1", "4.99.99", "5.0.0"])
    osv = [OsvResult(dep_key=d.key(), advisories=[adv])]
    f = build_vuln_findings([d], osv)[0]
    assert f.fixed_version == "4.99.99"


def test_related_findings_cross_reference() -> None:
    d = _dep()
    # Distinct CVE aliases so the alias-dedup pass doesn't collapse them.
    adv1 = _adv(osv_id="GHSA-1", aliases=["CVE-A"])
    adv2 = _adv(osv_id="GHSA-2", aliases=["CVE-B"])
    osv = [OsvResult(dep_key=d.key(), advisories=[adv1, adv2])]
    findings = build_vuln_findings([d], osv)
    f1, f2 = findings
    assert f2.finding_id in f1.related_findings
    assert f1.finding_id in f2.related_findings
    # No self-reference.
    assert f1.finding_id not in f1.related_findings


def test_crafted_alias_advisory_cannot_defang_real_finding() -> None:
    """Regression: a crafted GHSA record sharing the real CVE
    alias (severity none, understated fix, benign summary) must not
    shape the merged finding — severity, fix version, and summary all
    come from the genuine record; the crafted one only rides along."""
    d = _dep(name="pkg", version="1.2.0", ecosystem="PyPI")
    real = _adv(
        osv_id="PYSEC-2024-1", aliases=["CVE-2024-0001"],
        fixed=["2.0.1"], severity_score=9.8, severity_label="critical",
        summary="Genuine critical advisory",
    )
    crafted = _adv(
        osv_id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2024-0001"],
        fixed=["1.0.0"], severity_score=0.0, severity_label="none",
        summary="Nothing to see here",
    )
    osv = [OsvResult(dep_key=d.key(), advisories=[real, crafted])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.fixed_version == "2.0.1"
    # The genuine record is the face of the finding.
    assert "PYSEC-2024-1" in f.finding_id
    assert f.advisories[0].osv_id == "PYSEC-2024-1"
    assert f.advisories[0].summary == "Genuine critical advisory"
    # The crafted record is kept for transparency, never dropped.
    assert {a.osv_id for a in f.advisories} == {
        "PYSEC-2024-1", "GHSA-aaaa-bbbb-cccc",
    }


def test_alias_merge_prefers_ghsa_on_severity_tie() -> None:
    """Honest GHSA + PYSEC records for the same CVE at the same
    severity: GHSA stays the representative (the pre-fix preference,
    now applied only among equal-severity records)."""
    d = _dep()
    pysec = _adv(osv_id="PYSEC-2024-2", aliases=["CVE-2024-0002"])
    ghsa = _adv(osv_id="GHSA-dddd-eeee-ffff", aliases=["CVE-2024-0002"])
    osv = [OsvResult(dep_key=d.key(), advisories=[pysec, ghsa])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    assert findings[0].advisories[0].osv_id == "GHSA-dddd-eeee-ffff"
    assert len(findings[0].advisories) == 2


def test_intersecting_cve_alias_sets_merge() -> None:
    """Records whose alias sets intersect on any identifier merge into
    one finding; every member stays visible on the merged record."""
    d = _dep()
    one = _adv(osv_id="GHSA-1", aliases=["CVE-A"])
    both = _adv(osv_id="GHSA-2", aliases=["CVE-A", "CVE-B"])
    osv = [OsvResult(dep_key=d.key(), advisories=[one, both])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    assert {a.osv_id for a in findings[0].advisories} == {"GHSA-1", "GHSA-2"}


def test_ghsa_rustsec_pair_without_cve_merges() -> None:
    """A GHSA/RUSTSEC pair aliasing each other with no CVE alias at all
    collapses to one finding carrying the group-max severity, with both
    records visible on the merged finding."""
    d = _dep(name="tokio", version="1.28.0", ecosystem="Cargo")
    ghsa = _adv(
        osv_id="GHSA-rr8g-9fpq-6wmg", aliases=["RUSTSEC-2025-0023"],
        severity_score=3.1, severity_label="low", fixed=["1.38.2"],
    )
    rustsec = _adv(
        osv_id="RUSTSEC-2025-0023", aliases=["GHSA-rr8g-9fpq-6wmg"],
        severity_score=5.3, severity_label="medium", fixed=["1.38.2"],
    )
    osv = [OsvResult(dep_key=d.key(), advisories=[ghsa, rustsec])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert {a.osv_id for a in f.advisories} == {
        "GHSA-rr8g-9fpq-6wmg", "RUSTSEC-2025-0023",
    }


def test_one_sided_alias_merges() -> None:
    """One record naming the other as an alias suffices — the named
    record does not need to reciprocate for the pair to merge."""
    d = _dep(name="tokio", version="1.0.0", ecosystem="Cargo")
    ghsa = _adv(osv_id="GHSA-4q83-7cq4-p6wg", aliases=["RUSTSEC-2023-0005"])
    rustsec = _adv(osv_id="RUSTSEC-2023-0005", aliases=[])
    osv = [OsvResult(dep_key=d.key(), advisories=[ghsa, rustsec])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1


def test_transitive_alias_chain_merges() -> None:
    """A aliases B and B aliases C: all three collapse into one finding
    even though A and C share no identifier directly."""
    d = _dep()
    a = _adv(osv_id="GHSA-a", aliases=["GHSA-b"])
    b = _adv(osv_id="GHSA-b", aliases=["GHSA-c"])
    c = _adv(osv_id="GHSA-c", aliases=[])
    osv = [OsvResult(dep_key=d.key(), advisories=[a, b, c])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    assert {x.osv_id for x in findings[0].advisories} == {
        "GHSA-a", "GHSA-b", "GHSA-c",
    }


def test_disjoint_identifier_sets_do_not_merge() -> None:
    """Advisories on the same package whose identifier sets are fully
    disjoint stay separate findings — same-dep is not an alias
    relationship."""
    d = _dep()
    one = _adv(osv_id="GHSA-1", aliases=["RUSTSEC-2024-0001"])
    other = _adv(osv_id="GHSA-2", aliases=["CVE-B"])
    third = _adv(osv_id="RUSTSEC-2024-0003", aliases=[])
    osv = [OsvResult(dep_key=d.key(), advisories=[one, other, third])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 3


def test_crafted_bridge_alias_cannot_suppress_either_finding() -> None:
    """A crafted record whose fabricated aliases bridge two genuine
    advisories consolidates them into one finding but suppresses
    nothing: the merged finding carries the max severity across all
    members, the highest applicable fix, a genuine record as its face,
    and every member advisory visible."""
    d = _dep(name="pkg", version="1.2.0", ecosystem="PyPI")
    real_a = _adv(
        osv_id="PYSEC-2024-10", aliases=["CVE-2024-0010"],
        fixed=["2.0.1"], severity_score=9.8, severity_label="critical",
        summary="Genuine critical advisory",
    )
    real_b = _adv(
        osv_id="PYSEC-2024-11", aliases=["CVE-2024-0011"],
        fixed=["1.9.0"], severity_score=5.3, severity_label="medium",
        summary="Genuine medium advisory",
    )
    crafted = _adv(
        osv_id="GHSA-aaaa-bbbb-cccc",
        aliases=["CVE-2024-0010", "CVE-2024-0011"],
        fixed=["1.0.0"], severity_score=0.0, severity_label="none",
        summary="Nothing to see here",
    )
    osv = [OsvResult(dep_key=d.key(), advisories=[real_a, real_b, crafted])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.fixed_version == "2.0.1"
    assert f.advisories[0].osv_id == "PYSEC-2024-10"
    assert f.advisories[0].summary == "Genuine critical advisory"
    assert {a.osv_id for a in f.advisories} == {
        "PYSEC-2024-10", "PYSEC-2024-11", "GHSA-aaaa-bbbb-cccc",
    }
    assert {"CVE-2024-0010", "CVE-2024-0011"} <= set(
        alias for a in f.advisories for alias in a.aliases
    )


def test_alias_grouping_is_order_independent() -> None:
    """Group membership does not depend on advisory input order."""
    import itertools

    d = _dep()
    advs = [
        _adv(osv_id="GHSA-a", aliases=["GHSA-b"]),
        _adv(osv_id="GHSA-b", aliases=[]),
        _adv(osv_id="GHSA-x", aliases=["CVE-X"]),
        _adv(osv_id="RUSTSEC-2024-0009", aliases=["CVE-X"]),
        _adv(osv_id="OSV-lonely", aliases=[]),
    ]
    expected: set[frozenset[str]] | None = None
    for perm in itertools.permutations(advs):
        osv = [OsvResult(dep_key=d.key(), advisories=list(perm))]
        findings = build_vuln_findings([d], osv)
        groups = {
            frozenset(a.osv_id for a in f.advisories) for f in findings
        }
        if expected is None:
            expected = groups
        assert groups == expected
    assert expected == {
        frozenset({"GHSA-a", "GHSA-b"}),
        frozenset({"GHSA-x", "RUSTSEC-2024-0009"}),
        frozenset({"OSV-lonely"}),
    }


def test_severity_falls_back_to_medium_without_cvss() -> None:
    d = _dep()
    adv = Advisory(
        osv_id="GHSA-x", aliases=[], summary="", details="",
        affected=[], severity=None, fixed_versions=[],
        references=[],
    )
    f = build_vuln_findings([d], [OsvResult(dep_key=d.key(), advisories=[adv])])[0]
    assert f.severity == "medium"


def test_transitive_depth_inferred_from_direct_flag() -> None:
    direct = _dep(direct=True)
    transitive = _dep(direct=False)
    adv = _adv()
    findings = build_vuln_findings(
        [direct, transitive],
        [
            OsvResult(dep_key=direct.key(), advisories=[adv]),
            OsvResult(dep_key=transitive.key(), advisories=[adv]),
        ],
    )
    by_id = {f.dependency.direct: f for f in findings}
    assert by_id[True].transitive_depth == 0
    assert by_id[False].transitive_depth == 1


# ---------------------------------------------------------------------------
# write_findings_json
# ---------------------------------------------------------------------------

def test_write_findings_json_shape(tmp_path: Path) -> None:
    d = _dep()
    adv = _adv(aliases=["CVE-2021-44228"])
    findings = build_vuln_findings(
        [d],
        [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    hygiene = [HygieneFinding(
        finding_id="sca:hygiene:loose_pin:npm:lodash:/x",
        kind="loose_pin",
        dependency=d,
        detail="loose pin",
        severity="low",
        confidence=Confidence("high", reason="t"),
    )]
    out = tmp_path / "findings.json"
    n = write_findings_json(out, vuln_findings=findings,
                            hygiene_findings=hygiene)
    assert n == 2
    data = json.loads(out.read_text())
    assert isinstance(data, list)
    types = {row["vuln_type"] for row in data}
    assert "sca:vulnerable_dependency" in types
    assert "sca:hygiene:loose_pin" in types
    vuln_row = next(r for r in data
                    if r["vuln_type"] == "sca:vulnerable_dependency")
    assert vuln_row["sca"]["ecosystem"] == "npm"
    assert vuln_row["sca"]["name"] == "lodash"
    assert vuln_row["sca"]["fixed_version"] == "5.0.0"
    assert vuln_row["sca"]["advisory"]["id"] == "GHSA-x"


def test_write_findings_json_empty_inputs(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    n = write_findings_json(out)
    assert n == 0
    assert json.loads(out.read_text()) == []


def test_severity_fallback_label_used_over_medium_degrade() -> None:
    """A CVSS_V4-only advisory whose vector couldn't be scored carries
    the database-provided label; the finding gates at that severity
    instead of the blanket medium."""
    d = _dep()
    adv = _adv()
    adv.severity = None
    adv.severity_fallback = "critical"
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert findings[0].severity == "critical"
    assert findings[0].cvss_score is None   # no fabricated numeric score

    adv_no_label = _adv()
    adv_no_label.severity = None
    adv_no_label.severity_fallback = None
    findings2 = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv_no_label])],
    )
    assert findings2[0].severity == "medium"


def test_write_findings_json_scan_health_row(tmp_path: Path) -> None:
    """Scan-level degradation is recorded as an info-severity row so CI
    consumers of findings.json can see incomplete advisory coverage."""
    out = tmp_path / "findings.json"
    n = write_findings_json(out, scan_health=[{
        "kind": "osv_lookup_degraded",
        "detail": "OSV lookups failed transiently for 3 query slot(s)",
        "evidence": {"failed_lookups": 3, "total_deps": 10},
    }])
    assert n == 1
    row = json.loads(out.read_text())[0]
    assert row["vuln_type"] == "sca:scan_health:osv_lookup_degraded"
    assert row["severity"] == "info"
    assert row["suppressed"] is False
    assert row["sca"]["kind"] == "osv_lookup_degraded"
    assert row["sca"]["failed_lookups"] == 3
    assert row["sca"]["total_deps"] == 10
    assert "transiently" in row["description"]


def test_scan_health_row_never_trips_thresholds(tmp_path: Path) -> None:
    """The degradation marker must not fail existing severity gates —
    it is informational; pipelines gate on it explicitly if desired."""
    from packages.sca.thresholds import ThresholdConfig, evaluate
    out = tmp_path / "findings.json"
    write_findings_json(out, scan_health=[{
        "kind": "osv_lookup_degraded", "detail": "d", "evidence": {},
    }])
    rows = json.loads(out.read_text())
    passed, fails = evaluate(rows, ThresholdConfig(fail_on_severity="info"))
    assert passed and fails == []


def test_atomic_write_no_partial_file(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    write_findings_json(out)
    leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


def test_severity_rank_helper() -> None:
    assert severity_rank("critical") > severity_rank("high")
    assert severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low")
    assert severity_rank("low") > severity_rank("info")


# ---------------------------------------------------------------------------
# Commented-out dep handling — extends the existing vuln-side behaviour
# to hygiene / supply_chain / license findings.
# ---------------------------------------------------------------------------

def test_hygiene_finding_downgraded_to_info_when_commented() -> None:
    """A `# pkg==X` line that surfaces via --include-commented
    should produce hygiene findings at ``info`` severity (the
    operator doesn't want CI gated on commented hints).
    Mirrors the vuln-finding downgrade in _vuln_finding_to_row."""
    from packages.sca.findings import _hygiene_finding_to_row
    from packages.sca.models import HygieneFinding
    d = _dep()
    d.commented_out = True
    f = HygieneFinding(
        finding_id="x", kind="loose_pin", dependency=d,
        detail="t", severity="low",
        confidence=Confidence("high", reason="t"),
    )
    row = _hygiene_finding_to_row(f)
    assert row["severity"] == "info"
    assert row["sca"]["commented_out"] is True


def test_hygiene_finding_retains_severity_when_uncommented() -> None:
    """Non-commented entries keep their original severity."""
    from packages.sca.findings import _hygiene_finding_to_row
    from packages.sca.models import HygieneFinding
    d = _dep()
    assert not d.commented_out
    f = HygieneFinding(
        finding_id="x", kind="loose_pin", dependency=d,
        detail="t", severity="medium",
        confidence=Confidence("high", reason="t"),
    )
    row = _hygiene_finding_to_row(f)
    assert row["severity"] == "medium"
    assert row["sca"]["commented_out"] is False


def test_vuln_row_includes_commented_out_in_sca_block() -> None:
    """The vuln-finding's ``sca`` sub-dict now surfaces
    ``commented_out`` so JSON consumers see the same signal
    the SBOM properties already carry."""
    from packages.sca.findings import _vuln_finding_to_row
    from packages.sca.models import VulnFinding
    d = _dep()
    d.commented_out = True
    f = VulnFinding(
        finding_id="x", dependency=d, advisories=[],
        severity="high", in_kev=False, epss=None,
        fixed_version=None,
        reachability=Reachability(
            verdict="not_evaluated",
            confidence=Confidence("low", reason="t"),
            evidence=(),
        ),
        cvss_score=None, cvss_vector=None,
        version_match_confidence=Confidence("high", reason="t"),
        exposure_factor=1.0, transitive_depth=0,
    )
    row = _vuln_finding_to_row(f)
    assert row["sca"]["commented_out"] is True
    # Note: the vuln-side severity downgrade happens at
    # ``build_vuln_findings`` time (not at row emission), so
    # this row-builder test passes through whatever severity
    # the VulnFinding already carries.


# ---------------------------------------------------------------------------
# Advisory CWE ids in findings.json (P40)
# ---------------------------------------------------------------------------

class TestAdvisoryCweExport:
    def test_cwe_ids_surfaced(self):
        from packages.sca.findings import _advisory_summary

        adv = _adv()
        adv.cwe_ids = ["CWE-502", "CWE-400"]
        out = _advisory_summary(adv)
        assert out["cwe_ids"] == ["CWE-502", "CWE-400"]

    def test_no_cwe_ids_key_when_absent(self):
        from packages.sca.findings import _advisory_summary

        out = _advisory_summary(_adv())
        assert "cwe_ids" not in out


# ---------------------------------------------------------------------------
# Corridor (range-pin) findings — version_match_confidence
# ---------------------------------------------------------------------------

def test_corridor_finding_caps_version_match_confidence() -> None:
    """A finding matched through a version corridor (range pin, no
    concrete installed version) must not claim exact-match confidence."""
    import dataclasses
    d = dataclasses.replace(
        _dep(), version=None, pin_style=PinStyle.RANGE,
        version_ceiling="5.0.0",
    )
    adv = _adv()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert len(findings) == 1
    vmc = findings[0].version_match_confidence
    assert vmc.level == "medium"
    assert "corridor" in vmc.reason
    assert "5.0.0" in vmc.reason
    # The finding id survives a None version.
    assert "@" not in findings[0].finding_id.split(":", 2)[0]
    assert ":*:" in findings[0].finding_id


def test_corridor_finding_keeps_lower_parser_confidence() -> None:
    import dataclasses
    d = dataclasses.replace(
        _dep(), version=None, pin_style=PinStyle.RANGE,
        version_floor="1.0.0",
        parser_confidence=Confidence("low", reason="heuristic"),
    )
    adv = _adv()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert findings[0].version_match_confidence.level == "low"


def test_related_findings_capped() -> None:
    """The sibling cross-reference list is quadratic in a dep's
    advisory count — distro source packages carry hundreds of
    advisories, which put tens of MB of id strings into one
    findings.json before the cap."""
    d = _dep()
    advisories = [
        _adv(osv_id=f"OSV-{i:04d}", aliases=[f"CVE-2099-{i:04d}"])
        for i in range(40)
    ]
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=advisories)],
    )
    assert len(findings) == 40
    from packages.sca.findings import _MAX_RELATED_FINDINGS
    assert all(
        len(f.related_findings) <= _MAX_RELATED_FINDINGS
        for f in findings
    )
    # Still navigational — every finding keeps some siblings.
    assert all(f.related_findings for f in findings)


# ---------------------------------------------------------------------------
# Fork-tag prerelease false-positive filter
# ---------------------------------------------------------------------------

def test_fork_tag_prerelease_filtered_from_findings() -> None:
    """A Cargo dep at 0.4.3-succinct with a SEMVER advisory fixed at
    0.4.3 must be dropped — the fork-tag suffix is an org tag, not a
    genuine prerelease."""
    d = _dep(
        name="p3-challenger", version="0.4.3-succinct",
        ecosystem="crates.io",
    )
    adv = Advisory(
        osv_id="GHSA-vj64-rjf3-w3v7",
        aliases=["CVE-2026-46654"],
        summary="transcript malleability",
        details="",
        affected=[AffectedRange(
            type="SEMVER",
            events=[{"introduced": "0"}, {"fixed": "0.4.3"}],
        )],
        severity=CVSSScore(
            score=7.4,
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            severity="high",
        ),
        fixed_versions=["0.4.3"],
        references=[],
    )
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert findings == [], (
        "fork-tagged version at the fix base should not produce a finding"
    )


def test_genuine_prerelease_not_filtered() -> None:
    """A genuine prerelease (rc.1) at the fix version must still produce
    a finding — only fork tags are filtered."""
    d = _dep(
        name="some-crate", version="2.0.0-rc.1",
        ecosystem="crates.io",
    )
    adv = Advisory(
        osv_id="GHSA-test",
        aliases=["CVE-2099-0001"],
        summary="test",
        details="",
        affected=[AffectedRange(
            type="SEMVER",
            events=[{"introduced": "0"}, {"fixed": "2.0.0"}],
        )],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
        ),
        fixed_versions=["2.0.0"],
        references=[],
    )
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert len(findings) == 1, (
        "genuine prerelease should still produce a finding"
    )


def test_branch_snapshot_prerelease_not_filtered() -> None:
    """A vulnerable ``1.0.0-master`` pin is an upstream BRANCH
    snapshot, not a fork — the server-confirmed match must survive
    the fork-tag post-filter. Pre-fix, any digit-free prerelease
    token counted as a fork tag and the finding vanished."""
    d = _dep(name="some-pkg", version="1.0.0-master", ecosystem="npm")
    adv = Advisory(
        osv_id="GHSA-branch",
        aliases=["CVE-2099-0002"],
        summary="test",
        details="",
        affected=[AffectedRange(
            type="SEMVER",
            events=[{"introduced": "0"}, {"fixed": "1.0.0"}],
        )],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
        ),
        fixed_versions=["1.0.0"],
        references=[],
    )
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert len(findings) == 1, (
        "branch-snapshot prerelease must still produce a finding"
    )


def test_explicit_fork_tag_still_filtered() -> None:
    """The genuine fork-tag class (org/fork suffix at the fix base,
    e.g. ``1.0.0-fork.mycorp``) stays pruned — the filter's original
    purpose survives the tightening."""
    d = _dep(name="some-pkg", version="1.0.0-fork.mycorp", ecosystem="npm")
    adv = Advisory(
        osv_id="GHSA-fork",
        aliases=["CVE-2099-0003"],
        summary="test",
        details="",
        affected=[AffectedRange(
            type="SEMVER",
            events=[{"introduced": "0"}, {"fixed": "1.0.0"}],
        )],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
        ),
        fixed_versions=["1.0.0"],
        references=[],
    )
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[adv])],
    )
    assert findings == [], (
        "explicit fork tag at the fix base should stay filtered"
    )


def test_range_less_member_keeps_merged_group_unpruned() -> None:
    """A merged group containing a member with no affected ranges is
    never pruned by the fork-tag post-filter: that member's match
    rests on the server's verdict alone, and a sibling's rejected
    SEMVER ranges must not speak for it."""
    d = _dep(name="some-pkg", version="1.0.0-fork.mycorp", ecosystem="npm")
    rangeless = Advisory(
        osv_id="RUSTSEC-2099-0100",
        aliases=["GHSA-fork-pair"],
        summary="server-confirmed match",
        details="",
        affected=[],
        severity=None,
        fixed_versions=["1.0.0"],
        references=[],
    )
    semver_only = _adv(
        osv_id="GHSA-fork-pair",
        aliases=["RUSTSEC-2099-0100"],
        fixed=["1.0.0"],
    )
    semver_only.affected[:] = [AffectedRange(
        type="SEMVER",
        events=[{"introduced": "0"}, {"fixed": "1.0.0"}],
    )]
    findings = build_vuln_findings(
        [d],
        [OsvResult(dep_key=d.key(), advisories=[rangeless, semver_only])],
    )
    assert len(findings) == 1
    assert {a.osv_id for a in findings[0].advisories} == {
        "RUSTSEC-2099-0100", "GHSA-fork-pair",
    }


def test_bridge_alias_cannot_extend_suppression_to_new_advisory() -> None:
    """A crafted record aliasing both a long-suppressed advisory and a
    genuine new one merges all three, but the existing advisory_id
    suppression must not swallow the merged finding: the genuine
    record's own identifiers do not carry the suppressed id."""
    from packages.sca.suppressions import SuppressionEntry, apply_to_findings

    d = _dep(name="tokio", version="1.0.0", ecosystem="Cargo")
    suppressed_old = _adv(
        osv_id="RUSTSEC-2020-0001", aliases=[],
        severity_score=5.3, severity_label="medium",
    )
    crafted = _adv(
        osv_id="GHSA-bridge", aliases=["RUSTSEC-2020-0001", "GHSA-new-crit"],
        severity_score=0.0, severity_label="none",
    )
    victim = _adv(
        osv_id="GHSA-new-crit", aliases=[],
        severity_score=9.8, severity_label="critical",
    )
    osv = [OsvResult(
        dep_key=d.key(), advisories=[suppressed_old, crafted, victim],
    )]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    entry = SuppressionEntry(reason="accepted", advisory_id="RUSTSEC-2020-0001")
    assert apply_to_findings(findings, [entry]) == 0
    assert findings[0].suppressed is False
    assert findings[0].severity == "critical"


def test_bridge_alias_cannot_extend_finding_id_suppression() -> None:
    """When the newcomer's severity does not exceed the suppressed
    advisory's, the merged finding keeps the previously suppressed
    finding_id — a finding_id entry must still not swallow it, because
    the newcomer does not carry the representative's id."""
    from packages.sca.suppressions import SuppressionEntry, apply_to_findings

    d = _dep(name="tokio", version="1.0.0", ecosystem="Cargo")
    suppressed_old = _adv(
        osv_id="GHSA-old-med", aliases=[],
        severity_score=5.3, severity_label="medium",
    )
    old_fid = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[suppressed_old])],
    )[0].finding_id
    crafted = _adv(
        osv_id="GHSA-bridge", aliases=["GHSA-old-med", "RUSTSEC-2026-0777"],
        severity_score=0.0, severity_label="none",
    )
    newcomer = _adv(
        osv_id="RUSTSEC-2026-0777", aliases=[],
        severity_score=5.3, severity_label="medium",
    )
    osv = [OsvResult(
        dep_key=d.key(), advisories=[suppressed_old, crafted, newcomer],
    )]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    assert findings[0].finding_id == old_fid
    entry = SuppressionEntry(reason="accepted", finding_id=old_fid)
    assert apply_to_findings(findings, [entry]) == 0
    assert findings[0].suppressed is False


def test_finding_id_suppression_still_covers_genuine_alias_pair() -> None:
    """A mutual alias pair merged into one finding stays suppressible
    by its finding_id: every member carries the representative's id."""
    from packages.sca.suppressions import SuppressionEntry, apply_to_findings

    d = _dep(name="tokio", version="1.28.0", ecosystem="Cargo")
    ghsa = _adv(osv_id="GHSA-rr8g-9fpq-6wmg", aliases=["RUSTSEC-2025-0023"])
    rustsec = _adv(osv_id="RUSTSEC-2025-0023", aliases=["GHSA-rr8g-9fpq-6wmg"])
    osv = [OsvResult(dep_key=d.key(), advisories=[ghsa, rustsec])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    entry = SuppressionEntry(
        reason="accepted", finding_id=findings[0].finding_id,
    )
    assert apply_to_findings(findings, [entry]) == 1
    assert findings[0].suppressed is True


def test_suppression_still_covers_genuine_alias_pair() -> None:
    """A mutual GHSA/RUSTSEC alias pair merged into one finding stays
    suppressible by either id: both members carry both identifiers."""
    from packages.sca.suppressions import SuppressionEntry, apply_to_findings

    d = _dep(name="tokio", version="1.28.0", ecosystem="Cargo")
    ghsa = _adv(osv_id="GHSA-rr8g-9fpq-6wmg", aliases=["RUSTSEC-2025-0023"])
    rustsec = _adv(osv_id="RUSTSEC-2025-0023", aliases=["GHSA-rr8g-9fpq-6wmg"])
    osv = [OsvResult(dep_key=d.key(), advisories=[ghsa, rustsec])]
    findings = build_vuln_findings([d], osv)
    assert len(findings) == 1
    entry = SuppressionEntry(reason="accepted", advisory_id="RUSTSEC-2025-0023")
    assert apply_to_findings(findings, [entry]) == 1
    assert findings[0].suppressed is True


def test_write_findings_json_atomic_no_predictable_tmp(
    tmp_path: Path,
) -> None:
    """Content round-trips through the shared atomic-write primitive
    and no predictable ``<name>.json.tmp`` sibling is left behind
    (nor pre-creatable: a squatted sibling must not break the write)."""
    out = tmp_path / "findings.json"
    squat = tmp_path / "findings.json.tmp"
    squat.write_text("squatted", encoding="utf-8")

    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[_adv()])],
    )
    n = write_findings_json(out, vuln_findings=findings)
    assert n == 1

    rows = json.loads(out.read_text(encoding="utf-8"))
    assert rows[0]["vuln_type"] == "sca:vulnerable_dependency"
    assert rows[0]["sca"]["name"] == "lodash"
    # The squatted predictable-name sibling was never used.
    assert squat.read_text(encoding="utf-8") == "squatted"
    # No stray temp files remain.
    leftovers = {p.name for p in tmp_path.iterdir()} - {
        "findings.json", "findings.json.tmp",
    }
    assert leftovers == set()
