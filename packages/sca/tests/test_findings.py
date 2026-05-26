"""Tests for ``packages.sca.findings``."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from packages.sca.findings import (
    build_vuln_findings,
    severity_rank,
    write_findings_json,
)
from packages.sca.models import (
    AffectedRange,
    Advisory,
    CVSSScore,
    Confidence,
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
    aliases: List[str] | None = None,
    fixed: List[str] | None = None,
    severity_score: float = 9.8,
    severity_label: str = "critical",
) -> Advisory:
    cvss = CVSSScore(
        score=severity_score,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=severity_label,        # type: ignore[arg-type]
    )
    return Advisory(
        osv_id=osv_id,
        aliases=aliases or ["CVE-2099-9999"],
        summary="Test advisory",
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
    def __init__(self, hits: List[str] | None = None) -> None:
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
    vuln_row = [r for r in data
                if r["vuln_type"] == "sca:vulnerable_dependency"][0]
    assert vuln_row["sca"]["ecosystem"] == "npm"
    assert vuln_row["sca"]["name"] == "lodash"
    assert vuln_row["sca"]["fixed_version"] == "5.0.0"
    assert vuln_row["sca"]["advisory"]["id"] == "GHSA-x"


def test_write_findings_json_empty_inputs(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    n = write_findings_json(out)
    assert n == 0
    assert json.loads(out.read_text()) == []


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
    from packages.sca.models import HygieneFinding
    from packages.sca.findings import _hygiene_finding_to_row
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
    from packages.sca.models import HygieneFinding
    from packages.sca.findings import _hygiene_finding_to_row
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
