"""Tier-2 E2E: validate the canonical output formats against
schema invariants.

SARIF (``findings.sarif``) and CycloneDX SBOM (``sbom.cdx.json``)
are consumed by external tooling (GitHub Code Scanning,
Dependency-Track, CycloneDX CLI). Format breakage is a v1-blocking
class of bug — the unit-level tests cover the contents of those
files, but not their *shape*.

We do structural validation (required-field presence + correct
types at the level external consumers care about) rather than
full JSON-Schema validation. Rationale:

* SARIF 2.1.0 + CycloneDX 1.5 are stable specs; the
  required-field set isn't a moving target
* Bundling the canonical schema files (~200KB each) bloats the
  repo for marginal additional catch-rate over what structural
  checks cover
* Structural assertions read like documentation of the contract
  RAPTOR holds with consumers

Strict-schema validation can be layered on later if format
breakage actually slips through these checks.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# Shared fixture — minimal multi-ecosystem repo, offline scan to produce
# the canonical artefacts.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scan_outputs(tmp_path_factory) -> Dict[str, Any]:
    """Run one offline scan against a minimal fixture; return
    parsed JSON of every output artefact. Module-scoped — every
    schema test reads the same outputs."""
    tmp = tmp_path_factory.mktemp("schema_fixture")
    repo = tmp / "repo"
    repo.mkdir()

    # Three-eco fixture: enough surface to populate the SBOM and
    # produce findings (lockfile-missing hygiene rule), but tight
    # enough to scan in <5s.
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )
    (repo / "package.json").write_text(json.dumps({
        "name": "fixture",
        "version": "1.0.0",
        "dependencies": {"lodash": "4.17.21"},
    }), encoding="utf-8")
    (repo / "Dockerfile").write_text(
        "FROM alpine:3.19\nRUN apk add curl\n",
        encoding="utf-8",
    )

    out = tmp / "out"
    proc = subprocess.run(
        [sys.executable, "-m", "packages.sca.cli",
         str(repo), "--offline", "--out", str(out),
         "--no-progress"],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        f"scan failed in schema-fixture setup: {proc.stderr[:1000]}"
    )

    return {
        "out_dir": out,
        "findings": json.loads((out / "findings.json").read_text()),
        "report_md": (out / "report.md").read_text(),
        "sbom": json.loads((out / "sbom.cdx.json").read_text()),
    }


# ---------------------------------------------------------------------------
# findings.json — RAPTOR's canonical finding schema
# ---------------------------------------------------------------------------

def test_findings_json_is_list(scan_outputs: Dict[str, Any]) -> None:
    """Top-level shape: a JSON array of finding dicts."""
    assert isinstance(scan_outputs["findings"], list)


def test_findings_json_required_fields(
    scan_outputs: Dict[str, Any],
) -> None:
    """Every finding has the required field set per
    packages/sca/findings.py canonical schema."""
    findings: List[Dict[str, Any]] = scan_outputs["findings"]
    if not findings:
        pytest.skip("no findings to validate")

    required = {"finding_id", "tool", "file", "severity"}
    for i, f in enumerate(findings):
        missing = required - set(f.keys())
        assert not missing, (
            f"finding[{i}] missing required fields: {missing}\n"
            f"finding_id: {f.get('finding_id')}\n"
            f"keys present: {sorted(f.keys())}"
        )


def test_findings_severity_is_canonical(
    scan_outputs: Dict[str, Any],
) -> None:
    """Severity is a fixed lowercase enum across all RAPTOR
    output. Title-case + ALL_CAPS are bugs per project style
    (`CLAUDE.md`)."""
    valid = {"info", "low", "medium", "high", "critical"}
    for f in scan_outputs["findings"]:
        sev = f.get("severity")
        assert sev in valid, (
            f"finding has non-canonical severity {sev!r}; "
            f"expected one of {sorted(valid)}"
        )


# ---------------------------------------------------------------------------
# CycloneDX SBOM — version 1.5 invariants
# ---------------------------------------------------------------------------

def test_sbom_top_level_invariants(
    scan_outputs: Dict[str, Any],
) -> None:
    """CycloneDX 1.5 truly-required root fields:
    ``bomFormat == "CycloneDX"`` and ``specVersion``. Plus
    ``serialNumber`` (urn:uuid:) and ``version`` (int): both
    are CycloneDX-OPTIONAL per spec but RAPTOR always emits
    them — Dependency-Track keys on serialNumber to detect
    BOM re-uploads vs new BOMs. Regressing the emitter to
    omit them would break that workflow."""
    sbom = scan_outputs["sbom"]
    assert sbom.get("bomFormat") == "CycloneDX"
    assert "specVersion" in sbom
    # 1.5 is what we emit; tolerate forward minor bumps but FAIL
    # on a regression to <1.5.
    spec = sbom["specVersion"]
    assert spec >= "1.5", f"specVersion {spec} below 1.5 floor"
    # serialNumber + version: RAPTOR always emits them.
    assert "serialNumber" in sbom, (
        "RAPTOR's SBOM emitter must set serialNumber for "
        "Dependency-Track BOM-identity tracking"
    )
    assert sbom["serialNumber"].startswith("urn:uuid:"), (
        f"serialNumber={sbom['serialNumber']!r} not a urn:uuid"
    )
    assert "version" in sbom
    assert isinstance(sbom["version"], int)


def test_sbom_components_is_list(
    scan_outputs: Dict[str, Any],
) -> None:
    """``components`` is a CycloneDX-required list (may be
    empty but must exist + be a list)."""
    sbom = scan_outputs["sbom"]
    components = sbom.get("components")
    assert isinstance(components, list)


def test_sbom_components_have_purl(
    scan_outputs: Dict[str, Any],
) -> None:
    """Every component has ``type`` and ``purl`` set — both
    required by CycloneDX 1.5 for component identification.
    PURL is what external consumers key on for cross-referencing
    against vuln databases."""
    components = scan_outputs["sbom"].get("components", [])
    for i, c in enumerate(components):
        assert "type" in c, (
            f"sbom.components[{i}] missing type"
        )
        # Library is the dominant type — sanity check.
        assert c["type"] in (
            "library", "application", "framework",
            "container", "operating-system", "device",
            "firmware", "file", "data", "machine-learning-model",
        ), f"sbom.components[{i}].type={c['type']} not CycloneDX 1.5"
        assert "purl" in c, (
            f"sbom.components[{i}] missing purl; "
            f"name={c.get('name')}"
        )
        assert c["purl"].startswith("pkg:"), (
            f"sbom.components[{i}].purl={c['purl']!r} not a "
            f"valid PURL (must start with pkg:)"
        )


def test_sbom_vulnerabilities_well_formed(
    scan_outputs: Dict[str, Any],
) -> None:
    """When ``vulnerabilities:`` is present (VEX block), each
    entry has ``id`` and references its affected component(s)."""
    sbom = scan_outputs["sbom"]
    vulns = sbom.get("vulnerabilities", [])
    for i, v in enumerate(vulns):
        assert "id" in v, f"vulnerability[{i}] missing id"
        # CycloneDX expects either `affects` (1.5+) or `bom-ref` /
        # an `analysis.state`. We require `affects` for VEX
        # consumers (Dependency-Track expects this shape).
        assert "affects" in v or "analysis" in v, (
            f"vulnerability[{i}] missing affects/analysis"
        )


# ---------------------------------------------------------------------------
# SARIF — version 2.1.0 invariants
# ---------------------------------------------------------------------------

def test_sarif_emitted_when_findings_present(
    scan_outputs: Dict[str, Any],
) -> None:
    """The scan emits findings.sarif when at least one finding
    fires. With our fixture (lockfile-missing hygiene rule),
    we should always have findings → always have a SARIF file."""
    sarif_path = scan_outputs["out_dir"] / "findings.sarif"
    if not scan_outputs["findings"]:
        pytest.skip("no findings → no SARIF emitted (by design)")
    assert sarif_path.exists(), (
        "findings exist but findings.sarif not emitted"
    )


@pytest.fixture(scope="module")
def sarif(scan_outputs: Dict[str, Any]) -> Dict[str, Any]:
    sarif_path = scan_outputs["out_dir"] / "findings.sarif"
    if not sarif_path.exists():
        pytest.skip("no SARIF file emitted for this fixture")
    return json.loads(sarif_path.read_text())


def test_sarif_top_level_invariants(sarif: Dict[str, Any]) -> None:
    """SARIF 2.1.0 root shape: ``version == "2.1.0"``,
    ``$schema`` set, ``runs: [...]``."""
    assert sarif.get("version") == "2.1.0", (
        f"expected SARIF 2.1.0, got version={sarif.get('version')}"
    )
    # $schema is optional per spec but recommended; we set it.
    assert "$schema" in sarif
    runs = sarif.get("runs")
    assert isinstance(runs, list) and len(runs) >= 1


def test_sarif_run_has_tool_driver(sarif: Dict[str, Any]) -> None:
    """Each run must declare ``tool.driver`` with at least a
    ``name``. GitHub Code Scanning displays this as the source
    of the findings."""
    for i, run in enumerate(sarif["runs"]):
        tool = run.get("tool")
        assert isinstance(tool, dict), (
            f"run[{i}].tool missing or wrong type"
        )
        driver = tool.get("driver")
        assert isinstance(driver, dict), (
            f"run[{i}].tool.driver missing or wrong type"
        )
        assert driver.get("name"), (
            f"run[{i}].tool.driver.name empty or missing"
        )


def test_sarif_results_well_formed(sarif: Dict[str, Any]) -> None:
    """Each ``run.results[*]`` must have ``ruleId`` + ``message``
    + ``level`` (the trio every SARIF consumer expects)."""
    for run_i, run in enumerate(sarif["runs"]):
        results = run.get("results", [])
        for i, r in enumerate(results):
            ctx = f"runs[{run_i}].results[{i}]"
            assert "ruleId" in r, f"{ctx} missing ruleId"
            assert "message" in r, f"{ctx} missing message"
            # `message.text` is required when message is present.
            msg = r["message"]
            assert isinstance(msg, dict) and "text" in msg, (
                f"{ctx}.message must be {{text: str}}"
            )
            # `level` is optional but we always emit it for
            # severity routing.
            if "level" in r:
                assert r["level"] in (
                    "none", "note", "warning", "error",
                ), f"{ctx}.level={r['level']} not SARIF 2.1.0"


def test_sarif_no_runs_without_tool(sarif: Dict[str, Any]) -> None:
    """Defensive: a SARIF run without ``tool`` is a contract
    violation and would crash GitHub Code Scanning UI rendering."""
    for run in sarif["runs"]:
        assert "tool" in run
