"""Tests for ``packages.sca.render`` (the ``/sca render`` subcommand)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from packages.sca import render


def _vuln_row(
    *,
    severity: str = "critical",
    suppressed: bool = False,
    in_kev: bool = True,
    epss: float | None = 0.94,
    fix: str = "2.15.0",
) -> Dict[str, Any]:
    return {
        "id": "sca:vuln:Maven:log4j:2.14.1:GHSA-jfh8-c2jp-5v3q",
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": "/repo/pom.xml",
        "line": 0,
        "severity": severity,
        "suppressed": suppressed,
        "suppression_reason": "ack" if suppressed else None,
        "description": "Log4Shell",
        "sca": {
            "ecosystem": "Maven",
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1",
            "advisory": {"id": "GHSA-jfh8-c2jp-5v3q",
                         "aliases": ["CVE-2021-44228"]},
            "in_kev": in_kev,
            "epss": epss,
            "fixed_version": fix,
            "cvss_score": 10.0,
        },
    }


def _hygiene_row(kind: str = "loose_pin") -> Dict[str, Any]:
    return {
        "id": f"sca:hygiene:{kind}:npm:lodash:/repo/package.json",
        "vuln_type": f"sca:hygiene:{kind}",
        "file": "/repo/package.json",
        "line": 0,
        "severity": "low",
        "suppressed": False,
        "description": "loose pin shape",
        "sca": {"ecosystem": "npm", "name": "lodash", "kind": kind},
    }


def _findings_file(tmp_path: Path, rows: List[Dict[str, Any]]) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Default behaviour
# ---------------------------------------------------------------------------

def test_writes_report_and_sarif_next_to_findings(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    rc = render.main([str(f)])
    assert rc == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.sarif").exists()


def test_report_contains_severity_summary_and_kev_count(tmp_path: Path) -> None:
    rows = [_vuln_row(severity="critical", in_kev=True),
            _vuln_row(severity="medium", in_kev=False)]
    f = _findings_file(tmp_path, rows)
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "| Critical | 1 |" in md
    assert "| Medium | 1 |" in md
    assert "KEV-listed: **1**" in md


def test_suppressed_rows_marked_in_table(tmp_path: Path) -> None:
    rows = [_vuln_row(suppressed=True)]
    f = _findings_file(tmp_path, rows)
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "(suppressed)" in md
    # Suppressed findings still appear in the count summary as suppressed.
    assert "suppressed: **1**" in md


def test_hygiene_section_emitted_when_hygiene_rows_present(
    tmp_path: Path,
) -> None:
    f = _findings_file(tmp_path, [_hygiene_row()])
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "## Hygiene findings" in md
    assert "loose_pin" in md


def test_no_findings_message(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [])
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "No findings." in md


def test_sarif_output_is_valid(tmp_path: Path) -> None:
    rows = [_vuln_row()]
    f = _findings_file(tmp_path, rows)
    render.main([str(f)])
    sarif = json.loads((tmp_path / "findings.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def test_explicit_out_paths_honoured(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    md = tmp_path / "custom" / "x.md"
    sarif = tmp_path / "custom" / "y.sarif"
    rc = render.main([str(f), "--out-md", str(md),
                      "--out-sarif", str(sarif)])
    assert rc == 0
    assert md.exists() and sarif.exists()


def test_no_md_skips_markdown(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    render.main([str(f), "--no-md"])
    assert not (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.sarif").exists()


def test_no_sarif_skips_sarif(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    render.main([str(f), "--no-sarif"])
    assert (tmp_path / "report.md").exists()
    assert not (tmp_path / "findings.sarif").exists()


def test_no_md_and_no_sarif_returns_2(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    rc = render.main([str(f), "--no-md", "--no-sarif"])
    assert rc == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_missing_file_returns_2(tmp_path: Path) -> None:
    assert render.main([str(tmp_path / "nope.json")]) == 2


def test_corrupt_json_returns_2(tmp_path: Path) -> None:
    f = tmp_path / "findings.json"
    f.write_text("{ not json", encoding="utf-8")
    assert render.main([str(f)]) == 2


def test_non_list_top_level_returns_2(tmp_path: Path) -> None:
    f = tmp_path / "findings.json"
    f.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert render.main([str(f)]) == 2
