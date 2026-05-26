"""Tests for cross-tool related_findings linking (``packages.sca.cross_tool``)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.cross_tool import (
    _build_cve_index,
    _collect_sarif_refs,
    _extract_cves_from_finding,
    _extract_cves_from_sarif_result,
    link_related_findings,
)


def _write_findings(path: Path, findings: list) -> None:
    path.write_text(json.dumps(findings), encoding="utf-8")


def _write_sarif(path: Path, results: list, tool_name: str = "semgrep") -> None:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "rules": []}},
            "results": results,
        }],
    }
    path.write_text(json.dumps(sarif), encoding="utf-8")


# ---------------------------------------------------------------------------
# CVE extraction from SCA findings
# ---------------------------------------------------------------------------

def test_extract_cves_from_finding_osv_id():
    f = {"advisories": [{"osv_id": "CVE-2024-1234", "aliases": []}]}
    assert "CVE-2024-1234" in _extract_cves_from_finding(f)


def test_extract_cves_from_finding_aliases():
    f = {"advisories": [{"osv_id": "GHSA-abc-def-ghi", "aliases": ["CVE-2024-5678"]}]}
    cves = _extract_cves_from_finding(f)
    assert "CVE-2024-5678" in cves
    assert "GHSA-ABC-DEF-GHI" in cves


def test_extract_cves_from_empty_finding():
    assert _extract_cves_from_finding({}) == set()


# ---------------------------------------------------------------------------
# CVE index
# ---------------------------------------------------------------------------

def test_build_cve_index():
    findings = [
        {"finding_id": "sca:vuln:PyPI:requests:2.31.0:CVE-2024-1234",
         "advisories": [{"osv_id": "CVE-2024-1234", "aliases": ["GHSA-xxxx-xxxx-xxxx"]}]},
        {"finding_id": "sca:vuln:npm:lodash:4.17.21:CVE-2024-5678",
         "advisories": [{"osv_id": "CVE-2024-5678", "aliases": []}]},
    ]
    idx = _build_cve_index(findings)
    assert "CVE-2024-1234" in idx
    assert idx["CVE-2024-1234"] == ["sca:vuln:PyPI:requests:2.31.0:CVE-2024-1234"]
    assert "CVE-2024-5678" in idx
    assert "GHSA-XXXX-XXXX-XXXX" in idx


# ---------------------------------------------------------------------------
# SARIF CVE extraction
# ---------------------------------------------------------------------------

def test_extract_cves_from_sarif_message():
    result = {
        "ruleId": "js/sql-injection",
        "message": {"text": "This relates to CVE-2024-9999 in lodash"},
    }
    cves = _extract_cves_from_sarif_result(result, {"tool": {"driver": {"rules": []}}})
    assert "CVE-2024-9999" in cves


def test_extract_cves_from_sarif_properties_tags():
    result = {
        "ruleId": "py/command-injection",
        "message": {"text": "command injection"},
        "properties": {"tags": ["CVE-2024-1111", "security"]},
    }
    cves = _extract_cves_from_sarif_result(result, {"tool": {"driver": {"rules": []}}})
    assert "CVE-2024-1111" in cves


def test_extract_cves_from_sarif_properties_cve_field():
    result = {
        "ruleId": "rule1",
        "message": {"text": "something"},
        "properties": {"cve": "CVE-2024-3333"},
    }
    cves = _extract_cves_from_sarif_result(result, {"tool": {"driver": {"rules": []}}})
    assert "CVE-2024-3333" in cves


def test_extract_cves_from_sarif_help_uri():
    result = {"ruleId": "rule1", "message": {"text": "x"}}
    run = {
        "tool": {"driver": {"rules": [
            {"id": "rule1", "helpUri": "https://cve.org/CVE-2024-7777"},
        ]}},
    }
    cves = _extract_cves_from_sarif_result(result, run)
    assert "CVE-2024-7777" in cves


# ---------------------------------------------------------------------------
# SARIF collection
# ---------------------------------------------------------------------------

def test_collect_sarif_refs(tmp_path: Path):
    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()
    _write_sarif(sarif_dir / "findings.sarif", [
        {
            "ruleId": "py/sqli",
            "message": {"text": "SQL injection related to CVE-2024-1234"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 42},
                },
            }],
        },
    ])
    refs = _collect_sarif_refs([sarif_dir])
    assert "CVE-2024-1234" in refs
    assert len(refs["CVE-2024-1234"]) == 1
    assert refs["CVE-2024-1234"][0].startswith("sarif:semgrep:")


def test_collect_sarif_refs_empty_dir(tmp_path: Path):
    d = tmp_path / "empty"
    d.mkdir()
    assert _collect_sarif_refs([d]) == {}


def test_collect_sarif_refs_nonexistent_dir(tmp_path: Path):
    assert _collect_sarif_refs([tmp_path / "nope"]) == {}


# ---------------------------------------------------------------------------
# End-to-end linking
# ---------------------------------------------------------------------------

def test_link_related_findings_adds_cross_refs(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    _write_findings(findings_path, [
        {
            "finding_id": "sca:vuln:PyPI:requests:2.31.0:CVE-2024-1234",
            "advisories": [{"osv_id": "CVE-2024-1234", "aliases": []}],
            "related_findings": [],
        },
    ])

    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()
    _write_sarif(sarif_dir / "combined.sarif", [
        {
            "ruleId": "py/sqli",
            "message": {"text": "SQL injection via CVE-2024-1234"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "db.py"},
                    "region": {"startLine": 10},
                },
            }],
        },
    ])

    added = link_related_findings(findings_path, [sarif_dir])
    assert added == 1

    updated = json.loads(findings_path.read_text())
    related = updated[0]["related_findings"]
    assert any(r.startswith("sarif:") for r in related)


def test_link_related_findings_preserves_existing(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    _write_findings(findings_path, [
        {
            "finding_id": "sca:vuln:PyPI:pkg:1.0:CVE-2024-9999",
            "advisories": [{"osv_id": "CVE-2024-9999", "aliases": []}],
            "related_findings": ["sca:vuln:PyPI:pkg:1.0:GHSA-xxxx-xxxx-xxxx"],
        },
    ])

    sarif_dir = tmp_path / "codeql"
    sarif_dir.mkdir()
    _write_sarif(sarif_dir / "results.sarif", [
        {
            "ruleId": "py/ssrf",
            "message": {"text": "SSRF — see CVE-2024-9999"},
            "fingerprints": {"primaryLocationLineHash": "abc123"},
        },
    ], tool_name="codeql")

    added = link_related_findings(findings_path, [sarif_dir])
    assert added == 1

    updated = json.loads(findings_path.read_text())
    related = updated[0]["related_findings"]
    assert "sca:vuln:PyPI:pkg:1.0:GHSA-xxxx-xxxx-xxxx" in related
    assert any(r.startswith("sarif:codeql:") for r in related)


def test_link_no_matches_returns_zero(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    _write_findings(findings_path, [
        {
            "finding_id": "sca:vuln:PyPI:pkg:1.0:CVE-2024-1111",
            "advisories": [{"osv_id": "CVE-2024-1111", "aliases": []}],
            "related_findings": [],
        },
    ])

    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()
    _write_sarif(sarif_dir / "other.sarif", [
        {
            "ruleId": "py/xss",
            "message": {"text": "XSS vulnerability"},
        },
    ])

    added = link_related_findings(findings_path, [sarif_dir])
    assert added == 0


def test_link_idempotent(tmp_path: Path):
    """Running link twice doesn't duplicate references."""
    findings_path = tmp_path / "findings.json"
    _write_findings(findings_path, [
        {
            "finding_id": "sca:vuln:npm:lodash:4.17.21:CVE-2024-2222",
            "advisories": [{"osv_id": "CVE-2024-2222", "aliases": []}],
            "related_findings": [],
        },
    ])

    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()
    _write_sarif(sarif_dir / "findings.sarif", [
        {
            "ruleId": "js/prototype-pollution",
            "message": {"text": "CVE-2024-2222"},
            "fingerprints": {"x": "fp1"},
        },
    ])

    first = link_related_findings(findings_path, [sarif_dir])
    second = link_related_findings(findings_path, [sarif_dir])
    assert first == 1
    assert second == 0

    updated = json.loads(findings_path.read_text())
    sarif_refs = [r for r in updated[0]["related_findings"] if r.startswith("sarif:")]
    assert len(sarif_refs) == 1
