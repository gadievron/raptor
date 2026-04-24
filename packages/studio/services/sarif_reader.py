"""Parse SARIF 2.1.0 files into raptor-style finding dicts.

Raptor scan runs emit Semgrep + CodeQL findings in SARIF 2.1.0. When a run
has no post-processed findings.json (e.g., a plain `/scan` without the
agentic validation phase), the UI should still render findings by reading
SARIF directly.

This reader normalizes SARIF to match the finding shape raptor's own
exploitability_validation uses (file, line, vuln_type, cwe_id, tool,
status='pending' by default), so downstream rendering is identical.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_SEVERITY_BY_SARIF_LEVEL = {
    "error":   "high",
    "warning": "medium",
    "note":    "low",
    "none":    "info",
}


def _extract_cwe(rule: dict) -> str:
    # CWE tags live in rule.properties.tags as "external/cwe/cwe-78" or "CWE-78".
    tags = (rule.get("properties") or {}).get("tags") or []
    for t in tags:
        if not isinstance(t, str):
            continue
        low = t.lower()
        if "cwe" in low:
            # Find the first digit sequence
            digits = "".join(c for c in low.split("cwe")[-1] if c.isdigit())
            if digits:
                return f"CWE-{digits}"
    return ""


def _rule_by_id(rules: list, rule_id: str) -> dict:
    for r in rules or []:
        if isinstance(r, dict) and r.get("id") == rule_id:
            return r
    return {}


def parse_sarif_file(path: Path, tool_hint: str = "") -> list[dict]:
    """Parse one SARIF file into a list of normalized finding dicts."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    findings: list[dict] = []
    for run in data.get("runs", []) or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = driver.get("name", tool_hint or path.stem)
        rules = driver.get("rules") or []

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId", "")
            rule = _rule_by_id(rules, rule_id)
            level = result.get("level", "warning")

            locations = result.get("locations", []) or []
            file_path = ""
            line_number = None
            if locations:
                phys = (locations[0].get("physicalLocation") or {})
                loc = (phys.get("artifactLocation") or {})
                file_path = loc.get("uri", "")
                region = phys.get("region") or {}
                line_number = region.get("startLine")

            message = ""
            msg_obj = result.get("message") or {}
            if isinstance(msg_obj, dict):
                message = msg_obj.get("text", "")
            elif isinstance(msg_obj, str):
                message = msg_obj

            # Map rule.shortDescription / rule.name into vuln_type heuristically.
            rule_name = rule.get("name") or rule_id
            short = ""
            if rule.get("shortDescription"):
                if isinstance(rule["shortDescription"], dict):
                    short = rule["shortDescription"].get("text", "")
                else:
                    short = str(rule["shortDescription"])

            findings.append({
                "id": f"{path.stem}:{rule_id}:{file_path}:{line_number}",
                "tool": tool,
                "rule_id": rule_id,
                "vuln_type": rule_name,
                "cwe_id": _extract_cwe(rule),
                "severity_assessment": _SEVERITY_BY_SARIF_LEVEL.get(level, "info"),
                "confidence": "medium",  # SARIF has no confidence; assume medium pre-validation
                "final_status": "pending",
                "attack_scenario": message or short,
                "proof": {
                    "vulnerable_code": "",
                    "flow": [],
                },
                "poc": {},
                "file": file_path,
                "line": line_number,
            })
    return findings


def parse_run_sarif(run_dir: Path) -> list[dict]:
    """Parse all SARIF files in a run directory into normalized findings."""
    out: list[dict] = []
    if not run_dir.is_dir():
        return out
    for sarif in sorted(run_dir.glob("*.sarif")):
        tool = "semgrep" if "semgrep" in sarif.name.lower() else ("codeql" if "codeql" in sarif.name.lower() else "")
        out.extend(parse_sarif_file(sarif, tool_hint=tool))
    return out


def scan_metrics(run_dir: Path) -> dict | None:
    """Load scan_metrics.json if present."""
    path = run_dir / "scan_metrics.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
