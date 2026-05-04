"""OpenAnt → Raptor finding schema translation.

Converts findings from OpenAnt's pipeline_output.json to the normalised
Raptor finding dict used by packages/llm_analysis and exploitability_validation.

OpenAnt pipeline_output.json finding schema (from core/reporter.py:297-315):
  id              str   e.g. "VULN-001"
  stage1_verdict  str   "vulnerable" | "bypassable" | "inconclusive" | "protected" | "safe"
  stage2_verdict  str   "confirmed" | "agreed" | "rejected" | <stage1_verdict>
  location        dict  {file: str, function: str (route_key)}
  cwe_id          int   e.g. 78
  cwe_name        str   e.g. "OS Command Injection"
  description     str   vulnerability description / reasoning
  impact          str   attack vector / impact
  vulnerable_code str   the vulnerable code snippet
  name            str   human-readable vuln name
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_VERDICT_TO_LEVEL: dict[str, Optional[str]] = {
    "vulnerable": "warning",
    "bypassable": "note",
    "inconclusive": "note",
    "protected": "note",
    "safe": None,
}

_STAGE2_BOOSTS: frozenset[str] = frozenset({"confirmed", "agreed"})
_STAGE2_DEMOTES: frozenset[str] = frozenset({"rejected", "bypass_failed"})


def translate_pipeline_output(
    pipeline_output: dict,
    repo_path: str | Path,
) -> list[dict]:
    """Convert OpenAnt pipeline_output.json findings to Raptor finding schema.

    Returns empty list on empty or malformed input; never raises.
    """
    if not pipeline_output:
        return []
    findings = pipeline_output.get("findings") or []
    if not findings:
        return []
    repo_info = pipeline_output.get("repository") or {}
    repo_root = Path(repo_path)
    result = []
    for idx, finding in enumerate(findings):
        translated = _translate_finding(finding, repo_info, repo_root, idx)
        if translated is not None:
            result.append(translated)
    return result


def _translate_finding(
    finding: dict,
    repo_info: dict,
    repo_path: Path,
    index: int,
) -> Optional[dict]:
    # OpenAnt uses "stage1_verdict" in pipeline_output.json
    verdict = (finding.get("stage1_verdict") or "").lower()
    level = _compute_level(verdict, finding)
    if level is None:
        return None

    location = finding.get("location") or {}
    cwe_id_raw = finding.get("cwe_id")
    cwe_str = f"CWE-{cwe_id_raw}" if cwe_id_raw else None

    file_rel = location.get("file") or ""
    route_key = location.get("function") or finding.get("id") or ""
    snippet = finding.get("vulnerable_code") or ""
    message = finding.get("description") or finding.get("impact") or ""
    stage2_verdict = (finding.get("stage2_verdict") or "").lower()
    finding_name = finding.get("name") or finding.get("cwe_name") or ""

    return {
        "finding_id": _make_finding_id(finding, file_rel, cwe_id_raw, index),
        "rule_id": f"openant/CWE-{cwe_id_raw}" if cwe_id_raw else "openant/unknown",
        "file": file_rel,
        "startLine": None,
        "endLine": None,
        "snippet": snippet[:2000] if snippet else "",
        "message": message[:4000] if message else "",
        "level": level,
        "cwe_id": cwe_str,
        "tool": "openant",
        "has_dataflow": False,
        "metadata": {
            "function": route_key,
            "attack_vector": finding.get("impact") or "",
            "stage1_verdict": verdict,
            "stage2_verdict": stage2_verdict,
            "openant_id": finding.get("id") or f"VULN-{index+1:03d}",
            "route_key": route_key,
            "vuln_name": finding_name,
        },
    }


def _compute_level(verdict: str, finding: dict) -> Optional[str]:
    base = _VERDICT_TO_LEVEL.get(verdict)
    if base is None:
        return None

    stage2 = (finding.get("stage2_verdict") or "").lower()

    if stage2 in _STAGE2_BOOSTS:
        return "error"
    if stage2 in _STAGE2_DEMOTES and base == "warning":
        return "note"
    return base


def _make_finding_id(
    finding: dict,
    file_rel: str,
    cwe_id,
    index: int,
) -> str:
    openant_id = finding.get("id")
    if openant_id:
        return f"openant:{openant_id}"
    if file_rel:
        cwe_part = cwe_id or "0"
        return f"openant:{file_rel}:{cwe_part}:{index}"
    return f"openant:VULN-{index+1:03d}"


def _normalize_path(file_path: str) -> str:
    return os.path.normpath(file_path).lstrip(os.sep)


def deduplicate_with_sarif(
    openant_findings: list[dict],
    sarif_findings: list[dict],
) -> tuple[list[dict], int]:
    """Remove OpenAnt findings that duplicate SARIF findings.

    Deduplication key: (normalized_file, line_bucket_of_5, cwe_id_str).
    When the same issue is in both, keep the SARIF finding.

    Returns:
        (merged_unique_list, count_of_openant_dropped)
    """
    sarif_keys: set[tuple] = set()
    for f in sarif_findings:
        key = _sarif_key(f)
        if key:
            sarif_keys.add(key)

    kept = []
    dropped = 0
    for f in openant_findings:
        key = _openant_key(f)
        if key and key in sarif_keys:
            dropped += 1
        else:
            kept.append(f)

    return sarif_findings + kept, dropped


def _sarif_key(f: dict) -> Optional[tuple]:
    """Dedup key: (file, cwe).  Line number excluded — OpenAnt has none."""
    file_ = f.get("file") or ""
    cwe = f.get("cwe_id") or ""
    if not file_:
        return None
    return (_normalize_path(file_), str(cwe).upper())


def _openant_key(f: dict) -> Optional[tuple]:
    file_ = f.get("file") or ""
    cwe = f.get("cwe_id") or ""
    if not file_:
        return None
    return (_normalize_path(file_), str(cwe).upper())
