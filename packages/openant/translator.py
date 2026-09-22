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

from core.logging import get_logger

logger = get_logger()

# Stage-1 verdict -> finding level. ONLY "safe" suppresses. Any
# verdict spelling this map does not know (schema drift in a newer
# OpenAnt — the enumeration is pinned against the checkout commit in
# config.OPENANT_PINNED_COMMIT) is kept at "note" and warned with
# counts: an unknown verdict must never behave like "safe", or a
# renamed verdict upstream silently zeroes a run's findings.
_VERDICT_TO_LEVEL: dict[str, Optional[str]] = {
    "vulnerable": "warning",
    "bypassable": "note",
    "inconclusive": "note",
    "protected": "note",
    "safe": None,
}
_UNKNOWN_VERDICT_LEVEL = "note"

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
    unknown_verdicts: dict[str, int] = {}
    for idx, finding in enumerate(findings):
        verdict = (finding.get("stage1_verdict") or "").lower()
        if verdict not in _VERDICT_TO_LEVEL:
            unknown_verdicts[verdict or "<missing>"] = (
                unknown_verdicts.get(verdict or "<missing>", 0) + 1
            )
        translated = _translate_finding(finding, repo_info, repo_root, idx)
        if translated is not None:
            result.append(translated)
    if unknown_verdicts:
        logger.warning(
            "OpenAnt schema drift? %d finding(s) carry unknown "
            "stage1_verdict value(s) %s — kept at level=note; re-verify "
            "the checkout against the pinned commit",
            sum(unknown_verdicts.values()),
            sorted(unknown_verdicts),
        )
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
    if verdict in _VERDICT_TO_LEVEL:
        base = _VERDICT_TO_LEVEL[verdict]
        if base is None:
            return None  # "safe" — the only suppressing verdict
    else:
        base = _UNKNOWN_VERDICT_LEVEL

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


def _normalize_path(file_path: str, repo_root: Optional[Path] = None) -> str:
    """Repo-relative spelling for the dedup join key.

    SARIF findings carry base-joined resolved URIs (absolute for
    CodeQL's %SRCROOT%), OpenAnt findings carry repo-relative paths —
    without relativising the absolute side the two key populations
    could never be equal and the dedup was vacuous (every duplicate
    double-reported). Lexical relpath only; paths need not exist.
    """
    norm = os.path.normpath(str(file_path))
    if repo_root is not None and os.path.isabs(norm):
        try:
            rel = os.path.relpath(norm, os.path.normpath(str(repo_root)))
        except ValueError:
            rel = norm  # different drive (Windows) — keep absolute
        if not rel.startswith(".."):
            norm = rel
    return norm.lstrip(os.sep)


def deduplicate_with_sarif(
    openant_findings: list[dict],
    sarif_findings: list[dict],
    repo_path: Optional[str | Path] = None,
) -> tuple[list[dict], int]:
    """Remove OpenAnt findings that duplicate SARIF findings.

    Deduplication key: (repo_relative_file, cwe_id) — no line numbers
    (OpenAnt findings are function-granularity and carry none) and no
    function name (SARIF results don't reliably carry one), so two
    DISTINCT same-file same-CWE findings do collapse; the SARIF side
    is kept as the richer record. Pass ``repo_path`` so absolute SARIF
    URIs and repo-relative OpenAnt paths land in the same key
    population.

    Returns:
        (merged_unique_list, count_of_openant_dropped)
    """
    repo_root = Path(repo_path) if repo_path else None
    sarif_keys: set[tuple] = set()
    for f in sarif_findings:
        key = _finding_key(f, repo_root)
        if key:
            sarif_keys.add(key)

    kept = []
    dropped = 0
    for f in openant_findings:
        key = _finding_key(f, repo_root)
        if key and key in sarif_keys:
            dropped += 1
        else:
            kept.append(f)

    return sarif_findings + kept, dropped


def _finding_key(f: dict, repo_root: Optional[Path] = None) -> Optional[tuple]:
    """Dedup key: (repo-relative file, cwe). Shared by both sides."""
    file_ = f.get("file") or ""
    cwe = f.get("cwe_id") or ""
    if not file_:
        return None
    return (_normalize_path(file_, repo_root), str(cwe).upper())
