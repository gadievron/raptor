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


def _coerce_str(value) -> str:
    """Coerce an untrusted OpenAnt output field to ``str``.

    Scalars are stringified, everything else (dict, list, None)
    becomes ``""`` — pipeline_output.json is produced by an
    UNPINNED-by-consent external scanner over a hostile repo, so
    shape drift in any field is an expected input, never a crash."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def translate_pipeline_output(pipeline_output: dict) -> list[dict]:
    """Convert OpenAnt pipeline_output.json findings to Raptor finding schema.

    Returns empty list on empty input; shape drift never raises — a
    non-dict document or non-list ``findings`` warns and yields ``[]``,
    non-dict finding entries are skipped WITH a counted warning (same
    posture as the unknown-verdict counter: drifted output must stay
    visible, and under /agentic a raising translator silently zeroed a
    paid run's findings behind a blanket-except log line). OpenAnt
    reports repo-relative paths, so no repo root is needed here
    — path relativisation happens at the dedup join
    (``deduplicate_with_sarif``), where absolute SARIF URIs enter.
    """
    if not pipeline_output:
        return []
    if not isinstance(pipeline_output, dict):
        logger.warning(
            "OpenAnt pipeline output is %s, not a dict — treating as "
            "empty (schema drift?)", type(pipeline_output).__name__)
        return []
    findings = pipeline_output.get("findings") or []
    if not findings:
        return []
    if not isinstance(findings, list):
        logger.warning(
            "OpenAnt pipeline output 'findings' is %s, not a list — "
            "treating as empty (schema drift?)",
            type(findings).__name__)
        return []
    result = []
    unknown_verdicts: dict[str, int] = {}
    skipped_malformed = 0
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            skipped_malformed += 1
            continue
        verdict = _coerce_str(finding.get("stage1_verdict")).lower()
        if verdict not in _VERDICT_TO_LEVEL:
            unknown_verdicts[verdict or "<missing>"] = (
                unknown_verdicts.get(verdict or "<missing>", 0) + 1
            )
        translated = _translate_finding(finding, idx)
        if translated is not None:
            result.append(translated)
    if skipped_malformed:
        logger.warning(
            "OpenAnt schema drift? %d non-dict finding entrie(s) "
            "skipped — re-verify the checkout against the pinned "
            "commit", skipped_malformed)
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
    index: int,
) -> Optional[dict]:
    # OpenAnt uses "stage1_verdict" in pipeline_output.json
    verdict = _coerce_str(finding.get("stage1_verdict")).lower()
    level = _compute_level(verdict, finding)
    if level is None:
        return None

    location = finding.get("location")
    if not isinstance(location, dict):
        location = {}
    cwe_id_raw = finding.get("cwe_id")
    cwe_str = _canonical_cwe(cwe_id_raw)

    file_rel = _coerce_str(location.get("file"))
    route_key = _coerce_str(location.get("function")) or _coerce_str(finding.get("id"))
    snippet = _coerce_str(finding.get("vulnerable_code"))
    message = _coerce_str(finding.get("description")) or _coerce_str(finding.get("impact"))
    stage2_verdict = _coerce_str(finding.get("stage2_verdict")).lower()
    finding_name = _coerce_str(finding.get("name")) or _coerce_str(finding.get("cwe_name"))

    return {
        "finding_id": _make_finding_id(finding, file_rel, cwe_str, index),
        "rule_id": f"openant/{cwe_str}" if cwe_str else "openant/unknown",
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
            "attack_vector": _coerce_str(finding.get("impact")),
            "stage1_verdict": verdict,
            "stage2_verdict": stage2_verdict,
            "openant_id": _coerce_str(finding.get("id")) or f"VULN-{index+1:03d}",
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

    stage2 = _coerce_str(finding.get("stage2_verdict")).lower()

    if stage2 in _STAGE2_BOOSTS:
        return "error"
    if stage2 in _STAGE2_DEMOTES and base == "warning":
        return "note"
    return base


def _canonical_cwe(raw) -> Optional[str]:
    """Canonical ``CWE-N`` spelling via ``core.cve.cwe`` — never a
    hand-rolled f-string. OpenAnt documents ``cwe_id`` as an int, but
    LLM-shaped drift ships strings like ``"CWE-78"``: the old
    ``f"CWE-{raw}"`` minted ``CWE-CWE-78``, which silently voided the
    SARIF dedup join for that finding (the SARIF side canonicalises
    via the same module). Garbage yields ``None`` (rule
    ``openant/unknown``)."""
    from core.cve.cwe import canonicalize_cwe, format_cwe

    canon = format_cwe(raw)
    if canon is not None:
        return canon
    if isinstance(raw, str):
        return canonicalize_cwe(raw)
    return None


def _make_finding_id(
    finding: dict,
    file_rel: str,
    cwe: Optional[str],
    index: int,
) -> str:
    openant_id = _coerce_str(finding.get("id"))
    if openant_id:
        return f"openant:{openant_id}"
    if file_rel:
        cwe_part = cwe or "0"
        return f"openant:{file_rel}:{cwe_part}:{index}"
    return f"openant:VULN-{index+1:03d}"


def _normalize_path(file_path: str, repo_root: Optional[Path] = None) -> str:
    """Repo-relative spelling for the dedup join key.

    SARIF findings carry base-joined resolved URIs (absolute for
    CodeQL's %SRCROOT%, and SCHEME-CARRYING when the base was a
    ``file://`` URI — the shape the repo's own CodeQL SARIF tests
    model), OpenAnt findings carry repo-relative paths — without
    normalising the URI side the two key populations could never be
    equal and the dedup was vacuous (every duplicate
    double-reported). The scheme strip reuses
    ``core.sarif.import_normalizer._strip_file_scheme`` (one home for
    the spelling), and percent-encoding is unquoted to match the
    import normalizer's own semantics — a filename containing a
    LITERAL ``%XX`` run collapses with its decoded spelling, an
    accepted residual shared with that normalizer. Lexical relpath
    only; paths need not exist. Paths outside ``repo_root``
    (``..``-relative) keep their absolute spelling — both key
    populations flow through this one function, so the keys stay
    consistent, and stripping the leading separator (as this used to
    do) only manufactured collisions with genuinely relative names.
    """
    from urllib.parse import unquote

    s = str(file_path)
    if s.startswith("file://"):
        from core.sarif.import_normalizer import _strip_file_scheme
        stripped = _strip_file_scheme(s)
        # RFC 8089: a file-scheme URI path is absolute. The shared
        # stripper drops the leading slash of file:/// (its caller
        # re-roots); restore it so the relpath arm below fires.
        s = stripped if stripped.startswith("/") else "/" + stripped
    s = unquote(s)
    norm = os.path.normpath(s)
    if repo_root is not None and os.path.isabs(norm):
        try:
            rel = os.path.relpath(norm, os.path.normpath(str(repo_root)))
        except ValueError:
            return norm  # different drive (Windows) — keep absolute
        # `..`-PREFIXED NAMES (`..data/x.py`) are inside the root;
        # only a genuine parent traversal keeps the absolute spelling.
        if rel != ".." and not rel.startswith(".." + os.sep):
            return rel
    return norm


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
    """Dedup key: (repo-relative file, cwe). Shared by both sides.

    A finding missing EITHER half never joins (``None``): a missing
    cwe used to key as ``""``, which is not a CWE match but a wildcard
    bucket — any CWE-less OpenAnt finding was silently dropped against
    ANY CWE-less SARIF finding in the same file (both sides
    legitimately lack CWEs; same-file no-CWE collisions are far
    likelier than same-file same-CWE ones, and the failure direction
    is finding LOSS, not double-report)."""
    file_ = f.get("file") or ""
    cwe = f.get("cwe_id") or ""
    if not file_ or not cwe:
        return None
    return (_normalize_path(file_, repo_root), str(cwe).upper())
