"""LLM-assisted triage of SCA findings.

Takes the full set of findings (vuln + supply-chain + hygiene) and
asks the LLM to rank them into priority buckets:

- ``fix_today`` — actively exploited (KEV) or critical + reachable
- ``this_sprint`` — high severity, imported, or strong supply-chain signal
- ``this_quarter`` — medium severity or low reachability
- ``accept`` — informational, dev-only, or suppressed-eligible

The LLM also receives cross-tool context from ``/scan`` and ``/codeql``
findings if present in the same ``findings.json``, enabling reasoning
like "the same dep flagged for CVE is also called unsafely at line N."

**Mechanical override:** triage ranking is advisory.  It does not
change finding severity — only the ``priority_bucket`` and
``one_line_rationale`` fields in the output.
"""

from __future__ import annotations

import json as _json
import logging
from typing import Any, Dict, List, Optional

from core.llm.task_types import TaskType
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .exemplars import exemplar_blocks_for_supply_chain
from .prompts import TRIAGE_SYSTEM
from .schemas import TriageResult

logger = logging.getLogger(__name__)

_MAX_FINDINGS_FOR_LLM = 80
_MAX_FINDING_JSON_CHARS = 120_000


def triage_findings(
    client,
    sca_findings: List[Dict[str, Any]],
    cross_tool_findings: Optional[List[Dict[str, Any]]] = None,
) -> Optional[TriageResult]:
    """Rank SCA findings into priority buckets.

    Args:
        client: LLMClient instance.
        sca_findings: rows from this run's ``findings.json`` (SCA only).
        cross_tool_findings: rows from ``/scan``, ``/codeql``, or other
            tools present in the same merged ``findings.json``.  Used as
            context only — they don't get triaged themselves.

    Returns ``None`` when the LLM is unavailable.
    """
    if not sca_findings:
        return TriageResult(items=[], project_context_summary="No findings to triage.")

    trimmed = _trim_for_llm(sca_findings)
    cross_text = ""
    if cross_tool_findings:
        cross_trimmed = _trim_for_llm(cross_tool_findings, limit=20)
        cross_text = (
            "\n\n--- Cross-tool context (from /scan, /codeql) ---\n"
            + _json.dumps(cross_trimmed, indent=1, default=str)
        )

    findings_json = _json.dumps(trimmed, indent=1, default=str)
    if len(findings_json) > _MAX_FINDING_JSON_CHARS:
        findings_json = findings_json[:_MAX_FINDING_JSON_CHARS] + "\n... truncated ..."

    content = findings_json + cross_text

    blocks: list[UntrustedBlock] = [
        UntrustedBlock(
            content=content,
            kind="FINDINGS_LIST",
            origin="sca findings.json",
        ),
    ]
    ecosystem = _dominant_ecosystem(sca_findings)
    blocks.extend(exemplar_blocks_for_supply_chain(ecosystem))

    result: StageResult = run_stage(
        client=client,
        system=TRIAGE_SYSTEM,
        untrusted_blocks=tuple(blocks),
        slots={
            "total_findings": TaintedString(
                value=str(len(sca_findings)), trust="trusted",
            ),
        },
        schema_cls=TriageResult,
        task_type=TaskType.CLASSIFY,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.triage: failed: %s", result.error)
        return None

    return result.model  # type: ignore[return-value]


def _dominant_ecosystem(rows: List[Dict[str, Any]]) -> str:
    """Most-frequent ecosystem across findings, for exemplar selection."""
    counts: Dict[str, int] = {}
    for row in rows:
        eco = (row.get("sca") or {}).get("ecosystem", "")
        if eco:
            counts[eco] = counts.get(eco, 0) + 1
    if not counts:
        return "npm"
    return max(counts, key=counts.get)  # type: ignore[arg-type]


def _trim_for_llm(
    rows: List[Dict[str, Any]],
    limit: int = _MAX_FINDINGS_FOR_LLM,
) -> List[Dict[str, Any]]:
    """Reduce finding rows to the fields the LLM needs, capped."""
    keep_keys = {
        "id", "finding_id", "vuln_type", "severity", "description",
        "reachability", "in_kev", "epss",
        "cvss_score", "file_path", "line",
    }
    out = []
    for row in rows[:limit]:
        trimmed = {k: v for k, v in row.items() if k in keep_keys}
        sca = row.get("sca", {})
        if isinstance(sca, dict):
            for sk in ("ecosystem", "name", "version", "reachability",
                       "in_kev", "epss", "supply_chain_kind"):
                if sk in sca:
                    trimmed.setdefault("sca", {})[sk] = sca[sk]
        out.append(trimmed)
    return out
