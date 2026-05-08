"""Per-finding annotation emission for ``/agentic``.

Writes one ``core.annotations`` record per analysed vulnerability,
attached to the function that contains the finding. Annotations
land under ``<run_output_dir>/annotations/`` so they accumulate
across runs and so ``iter_all_annotations`` can aggregate them.

This is the first LLM-driven consumer of the annotations substrate.
Calls ``write_annotation(..., overwrite="respect-manual")`` so a
manual operator note (``source=human``) survives subsequent
``/agentic`` runs.

Status mapping (from the vuln's analysis dict):

  * ``is_true_positive=False``                           → ``clean``
  * ``is_true_positive=True``  + ``is_exploitable=True``  → ``finding``
  * ``is_true_positive=True``  + ``is_exploitable=False`` → ``suspicious``
  * neither set / no analysis                            → ``error``

Skipped silently when:

  * No inventory ``checklist`` provided (function name unknown).
  * No inventory entry matches the finding's file:line.
  * The finding has no ``file_path`` or ``start_line``.
  * An existing same-name annotation is ``source=human``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.annotations import (
    Annotation,
    compute_function_hash,
    write_annotation,
)
from core.inventory.lookup import lookup_function

logger = logging.getLogger(__name__)


def _resolve_function(
    vuln, checklist: Optional[Dict[str, Any]], repo_root: Path,
) -> Optional[Tuple[str, Optional[int], Optional[int]]]:
    """Find the function containing ``vuln``'s file:line in the
    inventory. Returns ``(name, line_start, line_end)`` or ``None``
    if not resolvable."""
    if not checklist:
        return None
    file_path = getattr(vuln, "file_path", None)
    start_line = getattr(vuln, "start_line", None)
    if not file_path or not start_line:
        return None
    try:
        func = lookup_function(
            checklist, file_path, int(start_line),
            repo_root=str(repo_root),
        )
    except (ValueError, TypeError):
        return None
    if not func:
        return None
    name = func.get("name")
    if not name:
        return None
    return name, func.get("line_start"), func.get("line_end")


def _derive_status(analysis: Optional[Dict[str, Any]]) -> str:
    """Map the analysis dict's verdict bools to the annotation
    status enum. Defaults to ``error`` when neither flag is set
    (analysis didn't complete or schema-violated)."""
    if not analysis:
        return "error"
    is_tp = analysis.get("is_true_positive")
    if is_tp is False:
        return "clean"
    if is_tp is True:
        return "finding" if analysis.get("is_exploitable") else "suspicious"
    return "error"


def _build_body(vuln) -> str:
    """Compose the annotation body. Prefers the LLM's own ``reasoning``
    field (the analysis schema's required prose key); falls back to
    the scanner's ``message`` when no analysis is available."""
    parts: list[str] = []
    analysis = getattr(vuln, "analysis", None) or {}

    reasoning = analysis.get("reasoning") or analysis.get("explanation")
    if reasoning:
        parts.append(str(reasoning).strip())

    severity = analysis.get("severity_assessment")
    if severity:
        parts.append(f"Severity: {severity}")

    if getattr(vuln, "has_dataflow", False):
        dv = analysis.get("dataflow_validation") or {}
        if dv:
            fp = dv.get("false_positive")
            if fp is not None:
                parts.append(f"Dataflow validation: false_positive={fp}")

    # Fall back to the scanner's own message when there's no LLM prose.
    if not parts:
        message = getattr(vuln, "message", None)
        if message:
            parts.append(f"Scanner message: {message}")

    return "\n\n".join(parts)


def _sanitise_meta(value) -> str:
    """``write_annotation`` rejects metadata values containing newlines,
    nulls, or HTML-comment delimiters (``<!--`` / ``-->``). Coerce to
    a single-line string and strip the forbidden sequences so we never
    raise from inside the agentic loop."""
    s = str(value)
    s = s.replace("\n", " ").replace("\r", " ").replace("\x00", "")
    s = s.replace("-->", "->").replace("<!--", "<!-")
    return s.strip()


def emit_finding_annotation(
    vuln,
    base_dir: Path,
    checklist: Optional[Dict[str, Any]],
    repo_root: Path,
) -> Optional[Path]:
    """Write one annotation for ``vuln`` if all the prerequisites are
    met. Returns the path written, or ``None`` if the emit was skipped
    (function not resolvable, or ``respect-manual`` blocked the write).

    Best-effort: any unexpected error is logged and swallowed so
    annotation-emit failures cannot break ``/agentic`` analysis.
    """
    try:
        resolved = _resolve_function(vuln, checklist, repo_root)
        if not resolved:
            return None
        name, line_start, line_end = resolved

        analysis = getattr(vuln, "analysis", None)
        metadata: Dict[str, str] = {
            "source": "llm",
            "status": _derive_status(analysis),
        }
        rule_id = getattr(vuln, "rule_id", None)
        if rule_id:
            metadata["rule_id"] = _sanitise_meta(rule_id)
        cwe_id = getattr(vuln, "cwe_id", None)
        if cwe_id:
            metadata["cwe"] = _sanitise_meta(cwe_id)
        tool = getattr(vuln, "tool", None)
        if tool:
            metadata["tool"] = _sanitise_meta(tool)

        if analysis:
            score = analysis.get("exploitability_score")
            if score is not None:
                try:
                    metadata["score"] = f"{float(score):.2f}"
                except (TypeError, ValueError):
                    pass

        # Stamp source-line hash for staleness detection. Skipped if
        # we don't have line bounds from the inventory (e.g. parser
        # didn't capture line_end for that function).
        file_path = getattr(vuln, "file_path", None)
        if file_path and line_start and line_end:
            src = Path(repo_root) / file_path
            h = compute_function_hash(src, line_start, line_end)
            if h:
                metadata["hash"] = h
                metadata["start_line"] = str(line_start)
                metadata["end_line"] = str(line_end)

        ann = Annotation(
            file=file_path,
            function=name,
            body=_build_body(vuln),
            metadata=metadata,
        )
        return write_annotation(base_dir, ann, overwrite="respect-manual")
    except Exception as e:
        # Annotation emission is best-effort. Log and move on.
        logger.warning(
            f"annotation emit failed for "
            f"{getattr(vuln, 'file_path', '?')}: {e}"
        )
        return None
