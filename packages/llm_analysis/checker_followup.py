"""KNighter follow-up after a confirmed /agentic finding.

When ``analyze_vulnerability`` confirms a finding as exploitable, this
module turns the bug into a Semgrep / Coccinelle rule via
``packages.checker_synthesis``, runs it across the codebase, and emits
``status=suspicious`` annotations for each variant match. One bug ⇒
N variant annotations.

Per the audit design doc (Mode 2): every confirmed hypothesis
potentially yields a reusable checker. The variants surfaced here are
candidate findings — operator triages them via ``/annotate`` review,
the next ``/agentic`` run can re-analyse them with full context, and
the synthesised rule itself is saved on disk for future ``/scan`` runs
(KNighter's permanent-rule pattern).

Best-effort: any exception is logged at DEBUG and swallowed so a
synthesis failure cannot break the analysis loop. The caller's
counter is bumped only when an annotation actually lands.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def _llm_callable_from_client(llm_client) -> Optional[Any]:
    """Adapt RAPTOR's ``LLMClient`` to checker_synthesis's
    ``LLMCallable`` Protocol. Returns None when the client doesn't
    expose ``generate_structured`` (e.g. ClaudeCodeProvider in
    prep-only mode — checker synthesis can't run without an LLM)."""
    if not hasattr(llm_client, "generate_structured"):
        return None
    from core.llm.task_types import TaskType

    def _call(prompt, schema, system_prompt):
        try:
            data, _full = llm_client.generate_structured(
                prompt=prompt,
                schema=schema,
                system_prompt=system_prompt,
                task_type=TaskType.ANALYSE,
            )
            return data
        except Exception as e:
            logger.debug(f"checker_synthesis LLM call failed: {e}")
            return None
    return _call


def _seed_from_vuln(vuln) -> Optional[Any]:
    """Build a ``SeedBug`` from a confirmed-exploitable
    ``VulnerabilityContext``. Returns None if the vuln lacks the
    fields needed to seed synthesis (no file_path, no line range,
    no resolved function name)."""
    from packages.checker_synthesis import SeedBug

    file_path = getattr(vuln, "file_path", "") or ""
    start_line = getattr(vuln, "start_line", None)
    end_line = getattr(vuln, "end_line", None) or start_line
    if not file_path or not start_line or not end_line:
        return None

    # Function name: prefer inventory-resolved metadata, fall back
    # to whatever the upstream finding adapter populated.
    meta = getattr(vuln, "metadata", None) or {}
    function_name = (
        meta.get("name")
        or getattr(vuln, "function_name", None)
        or ""
    )
    if not function_name:
        return None

    cwe = getattr(vuln, "cwe_id", "") or ""
    analysis = getattr(vuln, "analysis", None) or {}
    reasoning = (
        analysis.get("reasoning")
        or analysis.get("explanation")
        or getattr(vuln, "message", "")
        or ""
    )
    snippet = getattr(vuln, "full_code", "") or ""

    return SeedBug(
        file=file_path,
        function=function_name,
        line_start=int(start_line),
        line_end=int(end_line),
        cwe=cwe,
        reasoning=str(reasoning),
        snippet=str(snippet),
    )


def _resolve_match_function(
    match, checklist: Optional[Dict[str, Any]], repo_root: Path,
) -> Optional[str]:
    """Look up the function name covering ``match.file:match.line``.
    Returns None when not resolvable — the variant annotation needs
    a function name to land in the right .md section."""
    if not checklist:
        return None
    if not match.file or not match.line:
        return None
    try:
        from core.inventory.lookup import lookup_function
        func = lookup_function(
            checklist, match.file, int(match.line),
            repo_root=str(repo_root),
        )
    except (ValueError, TypeError, OSError):
        return None
    if not func:
        return None
    return func.get("name") or None


def _build_variant_body(seed, rule, match) -> str:
    """Compose the prose body for a variant annotation."""
    parts = [
        f"Candidate variant of bug pattern from "
        f"{seed.file}:{seed.line_start}-{seed.line_end} "
        f"({seed.function}).",
    ]
    if rule.rationale:
        parts.append(f"Pattern rationale: {rule.rationale.strip()}")
    if seed.cwe:
        parts.append(f"CWE: {seed.cwe}")
    parts.append(
        f"Surfaced by {rule.engine} rule ``{rule.rule_id}``. "
        f"Triage with ``/annotate show`` or re-run ``/agentic`` to "
        f"confirm or rule out."
    )
    if match.snippet:
        parts.append(f"Match snippet:\n```\n{match.snippet.rstrip()}\n```")
    return "\n\n".join(parts)


def _sanitise_meta(value) -> str:
    """Coerce metadata values to a safe single-line string. Mirrors
    the sanitiser in ``annotation_emit`` — strips newlines / nulls /
    HTML-comment delimiters that would corrupt the on-disk format."""
    s = str(value)
    s = s.replace("\n", " ").replace("\r", " ").replace("\x00", "")
    s = s.replace("-->", "->").replace("<!--", "<!-")
    return s.strip()


def emit_variant_annotations_for_finding(
    vuln,
    *,
    out_dir: Path,
    checklist: Optional[Dict[str, Any]],
    repo_root: Path,
    llm_client,
    max_matches: int = 10,
    triage_each: bool = True,
    max_triage_calls: int = 10,
) -> int:
    """For a confirmed exploitable finding, synthesise a checker
    rule, run it across ``repo_root``, and emit ``suspicious``
    annotations for every variant match.

    Returns the count of annotations actually written. Skipped
    silently when:

      * Seed couldn't be built (missing file/line/function info)
      * LLM client doesn't support ``generate_structured``
      * Synthesis didn't produce a rule (positive control failed)
      * No checklist (can't resolve match function names)

    Best-effort throughout — any exception is logged and swallowed.
    The caller's analysis loop must never crash because variant
    hunting failed.
    """
    try:
        seed = _seed_from_vuln(vuln)
        if seed is None:
            return 0

        llm_callable = _llm_callable_from_client(llm_client)
        if llm_callable is None:
            return 0

        from packages.checker_synthesis import synthesise_and_run
        result = synthesise_and_run(
            seed,
            repo_root=repo_root,
            out_dir=out_dir,
            llm=llm_callable,
            max_matches=max_matches,
            triage_each=triage_each,
            max_triage_calls=max_triage_calls,
        )
    except Exception:
        logger.debug("checker_followup: synthesis failed", exc_info=True)
        return 0

    if result.rule is None or not result.matches:
        return 0

    return _emit_variants(
        seed=seed,
        result=result,
        out_dir=out_dir,
        checklist=checklist,
        repo_root=repo_root,
    )


def _emit_variants(
    *,
    seed,
    result,
    out_dir: Path,
    checklist: Optional[Dict[str, Any]],
    repo_root: Path,
) -> int:
    """Walk synthesis matches → look up function names → write
    annotations. Triage verdicts (when present) gate emission:
    ``variant`` lands as ``suspicious``; ``false_positive`` and
    ``skipped`` are dropped; ``uncertain`` lands as ``suspicious``
    too (operator should look). Untriaged matches always land."""
    from core.annotations import Annotation, write_annotation

    triage_by_match = {
        (t.match.file, t.match.line): t.status
        for t in (result.triage or [])
    }

    written = 0
    base_dir = out_dir / "annotations"

    for m in result.matches:
        triage_status = triage_by_match.get((m.file, m.line))
        if triage_status in ("false_positive", "skipped"):
            continue

        function_name = _resolve_match_function(m, checklist, repo_root)
        if not function_name:
            continue

        metadata: Dict[str, str] = {
            "source": "llm",
            "status": "suspicious",
            "variant_of_file": _sanitise_meta(seed.file),
            "variant_of_function": _sanitise_meta(seed.function),
            "rule_id": _sanitise_meta(result.rule.rule_id),
            "engine": _sanitise_meta(result.rule.engine),
        }
        if seed.cwe:
            metadata["cwe"] = _sanitise_meta(seed.cwe)
        if triage_status:
            metadata["triage"] = _sanitise_meta(triage_status)

        ann = Annotation(
            file=m.file,
            function=function_name,
            body=_build_variant_body(seed, result.rule, m),
            metadata=metadata,
        )
        try:
            path = write_annotation(
                base_dir, ann, overwrite="respect-manual",
            )
        except Exception:
            logger.debug(
                f"checker_followup: variant annotation write failed for "
                f"{m.file}:{m.line}",
                exc_info=True,
            )
            continue
        if path is not None:
            written += 1
    return written
