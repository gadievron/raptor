"""KNighter follow-up after a confirmed /agentic finding.

When ``analyze_vulnerability`` confirms a finding as exploitable, this
module turns the bug into a Semgrep / Coccinelle rule via
``packages.checker_synthesis``, runs it across the codebase, and records
variant matches in ``checker-matches.jsonl``. One bug => N variant
matches.

Per the audit design doc (Mode 2): every confirmed hypothesis
potentially yields a reusable checker. The variants surfaced here are
candidate findings — the next ``/agentic`` run can analyse them with
full context, and the synthesised rule itself is saved on disk for
future ``/scan`` runs (KNighter's permanent-rule pattern).

Best-effort: any exception is logged at DEBUG and swallowed so a
synthesis failure cannot break the analysis loop. The caller's
counter is bumped only when a match is actually recorded.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CHECKER_MATCHES_FILE = "checker-matches.jsonl"


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
            logger.warning("checker_synthesis LLM call failed: %s", e)
            return None
    return _call


def _seed_from_vuln(vuln, repo_root: Optional[Path] = None) -> Optional[Any]:
    """Build a ``SeedBug`` from a confirmed-exploitable
    ``VulnerabilityContext``. Returns None if the vuln lacks the
    fields needed to seed synthesis (no file_path, no line range,
    no resolved function name)."""
    from packages.checker_synthesis import SeedBug

    file_path = getattr(vuln, "file_path", "") or ""
    start_line = getattr(vuln, "start_line", None)
    end_line = getattr(vuln, "end_line", None)
    if end_line is None:
        end_line = start_line
    if not file_path or start_line is None or end_line is None:
        return None

    # SARIF findings may carry absolute paths; synthesis requires
    # repo-relative paths (the path-traversal defence rejects absolutes).
    fp = Path(file_path)
    if fp.is_absolute() and repo_root is not None:
        try:
            file_path = str(fp.relative_to(Path(repo_root).resolve()))
        except ValueError:
            return None

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
    Returns None when not resolvable."""
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


def emit_variant_matches_for_finding(
    vuln,
    *,
    out_dir: Path,
    checklist: Optional[Dict[str, Any]],
    repo_root: Path,
    llm_client,
    max_matches: int = 10,
    triage_each: bool = True,
    max_triage_calls: int = 10,
    refine: bool = True,
    max_refine_iterations: int = 5,
    max_acceptable_fp_rate: float = 0.2,
) -> int:
    """For a confirmed exploitable finding, synthesise a checker
    rule, run it across ``repo_root``, and record variant matches
    in ``checker-matches.jsonl``.

    When ``refine=True`` (default), runs the iterative FP-elimination
    loop: each iteration feeds false positives back as negative
    examples until the FP rate drops below ``max_acceptable_fp_rate``
    or ``max_refine_iterations`` is exhausted.

    Returns the count of matches actually written. Skipped silently
    when:

      * Seed couldn't be built (missing file/line/function info)
      * LLM client doesn't support ``generate_structured``
      * Synthesis didn't produce a rule (positive control failed)

    Best-effort throughout — any exception is logged and swallowed.
    """
    try:
        seed = _seed_from_vuln(vuln, repo_root=repo_root)
        if seed is None:
            logger.debug(
                "checker_followup: skipped — could not build seed "
                "(missing file/line/function)",
            )
            return 0

        llm_callable = _llm_callable_from_client(llm_client)
        if llm_callable is None:
            logger.debug(
                "checker_followup: skipped — LLM client does not "
                "support generate_structured",
            )
            return 0

        logger.debug(
            "checker_followup: synthesising rule for %s:%s (%s)",
            seed.file, seed.line_start, seed.function,
        )

        if refine:
            from packages.checker_synthesis import synthesise_with_refinement
            result = synthesise_with_refinement(
                seed,
                repo_root=repo_root,
                out_dir=out_dir,
                llm=llm_callable,
                max_iterations=max_refine_iterations,
                max_acceptable_fp_rate=max_acceptable_fp_rate,
                max_matches=max_matches,
                max_triage_calls=max_triage_calls,
            )
        else:
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
        logger.warning("checker_followup: synthesis failed", exc_info=True)
        return 0

    if result.rule is None:
        logger.debug(
            "checker_followup: no rule produced for %s:%s "
            "(errors: %s)",
            seed.file, seed.line_start,
            "; ".join(result.errors[:3]) if result.errors else "none",
        )
        return 0
    logger.debug(
        "checker_followup: rule %s produced — %d match(es), "
        "positive_control=%s, dual_control=%s",
        result.rule.rule_id,
        len(result.matches),
        result.positive_control,
        result.dual_control,
    )
    if not result.matches:
        return 0

    return _record_matches(
        seed=seed,
        result=result,
        out_dir=out_dir,
        checklist=checklist,
        repo_root=repo_root,
    )


def _record_matches(
    *,
    seed,
    result,
    out_dir: Path,
    checklist: Optional[Dict[str, Any]],
    repo_root: Path,
) -> int:
    """Walk synthesis matches -> write to checker-matches.jsonl.
    Triage verdicts (when present) gate emission: ``variant`` lands;
    ``false_positive`` and ``skipped`` are dropped; ``uncertain``
    also lands (operator should look). Untriaged matches always land."""
    triage_by_match = {
        (t.match.file, t.match.line): t.status
        for t in (result.triage or [])
    }

    written = 0
    matches_path = out_dir / CHECKER_MATCHES_FILE
    out_dir.mkdir(parents=True, exist_ok=True)

    for m in result.matches:
        triage_status = triage_by_match.get((m.file, m.line))
        if triage_status in ("false_positive", "skipped"):
            continue

        function_name = _resolve_match_function(m, checklist, repo_root)

        record = {
            "file": m.file,
            "line": m.line,
            "function": function_name,
            "snippet": m.snippet or "",
            "seed_file": seed.file,
            "seed_function": seed.function,
            "seed_line_start": seed.line_start,
            "seed_line_end": seed.line_end,
            "cwe": seed.cwe or None,
            "rule_id": result.rule.rule_id,
            "engine": result.rule.engine,
            "rationale": result.rule.rationale or "",
            "triage": triage_status,
        }
        try:
            line = json.dumps(record, separators=(",", ":")) + "\n"
            with open(matches_path, "a", encoding="utf-8") as f:
                f.write(line)
            written += 1
        except Exception:
            logger.warning(
                "checker_followup: match write failed for %s:%s",
                m.file, m.line,
                exc_info=True,
            )
    return written
