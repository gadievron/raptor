"""KNighter follow-up after a confirmed /agentic finding.

When ``analyze_vulnerability`` confirms a finding as exploitable, this
module turns the bug into a Semgrep / Coccinelle rule via
``packages.checker_synthesis``, runs it across the codebase, and records
variant matches in ``checker-matches.jsonl``. One bug => N variant
matches.

Per the audit design doc (Mode 2): every confirmed hypothesis
potentially yields a reusable checker. The variants surfaced here are
candidate findings — the SAME run analyses a bounded number of them via
:func:`load_variant_candidates` (with the originating hypothesis as
context), and the synthesised rule itself is saved on disk for future
``/scan`` runs (KNighter's permanent-rule pattern).

Best-effort: any exception is logged at DEBUG and swallowed so a
synthesis failure cannot break the analysis loop. The caller's
counter is bumped only when a match is actually recorded.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CHECKER_MATCHES_FILE = "checker-matches.jsonl"

# Same-run variant reviews are bounded: each candidate costs a full
# LLM analysis call on top of the synthesis spend that produced it.
MAX_VARIANT_REVIEWS_PER_RUN = 10


def _llm_callable_from_client(
    llm_client, cost_tracker=None,
) -> Any | None:
    """Adapt RAPTOR's ``LLMClient`` to checker_synthesis's
    ``LLMCallable`` Protocol. Returns None when the client doesn't
    expose ``generate_structured`` (e.g. ClaudeCodeProvider in
    prep-only mode -- checker synthesis can't run without an LLM).

    When *cost_tracker* is provided, each call checks the budget
    before invoking the LLM and returns None (skipped) when the
    budget is exhausted.
    """
    if not hasattr(llm_client, "generate_structured"):
        return None
    from core.llm.task_types import TaskType

    def _call(prompt, schema, system_prompt):
        if cost_tracker is not None:
            try:
                max_cost = getattr(cost_tracker, "_max_cost", 0)
                if max_cost > 0 and cost_tracker.total_cost >= max_cost:
                    logger.debug(
                        "checker_synthesis skipped: budget exhausted",
                    )
                    return None
            except Exception:
                logger.debug("cost tracker probe failed", exc_info=True)
        try:
            data, _full = llm_client.generate_structured(
                prompt=prompt,
                schema=schema,
                system_prompt=system_prompt,
                task_type=TaskType.ANALYSE,
            )
            return data
        except Exception as e:  # noqa: BLE001 — any transport failure degrades to no-synthesis
            logger.warning(
                "checker_synthesis LLM call failed: %s", e,
            )
            return None
    return _call


def _seed_from_vuln(vuln, repo_root: Path | None = None) -> Any | None:
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
    match, checklist: dict[str, Any] | None, repo_root: Path,
) -> str | None:
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


def _try_replay_from_library(
    seed,
    repo_root: Path,
    out_dir: Path,
    llm_callable,
    *,
    max_matches: int,
    max_triage_calls: int,
):
    """Check the rule library for replayable rules matching this
    seed's CWE. Returns a ``CheckerSynthesisResult`` on hit, or
    None if no library rule qualifies."""
    try:
        from packages.checker_synthesis import RuleLibrary
        from packages.checker_synthesis.languages import detect_engine
        from packages.checker_synthesis.library import _DEFAULT_LIBRARY_DIR
        from packages.checker_synthesis.synthesise import _run_engine, _triage

        engine = detect_engine(seed.file)
        if engine is None:
            return None

        lib = RuleLibrary(_DEFAULT_LIBRARY_DIR)
        candidates = lib.find_replayable(seed.cwe, engine)
        if not candidates:
            return None

        entry = candidates[0]
        rule_path = lib.rule_path(entry)
        if not rule_path.exists():
            logger.debug(
                "checker_followup: library rule %s on disk missing",
                entry.rule_id,
            )
            return None

        from packages.checker_synthesis.models import (
            CheckerSynthesisResult,
            SynthesisedRule,
        )

        rule_body = rule_path.read_text(encoding="utf-8")
        rule = SynthesisedRule(
            engine=entry.engine,
            rule_id=entry.rule_id,
            body=rule_body,
            rationale=entry.rationale,
        )

        matches, errors = _run_engine(rule, rule_path, repo_root)
        from packages.checker_synthesis.synthesise import _is_seed_match
        variants = [m for m in matches if not _is_seed_match(seed, m)]
        if len(variants) > max_matches:
            variants = variants[:max_matches]

        triage_list = []
        if variants:
            triage_list, t_errors = _triage(
                seed, rule, variants, llm_callable, max_triage_calls,
            )
            errors.extend(t_errors)

        import hashlib
        target_hash = hashlib.sha256(
            str(repo_root).encode(),
        ).hexdigest()[:12]
        lib.update(
            entry.rule_id, target_hash, variants, triage_list,
        )

        result = CheckerSynthesisResult(seed=seed)
        result.rule = rule
        result.rule_path = rule_path
        result.positive_control = True
        result.dual_control = entry.dual_control
        # Replayed from the library — the mechanical controls passed
        # at promotion time.
        result.rule_tier = "library"
        result.matches = variants
        result.triage = triage_list
        result.errors = errors

        logger.info(
            "checker_followup: replayed library rule %s — %d match(es)",
            entry.rule_id, len(variants),
        )

        _try_graduate_after_update(lib)

        return result
    except Exception:
        logger.debug("checker_followup: library replay failed", exc_info=True)
        return None


def _try_promote_to_library(result, repo_root: Path):
    """Promote a synthesis result to the rule library if eligible."""
    try:
        import hashlib

        from packages.checker_synthesis import RuleLibrary
        from packages.checker_synthesis.library import _DEFAULT_LIBRARY_DIR

        lib = RuleLibrary(_DEFAULT_LIBRARY_DIR)
        target_hash = hashlib.sha256(
            str(repo_root).encode(),
        ).hexdigest()[:12]
        lib.promote(result, target_hash=target_hash)
    except Exception:
        logger.debug("checker_followup: library promotion failed", exc_info=True)


def _try_graduate_after_update(lib):
    """Graduate eligible rules after a library update.

    The disk manifest already tracks targets, TP rate, and variant
    counts — graduate() reads those directly.  No external state needed.
    """
    try:
        from core.config import RaptorConfig

        graduated = lib.graduate(RaptorConfig.ENGINE_DIR)
        if graduated:
            logger.info(
                "checker_followup: graduated %d rule(s): %s",
                len(graduated), ", ".join(graduated),
            )
    except Exception:
        logger.debug("checker_followup: graduation failed", exc_info=True)


def emit_variant_matches_for_finding(
    vuln,
    *,
    out_dir: Path,
    checklist: dict[str, Any] | None,
    repo_root: Path,
    llm_client,
    cost_tracker=None,
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

    Checks the rule library first: if a proven rule exists for this
    CWE + engine, replays it directly (zero LLM synthesis cost).
    Otherwise falls through to synthesis.

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

        llm_callable = _llm_callable_from_client(
            llm_client, cost_tracker=cost_tracker,
        )
        if llm_callable is None:
            logger.debug(
                "checker_followup: skipped — LLM client does not "
                "support generate_structured",
            )
            return 0

        # Check library before spending LLM tokens on synthesis.
        result = _try_replay_from_library(
            seed, repo_root, out_dir, llm_callable,
            max_matches=max_matches,
            max_triage_calls=max_triage_calls,
        )

        if result is None:
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
                    model_id=getattr(llm_client, "model_name", "") or "",
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
                    model_id=getattr(llm_client, "model_name", "") or "",
                )

            _try_promote_to_library(result, repo_root)
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
    checklist: dict[str, Any] | None,
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
            # Originating hypothesis (the seed finding's analysis
            # reasoning) — carried so the same-run variant review can
            # present it as context. Bounded: prior-LLM prose.
            "seed_reasoning": (getattr(seed, "reasoning", "") or "")[:500],
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


def load_variant_candidates(
    out_dir: Path,
    *,
    checklist: dict[str, Any] | None,
    repo_root: Path,
    exclude_keys: set[tuple[str, str]] | frozenset = frozenset(),
    max_candidates: int = MAX_VARIANT_REVIEWS_PER_RUN,
) -> list[dict[str, Any]]:
    """Read ``checker-matches.jsonl`` back as reviewable finding dicts.

    The same-run consumer of the variant matches: each entry is
    converted to a ``VulnerabilityContext``-shaped finding dict,
    resolved to its enclosing function via the inventory checklist.
    Unresolvable sites are dropped (no context slice to review), the
    seed's own function and ``exclude_keys`` (functions this run
    already analysed) are skipped, duplicates collapse per function,
    and the result is bounded by ``max_candidates``.

    Provenance is marked on each candidate: ``tool`` is
    ``checker-synthesis``, ``metadata.from_synthesis`` is True, and the
    seed finding / rule identity ride along. The originating hypothesis
    (rule rationale + seed reasoning, both prior-LLM prose over
    attacker-visible source) is returned under ``synthesis_context`` —
    the caller must wrap it in an ``UntrustedBlock`` before it reaches
    a prompt.
    """
    matches_path = Path(out_dir) / CHECKER_MATCHES_FILE
    if not matches_path.is_file():
        return []

    try:
        from core.inventory.lookup import lookup_function
    except ImportError:
        logger.debug("inventory lookup unavailable", exc_info=True)
        return []

    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set(exclude_keys)
    try:
        lines = matches_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        logger.debug("checker-matches read failed", exc_info=True)
        return []

    for raw in lines:
        if len(candidates) >= max_candidates:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("triage") in ("false_positive", "skipped"):
            continue
        file_path = rec.get("file") or ""
        try:
            line_no = int(rec.get("line") or 0)
        except (TypeError, ValueError):
            line_no = 0
        if not file_path or line_no <= 0:
            continue

        func = None
        try:
            func = lookup_function(
                checklist or {}, file_path, line_no,
                repo_root=str(repo_root),
            )
        except (ValueError, TypeError, OSError):
            func = None
        if not func or not func.get("name"):
            continue
        name = func["name"]

        key = (file_path, name)
        if key in seen:
            continue
        # The synthesised rule matching its own seed is confirmation,
        # not a variant.
        if (rec.get("seed_file"), rec.get("seed_function")) == key:
            continue
        seen.add(key)

        context_parts = []
        rationale = (rec.get("rationale") or "").strip()
        if rationale:
            context_parts.append(f"Checker rule rationale: {rationale}")
        seed_reasoning = (rec.get("seed_reasoning") or "").strip()
        if seed_reasoning:
            context_parts.append(
                "Originating hypothesis (analysis of the confirmed "
                f"seed finding): {seed_reasoning}"
            )

        candidates.append(
            {
                "finding_id": (
                    f"synthesis-variant:{rec.get('rule_id', '')}:"
                    f"{file_path}:{line_no}"
                ),
                "rule_id": rec.get("rule_id") or "synthesized-variant",
                "file": file_path,
                "startLine": line_no,
                "endLine": line_no,
                "snippet": rec.get("snippet") or "",
                "message": (
                    "Codebase-wide variant match from a checker "
                    "synthesized off the confirmed finding "
                    f"{rec.get('seed_file', '?')}:"
                    f"{rec.get('seed_function', '?')}"
                ),
                "level": "warning",
                "cwe_id": rec.get("cwe"),
                "tool": "checker-synthesis",
                "metadata": {
                    "name": name,
                    "from_synthesis": True,
                    "seed_file": rec.get("seed_file"),
                    "seed_function": rec.get("seed_function"),
                    "synthesis_rule_id": rec.get("rule_id"),
                    "synthesis_engine": rec.get("engine"),
                    "synthesis_triage": rec.get("triage"),
                },
                "synthesis_context": "\n".join(context_parts),
            }
        )
    return candidates
