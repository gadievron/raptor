"""Mid-loop checker synthesis amplification.

When the review loop confirms a finding, immediately synthesise a mechanical
checker (Semgrep or Coccinelle rule) and sweep the entire codebase.  One LLM
finding becomes N mechanical findings for near-zero additional cost.

Delegates to ``packages.checker_synthesis`` which provides grammar-aware
prompts, dual control (positive + negative test fixtures), and iterative
FP-elimination refinement.  This module adapts /audit's ``ReviewOutcome``
and ``OrchestratorConfig`` types to the substrate's ``SeedBug`` /
``LLMCallable`` protocol.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

MAX_SYNTHESIS_PER_RUN = 5
MAX_SWEEP_HITS_PER_RULE = 50

# Per-call timeout for synthesis LLM calls. Synthesis is the heaviest
# structured call class in /audit — a grammar-reference system prompt
# (full SmPL subset) plus --json-schema output — and reliably exceeds
# the claudecode provider's 600s default on Bedrock-backed CLIs
# (observed: two consecutive 600s timeout kills on a 52-SLOC target).
# Non-claudecode providers ignore the kwarg (SDK-timeout governed).
SYNTHESIS_TIMEOUT_S = 1800


@dataclass
class SynthesisResult:
    """Result of a mid-loop checker synthesis + sweep."""

    rule_id: str
    tool: str
    content: str
    cwe: str
    origin_file: str
    origin_function: str
    hits: List[Dict[str, Any]] = field(default_factory=list)
    cost_usd: float = 0.0


def _build_llm_callable(config: Any):
    """Build a ``packages.checker_synthesis.LLMCallable`` from /audit's
    LLM config. Returns ``(callable, client)`` or None when no LLM is
    available. The caller reads ``client.total_cost`` after synthesis to
    feed the cost back into the budget tracker."""
    try:
        from core.llm.client import LLMClient
        from core.llm.task_types import TaskType
    except ImportError:
        return None

    model = None
    models = getattr(config, "models", None)
    if models and models[0] != "default":
        model = models[0]
    client = LLMClient(pinned_model=model) if model else LLMClient()
    if not hasattr(client, "generate_structured"):
        return None

    def _call(prompt: str, schema: Dict[str, Any], system_prompt: str):
        try:
            data, _full = client.generate_structured(
                prompt=prompt,
                schema=schema,
                system_prompt=system_prompt,
                task_type=TaskType.AUDIT,
                # See SYNTHESIS_TIMEOUT_S — the provider default kills
                # this call class before it completes.
                timeout_s=SYNTHESIS_TIMEOUT_S,
            )
            return data
        except Exception as exc:
            logger.debug("checker_synthesis LLM call failed: %s", exc)
            return None

    return _call, client


def _seed_from_outcome(outcome: Any) -> Optional[Any]:
    """Build a ``SeedBug`` from a /audit ``ReviewOutcome``.
    Returns None when the outcome lacks the fields needed for synthesis."""
    from packages.checker_synthesis import SeedBug

    review = getattr(outcome, "review_result", None) or {}
    hypothesis = review.get("hypothesis") or getattr(outcome, "hypothesis", "") or ""
    if not hypothesis:
        return None

    cwe = review.get("cwe_class") or review.get("cwe") or ""
    if not cwe:
        return None

    file_path = getattr(outcome, "file", "")
    function = getattr(outcome, "function", "")
    if not file_path or not function:
        return None

    line = getattr(outcome, "line", None) or 0
    source = review.get("source_snippet") or ""

    return SeedBug(
        file=file_path,
        function=function,
        line_start=int(line) if line else 0,
        line_end=int(line) if line else 0,
        cwe=cwe,
        reasoning=hypothesis,
        snippet=source,
    )


def synthesize_and_sweep(
    outcome: Any,
    config: Any,
    seen_keys: Set[str],
    *,
    synthesis_count: int = 0,
    max_per_run: int = MAX_SYNTHESIS_PER_RUN,
) -> Optional[SynthesisResult]:
    """Synthesise a checker from a confirmed finding and sweep the codebase.

    Delegates to ``packages.checker_synthesis.synthesise_with_refinement``
    for grammar-aware rule generation with dual control (positive + negative
    test fixtures) and iterative FP-elimination refinement.

    Args:
        outcome: ReviewOutcome with file, function, hypothesis, review_result.
        config: OrchestratorConfig with target_path, out_dir, codeql_db_path.
        seen_keys: Retained for logging only. Site-level dedup happens
            downstream in ``orchestrator._synthesis_hits_to_gaps``, after
            each site is resolved to its enclosing function — a set of
            ``file:function`` keys cannot filter function-less sites.
        synthesis_count: How many syntheses have been done this run.
        max_per_run: Maximum synthesis attempts per run.

    Returns:
        SynthesisResult with hits, or None if synthesis failed or was skipped.
    """
    if synthesis_count >= max_per_run:
        logger.debug("synthesis cap reached (%d/%d)", synthesis_count, max_per_run)
        return None

    seed = _seed_from_outcome(outcome)
    if seed is None:
        return None

    llm_pair = _build_llm_callable(config)
    if llm_pair is None:
        return None
    llm_callable, llm_client = llm_pair
    cost_before = llm_client.total_cost

    out_dir = getattr(config, "out_dir", None)
    target_path = getattr(config, "target_path", None)
    if not out_dir or not target_path:
        return None

    try:
        from packages.checker_synthesis import RuleLibrary
        from packages.checker_synthesis.languages import detect_engine
    except ImportError:
        logger.debug("checker_synthesis packages not available")
        return None

    cs_result = None

    lib = RuleLibrary()
    engine = detect_engine(seed.file)
    if engine and seed.cwe:
        candidates = lib.find_replayable(seed.cwe, engine)
        if candidates:
            try:
                from packages.checker_synthesis.synthesise import _run_engine
                entry = candidates[0]
                rule_path = lib.rule_path(entry)
                if rule_path.exists():
                    from packages.checker_synthesis.models import SynthesisedRule
                    rule = SynthesisedRule(
                        engine=entry.engine,
                        rule_id=entry.rule_id,
                        body=rule_path.read_text(encoding="utf-8"),
                        rationale=entry.rationale,
                    )
                    matches, errors = _run_engine(rule, rule_path, Path(target_path))
                    if errors:
                        logger.warning(
                            "audit synthesis: engine errors for %s: %s",
                            entry.rule_id, "; ".join(errors),
                        )
                    from packages.checker_synthesis.synthesise import _is_seed_match
                    matches = [m for m in matches if not _is_seed_match(seed, m)]
                    if len(matches) > MAX_SWEEP_HITS_PER_RULE:
                        matches = matches[:MAX_SWEEP_HITS_PER_RULE]
                    from packages.checker_synthesis.models import CheckerSynthesisResult
                    cs_result = CheckerSynthesisResult(seed=seed)
                    cs_result.rule = rule
                    cs_result.rule_path = rule_path
                    cs_result.matches = matches
                    cs_result.dual_control = entry.dual_control
                    logger.info(
                        "audit synthesis: replayed library rule %s — %d match(es)",
                        entry.rule_id, len(matches),
                    )
            except Exception:
                logger.warning(
                    "audit synthesis: library replay failed for %s:%s",
                    seed.file, seed.function, exc_info=True,
                )

    if cs_result is None:
        try:
            from packages.checker_synthesis import synthesise_with_refinement
            cs_result = synthesise_with_refinement(
                seed,
                repo_root=Path(target_path),
                out_dir=Path(out_dir),
                llm=llm_callable,
                max_matches=MAX_SWEEP_HITS_PER_RULE,
            )
        except Exception:
            logger.warning(
                "audit synthesis: full synthesis failed for %s:%s",
                seed.file, seed.function, exc_info=True,
            )
            return None

    if cs_result.rule is None:
        logger.debug(
            "synthesis: no rule produced for %s:%s (errors: %s)",
            seed.file, seed.function,
            "; ".join(cs_result.errors[:3]) if cs_result.errors else "none",
        )
        return None

    file_path = getattr(outcome, "file", "")
    function = getattr(outcome, "function", "")

    # Emit every match, each carrying its origin. Two filters used to
    # live here and both dropped real variants:
    #
    #   * the dedup key was `<matched file>:<seed function>` — the seed's
    #     function name paired with a different file, which identifies
    #     nothing, and matched `seen_keys` only by accident;
    #   * `m.file != file_path` discarded every same-file match, so a
    #     second vulnerable sibling in the same source file was lost.
    #
    # Sites are function-less by nature (a codebase-wide rule matches
    # text), so both dedup and seed exclusion belong downstream in
    # `orchestrator._synthesis_hits_to_gaps`, once each site has been
    # resolved to its enclosing function. Excluding by line here would be
    # wrong anyway: `outcome.line` is the function's line_start, not the
    # vulnerable line, and is 0 when the inventory recorded none.
    new_hits = []
    for m in cs_result.matches:
        new_hits.append({
            "file": m.file,
            "line": m.line,
            "function": "",
            "snippet": m.snippet or "",
            "origin_file": file_path,
            "origin_function": function,
        })

    logger.info(
        "synthesis %s: %d sweep matches, %d new (deduped against %d seen)",
        cs_result.rule.rule_id, len(cs_result.matches),
        len(new_hits), len(seen_keys),
    )

    return SynthesisResult(
        rule_id=cs_result.rule.rule_id,
        tool=cs_result.rule.engine,
        content=cs_result.rule.body,
        cwe=seed.cwe,
        origin_file=file_path,
        origin_function=function,
        hits=new_hits,
        cost_usd=llm_client.total_cost - cost_before,
    )
