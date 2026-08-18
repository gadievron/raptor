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
from typing import Any

logger = logging.getLogger(__name__)

MAX_SYNTHESIS_PER_RUN = 5
MAX_SWEEP_HITS_PER_RULE = 50

# On-demand Mode-2 synthesis: verification channel for chain-less
# hypotheses — suspicious outcomes whose (possibly inferred) CWE has no
# dispatch-table entry and whose hypothesis binds no keyword channel.
# Separate, larger cap from the amplification lane: these are
# single-function verification attempts, not codebase sweeps seeded
# from confirmed findings.
MAX_ONDEMAND_SYNTHESIS_PER_RUN = 10

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
    hits: list[dict[str, Any]] = field(default_factory=list)
    cost_usd: float = 0.0
    # Mechanical-control evidence, threaded into RuleLibrary.add_rule
    # so persistence carries the tier gate (library requires
    # dual_control AND every control passed).
    dual_control: bool = False
    rule_tier: str = "sweep_once"


def _synthesis_class_cost(client: Any) -> float:
    """Completed-call spend recorded for the checker_synthesis class.

    The budget client is shared across audit phases, so deltas must be
    read from the per-class history rather than ``total_cost`` (which
    moves with every concurrent call class)."""
    hist = getattr(client, "_call_cost_history", None) or {}
    entry = hist.get("checker_synthesis")
    return float(entry[1]) if entry else 0.0


def _build_llm_callable(config: Any):
    """Build a ``packages.checker_synthesis.LLMCallable`` from /audit's
    LLM config. Returns ``(callable, client)`` or None when no LLM is
    available. The caller reads ``client.total_cost`` after synthesis to
    feed the cost back into the budget tracker."""
    try:
        from core.llm.task_types import TaskType
    except ImportError:
        return None

    # Budget-governed client: synthesis spend must hit the run ledger
    # and the per-call reservation gate. Falls back to a fresh client
    # (pinned to the run's primary model) for library callers.
    client = getattr(config, "llm_budget_client", None)
    if client is None:
        try:
            from core.llm.client import LLMClient
        except ImportError:
            return None
        model = None
        models = getattr(config, "models", None)
        if models and models[0] != "default":
            model = models[0]
        client = LLMClient(pinned_model=model) if model else LLMClient()
    if not hasattr(client, "generate_structured"):
        return None

    def _call(prompt: str, schema: dict[str, Any], system_prompt: str):
        from core.security.prompt_framing import with_audit_framing
        try:
            data, _full = client.generate_structured(
                prompt=prompt,
                schema=schema,
                # Audit-purpose framing at the audit boundary — the
                # packages-side grammar prompt states the rule-author
                # role but not the audit context (see
                # core.security.prompt_framing).
                system_prompt=with_audit_framing(system_prompt),
                task_type=TaskType.AUDIT,
                # Telemetry class matches the "checker_synthesis"
                # phase the orchestrator books this spend into, so
                # end-of-run class booking doesn't double-count it.
                call_class="checker_synthesis",
                # See SYNTHESIS_TIMEOUT_S — the provider default kills
                # this call class before it completes.
                timeout_s=SYNTHESIS_TIMEOUT_S,
            )
            return data
        except Exception as exc:  # noqa: BLE001 — any transport failure degrades to no-synthesis
            logger.debug("checker_synthesis LLM call failed: %s", exc)
            return None

    return _call, client


def _seed_from_outcome(outcome: Any) -> Any | None:
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


def _sage_replay_rule(
    engine: str,
    cwe: str,
    seed: Any,
    target_path: Path,
) -> tuple[Any, str] | None:
    """Replay a SAGE-recalled proven rule against the target.

    Consumes ``recall_verified_proven_rules`` — HMAC-verified,
    replay-gated rows only. The referenced rule body must still exist
    on disk and hash to the stamped ``rule_body_hash`` (the recall row
    is an index, not the rule). Returns ``(CheckerSynthesisResult,
    provenance)`` with provenance ``sage:<rule_id>``, or None.
    """
    import hashlib

    try:
        from core.sage import recall_verified_proven_rules
    except ImportError:
        return None
    try:
        metas = recall_verified_proven_rules(engine, cwe)
    except Exception:
        logger.debug("SAGE proven-rule recall failed", exc_info=True)
        return None
    if not metas:
        return None

    try:
        from packages.checker_synthesis.models import (
            CheckerSynthesisResult,
            SynthesisedRule,
        )
        from packages.checker_synthesis.synthesise import (
            _is_seed_match,
            _run_engine,
        )
    except ImportError:
        return None

    for meta in metas:
        rule_id = str(meta.get("rule_id") or "")
        rule_path = Path(str(meta.get("rule_path") or ""))
        stored_hash = str(meta.get("rule_body_hash") or "")
        if not rule_id or len(stored_hash) < 16 or not rule_path.is_file():
            continue
        try:
            body = rule_path.read_text(encoding="utf-8")
        except OSError:
            continue
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if not digest.startswith(stored_hash):
            logger.debug(
                "SAGE rule %s: on-disk body no longer matches stamped "
                "hash — skipping replay", rule_id,
            )
            continue
        try:
            rule = SynthesisedRule(
                engine=engine,
                rule_id=rule_id,
                body=body,
                rationale="SAGE-recalled proven rule",
            )
            matches, errors = _run_engine(rule, rule_path, target_path)
            if errors:
                logger.warning(
                    "audit synthesis: engine errors for SAGE rule %s: %s",
                    rule_id, "; ".join(errors),
                )
            matches = [m for m in matches if not _is_seed_match(seed, m)]
            if len(matches) > MAX_SWEEP_HITS_PER_RULE:
                matches = matches[:MAX_SWEEP_HITS_PER_RULE]
            cs_result = CheckerSynthesisResult(seed=seed)
            cs_result.rule = rule
            cs_result.rule_path = rule_path
            cs_result.matches = matches
            cs_result.dual_control = bool(meta.get("dual_control", False))
            # Verified replay of a rule whose mechanical controls
            # passed at promotion time (dual control is part of the
            # should_replay_rule gate).
            cs_result.rule_tier = "library"
            logger.info(
                "audit synthesis: replayed SAGE-recalled rule %s — "
                "%d match(es)", rule_id, len(matches),
            )
            return cs_result, f"sage:{rule_id}"
        except Exception:
            logger.warning(
                "audit synthesis: SAGE rule replay failed for %s",
                rule_id, exc_info=True,
            )
    return None


def synthesize_and_sweep(
    outcome: Any,
    config: Any,
    seen_keys: set[str],
    *,
    synthesis_count: int = 0,
    max_per_run: int = MAX_SYNTHESIS_PER_RUN,
) -> SynthesisResult | None:
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
    cost_before = _synthesis_class_cost(llm_client)

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
                    # Replayed from the library — the mechanical
                    # controls passed at promotion time.
                    cs_result.rule_tier = "library"
                    logger.info(
                        "audit synthesis: replayed library rule %s — %d match(es)",
                        entry.rule_id, len(matches),
                    )
            except Exception:
                logger.warning(
                    "audit synthesis: library replay failed for %s:%s",
                    seed.file, seed.function, exc_info=True,
                )

    # No local library rule — try SAGE-recalled proven rules. Only
    # HMAC-verified rows join sweeps (unverified recall is hint-only
    # per operator policy); the rule body on disk must still match the
    # stamped body hash.
    sage_provenance = ""
    if cs_result is None and engine and seed.cwe:
        replay = _sage_replay_rule(engine, seed.cwe, seed, Path(target_path))
        if replay is not None:
            cs_result, sage_provenance = replay

    if cs_result is None:
        try:
            from packages.checker_synthesis import synthesise_with_refinement
            cs_result = synthesise_with_refinement(
                seed,
                repo_root=Path(target_path),
                out_dir=Path(out_dir),
                llm=llm_callable,
                max_matches=MAX_SWEEP_HITS_PER_RULE,
                model_id=getattr(llm_client, "model_name", "") or "",
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
        hit = {
            "file": m.file,
            "line": m.line,
            "function": "",
            "snippet": m.snippet or "",
            "origin_file": file_path,
            "origin_function": function,
        }
        if sage_provenance:
            hit["provenance"] = sage_provenance
        new_hits.append(hit)

    logger.info(
        "synthesis %s: %d sweep matches emitted "
        "(site-level dedup happens downstream; seen_keys=%d)",
        cs_result.rule.rule_id, len(new_hits), len(seen_keys),
    )

    return SynthesisResult(
        rule_id=cs_result.rule.rule_id,
        tool=cs_result.rule.engine,
        content=cs_result.rule.body,
        cwe=seed.cwe,
        origin_file=file_path,
        origin_function=function,
        hits=new_hits,
        cost_usd=_synthesis_class_cost(llm_client) - cost_before,
        dual_control=bool(cs_result.dual_control),
        rule_tier=getattr(cs_result, "rule_tier", "sweep_once"),
    )


def synthesize_from_external_seed(
    ext_seed: Any,
    config: Any,
    *,
    synthesis_count: int = 0,
    max_per_run: int = MAX_SYNTHESIS_PER_RUN,
) -> SynthesisResult | None:
    """Synthesise a checker from an EXTERNAL ground-truth seed.

    Counterpart to :func:`synthesize_and_sweep` for seeds that did not
    come from this run's review outcomes: prior-run journal findings,
    crash RCAs, and cvefix-mined fixture pairs
    (``core.audit.synthesis_seeds.ExternalSeed``). Seeds with fixture
    pairs go through the substrate's ground-truth control (positive =
    known-vulnerable form, negative = fixed form); repo-anchored seeds
    use the standard positive control. Shares the amplification lane's
    per-run cap.
    """
    if synthesis_count >= max_per_run:
        logger.debug(
            "external seed synthesis cap reached (%d/%d)",
            synthesis_count, max_per_run,
        )
        return None

    seed = getattr(ext_seed, "seed", None)
    if seed is None or not getattr(seed, "file", ""):
        return None

    out_dir = getattr(config, "out_dir", None)
    target_path = getattr(config, "target_path", None)
    if not out_dir or not target_path:
        return None

    llm_pair = _build_llm_callable(config)
    if llm_pair is None:
        return None
    llm_callable, llm_client = llm_pair
    cost_before = _synthesis_class_cost(llm_client)

    positive = getattr(ext_seed, "positive_fixture", None)
    negative = getattr(ext_seed, "negative_fixture", None)

    try:
        from packages.checker_synthesis.synthesise import synthesise_and_run
        cs_result = synthesise_and_run(
            seed,
            repo_root=Path(target_path),
            out_dir=Path(out_dir),
            llm=llm_callable,
            max_matches=MAX_SWEEP_HITS_PER_RULE,
            model_id=getattr(llm_client, "model_name", "") or "",
            ground_truth_fixtures=(
                (positive, negative) if positive else None
            ),
        )
    except Exception:
        logger.warning(
            "external seed synthesis failed for %s (%s)",
            seed.file, getattr(seed, "provenance", ""), exc_info=True,
        )
        return None

    if cs_result.rule is None:
        logger.debug(
            "external seed synthesis: no rule for %s (%s): %s",
            seed.file, getattr(seed, "provenance", ""),
            "; ".join(cs_result.errors[:3]) if cs_result.errors else "none",
        )
        return None

    provenance = getattr(seed, "provenance", "") or "external"
    hits = [
        {
            "file": m.file,
            "line": m.line,
            "function": "",
            "snippet": m.snippet or "",
            "origin_file": seed.file,
            "origin_function": seed.function,
            "provenance": provenance,
        }
        for m in cs_result.matches
    ]
    logger.info(
        "external seed synthesis %s (%s): %d sweep matches",
        cs_result.rule.rule_id, provenance, len(hits),
    )
    return SynthesisResult(
        rule_id=cs_result.rule.rule_id,
        tool=cs_result.rule.engine,
        content=cs_result.rule.body,
        cwe=seed.cwe,
        origin_file=seed.file,
        origin_function=seed.function,
        hits=hits,
        cost_usd=_synthesis_class_cost(llm_client) - cost_before,
        dual_control=bool(cs_result.dual_control),
        rule_tier=getattr(cs_result, "rule_tier", "sweep_once"),
    )


@dataclass
class OnDemandSynthesisResult:
    """Result of an on-demand verification synthesis attempt.

    ``confirmed`` is True only when the synthesized rule passed BOTH
    mechanical controls: the positive control (matched the suspect
    function) and the dual control (matched the positive fixture,
    stayed silent on the negative fixture). ``stamp`` is empty unless
    confirmed.
    """

    stamp: str = ""
    rule_id: str = ""
    tool: str = ""
    content: str = ""
    cwe: str = ""
    confirmed: bool = False
    cost_usd: float = 0.0


def synthesize_verification_rule(
    outcome: Any,
    config: Any,
    *,
    cwe: str = "",
    source_snippet: str = "",
    synthesis_count: int = 0,
    max_per_run: int = MAX_ONDEMAND_SYNTHESIS_PER_RUN,
) -> OnDemandSynthesisResult | None:
    """Synthesise a one-off verification rule for a chain-less hypothesis.

    Verification-channel counterpart to :func:`synthesize_and_sweep`:
    instead of amplifying a confirmed finding across the codebase, it
    tests an UNCONFIRMED suspicious hypothesis whose CWE has no
    dispatch-table entry. The rule goes through the standard synthesis
    controls (positive control against the suspect function, dual
    control against LLM-emitted positive/negative fixtures); only a
    rule that passes both earns a ``<engine>:synth-<rule_id>`` receipt.
    Survivors are persisted to the rule library so the class stays
    covered on later runs.

    Args:
        outcome: ReviewOutcome — must be suspicious or finding, never
            clean (verification money is for candidates only).
        config: OrchestratorConfig with target_path, out_dir, models.
        cwe: Effective CWE (review-supplied or inferred); may be empty.
        source_snippet: The function source, when the caller already
            read it (falls back to review_result.source_snippet).
        synthesis_count: On-demand syntheses already attempted this run.
        max_per_run: Per-run attempt cap.

    Returns:
        OnDemandSynthesisResult when an LLM synthesis was attempted
        (confirmed or not — the attempt consumed budget either way),
        or None when skipped (cap reached, ineligible outcome, no LLM).
    """
    if synthesis_count >= max_per_run:
        logger.debug(
            "on-demand synthesis cap reached (%d/%d)",
            synthesis_count, max_per_run,
        )
        return None

    status = getattr(outcome, "status", "")
    if status not in ("suspicious", "finding"):
        return None

    review = getattr(outcome, "review_result", None) or {}
    hypothesis = review.get("hypothesis") or getattr(outcome, "hypothesis", "") or ""
    if not hypothesis:
        return None

    file_path = getattr(outcome, "file", "")
    function = getattr(outcome, "function", "")
    if not file_path or not function:
        return None

    out_dir = getattr(config, "out_dir", None)
    target_path = getattr(config, "target_path", None)
    if not out_dir or not target_path:
        return None

    llm_pair = _build_llm_callable(config)
    if llm_pair is None:
        return None
    llm_callable, llm_client = llm_pair
    cost_before = _synthesis_class_cost(llm_client)

    try:
        from packages.checker_synthesis import SeedBug
        from packages.checker_synthesis.synthesise import synthesise_and_run
    except ImportError:
        logger.debug("checker_synthesis packages not available")
        return None

    line = getattr(outcome, "line", None) or 0
    seed = SeedBug(
        file=file_path,
        function=function,
        line_start=int(line) if line else 0,
        line_end=int(line) if line else 0,
        cwe=cwe or review.get("cwe_class") or review.get("cwe") or "",
        reasoning=hypothesis,
        snippet=source_snippet or review.get("source_snippet") or "",
    )

    try:
        cs = synthesise_and_run(
            seed,
            repo_root=Path(target_path),
            out_dir=Path(out_dir),
            llm=llm_callable,
            max_matches=MAX_SWEEP_HITS_PER_RULE,
            model_id=getattr(llm_client, "model_name", "") or "",
        )
    except Exception:
        logger.warning(
            "on-demand synthesis failed for %s:%s",
            file_path, function, exc_info=True,
        )
        return OnDemandSynthesisResult(
            cwe=seed.cwe,
            cost_usd=_synthesis_class_cost(llm_client) - cost_before,
        )

    cost = _synthesis_class_cost(llm_client) - cost_before
    if cs.rule is None:
        logger.debug(
            "on-demand synthesis: no rule produced for %s:%s (errors: %s)",
            file_path, function,
            "; ".join(cs.errors[:3]) if cs.errors else "none",
        )
        return OnDemandSynthesisResult(cwe=seed.cwe, cost_usd=cost)

    confirmed = bool(cs.positive_control and cs.dual_control)
    stamp = f"{cs.rule.engine}:synth-{cs.rule.rule_id}" if confirmed else ""

    if confirmed:
        try:
            from packages.checker_synthesis import RuleLibrary
            RuleLibrary().add_rule(
                rule_id=cs.rule.rule_id,
                engine=cs.rule.engine,
                body=cs.rule.body,
                cwe=seed.cwe,
                seed_file=file_path,
                seed_function=function,
                source="audit-ondemand",
                # Tier gate: positive+dual alone is sweep_once; only
                # a full control run (incl. fix-mutant) stamps
                # rule_tier="library" on the synthesis result.
                dual_control=bool(cs.dual_control),
                rule_tier=getattr(cs, "rule_tier", "sweep_once"),
            )
        except Exception:
            logger.debug(
                "on-demand synthesis: library persist failed",
                exc_info=True,
            )

    return OnDemandSynthesisResult(
        stamp=stamp,
        rule_id=cs.rule.rule_id,
        tool=cs.rule.engine,
        content=cs.rule.body,
        cwe=seed.cwe,
        confirmed=confirmed,
        cost_usd=cost,
    )
