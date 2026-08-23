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


def is_self_match_synth_receipt(
    tool_id: str,
    file_path: str,
    function: str,
) -> bool:
    """True when *tool_id* is an ``<engine>:synth-<rule_id>`` receipt
    whose rule was synthesized from this very function.

    A rule distilled from function F's own code shape necessarily
    matches F — the match is circular and can never disconfirm, so it
    may not serve as promoting evidence ON F. It still counts on other
    functions (variant discovery). Detection is structural: rule ids
    are ``<slug(file)>.<slug(function)>.<slug(cwe)>.<attempt>``.
    """
    tid = tool_id or ""
    if ":synth-" not in tid:
        return False
    rule_id = tid.split(":synth-", 1)[1]
    try:
        from packages.checker_synthesis.synthesise import _slugify
    except ImportError:
        return False
    if not file_path or not function:
        return False
    prefix = f"{_slugify(file_path)}.{_slugify(function)}."
    if rule_id.startswith(prefix):
        return True
    # The seed file may have been recorded basename-only or with a
    # different root prefix; the function+cwe tail is the stable part.
    from pathlib import PurePosixPath
    base_prefix = (
        f"{_slugify(PurePosixPath(file_path).name)}.{_slugify(function)}."
    )
    return f".{base_prefix}" in f".{rule_id}" and rule_id.split(".")[-1].isdigit()


def _hypothesis_self_classified_refuted(
    outcome: Any,
    hypothesis: str,
) -> bool:
    """True when the review STRUCTURALLY classified *hypothesis* as
    refuted (no plausible defect).

    The review schema carries the verdict field: each ``hypotheses[]``
    entry has ``confidence`` with the enum value ``"refuted"``. A rule
    synthesized from a hypothesis whose own review says "no defect
    here" can only ever mint circular confirmations — one such rule
    "confirmed" a no-plausible-defect hypothesis, promoted the outcome
    suspicious -> finding (a false positive), and then ran at 0%
    precision for the rest of the run. The check is structural (the
    confidence field), never text matching on the prose.

    Resolution mirrors the orchestrator's primary-entry matching:
    the entry whose mechanism text backs the primary hypothesis
    decides; when the primary matches no entry, an all-refuted array
    is still a no-defect self-classification.
    """
    hyps = getattr(outcome, "hypotheses", None) or []
    if not hyps:
        review = getattr(outcome, "review_result", None) or {}
        hyps = review.get("hypotheses") or []
    entries = [h for h in hyps if isinstance(h, dict)]
    if not entries:
        return False

    def _refuted(entry: dict[str, Any]) -> bool:
        return (entry.get("confidence") or "").strip().lower() == "refuted"

    head = (hypothesis or "").strip()[:120]
    if head:
        for h in entries:
            mech = (h.get("mechanism") or "").strip()
            if mech and (
                mech.startswith(head) or head.startswith(mech[:120])
            ):
                return _refuted(h)
    return all(_refuted(h) for h in entries)


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

    # Persistent-auth fail-closed: the synthesis engine (packages.
    # checker_synthesis) catches exceptions around its LLM calls, so
    # an auth abort cannot propagate from inside it. The tracker rides
    # the callable instead; the phase drivers check it AFTER the
    # engine returns (see _raise_if_auth_tripped) and abort the phase
    # rather than reporting refusal-shaped "no synthesis" as success.
    from core.llm.client import AuthFailureTracker
    auth_tracker = AuthFailureTracker("checker-synthesis")

    def _call(prompt: str, schema: dict[str, Any], system_prompt: str):
        from core.security.prompt_framing import with_audit_framing
        if auth_tracker.tripped:
            # Terminal: every further call is a guaranteed refusal —
            # skip the network round trip; the phase driver raises.
            return None
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
            auth_tracker.note_success()
            return data
        except Exception as exc:  # noqa: BLE001 — any transport failure degrades to no-synthesis
            auth_tracker.note_failure(exc)
            logger.debug("checker_synthesis LLM call failed: %s", exc)
            return None

    _call.auth_tracker = auth_tracker
    return _call, client


def _raise_if_auth_tripped(llm_callable: Any) -> None:
    """Raise ``LLMAuthPersistentError`` when *llm_callable*'s auth
    tracker tripped during an engine run. Called by the phase drivers
    after each engine leg — inside the engine the callable degrades
    each refused call to ``None`` (the engine's own contract), so
    without this check a dead dispatcher token turns the whole phase
    into an apparent "nothing synthesised" success."""
    tracker = getattr(llm_callable, "auth_tracker", None)
    if tracker is not None:
        tracker.raise_if_tripped()


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
    quarantined_rules: set[str] | None = None,
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
        quarantined_rules: Run-scoped quarantine set of rule IDs.
            Library-replay candidates whose ``rule_id`` is in this set
            are skipped (this run already triaged their matches all-FP).

    Returns:
        SynthesisResult with hits, or None if synthesis failed or was skipped.
    """
    if synthesis_count >= max_per_run:
        logger.debug("synthesis cap reached (%d/%d)", synthesis_count, max_per_run)
        return None

    seed = _seed_from_outcome(outcome)
    if seed is None:
        return None

    if _hypothesis_self_classified_refuted(outcome, seed.reasoning):
        logger.info(
            "synthesis refused for %s:%s — the review structurally "
            "classified the seed hypothesis as refuted (no plausible "
            "defect)",
            seed.file, seed.function,
        )
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
    # Graduated-rule replay is an accumulated-knowledge read: gated
    # off in cold-profile corpus runs (library writes and the fresh
    # synthesis below stay on).
    if engine and seed.cwe and getattr(config, "library_replay", True):
        candidates = lib.find_replayable(seed.cwe, engine)
        if quarantined_rules:
            # Run-scoped quarantine: a rule whose matches this run has
            # already triaged all-FP may not be replayed this run.
            candidates = [
                c for c in candidates
                if c.rule_id not in quarantined_rules
            ]
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
    if (
        cs_result is None
        and engine
        and seed.cwe
        # SAGE rule replay is a recall read — same gate as the other
        # SAGE recall surfaces (cold-profile corpus runs).
        and getattr(config, "sage_recall", True)
    ):
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
            # Persistent auth refusal outranks the degrade path — the
            # phase aborts loudly instead of reading as "no rule".
            _raise_if_auth_tripped(llm_callable)
            logger.warning(
                "audit synthesis: full synthesis failed for %s:%s",
                seed.file, seed.function, exc_info=True,
            )
            return None
        _raise_if_auth_tripped(llm_callable)

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
            # Producing rule — the in-run quarantine joins triage
            # verdicts back to the rule through this.
            "rule_id": cs_result.rule.rule_id,
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
        # Persistent auth refusal outranks the degrade path — the
        # phase aborts loudly instead of reading as "no rule".
        _raise_if_auth_tripped(llm_callable)
        logger.warning(
            "external seed synthesis failed for %s (%s)",
            seed.file, getattr(seed, "provenance", ""), exc_info=True,
        )
        return None
    _raise_if_auth_tripped(llm_callable)

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
            "rule_id": cs_result.rule.rule_id,
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


# The review schema's impact.primitive enum (llm_review.REVIEW_SCHEMA
# properties.impact.properties.primitive.enum) — re-validated at the
# harm gate because the schema constrains only conforming reviews;
# LLM drift can emit "none"/"n/a", which state no harm and must not
# open the synthesis lane. Pinned against the schema by test.
_KNOWN_IMPACT_PRIMITIVES = frozenset({
    "read", "write", "execute", "auth_bypass", "dos", "info_leak",
})


def ondemand_synthesis_refusal_reason(
    cwe: str,
    hypothesis: str,
    review: dict[str, Any] | None = None,
) -> str:
    """Why the on-demand verification lane may not synthesize for this
    hypothesis ('' when it may).

    Two policy gates, both structural (never prose heuristics):

    1. Not-tool-verifiable classes
       (``cwe_dispatch.CWE_NOT_TOOL_VERIFIABLE`` — CWE-778, CWE-1164):
       quality/operational properties where a rule "confirming" the
       hypothesis is always a shape assertion, never harm evidence.

    2. Harm gate: a placeholder or absent class (CWE-NOINFO, CWE-000,
       empty) must be backed by a stated harm — the review's
       structured ``impact.primitive`` (what the attacker gains,
       validated against the schema enum), or a hypothesis naming a
       recognized harm mechanism (``infer_cwe_from_hypothesis`` —
       structural reuse of the keyword dispatch table). A hypothesis
       that states neither has stated no harm; the long instrumented
       run watched exactly this shape promote "empty function body
       cannot cause memory unsafety" to finding/high through a
       self-referential pattern match.

    Refused outcomes stay at suspicious/hypothesis grade; the
    orchestrator chokepoint persists the reason to
    ``suppressions.jsonl`` so the parking is never silent.
    """
    try:
        from .cwe_dispatch import (
            infer_cwe_from_hypothesis,
            is_placeholder_cwe,
            not_tool_verifiable_reason,
        )
    except ImportError:
        return ""

    reason = not_tool_verifiable_reason(cwe)
    if reason:
        return f"not tool-verifiable by policy: {reason}"
    if not cwe or is_placeholder_cwe(cwe):
        impact = (review or {}).get("impact") or {}
        primitive = (
            impact.get("primitive") if isinstance(impact, dict) else ""
        ) or ""
        if primitive.strip().lower() in _KNOWN_IMPACT_PRIMITIVES:
            return ""
        if infer_cwe_from_hypothesis(hypothesis or "") is None:
            stated = cwe or "no CWE"
            return (
                f"no harm-stating hypothesis: the review stated no "
                f"concrete defect class ({stated}), no impact "
                f"primitive, and the hypothesis names no recognized "
                f"harm mechanism — re-classify with a concrete CWE "
                f"for tool verification"
            )
    return ""


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

    if _hypothesis_self_classified_refuted(outcome, hypothesis):
        logger.info(
            "on-demand synthesis refused for %s:%s — the review "
            "structurally classified the hypothesis as refuted "
            "(no plausible defect); a rule distilled from it could "
            "only confirm circularly",
            getattr(outcome, "file", ""), getattr(outcome, "function", ""),
        )
        return None

    effective_cwe = cwe or review.get("cwe_class") or review.get("cwe") or ""
    refusal = ondemand_synthesis_refusal_reason(
        effective_cwe, hypothesis, review,
    )
    if refusal:
        # Belt-and-braces for non-orchestrator callers — the
        # orchestrator records the reason on the outcome before it
        # ever gets here (see _synthesize_unmapped_suspicious).
        logger.info(
            "on-demand synthesis refused for %s:%s — %s",
            getattr(outcome, "file", ""), getattr(outcome, "function", ""),
            refusal,
        )
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
