"""Python orchestrator for autonomous /audit review loops.

Drives the review-sweep-record cycle without human-in-the-loop. Used by:
  - `/audit --agentic` (future CLI flag)
  - programmatic invocations from CI or larger pipelines

The orchestrator:
  1. Loads gaps (with priority scoring)
  2. Resumes from last checkpoint (skip already-reviewed)
  3. For each function: assembles context, dispatches to LLM, records result
  4. Optionally runs multi-model consensus
  5. Runs critique pass at configurable intervals

Reuse contract: The orchestrator calls the same context/record/sweep/gaps
modules as the skill-driven path. The only difference is WHO drives the
loop — here it's Python; in skill mode it's the human+Claude.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading as _threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .constraints import (
    extract_constraints_from_review,
    load_constraints,
    merge_constraint,
    open_constraints,
    save_constraints,
)
from .context import assemble_context
from .gaps import (
    compute_gaps,
    gap_for_site,
    hydrate_gap_source,
    load_checklist,
    load_context_map,
    mark_checked,
    write_gaps,
)
from .priority import (
    group_by_subsystem, load_flow_traces, load_fuzz_coverage as _load_fuzz_coverage_from_runs,
    load_tool_failures, score_functions,
)
from .propagation import DEFAULT_MAX_DEPTH, PropagationConfig, propagate_one_hop
from .prefilter import PrefilterResult, run_prefilter
from .shared_state import SharedState
from .topo_order import topological_sort as _topological_sort
from .triage import TriageBucket, classify_all, format_triage_summary
from .findings import write_findings
from .record import (
    append_audit_log, load_audit_log, record_review,
    _resolve_annotations_dir as _resolve_ann_dir,
)
from .sweep import (
    SarifCache,
    run_consistency_check,
    run_semgrep_sweep,
    run_smt_verb_direct,
)
from core.evidence import (
    EvidenceRecord,
    build_evidence_index,
    format_evidence_prose,
    format_evidence_structured,
)
from .cost_tracker import CostTracker
from packages.checker_synthesis.library import RuleLibrary
from .exploit_feedback import (
    FeedbackState, load_feedback_state, format_feedback_summary,
    format_feedback_for_context,
)
from ._util import (
    extract_context_map_set,
    is_stamped_tool_evidence,
)
from core.analysis.reachability_gates import (
    build_sink_reachable_set,
    check_sink_guarded,
    compute_demotion_verdict,
)

logger = logging.getLogger(__name__)

_shutdown_event = _threading.Event()


def is_shutdown_requested() -> bool:
    return _shutdown_event.is_set()


def request_shutdown() -> None:
    _shutdown_event.set()


def _update_run_progress(out_dir: Path, result: Any) -> None:
    """Update run metadata with progress checkpoint."""
    meta_path = out_dir / ".raptor-run.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta.setdefault("extra", {})["progress"] = {
            "completed": getattr(result, "completed", 0),
        }
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
    except Exception:
        logger.debug("progress checkpoint write failed", exc_info=True)


@dataclass
class OrchestratorConfig:
    """Configuration for an orchestrator run."""

    target_path: Path
    out_dir: Path
    budget: Optional[int] = None
    scope: Optional[str] = None
    strategy_filter: Optional[str] = None
    models: List[str] = field(default_factory=lambda: ["default"])
    multi_model: bool = False
    adversarial: bool = False
    critique_interval: int = 10
    max_cost_usd: Optional[float] = None
    max_seconds: Optional[float] = None
    resume: bool = True
    annotations_dir: Optional[Path] = None
    include_stale: bool = True
    subsystem_depth: int = 0
    batch_sloc_threshold: int = 5
    propagate_constraints: bool = True
    binary_verdicts: Optional[Dict[str, str]] = None
    inventory: Optional[Dict[str, Any]] = None
    codeql_db_path: Optional[str] = None
    threat_model: Optional[Dict[str, Any]] = None
    validate: bool = True
    prefilter: bool = True
    sweep_validate_findings: bool = True
    deepen_suspicious: bool = True
    enable_session_context: bool = True
    review_passes: int = 1
    max_propagation_depth: Optional[int] = None
    force: bool = False
    joern_overrides: Optional[Dict[str, Any]] = None
    blind_first_pass: bool = False
    max_refinements: int = 2
    clean_check: bool = True
    dynamic_validation: bool = False
    caps: Optional[Any] = None
    max_workers: int = 0  # 0 = auto (derive from model RPM), 1 = serial


@dataclass
class ReviewOutcome:
    """Result of reviewing a single function."""

    file: str
    function: str
    status: str
    body: str
    hypothesis: str = ""
    hypotheses: Optional[List[Dict[str, Any]]] = None
    evidence_tool: str = ""
    cost_usd: float = 0.0
    model: str = ""
    duration_s: float = 0.0
    review_result: Optional[Dict[str, Any]] = None
    line: int = 0
    error_class: str = ""
    tools_dispatched: Optional[set] = field(default=None, repr=False)
    _propagated: bool = field(default=False, repr=False)


@dataclass
class TierCounters:
    """Per-tier mechanical evidence hit/miss/skip counts."""

    confirmed: int = 0
    refuted: int = 0
    inconclusive: int = 0
    skipped: int = 0
    errors: int = 0
    wall_time_s: float = 0.0
    cpg_build_s: float = 0.0


def _make_tier_counters() -> Dict[str, TierCounters]:
    return {
        "prefilter": TierCounters(),
        "sink_unreach": TierCounters(),
        "taint_approx": TierCounters(),
        "taint_summary": TierCounters(),
        "semgrep": TierCounters(),
        "joern": TierCounters(),
        "codeql": TierCounters(),
        "coccinelle": TierCounters(),
        "smt": TierCounters(),
    }


@dataclass
class OrchestratorResult:
    """Final result of an orchestrator run."""

    reviewed: int = 0
    skipped: int = 0
    findings: int = 0
    suspicious: int = 0
    clean: int = 0
    errors: int = 0
    total_cost_usd: float = 0.0
    total_duration_s: float = 0.0
    terminated_by: str = "complete"
    prefilter_skipped: int = 0
    prefilter_hits: int = 0
    sweep_validated: int = 0
    sweep_demoted: int = 0
    sweep_promoted: int = 0
    synthesis_amplified: int = 0
    refinement_rounds: int = 0
    clean_checks: int = 0
    clean_check_rescues: int = 0
    outcomes: List[ReviewOutcome] = field(default_factory=list)
    dormant: int = 0
    error_counts: Dict[str, int] = field(default_factory=dict)
    error_retries: int = 0
    error_retry_recovered: int = 0
    tier_counters: Dict[str, TierCounters] = field(
        default_factory=_make_tier_counters,
    )
    cost_tracker: CostTracker = field(default_factory=CostTracker)
    _lock: _threading.Lock = field(
        default_factory=_threading.Lock, repr=False,
    )


def get_reviewed_set(out_dir: Path) -> set:
    """Load set of already-reviewed file:function keys from audit log."""
    reviewed = set()
    for entry in load_audit_log(out_dir):
        if entry.get("action") in ("record", "orchestrator_review"):
            key = entry.get("key", "")
            if key:
                reviewed.add(key)
    return reviewed


def run_orchestrator(
    config: OrchestratorConfig,
    review_fn: Callable[[Dict[str, Any], OrchestratorConfig], ReviewOutcome],
    *,
    on_progress: Optional[Callable[[int, int, ReviewOutcome], None]] = None,
) -> OrchestratorResult:
    """Run the orchestrator loop.

    Args:
        config: Run configuration.
        review_fn: Called for each function. Takes (context_dict, config)
            and returns a ReviewOutcome. This is where the LLM call happens.
            The orchestrator is agnostic to HOW the LLM is called — the
            consumer provides the implementation.
        on_progress: Optional callback (current_idx, total, outcome).

    Returns:
        OrchestratorResult summarizing the run.
    """
    start_time = time.monotonic()
    _sink_guard_cache.clear()
    result = OrchestratorResult()
    _jt = _joern_tunables(overrides=config.joern_overrides)
    if _jt is not None:
        joern_timeout_s = _jt.cpg_timeout_s + _jt.query_timeout_s
    else:
        joern_timeout_s = 600

    joern_server = _start_joern_server(config, _jt)
    _joern_lifecycle = joern_server is not None and hasattr(joern_server, '_proc') and joern_server._proc is None
    try:
        return _run_audit_body(
            config, review_fn, on_progress,
            result=result, start_time=start_time,
            joern_server=joern_server,
            joern_timeout_s=joern_timeout_s,
        )
    finally:
        from core.analysis.reach_audit import set_joern_server
        set_joern_server(None)
        if _joern_lifecycle:
            try:
                from packages.joern.lifecycle import joern_release
                joern_release()
            except Exception:
                logger.debug("joern lifecycle release failed", exc_info=True)
        else:
            _stop_joern_server(joern_server)



def review_one_function(
    gap: dict,
    shared,
    config,
    review_fn,
    result,
    *,
    joern_server=None,
    audit_log=None,
    workqueue=None,
    reviewed_set=None,
    start_time=0.0,
    layer_disagreements=None,
    on_progress=None,
    review_idx=0,
    total=0,
    collector=None,
):
    """Review a single function gap and return the outcome.

    Extracted from the main loop in ``_run_audit_body`` so that the executor
    can drive the loop (serial or parallel) while the per-function logic
    lives in one place.

    Raises ``RuntimeError`` with "budget exceeded" when the LLM client
    exhausts its cost cap — the caller is expected to catch this and break
    the loop.
    """
    from .negative_space import check_negative_space

    # ── Read-only aliases ──────────────────────────────────────────────
    checklist = shared.checklist
    context_map = shared.context_map
    evidence_index = shared.evidence_index
    sarif_cache = shared.sarif_cache
    flow_traces = shared.flow_traces
    variant_targets = shared.variant_targets
    entry_points = shared.entry_points
    sinks_set = shared.sinks_set
    widely_used_keys = shared.widely_used_keys
    conventions = shared.conventions
    sibling_ns_findings = shared.sibling_ns_findings
    sibling_postcond_violations = shared.sibling_postcond_violations
    fuzz_coverage = shared.fuzz_coverage
    discovered_tests = shared.discovered_tests
    typestate_models = shared.typestate_models
    summary_cache = shared.summary_cache
    checker_library = shared.checker_library
    triage_results = shared.triage_results
    project_learnings = shared.project_learnings
    feedback_state = shared.feedback_state
    fp_patterns = shared.fp_patterns
    prop_config = shared.prop_config
    call_edges = shared.call_edges
    mechanical_findings = shared.mechanical_findings
    provenance_map = shared.provenance_map
    security_decision_keys = shared.security_decision_keys
    feeds_security_keys = shared.feeds_security_keys
    domain_model = shared.domain_model

    # ── Mutable aliases ───────────────────────────────────────────────
    taint_summary_results = shared.taint_summary_results
    session_observations = shared.session_observations
    discovered_evidence = shared.discovered_evidence
    expansion_budget = shared.expansion_budget
    live_classifications = shared.live_classifications

    gap_key = f"{gap['file']}:{gap['name']}"

    # ── Triage skip ───────────────────────────────────────────────────
    triage = triage_results.get(gap_key)
    if triage and triage.bucket == TriageBucket.SKIP:
        _increment_tier(result, "triage_skip", "confirmed")
        outcome = ReviewOutcome(
            file=gap["file"],
            function=gap["name"],
            status="clean",
            body=(
                f"[triage: {', '.join(triage.reasons)}] "
                f"Triage classifier determined this function "
                f"does not need LLM review."
            ),
            evidence_tool="triage",
        )
        outcome.line = gap.get("line_start", 0)
        result.prefilter_skipped += 1
        try:
            if collector is not None:
                collector.submit(outcome, gap)
            else:
                _commit_outcome(config, outcome, gap)
        except Exception as exc:
            logger.warning(
                "commit failed for %s:%s: %s",
                gap["file"], gap["name"], exc,
            )
        _tally_outcome(result, outcome)
        if on_progress:
            on_progress(review_idx, total, outcome)
        return outcome

    # ── Build context ─────────────────────────────────────────────────
    ctx = _build_context(
        config, gap, checklist, context_map, evidence_index,
        discovered_evidence=discovered_evidence,
        blind=config.blind_first_pass,
    )

    if triage:
        ctx["triage_bucket"] = triage.bucket.value
        ctx["triage_token_budget"] = triage.token_budget

    gap_key_mech = gap_key
    if mechanical_findings and gap_key_mech in mechanical_findings:
        ctx["mechanical_detector_findings"] = mechanical_findings[gap_key_mech]

    # --- Mechanical gates: per-function context enrichment ---
    if provenance_map and gap_key_mech in provenance_map:
        try:
            from .mechanical_gates import format_provenance_for_context
            ctx["entry_point_provenance"] = format_provenance_for_context(
                provenance_map[gap_key_mech],
            )
        except Exception:
            pass

    if gap_key_mech in security_decision_keys:
        ctx["is_security_decision"] = True
    if gap_key_mech in feeds_security_keys:
        ctx["feeds_security_decision"] = True

    if ctx.get("source") and gap.get("file", "").endswith(".py"):
        try:
            from .mechanical_gates import detect_constant_dangerous_calls
            const_calls = detect_constant_dangerous_calls(
                ctx["source"], gap["file"],
            )
            if const_calls:
                ctx["constant_dangerous_calls"] = const_calls
        except Exception:
            pass

    if ctx.get("callers"):
        try:
            from .mechanical_gates import sort_callers_by_constraint
            ctx["callers"] = sort_callers_by_constraint(ctx["callers"])
        except Exception:
            pass

    if ctx.get("source"):
        try:
            from .mechanical_gates import extract_type_constraints
            tc = extract_type_constraints(
                ctx["source"], gap.get("name", ""),
            )
            if tc:
                ctx["type_constraints"] = tc
        except Exception:
            pass

    try:
        from .condition_cpg import check_interprocedural_guards
        ipc_result = check_interprocedural_guards(
            gap.get("name", ""),
            gap["file"],
            joern_server=joern_server,
        )
        if ipc_result.unguarded_callers > 0:
            ctx["interprocedural_guards"] = ipc_result.to_dict()
    except Exception:
        pass

    if taint_summary_results and ctx.get("callees"):
        callee_sums = []
        for ce in ctx["callees"]:
            ce_key = f"{ce.get('file', '')}:{ce.get('name', '')}"
            if not expansion_budget.try_expand(ce_key):
                continue
            s = taint_summary_results.get(ce_key)
            if s is not None:
                callee_sums.append(s)
            elif summary_cache:
                ce_name = ce.get("name", "")
                for lib_info in summary_cache.available_libraries():
                    cached = summary_cache.lookup(
                        lib_info["library"], lib_info["version"], ce_name,
                    )
                    if cached:
                        callee_sums.append(cached)
                        break
        if callee_sums:
            ctx["callee_summaries"] = callee_sums

    if ctx.get("callee_summaries"):
        try:
            from .contracts import extract_callee_contracts, enforce_callee_contracts
            summaries_dict = {
                f"{getattr(s, 'file', '')}:{getattr(s, 'function', '')}": s
                for s in ctx["callee_summaries"]
            }
            contracts = extract_callee_contracts(gap, summaries_dict)
            if contracts:
                ctx["callee_contracts"] = contracts
            source = ctx.get("source", "")
            if source:
                violations = enforce_callee_contracts(gap, ctx["callee_summaries"], source)
                if violations:
                    ctx["contract_violations"] = violations
        except ImportError:
            pass

    try:
        from .spec_inference import infer_spec_mechanical
        summaries_for_spec = None
        if ctx.get("callee_summaries"):
            summaries_for_spec = {
                f"{getattr(s, 'file', '')}:{getattr(s, 'function', '')}": s
                for s in ctx["callee_summaries"]
            }
        spec = infer_spec_mechanical(
            gap, checklist=checklist,
            tests=discovered_tests or None,
            summaries=summaries_for_spec,
        )
        if spec and spec.intent:
            ctx["inferred_spec"] = spec
            if spec.preconditions and ctx.get("source"):
                try:
                    from .contracts import enforce_callee_contracts, ContractContext
                    spec_contracts = [ContractContext(
                        callee_function=gap.get("name", ""),
                        callee_file=gap.get("file", ""),
                        preconditions=spec.preconditions,
                        source="spec_inference",
                    )]
                    existing = ctx.get("callee_contracts", [])
                    ctx["callee_contracts"] = existing + spec_contracts
                except ImportError:
                    pass
    except Exception:
        logger.debug(
            "spec_inference failed for %s:%s",
            gap.get("file"), gap.get("name"), exc_info=True,
        )

    if not ctx.get("inferred_spec") or not ctx["inferred_spec"].intent:
        role_ctx = gap.get("role_context", {})
        is_high_value = (
            role_ctx.get("role") in ("entry_point", "sink")
            or gap.get("priority_score", 0) >= 0.7
        )
        if is_high_value and gap.get("source"):
            try:
                from .spec_inference import infer_spec_with_llm_sync
                llm_spec = infer_spec_with_llm_sync(
                    gap, mechanical_spec=ctx.get("inferred_spec"),
                )
                if llm_spec and llm_spec.intent:
                    ctx["inferred_spec"] = llm_spec
            except Exception:
                logger.debug(
                    "llm spec_inference failed for %s:%s",
                    gap.get("file"), gap.get("name"), exc_info=True,
                )

    if typestate_models and ctx.get("source"):
        try:
            from core.analysis.typestate import check_typestate_violations
            ts_violations = check_typestate_violations(
                ctx["source"], typestate_models,
            )
            if ts_violations:
                ctx["typestate_violations"] = ts_violations
        except Exception:
            logger.debug(
                "typestate check failed for %s:%s",
                gap.get("file"), gap.get("name"), exc_info=True,
            )

    if conventions:
        strategies = gap.get("strategies", set())
        if isinstance(strategies, (list, tuple)):
            strategies = set(strategies)
        ns_findings = []
        for strat in (strategies or {"general"}):
            ns_findings.extend(check_negative_space(gap, conventions, strat))

        func_sibling_ns = [
            f for f in sibling_ns_findings
            if gap.get("name", "") in f.evidence
        ]
        ns_findings.extend(func_sibling_ns)

        if ns_findings:
            ctx["negative_space"] = ns_findings
            evidence_key = f"{gap['file']}:{gap['name']}"
            if evidence_key in evidence_index:
                evidence_index[evidence_key].negative_space = ns_findings

    func_name = gap.get("name", "")
    func_file = gap.get("file", "")
    sib_viols = [
        v for v in sibling_postcond_violations
        if v.function == func_name and v.file == func_file
    ]
    if sib_viols:
        ctx.setdefault("postcondition_violations", []).extend(sib_viols)

    if fuzz_coverage:
        ctx["fuzz_coverage"] = _fuzz_coverage_for(
            fuzz_coverage, gap["file"], gap["name"],
        )

    if gap_key in widely_used_keys:
        ctx["widely_used"] = True
    if gap_key in variant_targets:
        ctx["variant_match"] = True
    if sarif_cache:
        sarif_hits = sarif_cache.lookup(gap["file"])
        if sarif_hits is not None and not sarif_hits:
            ctx["codeql_no_alerts"] = True

    if config.enable_session_context and session_observations:
        ctx["session_observations"] = list(session_observations)
    if project_learnings:
        ctx["project_context"] = project_learnings
    if fp_patterns:
        try:
            from .fp_feedback import format_fp_warnings
            fp_warn = format_fp_warnings(fp_patterns, gap["file"])
            if fp_warn:
                ctx["fp_warnings"] = fp_warn
        except Exception:
            pass
    if feedback_state and feedback_state.source_precision:
        fb_text = format_feedback_for_context(feedback_state)
        if fb_text:
            ctx["exploit_feedback"] = fb_text
    if shared.constraints:
        relevant = _constraints_for_function(
            shared.constraints, gap["file"], gap["name"],
        )
        if relevant:
            ctx["active_constraints"] = relevant

    # ── Prefilter ─────────────────────────────────────────────────────
    pf_result = None
    if config.prefilter:
        pf_result = _run_prefilter_for_gap(config, gap, ctx)
        if pf_result.skip_llm:
            if ctx.get("sink_unreachable"):
                _increment_tier(result, "sink_unreach", "confirmed")
            _increment_tier(result, "prefilter", "confirmed")
            outcome = ReviewOutcome(
                file=gap["file"],
                function=gap["name"],
                status="clean",
                body=(
                    f"[prefilter: {pf_result.skip_reason}] "
                    f"Mechanical pre-filter determined this function "
                    f"cannot contain vulnerabilities."
                ),
                evidence_tool="prefilter",
            )
            outcome.line = gap.get("line_start", 0)
            result.prefilter_skipped += 1
            try:
                if collector is not None:
                    collector.submit(outcome, gap)
                else:
                    _commit_outcome(config, outcome, gap)
            except Exception as exc:
                logger.warning(
                    "commit failed for %s:%s: %s",
                    gap["file"], gap["name"], exc,
                )
            _tally_outcome(result, outcome)
            if on_progress:
                on_progress(review_idx, total, outcome)
            return outcome

        if pf_result.hits:
            result.prefilter_hits += len(pf_result.hits)
            if not config.blind_first_pass:
                ctx["prefilter_results"] = pf_result

    # ── Block-level context ───────────────────────────────────────────
    try:
        block_ctx = _try_block_level_context(
            gap, ctx, config, evidence_index,
        )
        if block_ctx:
            ctx["block_analysis"] = block_ctx
    except Exception:
        logger.debug(
            "block-level analysis failed for %s:%s",
            gap["file"], gap["name"], exc_info=True,
        )

    _fuse_all_evidence(ctx)

    # ── LLM review ────────────────────────────────────────────────────
    review_start = time.monotonic()
    if config.review_passes > 1:
        outcome = _multi_pass_review(
            review_fn, ctx, config, config.review_passes,
        )
    else:
        try:
            outcome = review_fn(ctx, config)
        except _ContentFilterError:
            outcome = ReviewOutcome(
                file=gap["file"],
                function=gap["name"],
                status="error",
                body="blocked by content filter",
            )
        except Exception as exc:
            logger.warning(
                "review_fn failed for %s:%s: %s",
                gap["file"], gap["name"], exc,
            )
            outcome = _error_outcome(gap, exc)

    outcome.line = gap.get("line_start", 0)
    result.cost_tracker.record_call(
        "review",
        cost_usd=outcome.cost_usd,
        wall_time_s=time.monotonic() - review_start,
    )

    # ── Post-review: structural prefilter override ────────────────────
    if (
        outcome.status == "clean"
        and pf_result is not None
        and pf_result.hits
        and any(
            h.rule_id in _STRUCTURAL_PREFILTER_RULES
            for h in pf_result.hits
        )
    ):
        hit = next(
            h for h in pf_result.hits
            if h.rule_id in _STRUCTURAL_PREFILTER_RULES
        )
        outcome.status = "suspicious"
        outcome.body = (
            f"[prefilter override: {hit.rule_id}] "
            f"LLM ruled clean but mechanical detector flagged "
            f"a structural bug: {hit.message}"
        )
        logger.warning(
            "prefilter override %s:%s: %s (LLM said clean)",
            gap["file"], gap["name"], hit.rule_id,
        )

    # ── Clean check ───────────────────────────────────────────────────
    if config.clean_check and outcome.status == "clean":
        try:
            from .refinement import (
                build_clean_check_prompt,
                merge_outcomes as _merge_clean,
                should_clean_check as _should_cc,
            )
            bucket_val = triage.bucket.value if triage else "investigate"
            is_ep = gap_key in entry_points
            is_sk = gap_key in sinks_set
            gap_sloc = gap.get("sloc", 0)
            if _should_cc(outcome, bucket_val, is_ep, is_sk, sloc=gap_sloc):
                result.clean_checks += 1
                cc_flows = _run_clean_check_sweep(
                    outcome, config, evidence_index, joern_server,
                )
                if cc_flows:
                    cc_prompt = build_clean_check_prompt(ctx, cc_flows)
                    cc_ctx = dict(ctx)
                    cc_ctx["clean_check"] = cc_prompt
                    try:
                        revised = review_fn(cc_ctx, config)
                        if revised.status != "clean":
                            outcome = _merge_clean(outcome, revised)
                            result.clean_check_rescues += 1
                            logger.info(
                                "clean-check rescue %s:%s → %s",
                                gap["file"], gap["name"],
                                outcome.status,
                            )
                    except Exception:
                        logger.debug(
                            "clean-check review failed for %s:%s",
                            gap["file"], gap["name"], exc_info=True,
                        )
        except ImportError:
            pass

    # ── Sweep validation ──────────────────────────────────────────────
    pre_sweep_status = outcome.status
    if outcome.status == "finding" and config.sweep_validate_findings:
        outcome = _sweep_validate(
            outcome, config, sarif_cache,
            tier_counters=result.tier_counters,
            evidence_index=evidence_index,
            joern_server=joern_server,
        )
        if outcome.status == "finding":
            result.sweep_validated += 1
        else:
            result.sweep_demoted += 1

    # ── Proactive validation ──────────────────────────────────────────
    if outcome.status in ("finding", "suspicious") and not config.blind_first_pass:
        outcome = _proactive_validate(
            outcome, config, evidence_index,
            tier_counters=result.tier_counters,
            dispatched_tools=outcome.tools_dispatched,
            discovered_evidence=discovered_evidence,
            flow_traces=flow_traces,
            joern_server=joern_server,
        )
        if outcome.evidence_tool:
            _inject_discovered_evidence(
                discovered_evidence,
                outcome.file, outcome.function,
                outcome.evidence_tool, outcome.hypothesis,
            )

    # ── Refinement ────────────────────────────────────────────────────
    if config.max_refinements > 0:
        try:
            from .refinement import (
                build_refinement_prompt,
                collect_tool_results,
                merge_outcomes as _merge_refined,
                RefinementContext,
                should_refine as _should_refine,
            )
            bucket_val = triage.bucket.value if triage else "investigate"
            ref_round = 0
            while (
                _should_refine(
                    outcome, bucket_val,
                    round_number=ref_round,
                    max_refinements=config.max_refinements,
                )
                and not _check_budget(config, start_time, result)
            ):
                ref_round += 1
                result.refinement_rounds += 1
                tool_results = collect_tool_results(
                    outcome, evidence_index=evidence_index,
                )
                prior_review = outcome.review_result or {}
                ref_ctx = RefinementContext(
                    prior_hypothesis=outcome.hypothesis or "",
                    prior_status=outcome.status,
                    tool_results=tool_results,
                    tools_dispatched=outcome.tools_dispatched or set(),
                    round_number=ref_round,
                    tool_query_suggestion=prior_review.get(
                        "tool_query_suggestion", "",
                    ),
                )
                ref_prompt = build_refinement_prompt(ctx, ref_ctx)
                ref_review_ctx = dict(ctx)
                ref_review_ctx["refinement"] = ref_prompt
                try:
                    refined = review_fn(ref_review_ctx, config)
                except Exception:
                    logger.debug(
                        "refinement review failed for %s:%s round %d",
                        gap["file"], gap["name"], ref_round,
                        exc_info=True,
                    )
                    break
                outcome = _merge_refined(outcome, refined)
                logger.info(
                    "refinement round %d for %s:%s → %s",
                    ref_round, gap["file"], gap["name"],
                    outcome.status,
                )
        except ImportError:
            pass

    # ── Reachability gate ─────────────────────────────────────────────
    if outcome.status == "finding":
        outcome = _apply_reachability_gate(
            outcome, ctx, entry_points, config,
        )

    # ── Finding gates ─────────────────────────────────────────────────
    if outcome.status == "finding":
        gate_violations = _check_finding_gates(
            outcome, audit_log=audit_log,
            domain_model=domain_model,
        )
        if gate_violations:
            for v in gate_violations:
                logger.warning(
                    "gate violation %s:%s: %s — demoted to suspicious",
                    outcome.file, outcome.function, v,
                )
            outcome = _demote_outcome(
                outcome,
                f"[gate violation: {'; '.join(gate_violations)}]",
            )

    # ── Dynamic validation ────────────────────────────────────────────
    if config.dynamic_validation and outcome.status == "finding":
        try:
            from .dynamic_sweep import should_run_dynamic, run_dynamic_sweep
            if should_run_dynamic(outcome, config):
                dyn_result = run_dynamic_sweep(outcome, ctx, config)
                if dyn_result and dyn_result.evidence_strength == "sanitizer":
                    outcome.evidence_tool = "dynamic"
                elif dyn_result and dyn_result.evidence_strength == "crash":
                    outcome.evidence_tool = "dynamic:crash"
                elif dyn_result and dyn_result.evidence_strength == "refuted":
                    outcome = _demote_outcome(outcome, "[dynamic: refuted]")
        except Exception:
            logger.debug(
                "dynamic sweep failed for %s:%s",
                gap.get("file"), gap.get("name"), exc_info=True,
            )

        # Frida runs as a second opinion when the dynamic sweep produced only
        # a bare crash ("dynamic:crash") — that's weak evidence and Frida may
        # upgrade it to runtime-confirmed. Skip only when the sanitiser already
        # confirmed ("dynamic").
        if outcome.status == "finding" and outcome.evidence_tool != "dynamic":
            try:
                from .frida_observe import should_run_frida, run_frida_observation
                if should_run_frida(outcome, config):
                    frida_result = run_frida_observation(outcome, ctx, config)
                    if frida_result and frida_result.evidence_strength == "confirmed":
                        outcome.evidence_tool = "frida"
            except Exception:
                logger.debug(
                    "Frida observation failed for %s:%s",
                    gap.get("file"), gap.get("name"), exc_info=True,
                )

    # ── Mid-loop synthesis ────────────────────────────────────────────
    if outcome.status == "finding" and outcome.evidence_tool:
        try:
            from .checker_synthesis import synthesize_and_sweep
            # Current-run workqueue only. Folding in `reviewed_set` (which
            # get_reviewed_set loads from the *persisted* audit log, so it
            # spans prior runs) suppressed exactly the sites worth
            # re-reviewing: a synthesized checker encodes a pattern that was
            # unknown when those functions were first looked at.
            seen_keys = {
                f"{g['file']}:{g['name']}" for g in (workqueue or [])
            }
            synth = synthesize_and_sweep(
                outcome, config, seen_keys,
                synthesis_count=result.synthesis_amplified,
            )
            if synth and synth.hits:
                for hit in synth.hits:
                    hit.setdefault("priority_score", 0.8)
                    shared.synthesis_queue.append(hit)
                result.synthesis_amplified += len(synth.hits)
                if checker_library and synth.rule_id:
                    checker_library.add_rule(
                        rule_id=synth.rule_id,
                        engine=synth.tool,
                        body=synth.content,
                        cwe=synth.cwe or "",
                        seed_file=outcome.file,
                        seed_function=outcome.function,
                        source="audit",
                    )
                logger.info(
                    "mid-loop synthesis: %d new targets from %s:%s",
                    len(synth.hits), outcome.file, outcome.function,
                )
        except Exception:
            logger.debug(
                "mid-loop synthesis failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )

    # ── Commit ────────────────────────────────────────────────────────
    try:
        if collector is not None:
            collector.submit(outcome, gap)
        else:
            _commit_outcome(config, outcome, gap)
    except Exception as exc:
        logger.warning(
            "commit failed for %s:%s: %s",
            gap["file"], gap["name"], exc,
        )

    # ── Post-commit tracking ──────────────────────────────────────────
    review_result = getattr(outcome, "review_result", None)
    if review_result and review_result.get("reading_list"):
        shared.reading_list_functions.add(f"{gap['file']}:{gap['name']}")

    if live_classifications is not None and outcome.review_result:
        try:
            from .live_classifications import extract_from_outcome as _extract_live
            _extract_live(outcome, gap, live_classifications)
        except Exception:
            logger.debug(
                "live classification extraction failed for %s:%s",
                gap.get("file", ""), gap.get("name", ""),
                exc_info=True,
            )

    if config.propagate_constraints and outcome.review_result:
        with shared._constraints_lock:
            shared.constraints = _extract_and_propagate(
                outcome, shared.constraints, checklist, entry_points,
                prop_config, tier_counters=result.tier_counters,
            )

    if outcome.review_result and taint_summary_results is not None:
        from core.analysis.summaries import summary_from_review_result, propagate_taint_upward
        llm_summary = summary_from_review_result(
            outcome.function, outcome.file, outcome.review_result,
        )
        if llm_summary:
            key = f"{outcome.file}:{outcome.function}"
            if key not in taint_summary_results:
                taint_summary_results[key] = llm_summary

            for edge in (call_edges or []):
                callee_name = edge.get("callee", "")
                if callee_name != outcome.function:
                    continue
                caller_key = f"{edge['caller_file']}:{edge['caller']}"
                caller_sum = taint_summary_results.get(caller_key)
                if caller_sum:
                    call_args = edge.get("args", [])
                    propagate_taint_upward(llm_summary, caller_sum, call_args)

    _tally_outcome(result, outcome)

    if pf_result and pf_result.hits and checker_library and checker_library.all_entries():
        is_tp = outcome.status in ("finding", "suspicious")
        for hit in pf_result.hits:
            checker_library.record_match(hit.rule_id, is_tp)

    disagree = _check_layer_disagreement(outcome, ctx, gap)
    if disagree is not None:
        if layer_disagreements is not None:
            layer_disagreements.append(disagree)

    if config.enable_session_context and outcome.review_result:
        _accumulate_observations(
            session_observations, outcome, gap,
            sweep_pre_status=pre_sweep_status,
        )

    if (
        config.critique_interval > 0
        and review_idx > 0
        and review_idx % config.critique_interval == 0
    ):
        _run_critique(result, config, sarif_cache, joern_server=joern_server)

    if on_progress:
        on_progress(review_idx, total, outcome)

    return outcome



def _run_audit_body(
    config,
    review_fn,
    on_progress,
    *,
    result,
    start_time,
    joern_server,
    joern_timeout_s,
):
    """Inner orchestrator body, always wrapped in try/finally for server cleanup."""
    if joern_server is not None:
        from core.analysis.reach_audit import set_joern_server
        set_joern_server(joern_server)

    checklist = load_checklist(config.out_dir)
    if not checklist:
        logger.error("no checklist.json in %s", config.out_dir)
        result.terminated_by = "no_checklist"
        return result

    context_map = load_context_map(config.out_dir)
    if context_map is None:
        context_map = _try_understand_bridge(config)
    if context_map is None:
        context_map = {}
    if "call_edges" not in context_map:
        from core.orchestration.context_map_callgraph import enrich_with_call_edges
        edge_count = enrich_with_call_edges(
            context_map, checklist=checklist,
        )
        if edge_count:
            logger.info("bootstrapped %d call edges from checklist", edge_count)
    flow_traces = load_flow_traces(config.out_dir)

    variant_targets = _load_variants(config.out_dir)

    sarif_cache = SarifCache.from_directory(config.out_dir)

    if config.codeql_db_path and not sarif_cache:
        _codeql_pre_sweep(config, sarif_cache)

    # Build per-function evidence index
    taint_approx_results = _load_or_build_taint_approx(config)
    taint_summary_results = _build_taint_summary(config)
    sink_results = _build_sink_results(config, taint_approx_results, checklist=checklist)

    if sink_results is not None and "sinks" not in context_map:
        from core.orchestration.context_map_sinks import _populate_sinks_array
        _populate_sinks_array(context_map, sink_results)

    joern_future: Optional[Future] = None
    joern_flows: Optional[Dict[str, list]] = None

    imported_joern = _import_sibling_joern_flows(config)

    cm_sinks = (
        context_map.get("sink_details", [])
        if context_map else None
    )

    from .binary_bridge import load_binary_bridge
    binary_bridge_early = load_binary_bridge(config.out_dir)

    evidence_index = build_evidence_index(
        checklist=checklist,
        sink_results=sink_results,
        taint_approx_results=taint_approx_results,
        taint_summary_results=taint_summary_results,
        joern_flows=joern_flows,
        imported_joern_flows=imported_joern,
        sarif_cache=sarif_cache,
        context_map_sinks=cm_sinks or None,
        binary_bridge=binary_bridge_early,
    )

    try:
        from .validate_bridge import import_validate_evidence
        bridge_result = import_validate_evidence(config.out_dir)
        if bridge_result and (bridge_result.feasibility_verdicts or bridge_result.runtime_evidence):
            _merge_validate_evidence(bridge_result, evidence_index)
            logger.info(
                "validate bridge: imported %d feasibility verdicts, %d runtime evidence items",
                len(bridge_result.feasibility_verdicts),
                len(bridge_result.runtime_evidence),
            )
    except Exception:
        logger.debug("validate bridge import failed", exc_info=True)

    try:
        from .binary_layer0 import scan_function as layer0_scan, format_layer0_summary, Layer0Result
        l0_result = Layer0Result()
        for key, rec in evidence_index.items():
            src = _read_function_source(config.target_path, rec.file, rec.function)
            if not src:
                continue
            l0_findings = layer0_scan(rec.function, [], source=src, file=rec.file)
            if l0_findings:
                rec.binary_layer0_findings = l0_findings
                l0_result.findings.extend(l0_findings)
            l0_result.functions_scanned += 1
        if l0_result.findings:
            logger.info(format_layer0_summary(l0_result))
    except Exception:
        logger.debug("binary layer0 pre-sweep failed", exc_info=True)

    from .capabilities import probe_capabilities
    from .degradation import assess_degradation, format_degradation_report
    caps = probe_capabilities(
        binary_path=Path(config.binary_verdicts["_binary_path"])
        if config.binary_verdicts and "_binary_path" in config.binary_verdicts
        else None,
    )
    config.caps = caps
    tool_capabilities = {
        "joern": joern_server is not None,
        "binary": binary_bridge_early is not None,
        "codeql": config.codeql_db_path is not None,
        "semgrep": caps.semgrep,
        "coccinelle": caps.coccinelle,
        "r2": caps.r2,
        "frida": caps.frida,
    }
    degradation_report = assess_degradation(tool_capabilities)
    if degradation_report.degraded:
        logger.info(
            "degradation: %d tools degraded to fallback\n%s",
            len(degradation_report.degraded),
            format_degradation_report(degradation_report),
        )

    # --- Mechanical gates: pre-compute provenance + security-decision sets ---
    provenance_map: Dict[str, List[Dict[str, str]]] = {}
    security_decision_keys: frozenset = frozenset()
    feeds_security_keys: frozenset = frozenset()
    try:
        from .mechanical_gates import (
            build_provenance_map,
            build_security_decision_set,
            build_feeds_security_map,
        )
        if context_map:
            provenance_map = build_provenance_map(
                context_map, threat_model=config.threat_model,
            )
            security_decision_keys = build_security_decision_set(context_map)
            feeds_security_keys = frozenset(
                build_feeds_security_map(context_map).keys(),
            )
            if provenance_map:
                logger.info(
                    "mechanical gates: provenance map covers %d functions, "
                    "%d security-decision points",
                    len(provenance_map), len(security_decision_keys),
                )
    except Exception:
        logger.debug("mechanical gates init failed", exc_info=True)

    checker_library = RuleLibrary()
    if checker_library.all_entries():
        logger.info(checker_library.summary())

    summary_cache = None
    try:
        from .summary_cache import load_summary_cache
        summary_cache = load_summary_cache()
        if summary_cache.available_libraries():
            logger.info(summary_cache.summary())
    except Exception:
        logger.debug("summary_cache load failed", exc_info=True)

    discovered_tests: Optional[Dict[str, Any]] = None
    try:
        from core.analysis.test_discovery import discover_tests
        discovered_tests = discover_tests(config.target_path)
        if discovered_tests:
            logger.info(
                "test_discovery: %d functions with tests",
                len(discovered_tests),
            )
    except Exception:
        logger.debug("test_discovery failed", exc_info=True)

    typestate_models: Optional[Dict[str, Any]] = None
    try:
        from core.analysis.typestate import extract_typestate_models
        typestate_models = extract_typestate_models(
            checklist,
            joern_summaries=taint_summary_results,
        )
        if typestate_models:
            logger.info(
                "typestate: %d lifecycle models loaded",
                len(typestate_models),
            )
    except Exception:
        logger.debug("typestate model extraction failed", exc_info=True)

    coverage_records = _load_coverage_records(config.out_dir)
    ann_dir = config.annotations_dir or _resolve_ann_dir(config.out_dir)
    coverage_records = _recreate_coverage_from_annotations(
        coverage_records, ann_dir, checklist,
    )
    fuzz_coverage = _load_fuzz_coverage(config.out_dir)

    gaps = compute_gaps(
        checklist,
        [] if config.force else coverage_records,
        context_map=context_map,
        strategy_filter=config.strategy_filter,
        scope=config.scope,
        fuzz_coverage=fuzz_coverage,
    )

    # Launch Joern only when there are functions to review — the Scala
    # query is expensive and pointless when the gap list is empty.
    if gaps:
        def _joern_progress_cb(msg: str) -> None:
            if on_progress:
                placeholder = ReviewOutcome(
                    file="", function="", status="clean",
                    body=msg,
                )
                on_progress(-1, 0, placeholder)

        joern_flows, joern_future = _resolve_joern_evidence(
            config, on_joern_progress=_joern_progress_cb,
            joern_server=joern_server,
        )

        if joern_flows is not None:
            evidence_index = _merge_joern_flows(
                joern_flows, evidence_index, checklist, sarif_cache,
            )
            if joern_server is not None and taint_summary_results is not None:
                _enrich_summaries_from_joern(
                    joern_server, joern_flows, taint_summary_results,
                )

    iris_taint_specs: list = []
    try:
        from .iris_specs import identify_candidates, compile_joern_config, specs_to_json
        taint_chain_callees: Set[str] = set()
        if taint_summary_results:
            for _ts_key, _ts_summ in taint_summary_results.items():
                for _ts_callee in getattr(_ts_summ, "callees", []):
                    taint_chain_callees.add(_ts_callee)
        iris_candidates = identify_candidates(
            gaps, taint_chain_callees=taint_chain_callees,
        )
        if iris_candidates:
            iris_taint_specs = [
                _iris_candidate_to_spec(c) for c in iris_candidates
            ]
            if iris_taint_specs and config.out_dir:
                spec_path = config.out_dir / "iris-taint-specs.json"
                spec_path.write_text(specs_to_json(iris_taint_specs))
                joern_cfg = compile_joern_config(iris_taint_specs)
                if joern_cfg.strip():
                    (config.out_dir / "iris-joern.scala").write_text(joern_cfg)
                logger.info(
                    "IRIS: synthesised %d taint specs (%d sources, %d sinks, "
                    "%d sanitisers, %d propagators)",
                    len(iris_taint_specs),
                    sum(1 for s in iris_taint_specs if s.role == "source"),
                    sum(1 for s in iris_taint_specs if s.role == "sink"),
                    sum(1 for s in iris_taint_specs if s.role == "sanitiser"),
                    sum(1 for s in iris_taint_specs if s.role == "propagator"),
                )
    except Exception:
        logger.debug("IRIS spec synthesis failed", exc_info=True)

    if config.include_stale:
        ann_dir = config.annotations_dir or _resolve_ann_dir(config.out_dir)
        gaps = _merge_stale(gaps, ann_dir, config.target_path)

    prior_constraints = load_constraints(config.out_dir)
    open_keys = {
        f"{c.file}:{c.function}" for c in open_constraints(prior_constraints)
    } if prior_constraints else None

    sibling_dirs = _sibling_run_dirs(config.out_dir, target_path=config.target_path)
    tool_failures = load_tool_failures(sibling_dirs) if sibling_dirs else None
    fuzz_cov_files = _load_fuzz_coverage_from_runs(sibling_dirs) if sibling_dirs else None

    from .strategy_stats import load_strategy_weights
    strat_weights = load_strategy_weights(config.out_dir, target_path=config.target_path)

    gaps = score_functions(
        gaps, context_map=context_map, flow_traces=flow_traces,
        threat_model=config.threat_model,
        open_constraint_keys=open_keys,
        tool_failures=tool_failures,
        fuzz_coverage=fuzz_cov_files,
        strategy_weights=strat_weights,
        binary_bridge=binary_bridge_early,
    )

    if config.budget and config.budget > 0:
        gaps = gaps[:config.budget]

    # Hydrate function bodies once the gap list is final — after the
    # stale merge, scoring and budget truncation. The mechanical
    # detectors below (negative-space conventions, sibling asymmetry)
    # read gap["source"] and no-op without it, and doing it here rather
    # than in compute_gaps means stale gaps are covered and no source is
    # read for gaps the budget dropped.
    hydrate_gap_source(gaps, Path(config.target_path))

    # Triage classification — assign depth buckets before review
    entry_points = extract_context_map_set(context_map, "entry_points")
    sinks_set = extract_context_map_set(context_map, "sinks")
    trust_boundary_set = extract_context_map_set(
        context_map, "trust_boundaries", nested_key="functions",
    )
    joern_flow_keys = frozenset(
        k for k, rec in evidence_index.items()
        if rec.all_joern_flows()
    ) if evidence_index else frozenset()
    sink_unreachable_keys = frozenset(
        k for k, rec in evidence_index.items()
        if rec.sink_unreachable
    ) if evidence_index else frozenset()
    dangerous_callee_keys = frozenset(
        k for k, rec in evidence_index.items()
        if rec.has_any_evidence()
        and not rec.sink_unreachable
    ) if evidence_index else frozenset()
    priority_scores = {
        f"{g['file']}:{g['name']}": g.get("priority_score", 0.0) for g in gaps
    }
    taint_path_keys = frozenset(
        k for k, approx in (taint_approx_results or {}).items()
        if getattr(approx, "has_any_dangerous_flow", lambda: False)()
        or getattr(approx, "direct_flows", None)
    )
    from .triage import detect_generated_files
    generated_files = set(detect_generated_files(gaps))
    if generated_files:
        logger.info(
            "triage: %d generated files detected — functions will be skipped",
            len(generated_files),
        )
    gen_prefilters: Dict[str, PrefilterResult] = {}
    for gap in gaps:
        if gap["file"] in generated_files:
            key = f"{gap['file']}:{gap['name']}"
            gen_prefilters[key] = PrefilterResult(
                file=gap["file"],
                function=gap["name"],
                skip_llm=True,
                skip_reason="generated code",
            )
    triage_results = classify_all(
        gaps,
        entry_points=frozenset(entry_points),
        sinks=frozenset(sinks_set),
        trust_boundaries=frozenset(trust_boundary_set),
        taint_path_keys=taint_path_keys,
        joern_flow_keys=joern_flow_keys,
        sink_unreachable_keys=sink_unreachable_keys,
        dangerous_callee_keys=dangerous_callee_keys,
        priority_scores=priority_scores,
        prefilter_results=gen_prefilters or None,
    )
    logger.info(format_triage_summary(triage_results))

    from .negative_space import (
        discover_conventions,
        check_sibling_negative_space,
    )
    conventions = discover_conventions(gaps)
    if conventions:
        logger.info(
            "negative-space: discovered %d security conventions",
            len(conventions),
        )

    sibling_ns_findings = check_sibling_negative_space(gaps, conventions) if conventions else []
    if sibling_ns_findings:
        logger.info(
            "sibling analysis: %d asymmetry findings across peer groups",
            len(sibling_ns_findings),
        )

    from .sibling_analysis import (
        identify_peer_groups,
        identify_parallel_loops,
        identify_paired_operations,
    )
    gap_func_dicts = [
        {"name": g.get("name", ""), "file": g.get("file", ""),
         "line": g.get("line", 0), "source": g.get("source", "")}
        for g in gaps if g.get("name")
    ]
    peer_groups = identify_peer_groups(gap_func_dicts)
    peer_groups.extend(identify_parallel_loops(gap_func_dicts))
    peer_groups.extend(identify_paired_operations(gap_func_dicts))

    from .postcondition_verify import (
        check_sibling_ordering,
        check_sibling_sanitizer_strength,
    )
    sibling_postcond_violations = []
    for pg in peer_groups:
        pg_gaps = [
            g for g in gaps
            if any(s.function == g.get("name") and s.file == g.get("file")
                   for s in pg.siblings)
        ]
        sibling_postcond_violations.extend(check_sibling_ordering(pg_gaps))
        sibling_postcond_violations.extend(check_sibling_sanitizer_strength(pg_gaps))

    if sibling_postcond_violations:
        logger.info(
            "sibling postcondition: %d ordering/strength violations",
            len(sibling_postcond_violations),
        )

    try:
        from .sibling_analysis import check_semantic_consistency
        source_map = {
            f"{g['file']}:{g['name']}": {"source": g.get("source", "")}
            for g in gaps if g.get("source")
        }
        semantic_findings = check_semantic_consistency(peer_groups, source_map)
        if semantic_findings:
            logger.info(
                "semantic consistency: %d outliers across peer groups",
                len(semantic_findings),
            )
    except Exception:
        logger.debug("semantic consistency check failed", exc_info=True)

    # --- Pre-loop mechanical detectors ---
    mechanical_findings: Dict[str, List[Dict[str, Any]]] = {}
    try:
        mechanical_findings = _run_mechanical_detectors(
            gaps, config,
            context_map=context_map,
            evidence_index=evidence_index,
            joern_server=joern_server,
        )
    except Exception:
        logger.debug("mechanical detectors phase failed", exc_info=True)

    if mechanical_findings and config.out_dir:
        try:
            mech_path = config.out_dir / "mechanical-findings.json"
            mech_path.write_text(json.dumps(mechanical_findings, indent=2))
            logger.info("wrote %d mechanical findings to %s",
                        sum(len(v) for v in mechanical_findings.values()),
                        mech_path)
        except Exception:
            logger.debug("failed to persist mechanical findings", exc_info=True)

    write_gaps(gaps, config.out_dir)

    reviewed_set = (
        set() if config.force
        else get_reviewed_set(config.out_dir) if config.resume
        else set()
    )
    audit_log = load_audit_log(config.out_dir) if config.resume else []

    workqueue = []
    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        if key in reviewed_set:
            result.skipped += 1
            continue
        workqueue.append(gap)

    # Bottom-up ordering: callees before callers so summaries propagate.
    # Build adjacency from context_map call edges (already enriched above).
    call_edges = context_map.get("call_edges", []) if context_map else []
    if call_edges:
        topo_adj: dict[str, list[str]] = {}
        for edge in call_edges:
            caller_file = edge.get("caller_file", "")
            caller_func = edge.get("caller", "")
            if not caller_file and ":" in caller_func:
                caller_file, _, caller_func = caller_func.partition(":")
                caller_func = caller_func.split("(")[0].strip()
            if not caller_file or not caller_func:
                continue
            caller_key = f"{caller_file}:{caller_func}"
            callee_raw = edge.get("callee", "")
            callee_file = edge.get("callee_file", "")
            callee_name = callee_raw
            if not callee_file and ":" in callee_raw:
                callee_file, _, callee_name = callee_raw.partition(":")
                callee_name = callee_name.split("(")[0].strip()
            if not callee_file:
                callee_file = caller_file
            if callee_name:
                topo_adj.setdefault(caller_key, []).append(
                    f"{callee_file}:{callee_name}",
                )
        priority_scores = {
            f"{g['file']}:{g['name']}": g.get("priority_score", 0.0)
            for g in workqueue
        }
        topo_order = _topological_sort(topo_adj, priority_scores=priority_scores)
        topo_rank = {k: i for i, k in enumerate(topo_order)}

        workqueue.sort(
            key=lambda g: topo_rank.get(f"{g['file']}:{g['name']}", len(topo_order)),
        )
        logger.info(
            "topo_order: reordered %d functions using %d call edges",
            len(workqueue), len(call_edges),
        )

    if config.subsystem_depth > 0:
        subsystem_groups = group_by_subsystem(
            workqueue, depth=config.subsystem_depth,
        )
        ordered_work = []
        ranked = sorted(
            subsystem_groups,
            key=lambda s: max(
                (g.get("priority_score", 0) for g in subsystem_groups[s]),
                default=0,
            ),
            reverse=True,
        )
        for subsystem in ranked:
            ordered_work.extend(subsystem_groups[subsystem])
        workqueue = ordered_work

    from .priority import detect_widely_used
    widely_used_keys = detect_widely_used(checklist)

    batched, workqueue = _batch_trivial(workqueue, config.batch_sloc_threshold)

    batched_count = sum(len(b) for b in batched)
    total = len(workqueue) + batched_count
    logger.info(
        "orchestrator: %d functions to review (%d skipped, %d batched as trivial)",
        total, result.skipped, batched_count,
    )

    try:
        from .llm_summaries import identify_summary_candidates, run_llm_summary_pass
        summary_candidates = identify_summary_candidates(
            workqueue, taint_summary_results, checklist,
        )
        if summary_candidates:
            llm_summaries = run_llm_summary_pass(
                summary_candidates, config.target_path, config,
            )
            if llm_summaries:
                if taint_summary_results is None:
                    taint_summary_results = {}
                for sk, sv in llm_summaries.items():
                    if sk not in taint_summary_results:
                        taint_summary_results[sk] = sv
    except Exception:
        logger.debug("pre-loop LLM summary pass failed", exc_info=True)

    constraints = prior_constraints

    prop_config = PropagationConfig(
        max_depth=_adaptive_max_depth(
            config.inventory,
            entry_points,
            operator_override=config.max_propagation_depth,
        ),
        codeql_db_path=config.codeql_db_path,
        target_path=config.target_path,
        binary_verdicts=config.binary_verdicts,
        inventory=config.inventory,
        evidence_index=evidence_index,
    )

    session_observations: List[Dict[str, str]] = []
    discovered_evidence: Dict[str, Any] = {}
    reviewed_before_joern: List[Dict[str, Any]] = []
    joern_submit_time = time.time() if joern_future is not None else None

    from .project_context import load_project_context
    project_ctx = load_project_context(config.out_dir)
    project_learnings = [
        {"text": lrn.text, "category": lrn.category, "strategy": lrn.strategy}
        for lrn in project_ctx.learnings
    ]

    # --- Live classifications: runtime-discovered sinks/sanitisers ---
    live_classifications = None
    try:
        from .live_classifications import (
            expand_wrapper_sinks,
            load_from_project_context as _load_live_from_project,
        )
        live_classifications = _load_live_from_project(
            project_learnings, checklist=checklist,
        )
    except Exception:
        logger.debug("live classifications init failed", exc_info=True)

    # --- Collector: batched I/O with journal + reading-list capture ---
    collector = None
    try:
        from .collector import Collector
        collector = Collector(
            out_dir=config.out_dir,
            target_path=config.target_path,
            run_id=config.out_dir.name if config.out_dir else "",
        )
    except Exception:
        logger.debug("collector init failed", exc_info=True)

    # --- Domain model: loaded once, reloaded after study loop ---
    domain_model = None
    try:
        from .journal import load_domain_model
        domain_model = load_domain_model(config.out_dir)
        if domain_model:
            n_inv = len(domain_model.get("invariants", []))
            n_con = len(domain_model.get("concepts", []))
            if n_inv or n_con:
                logger.info(
                    "domain model: %d concepts, %d invariants loaded",
                    n_con, n_inv,
                )
    except Exception:
        logger.debug("domain model load failed", exc_info=True)

    feedback_state = _load_exploit_feedback(config)
    if feedback_state.outcomes:
        logger.info(format_feedback_summary(feedback_state))

    from .demand_explore import ExpansionBudget
    expansion_budget = ExpansionBudget(max_expansions=min(50, len(workqueue)))

    fp_patterns: List[Any] = []
    try:
        from .fp_feedback import scan_fp_patterns, load_fp_patterns
        if config.annotations_dir and config.annotations_dir.is_dir():
            fp_patterns = scan_fp_patterns(
                config.annotations_dir,
                journal_dir=config.out_dir,
            )
            logger.info("fp_feedback: loaded %d FP patterns from annotations + journal", len(fp_patterns))
        if not fp_patterns and config.out_dir:
            fp_patterns = load_fp_patterns(config.out_dir)
    except Exception:
        logger.debug("fp_feedback: load failed", exc_info=True)

    # --- SharedState: bundle prep outputs for the executor ---
    shared = SharedState.from_prep(
        checklist=checklist,
        context_map=context_map,
        evidence_index=evidence_index,
        provenance_map=provenance_map,
        security_decision_keys=security_decision_keys,
        feeds_security_keys=feeds_security_keys,
        taint_approx_results=taint_approx_results,
        sarif_cache=sarif_cache,
        flow_traces=flow_traces,
        variant_targets=variant_targets,
        entry_points=entry_points,
        sinks_set=sinks_set,
        widely_used_keys=widely_used_keys,
        conventions=conventions,
        sibling_ns_findings=sibling_ns_findings,
        sibling_postcond_violations=sibling_postcond_violations,
        peer_groups=peer_groups,
        mechanical_findings=mechanical_findings,
        fuzz_coverage=fuzz_coverage,
        discovered_tests=discovered_tests,
        typestate_models=typestate_models,
        summary_cache=summary_cache,
        checker_library=checker_library,
        triage_results=triage_results,
        project_learnings=project_learnings,
        feedback_state=feedback_state,
        fp_patterns=fp_patterns,
        prop_config=prop_config,
        iris_taint_specs=iris_taint_specs,
        call_edges=call_edges,
        domain_model=domain_model,
        taint_summary_results=taint_summary_results,
        constraints=constraints,
        expansion_budget=expansion_budget,
    )
    shared.discovered_evidence = discovered_evidence
    shared.session_observations = session_observations
    shared.reviewed_before_joern = reviewed_before_joern
    shared.live_classifications = live_classifications

    # --- Executor config ---
    from .executor import ExecutorConfig, run_executor_sync
    from core.llm.concurrency import derive_max_workers
    from .task_graph import TaskGraph

    if config.max_workers == 0:
        model = config.models[0] if config.models else "default"
        resolved_workers = derive_max_workers(model)
        logger.info(
            "auto workers: model=%s → max_workers=%d", model, resolved_workers,
        )
    else:
        resolved_workers = config.max_workers
    executor_config = ExecutorConfig(max_workers=resolved_workers)

    layer_disagreements: List[Any] = []

    # --- Glance batches (run before main executor) ---
    review_idx = 0
    for batch in batched:
        if _check_budget(config, start_time, result):
            break
        batch_outcomes = _review_items(
            batch, config, review_fn, checklist, context_map,
            fuzz_coverage, evidence_index,
            discovered_evidence=discovered_evidence,
        )
        for outcome, gap in zip(batch_outcomes, batch):
            outcome.line = gap.get("line_start", 0)
            _tally_outcome(result, outcome)
            if on_progress:
                on_progress(review_idx, total, outcome)
            review_idx += 1

    # --- Joern tick: drain future between dispatches ---
    joern_state = {"future": joern_future, "submit_time": joern_submit_time}

    def _joern_tick(gap: dict) -> None:
        jf = joern_state["future"]
        if jf is not None and jf.done():
            nonlocal evidence_index
            evidence_index = _drain_joern_future(
                jf, evidence_index, checklist, sarif_cache,
            )
            shared.evidence_index = evidence_index
            joern_state["future"] = None
        elif jf is not None:
            joern_elapsed = time.time() - (joern_state["submit_time"] or start_time)
            if joern_elapsed > joern_timeout_s:
                logger.warning(
                    "Joern CPG build stalled after %.0fs — cancelling",
                    joern_elapsed,
                )
                jf.cancel()
                joern_state["future"] = None
                joern_state["submit_time"] = None

        if joern_state["future"] is not None:
            shared.reviewed_before_joern.append(gap)

    # --- Main executor pass ---
    graph = TaskGraph.from_workqueue(workqueue, call_edges)
    executor_stats = run_executor_sync(
        graph, review_fn, shared, config, result,
        executor_config,
        joern_server=joern_server,
        audit_log=audit_log,
        workqueue=workqueue,
        reviewed_set=reviewed_set,
        start_time=start_time,
        layer_disagreements=layer_disagreements,
        on_progress=on_progress,
        collector=collector,
        budget_check=lambda: _check_budget(config, start_time, result),
        on_tick=_joern_tick,
    )
    joern_future = joern_state["future"]
    if executor_stats.budget_stopped and not result.terminated_by:
        result.terminated_by = "llm_budget_exceeded"

    # --- Synthesis queue second pass ---
    if shared.synthesis_queue and not executor_stats.budget_stopped:
        synth_hits = list(shared.synthesis_queue)
        shared.synthesis_queue.clear()
        synth_gaps = _synthesis_hits_to_gaps(
            synth_hits, checklist, config.out_dir,
        )
        logger.info(
            "synthesis pass: %d targets from mid-loop synthesis "
            "(%d hits resolved to reviewable functions)",
            len(synth_hits), len(synth_gaps),
        )
    else:
        synth_gaps = []

    if synth_gaps:
        synth_graph = TaskGraph.from_workqueue(synth_gaps, call_edges)
        run_executor_sync(
            synth_graph, review_fn, shared, config, result,
            executor_config,
            joern_server=joern_server,
            audit_log=audit_log,
            workqueue=workqueue,
            reviewed_set=reviewed_set,
            start_time=start_time,
            layer_disagreements=layer_disagreements,
            on_progress=on_progress,
            collector=collector,
            budget_check=lambda: _check_budget(config, start_time, result),
        )

    # --- Sync mutable state back from SharedState ---
    constraints = shared.constraints
    evidence_index = shared.evidence_index
    session_observations = shared.session_observations
    discovered_evidence = shared.discovered_evidence
    reviewed_before_joern = shared.reviewed_before_joern
    reading_list_functions = shared.reading_list_functions

    if collector is not None:
        collector.flush()

    # --- Post-executor: joern drain + constraint save ---
    if joern_future is not None:
        if not joern_future.done():
            logger.info("waiting for Joern CPG build (timeout %ds)...", joern_timeout_s)
            try:
                joern_future.result(timeout=joern_timeout_s)
            except TimeoutError:
                logger.warning("Joern CPG build stalled — skipping Joern evidence")
                joern_future.cancel()
                joern_future = None
        if joern_future is not None:
            evidence_index = _drain_joern_future(
                joern_future, evidence_index, checklist, sarif_cache,
            )
        joern_future = None

    if config.propagate_constraints and constraints:
        save_constraints(constraints, config.out_dir)

    if reviewed_before_joern:
        result = _re_review_joern_enriched(
            result, config, review_fn, checklist, context_map,
            fuzz_coverage, evidence_index, sarif_cache,
            entry_points, reviewed_before_joern, start_time,
            on_progress, audit_log=audit_log,
            session_observations=session_observations,
            discovered_evidence=discovered_evidence,
            joern_server=joern_server,
        )

    if config.deepen_suspicious:
        result = _deepen_suspicious(
            result, config, review_fn, checklist, context_map,
            fuzz_coverage, session_observations, sarif_cache,
            entry_points, start_time, on_progress,
            evidence_index, audit_log=audit_log,
            discovered_evidence=discovered_evidence,
            joern_server=joern_server,
            project_learnings=project_learnings,
        )

    if config.deepen_suspicious:
        logger.info("entering post-deepen mechanical sweep")
        sink_reachable = build_sink_reachable_set(context_map)
        new_outcomes = []
        for outcome in result.outcomes:
            if outcome.status == "finding":
                corroborated = _has_mechanical_corroboration(
                    outcome, config, sarif_cache, checklist,
                    domain_model=domain_model,
                )
                if corroborated:
                    new_outcomes.append(outcome)
                    continue
                checked = _check_preconditions(outcome, config, context_map)
                if checked.status != outcome.status:
                    result.findings -= 1
                    result.suspicious += 1
                    new_outcomes.append(checked)
                else:
                    reason = compute_demotion_verdict(
                        outcome.function,
                        outcome.body or "",
                        context_map,
                        sink_reachable=sink_reachable,
                        joern_server=joern_server,
                    )
                    if reason is None:
                        reason = _smt_demotion_reason(
                            outcome, config, checklist,
                        )
                    if reason is not None:
                        logger.info(
                            "gate: %s:%s demoted — %s",
                            outcome.file, outcome.function, reason,
                        )
                        demoted = _demote_outcome(outcome, reason)
                        result.findings -= 1
                        result.suspicious += 1
                        new_outcomes.append(demoted)
                    else:
                        new_outcomes.append(checked)
            else:
                new_outcomes.append(outcome)
        result.outcomes = new_outcomes
        logger.info("exited post-deepen mechanical sweep")

    logger.info("entering _iterative_re_review")
    result = _iterative_re_review(
        result, config, review_fn, checklist, context_map,
        fuzz_coverage, entry_points, constraints, prop_config,
        sarif_cache, start_time, on_progress,
        evidence_index, audit_log=audit_log,
        session_observations=session_observations,
        discovered_evidence=discovered_evidence,
        joern_server=joern_server,
    )
    logger.info("exited _iterative_re_review")

    # --- Live-sink expansion + re-queue ---
    if live_classifications is not None and live_classifications.sinks:
        try:
            expand_wrapper_sinks(
                live_classifications,
                call_edges or [],
            )
            live_sink_targets = []
            for gap in gaps:
                gap_key = f"{gap['file']}:{gap['name']}"
                already_reviewed = any(
                    o.file == gap["file"] and o.function == gap["name"]
                    for o in result.outcomes
                )
                if not already_reviewed:
                    continue
                callees = [
                    e.get("callee", "")
                    for e in (call_edges or [])
                    if f"{e.get('caller_file', '')}:{e.get('caller', '')}" == gap_key
                ]
                upgrade = live_classifications.should_upgrade_triage(gap_key, callees)
                if upgrade:
                    prior = next(
                        (o for o in result.outcomes
                         if o.file == gap["file"] and o.function == gap["name"]),
                        None,
                    )
                    if prior and prior.status == "clean":
                        live_sink_targets.append(gap)
            if live_sink_targets:
                logger.info(
                    "live-sink re-queue: %d functions to re-review at DEEP_DIVE depth",
                    len(live_sink_targets),
                )
                for target_gap in live_sink_targets:
                    if _check_budget(config, start_time, result):
                        break
                    try:
                        ctx = _build_context(
                            config, target_gap, checklist, context_map,
                            evidence_index,
                            discovered_evidence=discovered_evidence,
                        )
                        ctx["live_sinks"] = sorted(live_classifications.sinks)
                        ctx["triage_bucket"] = "DEEP_DIVE"
                        prior = next(
                            (o for o in result.outcomes
                             if o.file == target_gap["file"]
                             and o.function == target_gap["name"]),
                            None,
                        )
                        outcome = review_fn(ctx, config)
                        if prior is not None:
                            _untally_outcome(result, prior)
                            result.outcomes.remove(prior)
                        _tally_outcome(result, outcome)
                        if collector is not None:
                            collector.submit(outcome, target_gap)
                        else:
                            _commit_outcome(config, outcome, target_gap)
                    except Exception:
                        logger.warning(
                            "live-sink re-review failed for %s:%s: %s",
                            target_gap["file"], target_gap["name"],
                            sys.exc_info()[1],
                        )
        except Exception:
            logger.debug("live-sink expansion failed", exc_info=True)

    if config.sweep_validate_findings:
        logger.info("entering _promote_suspicious")
        _promote_suspicious(result, config, sarif_cache, checklist,
                            joern_server=joern_server)
        logger.info("exited _promote_suspicious")

    logger.info("entering _resolve_gate_demoted")
    _resolve_gate_demoted(result, config, sarif_cache, checklist,
                          domain_model=domain_model,
                          available_tools=tool_capabilities)
    logger.info("exited _resolve_gate_demoted")

    logger.info("entering _auto_synthesize_rules")
    _auto_synthesize_rules(result, config)
    logger.info("exited _auto_synthesize_rules")

    retired = checker_library.retire_low_precision()
    if retired:
        logger.info("rule library: retired %d low-precision rules", len(retired))

    if config.out_dir and checker_library.all_entries():
        try:
            engine_rules_dir = config.out_dir.parent / "engine-rules"
            graduated = checker_library.graduate(engine_rules_dir)
            if graduated:
                logger.info(
                    "rule library: graduated %d rules to %s",
                    len(graduated), engine_rules_dir,
                )
        except Exception:
            logger.debug("rule graduation failed", exc_info=True)

    if layer_disagreements and config.out_dir:
        try:
            from .layer_resolution import write_disagreements, format_disagreement_summary
            write_disagreements(layer_disagreements, config.out_dir)
            logger.info(format_disagreement_summary(layer_disagreements))
        except Exception:
            logger.debug("layer disagreement persistence failed", exc_info=True)

    result = _review_flow_traces(
        result, config, review_fn, checklist,
        evidence_index=evidence_index,
        joern_server=joern_server,
        sarif_cache=sarif_cache,
    )

    # --- Study loop: enrich domain model from reading-list items ---
    if reading_list_functions and config.out_dir:
        try:
            rl_path = config.out_dir / "reading-list.json"
            if not rl_path.exists():
                import json as _rl_json
                rl_items: list[dict[str, str]] = []
                for out in result.outcomes:
                    rr = getattr(out, "review_result", None)
                    if rr and rr.get("reading_list"):
                        for item in rr["reading_list"]:
                            if isinstance(item, dict):
                                rl_items.append(item)
                if rl_items:
                    rl_path.write_text(_rl_json.dumps(rl_items, indent=2))
                    logger.info(
                        "study-loop: wrote %d reading-list items from %d functions",
                        len(rl_items), len(reading_list_functions),
                    )

            if rl_path.exists():
                study_cmd = [
                    sys.executable, str(Path(__file__).resolve().parents[2] / "libexec" / "raptor-study-loop"),
                    str(config.target_path),
                    str(config.out_dir),
                ]
                study_env = os.environ.copy()
                study_env["_RAPTOR_TRUSTED"] = "1"
                study_result = subprocess.run(
                    study_cmd,
                    env=study_env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if study_result.returncode == 0:
                    logger.info("study-loop: completed successfully")
                    # Reload domain model after study enrichment
                    try:
                        from .journal import load_domain_model
                        domain_model = load_domain_model(config.out_dir)
                        if domain_model:
                            n_inv = len(domain_model.get("invariants", []))
                            n_con = len(domain_model.get("concepts", []))
                            logger.info(
                                "domain model reloaded: %d concepts, %d invariants",
                                n_con, n_inv,
                            )
                        if collector is not None:
                            collector.invalidate_domain_model_cache()
                    except Exception:
                        logger.debug("domain model reload failed", exc_info=True)
                else:
                    logger.warning(
                        "study-loop: exited %d: %s",
                        study_result.returncode,
                        study_result.stderr[:500] if study_result.stderr else "(no stderr)",
                    )
        except subprocess.TimeoutExpired:
            logger.warning("study-loop: timed out after 300s")
        except Exception:
            logger.debug("study-loop dispatch failed", exc_info=True)

    if result.findings > 0:
        logger.info("entering _persist_findings")
        _persist_findings(result, config)

    if iris_taint_specs and joern_server is not None and result.findings > 0:
        try:
            from .iris_specs import compile_joern_config
            requery_cfg = compile_joern_config(iris_taint_specs)
            if requery_cfg.strip():
                try:
                    requery_hits = _joern_live_query(
                        joern_server, requery_cfg, [],
                    )
                except Exception:
                    logger.debug("IRIS re-query failed", exc_info=True)
                    requery_hits = []
                if requery_hits:
                    for hit in requery_hits:
                        key = hit.get("key", "")
                        if key and key in evidence_index:
                            rec = evidence_index[key]
                            rec.joern_flows.extend(hit.get("flows", []))
                    logger.info(
                        "IRIS re-query: %d additional flows from synthesised specs",
                        sum(len(h.get("flows", [])) for h in requery_hits),
                    )
        except Exception:
            logger.debug("IRIS re-query failed", exc_info=True)

    # --- IRIS refinement loop + bypass detection ---
    try:
        from core.iris.refine import refine_loop as iris_refine_loop
        from .iris_specs import identify_candidates

        taint_chain_callees_post: Set[str] = set()
        if taint_summary_results:
            for _ts_key, _ts_summ in taint_summary_results.items():
                for _ts_callee in getattr(_ts_summ, "callees", []):
                    taint_chain_callees_post.add(_ts_callee)
        iris_candidates = identify_candidates(
            gaps, taint_chain_callees=taint_chain_callees_post,
        )
        if iris_candidates:
            joern_tool_runner = None
            if joern_server is not None:
                from .iris_specs import compile_joern_config as _iris_compile
                def joern_tool_runner(specs):
                    cfg = _iris_compile(specs)
                    if not cfg.strip():
                        from core.iris.refine import RefinementFeedback
                        return RefinementFeedback([], [], [])
                    hits = _joern_live_query(joern_server, cfg, label="iris-refine")
                    from core.iris.refine import RefinementFeedback
                    confirmed = [h.get("key", "") for h in (hits or []) if h.get("flows")]
                    return RefinementFeedback(
                        confirmed_keys=confirmed,
                        refuted_keys=[],
                        tool_errors=[],
                    )

            bypass_runner = None
            try:
                from core.iris import CompositionalAnalyzer
                from core.inventory.call_graph import load_call_graphs
                call_graphs = load_call_graphs(config.target_path, checklist)
                if call_graphs:
                    analyzer = CompositionalAnalyzer(call_graphs)
                    def bypass_runner(assumptions):
                        findings = []
                        seen: set[tuple[str, str, str]] = set()
                        for a in assumptions:
                            findings.extend(analyzer.detect_bypasses(a))
                            findings.extend(analyzer.detect_ordering_violations(a))
                            findings.extend(analyzer.detect_type_hierarchy_bypasses(a))
                        widened: list = []
                        for f in findings:
                            if f.via_intermediate:
                                widened.extend(analyzer.widen_from_finding(f))
                        findings.extend(widened)
                        deduped: list = []
                        for f in findings:
                            key = (f.caller_file, f.caller_function, f.missing_enforcer)
                            if key not in seen:
                                seen.add(key)
                                deduped.append(f)
                        return deduped
            except Exception:
                logger.debug("IRIS bypass analyzer init failed", exc_info=True)

            iris_llm = None
            try:
                from core.llm.client import LLMClient
                iris_llm = LLMClient()
            except Exception:
                logger.debug("IRIS LLM client init failed", exc_info=True)

            codeql_tool_runner = None
            if config.codeql_db_path:
                try:
                    from core.iris.codeql_runner import make_codeql_tool_runner
                    codeql_tool_runner = make_codeql_tool_runner(
                        db_path=Path(config.codeql_db_path),
                        out_dir=config.out_dir,
                    )
                except Exception:
                    logger.debug("IRIS CodeQL runner init failed", exc_info=True)

            iris_tool_runner = _composite_tool_runner(
                joern_tool_runner, codeql_tool_runner,
            )

            prior_specs = iris_taint_specs or []
            refined_specs, history, assumptions, bypass_findings = iris_refine_loop(
                iris_candidates,
                llm_client=iris_llm,
                tool_runner=iris_tool_runner,
                prior_specs=prior_specs,
                bypass_runner=bypass_runner,
                target_path=config.target_path,
            )

            if refined_specs:
                from .iris_specs import specs_to_json
                logger.info(
                    "IRIS: refined %d specs (%d rounds)",
                    len(refined_specs), len(history),
                )
                if config.out_dir:
                    spec_path = config.out_dir / "iris-taint-specs-refined.json"
                    spec_path.write_text(specs_to_json(refined_specs))

            if assumptions:
                logger.info(
                    "iris.synthesise: %d assumptions from %d sink/sanitiser specs",
                    len(assumptions),
                    sum(1 for s in refined_specs
                        if s.role in ("sink", "sanitiser")),
                )

            if bypass_findings:
                logger.info(
                    "IRIS bypass: %d bypass findings",
                    len(bypass_findings),
                )
                if config.out_dir:
                    bp_path = config.out_dir / "iris-bypass-findings.json"
                    bp_path.write_text(json.dumps(
                        [
                            {
                                "caller_file": bf.caller_file,
                                "caller_function": bf.caller_function,
                                "missing_enforcer": bf.missing_enforcer,
                                "assumption": str(bf.assumption),
                            }
                            for bf in bypass_findings
                            if hasattr(bf, "caller_file")
                        ],
                        indent=2,
                    ))
    except Exception:
        logger.debug("IRIS refinement/bypass failed", exc_info=True)

    if result.findings >= 2 and config.out_dir:
        try:
            from .attacker_synthesis import synthesize_chains, write_attack_chains, format_chains_summary
            chains = synthesize_chains(result.outcomes, context_map)
            if chains:
                write_attack_chains(chains, config.out_dir)
                logger.info(format_chains_summary(chains))
        except Exception:
            logger.debug("attacker synthesis failed", exc_info=True)

    try:
        post_loop_findings: list[dict] = []

        from .taint_specs import check_stored_taint, check_config_dependent
        for tf in check_stored_taint(gaps):
            post_loop_findings.append(tf.to_dict())
        for tf in check_config_dependent(gaps):
            post_loop_findings.append(tf.to_dict())

        try:
            from core.iris.synthesise import stored_taint_assumptions, config_provenance_assumptions
            heuristic_assumptions = stored_taint_assumptions(gaps) + config_provenance_assumptions(gaps)
            # Only pass assumptions that have enforcers — without enforced_by,
            # detect_bypasses flags every caller as "unsafe" (false positive flood).
            heuristic_with_enforcers = [a for a in heuristic_assumptions if a.enforced_by]
            if heuristic_with_enforcers and bypass_runner is not None:
                heuristic_bypasses = bypass_runner(heuristic_with_enforcers)
                for bf in heuristic_bypasses:
                    post_loop_findings.append({
                        "check": f"iris_{bf.assumption.bug_class or 'bypass'}",
                        "title": f"IRIS bypass: {bf.caller_function} skips {bf.missing_enforcer}",
                        "description": (
                            f"Caller {bf.caller_file}:{bf.caller_function} reaches "
                            f"{bf.assumption.target} without {bf.missing_enforcer}"
                        ),
                        "file": bf.caller_file,
                        "function": bf.caller_function,
                        "cwe": bf.assumption.bug_class or "",
                        "confidence": "medium",
                    })
        except Exception:
            logger.debug("IRIS heuristic assumption bypass failed", exc_info=True)

        from .negative_space import (
            check_deployment_assumptions,
            check_lock_ordering,
            check_missing_app_features,
            check_multi_process,
            check_protocol_ambiguity,
            check_resource_exhaustion,
            check_side_channels,
            check_signal_safety,
            check_ub_patterns,
        )
        for nf in check_resource_exhaustion(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_protocol_ambiguity(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_missing_app_features(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_signal_safety(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_ub_patterns(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_side_channels(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_multi_process(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_deployment_assumptions(gaps):
            post_loop_findings.append(nf.to_dict())
        for nf in check_lock_ordering(gaps):
            post_loop_findings.append(nf.to_dict())

        from .postcondition_verify import verify_postconditions
        pc_result = verify_postconditions(
            gaps, taint_summary_results or {},
        )
        if pc_result.violations:
            for v in pc_result.violations:
                post_loop_findings.append(v.to_dict())
            logger.info(
                "postcondition: %d violations from %d postconditions",
                len(pc_result.violations), pc_result.functions_with_postconditions,
            )

        from .triage import detect_generated_files
        generated = detect_generated_files(gaps)

        if post_loop_findings:
            logger.info(
                "Post-loop pattern checks: %d findings", len(post_loop_findings),
            )
        if generated:
            logger.info(
                "%d generated files detected — review depth reduced",
                len(generated),
            )

        if config.out_dir and (post_loop_findings or generated):
            pl_path = config.out_dir / "post-loop-findings.json"
            pl_path.write_text(json.dumps({
                "findings": post_loop_findings,
                "generated_files": generated,
                "finding_count": len(post_loop_findings),
            }, indent=2))

        for plf in post_loop_findings:
            plf_file = plf.get("file", "")
            plf_func = plf.get("function", "")
            if plf_file and plf_func:
                plf_status = "suspicious"
                plf_body = plf.get("description", plf.get("detail", ""))
                plf_cwe = plf.get("cwe", "")
                try:
                    record_review(
                        out_dir=config.out_dir,
                        target_path=config.target_path,
                        file_path=plf_file,
                        function_name=plf_func,
                        status=plf_status,
                        body=f"[mechanical] {plf_body}",
                        cwe=plf_cwe,
                        checked_by=["audit:post-loop"],
                    )
                except Exception:
                    pass
    except Exception:
        logger.debug("post-loop pattern checks failed", exc_info=True)

    if config.validate and result.findings > 0:
        from .validate import validate_findings
        result = validate_findings(
            result,
            target_path=config.target_path,
            out_dir=config.out_dir,
        )

    try:
        result = _retry_error_outcomes(
            result, config, review_fn, checklist, None, None,
            start_time, sarif_cache,
        )
    except Exception:
        logger.debug("error retry pass failed", exc_info=True)

    try:
        _run_dark_verification(result, config)
    except Exception:
        logger.debug("dark verification pass failed", exc_info=True)

    result.total_duration_s = time.monotonic() - start_time

    # --- Collector flush: write all buffered state to disk ---
    if collector is not None:
        try:
            collector.flush()
        except Exception:
            logger.debug("collector flush failed", exc_info=True)

    _persist_project_learnings(
        config.out_dir, session_observations, result,
    )

    if fp_patterns and config.out_dir:
        try:
            from .fp_feedback import save_fp_patterns
            save_fp_patterns(fp_patterns, config.out_dir)
        except Exception:
            logger.debug("fp_feedback: save failed", exc_info=True)

    try:
        write_tier_diagnostics(result.tier_counters, config.out_dir)
        diag_text = format_tier_diagnostics(result.tier_counters)
        if diag_text.count("\n") > 1:
            logger.info(diag_text)
    except Exception:
        logger.debug("tier diagnostics output failed", exc_info=True)

    try:
        from .findings_export import export_findings, write_graded_findings
        chains = None
        chains_path = config.out_dir / "attack-chains.json"
        if chains_path.exists():
            import json as _json
            chains = _json.loads(chains_path.read_text())
        graded = export_findings(
            result.outcomes,
            evidence_index=evidence_index,
            attack_chains=chains,
        )
        if feedback_state and feedback_state.confirmed_finding_ids:
            for finding in graded.get("findings", []):
                if finding.get("id") in feedback_state.confirmed_finding_ids:
                    finding["confidence"] = "high"
                    finding["evidence_chain"].append({
                        "source": "dynamic:exploit_confirmed",
                        "confidence": "high",
                        "description": "exploit confirmation from /exploit run",
                    })
        write_graded_findings(graded, config.out_dir)
        logger.info(
            "graded findings: %d total (%d high, %d medium, %d low confidence)",
            graded["stats"]["total"],
            graded["stats"]["high_confidence"],
            graded["stats"]["medium_confidence"],
            graded["stats"]["low_confidence"],
        )
    except Exception:
        logger.debug("graded findings export failed", exc_info=True)

    if config.out_dir:
        try:
            from .measurement import load_ground_truth, evaluate_run, write_evaluation, format_evaluation
            ground_truth = load_ground_truth(config.target_path)
            if ground_truth:
                evaluation = evaluate_run(config.out_dir, ground_truth)
                write_evaluation(evaluation, config.out_dir)
                logger.info(format_evaluation(evaluation))
        except Exception:
            logger.debug("measurement evaluation failed", exc_info=True)

    if config.out_dir:
        try:
            from .adversarial_test import (
                load_planted_bugs, match_findings_to_bugs,
                build_matrix, format_matrix_report, write_matrix,
            )
            planted = load_planted_bugs(config.target_path / "planted-bugs.json")
            if planted:
                matrix = build_matrix(planted)
                graded_path = config.out_dir / "findings-graded.json"
                if graded_path.is_file():
                    import json as _at_json
                    graded_data = _at_json.loads(graded_path.read_text())
                    graded_findings = graded_data.get("findings", [])
                    detections = match_findings_to_bugs(graded_findings, planted)
                    for det in detections:
                        bug = next((b for b in planted if b.bug_id == det.bug_id), None)
                        if bug:
                            matrix.record_detection(
                                det.bug_id, det.detected,
                                evidence_tier=det.evidence_tier,
                            )
                    write_matrix(matrix, config.out_dir)
                    logger.info(format_matrix_report(matrix))
        except Exception:
            logger.debug("adversarial self-test failed", exc_info=True)

    if taint_summary_results and config.out_dir:
        try:
            import json as _json
            summaries_out = {}
            for key, summary in taint_summary_results.items():
                if hasattr(summary, "to_dict"):
                    summaries_out[key] = summary.to_dict()
                else:
                    summaries_out[key] = summary
            sp = config.out_dir / "summaries.json"
            sp.write_text(_json.dumps(summaries_out, indent=2) + "\n")
            logger.info("summaries: wrote %d entries to summaries.json", len(summaries_out))
        except Exception:
            logger.debug("summaries.json write failed", exc_info=True)

    try:
        result.cost_tracker.write(config.out_dir)
        logger.info(result.cost_tracker.summary())
    except Exception:
        logger.debug("cost breakdown write failed", exc_info=True)

    try:
        from .sandbox_policy import validate_all_tools_sandboxed
        invoked = list(result.cost_tracker.phases.keys())
        unsandboxed = validate_all_tools_sandboxed(invoked)
        if unsandboxed:
            logger.warning(
                "sandbox policy: %d tools invoked without policy: %s",
                len(unsandboxed), ", ".join(unsandboxed),
            )
    except Exception:
        logger.debug("sandbox policy validation failed", exc_info=True)

    return result


def _composite_tool_runner(joern_runner, codeql_runner):
    """Combine Joern and CodeQL tool runners into a single runner.

    Merges confirmed_keys from both; tool_errors are concatenated.
    Returns None when neither runner is available.
    """
    if joern_runner is None and codeql_runner is None:
        return None
    if joern_runner is None:
        return codeql_runner
    if codeql_runner is None:
        return joern_runner

    def _composite(specs):
        from core.iris.refine import RefinementFeedback
        j_fb = joern_runner(specs)
        c_fb = codeql_runner(specs)
        confirmed = list(
            dict.fromkeys(j_fb.confirmed_keys + c_fb.confirmed_keys),
        )
        return RefinementFeedback(
            confirmed_keys=confirmed,
            refuted_keys=j_fb.refuted_keys + c_fb.refuted_keys,
            tool_errors=j_fb.tool_errors + c_fb.tool_errors,
        )

    return _composite


def _run_mechanical_detectors(
    gaps: List[Dict[str, Any]],
    config: OrchestratorConfig,
    context_map: Optional[Dict[str, Any]] = None,
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    joern_server: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Run pre-loop mechanical detectors over all source files.

    Returns findings keyed by "file:function".  Each value is a list of
    finding dicts with keys: file, function, detector, line, description.

    Design ref: ~/design/audit.md lines 782-813.
    """
    mechanical_findings: Dict[str, List[Dict[str, Any]]] = {}
    total = 0

    source_texts: Dict[str, str] = {}
    for gap in gaps:
        fp = gap.get("file", "")
        if fp and fp not in source_texts:
            try:
                src_path = config.target_path / fp
                if src_path.is_file():
                    source_texts[fp] = src_path.read_text(errors="replace")
            except Exception:
                pass

    if not source_texts:
        return mechanical_findings

    def _add(file: str, func: str, detector: str,
             line: int, description: str) -> None:
        nonlocal total
        key = f"{file}:{func}"
        mechanical_findings.setdefault(key, []).append({
            "file": file, "function": func,
            "detector": detector, "line": line,
            "description": description,
        })
        total += 1

    sinks_set: frozenset[str] = frozenset()
    if context_map:
        from .gaps import extract_context_map_set
        sinks_set = frozenset(extract_context_map_set(context_map, "sinks"))

    # --- L0: condition extraction + L1 adequacy/binding ---
    try:
        from .condition_extraction import extract_sink_guards
        from .condition_adequacy import assess_file_guards
        from .condition_binding import check_all_bindings

        for fp, src in source_texts.items():
            try:
                guards = extract_sink_guards(
                    src, fp,
                    sink_names=sinks_set or None,
                )
                if not guards:
                    continue

                adequacy_results, asymmetries = assess_file_guards(guards)
                for sg, ar in zip(guards, adequacy_results):
                    v = ar.verdict
                    if hasattr(v, "value"):
                        v = v.value
                    if v in ("irrelevant", "insufficient", "unknown"):
                        notes = "; ".join(ar.notes) if ar.notes else ""
                        _add(fp, sg.sink_function, f"guard_{v}",
                             sg.sink_line,
                             f"{v} guard for {ar.sink_api}: {notes}")
                for asym in asymmetries:
                    _add(fp, asym.sink_function, "sink_guard_asymmetry",
                         asym.unguarded_line,
                         f"asymmetric guarding of {asym.sink_api}: "
                         f"guarded at L{asym.guarded_line}, "
                         f"unguarded at L{asym.unguarded_line}")

                binding_analyses = check_all_bindings(src, guards)
                for sg, ba in zip(guards, binding_analyses):
                    if ba.all_guards_decorative:
                        _add(fp, sg.sink_function, "unbound_guard",
                             sg.sink_line,
                             f"all {ba.decorative_guard_count} guard(s) "
                             f"decorative for {ba.sink_api}")
            except Exception:
                logger.debug("condition extraction failed for %s", fp,
                             exc_info=True)
    except Exception:
        logger.debug("mechanical: condition chain failed", exc_info=True)

    # --- L2: CPG guard verification (Joern) ---
    if joern_server is not None:
        try:
            from .condition_extraction import extract_sink_guards as _extract_sg_l2
            from .condition_cpg import verify_guard_relevance_cpg
            for fp, src in source_texts.items():
                try:
                    sg_list = _extract_sg_l2(
                        src, fp, sink_names=sinks_set or None,
                    )
                    for sg in sg_list:
                        cpg_results = verify_guard_relevance_cpg(
                            sg, joern_server=joern_server,
                        )
                        for cr in cpg_results:
                            if (cr.data_dep_bound is False
                                    and cr.dominates_sink is False):
                                _add(fp, sg.sink_function,
                                     "decorative_guard_cpg",
                                     sg.sink_line,
                                     f"CPG: guard '{cr.guard_text}' neither "
                                     f"on data-dep path nor dominates sink "
                                     f"{cr.sink_api}")
                except Exception:
                    logger.debug("condition_cpg failed for %s", fp,
                                 exc_info=True)
        except Exception:
            logger.debug("mechanical: condition_cpg import failed",
                         exc_info=True)

    # --- L3: SMT guard sufficiency ---
    try:
        from .condition_extraction import extract_sink_guards as _extract_sg_l3
        from .condition_smt import check_all_sufficiency
        for fp, src in source_texts.items():
            try:
                sg_list = _extract_sg_l3(
                    src, fp, sink_names=sinks_set or None,
                )
                if not sg_list:
                    continue
                smt_per_guard = check_all_sufficiency(sg_list)
                for sg, results in zip(sg_list, smt_per_guard):
                    for sr in results:
                        if sr.feasible is True:
                            detail = sr.reasoning or ""
                            if sr.concrete_values:
                                vals = ", ".join(
                                    f"{k}={v}"
                                    for k, v in sr.concrete_values.items()
                                )
                                detail = f"{detail} ({vals})" if detail else vals
                            _add(fp, sg.sink_function,
                                 "insufficient_guard_smt",
                                 sg.sink_line,
                                 f"SMT: guard '{sr.guard_text}' insufficient "
                                 f"for {sg.sink_api}: {detail}")
            except Exception:
                logger.debug("condition_smt failed for %s", fp, exc_info=True)
    except Exception:
        logger.debug("mechanical: condition_smt import failed", exc_info=True)

    # --- Structural detectors ---
    call_graphs = None
    try:
        from core.inventory.call_graph import load_call_graphs
        call_graphs = load_call_graphs(config.target_path, None)
    except Exception:
        pass

    try:
        from .sentinel_collapse import detect_sentinel_collapses
        for sc in detect_sentinel_collapses(source_texts, call_graphs):
            _add(sc.file, sc.function, "sentinel_collapse",
                 sc.line,
                 f"{sc.write_value} coerced via {sc.read_coercion}: "
                 f"{sc.semantic_loss}")
    except Exception:
        logger.debug("mechanical: sentinel_collapse failed", exc_info=True)

    try:
        from .fail_open_detector import detect_fail_open_patterns
        for fo in detect_fail_open_patterns(source_texts, call_graphs):
            _add(fo.file, fo.function, "fail_open",
                 fo.line, fo.description)
    except Exception:
        logger.debug("mechanical: fail_open failed", exc_info=True)

    try:
        from .pattern_completeness import detect_pattern_gaps
        for pg in detect_pattern_gaps(source_texts):
            _add(pg.file, pg.function, "pattern_gap",
                 pg.line,
                 f"{pg.gap_type}: {pg.pattern} — {pg.suggestion}")
    except Exception:
        logger.debug("mechanical: pattern_completeness failed", exc_info=True)

    try:
        from .callsite_consistency import detect_callsite_deviations
        for cd in detect_callsite_deviations(source_texts):
            _add(cd.file, cd.enclosing_function, "callsite_deviation",
                 cd.line,
                 f"{cd.callee}: {cd.discarded_count}/{cd.total_sites} "
                 f"sites discard return value")
    except Exception:
        logger.debug("mechanical: callsite_consistency failed", exc_info=True)

    try:
        from .transform_sequence import detect_transform_order_violations
        for tv in detect_transform_order_violations(source_texts):
            _add(tv.file, tv.function, "transform_order",
                 tv.line,
                 f"{tv.violation} — fix: {tv.fix}")
    except Exception:
        logger.debug("mechanical: transform_sequence failed", exc_info=True)

    try:
        from .value_space_checker import detect_value_space_mismatches
        for vm in detect_value_space_mismatches(source_texts, call_graphs):
            unhandled = ", ".join(vm.unhandled[:5])
            _add(vm.consumer_file, vm.consumer_function,
                 "value_space_mismatch", 0,
                 f"producer {vm.producer_function} emits values "
                 f"not handled by consumer: [{unhandled}]")
    except Exception:
        logger.debug("mechanical: value_space_checker failed", exc_info=True)

    try:
        from .type_confusion import detect_type_confusion
        for tcf in detect_type_confusion(source_texts, call_graphs,
                                         joern_server):
            subtypes_str = ", ".join(
                getattr(tcf, "overriding_subtypes", [])[:3])
            _add(tcf.file, tcf.function, "type_confusion",
                 tcf.line,
                 f"deserialised object reaches virtual dispatch "
                 f"of {getattr(tcf, 'overridden_method', '?')}() — "
                 f"subtypes [{subtypes_str}] override this method")
    except Exception:
        logger.debug("mechanical: type_confusion failed", exc_info=True)

    if total:
        unique_funcs = len(mechanical_findings)
        logger.info(
            "mechanical detectors: %d findings across %d unique functions",
            total, unique_funcs,
        )

    return mechanical_findings


def _merge_stale(
    gaps: List[Dict[str, Any]],
    annotations_dir: Path,
    target_path: Path,
) -> List[Dict[str, Any]]:
    """Merge stale annotations into the gap list for re-review."""
    try:
        from .staleness import find_stale_annotations, stale_as_gaps
        stale_items = find_stale_annotations(annotations_dir, target_path)
        if stale_items:
            logger.info(
                "found %d stale annotation(s) for re-review", len(stale_items),
            )
            return stale_as_gaps(stale_items, gaps)
    except Exception:
        logger.warning("stale detection failed", exc_info=True)
    return gaps


def _build_context(
    config: OrchestratorConfig,
    gap: Dict[str, Any],
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    *,
    blind: bool = False,
) -> Dict[str, Any]:
    """Assemble context for one function.

    When *blind* is True, mechanical evidence is withheld from the prompt
    so the LLM reasons from code alone.  sink_unreachable is still set
    (it's a prefilter, not a leading hint).
    """
    ann_dir = config.annotations_dir or _resolve_ann_dir(config.out_dir)
    ctx = assemble_context(
        target_path=config.target_path,
        file_path=gap["file"],
        function_name=gap["name"],
        line_start=gap.get("line_start", 0),
        line_end=gap.get("line_end"),
        checklist=checklist,
        context_map=context_map,
        annotations_dir=ann_dir,
        inventory=config.inventory,
        out_dir=config.out_dir,
    )

    if evidence_index:
        key = f"{gap['file']}:{gap['name']}"
        rec = evidence_index.get(key)
        if not blind and rec and rec.has_any_evidence():
            ctx["mechanical_evidence"] = format_evidence_prose(rec)
            ctx["mechanical_evidence_structured"] = format_evidence_structured(rec)

            from .evidence_grade import grade_evidence_record
            graded = grade_evidence_record(rec)
            if graded:
                ctx["_graded_mechanical"] = graded

        if rec and rec.sink_unreachable:
            has_mechanical_flow = (
                rec.all_joern_flows()
                or (rec.taint_approx and rec.taint_approx.dangerous_flows)
                or rec.binary_sink_edges
            )
            if not has_mechanical_flow:
                ctx["sink_unreachable"] = True
                if rec.sink_narrowed_classes:
                    ctx["sink_narrowed_classes"] = rec.sink_narrowed_classes

    if not blind and discovered_evidence:
        key = f"{gap['file']}:{gap['name']}"
        disc = discovered_evidence.get(key)
        if disc:
            existing = ctx.get("mechanical_evidence", "")
            disc_text = "\n".join(
                f"- [mid-loop {d.get('tool', '?')}] {d.get('text', '')}"
                for d in disc[:20]
            )
            if disc_text:
                ctx["mechanical_evidence"] = (
                    f"{existing}\n\n### Mid-loop tool discoveries\n{disc_text}"
                    if existing
                    else f"### Mid-loop tool discoveries\n{disc_text}"
                )

    if config.models:
        ctx["model"] = config.models[0]

    return ctx


def _commit_outcome(
    config: OrchestratorConfig,
    outcome: ReviewOutcome,
    gap: Dict[str, Any],
    *,
    batch: bool = False,
) -> None:
    """Write the review result to annotations + coverage-audit."""
    checked_by = ["audit"]
    if outcome.model:
        checked_by.append(outcome.model)

    record_review(
        out_dir=config.out_dir,
        target_path=config.target_path,
        file_path=outcome.file,
        function_name=outcome.function,
        status=outcome.status,
        body=outcome.body,
        line_start=gap.get("line_start", 0),
        line_end=gap.get("line_end"),
        strategies=gap.get("strategies"),
        checked_by=checked_by,
    )

    if outcome.status != "error":
        mark_checked(
            config.out_dir, outcome.file, outcome.function, checked_by,
        )

    entry: Dict[str, Any] = {
        "action": "orchestrator_review",
        "key": f"{outcome.file}:{outcome.function}",
        "status": outcome.status,
        "model": outcome.model,
        "cost_usd": outcome.cost_usd,
        "duration_s": outcome.duration_s,
    }
    if outcome.hypothesis:
        entry["hypothesis"] = outcome.hypothesis
    if outcome.hypotheses:
        entry["hypotheses"] = outcome.hypotheses
    if outcome.evidence_tool:
        entry["evidence_tool"] = outcome.evidence_tool
    if outcome.review_result and outcome.review_result.get("preconditions"):
        entry["preconditions"] = outcome.review_result["preconditions"]
    strategies = gap.get("strategies")
    if strategies:
        entry["strategies"] = strategies
    if batch:
        entry["batch"] = True
    append_audit_log(config.out_dir, entry)


_GATE_DEMOTION_PREFIX = "[gate violation:"


def _is_evidence_only_gate_demotion(body: str) -> bool:
    """True when a gate demotion cited G2 (no receipt) and nothing else.

    G2 says "no tool has confirmed this *yet*" — running a tool later and
    getting a receipt is precisely the resolution, so the post-loop sweep
    must still be allowed to promote it. Every other gate (no hypothesis,
    empty body, language/CWE mismatch) is a reasoning defect that a tool
    hit does not repair, and those stay authoritative.
    """
    if not body.startswith(_GATE_DEMOTION_PREFIX):
        return False
    end = body.find("]")
    if end == -1:
        return False
    inner = body[len(_GATE_DEMOTION_PREFIX):end]
    reasons = [r.strip() for r in inner.split(";") if r.strip()]
    return bool(reasons) and all(r.startswith("G2") for r in reasons)


def _is_ungrounded_evidence(evidence: str) -> bool:
    """True when *evidence* carries no orchestrator-issued tool receipt.

    Stated positively rather than as a blacklist: G2 passes only for a
    value ``_stamp_evidence`` could have issued. A blacklist let every
    unenumerated string through — the sentinels (``llm``, ``manual``)
    were caught, but a bare ``joern`` or an arbitrary ``madeup:thing``
    was read as grounded.
    """
    return not is_stamped_tool_evidence((evidence or "").strip())


def _match_domain_model_invariants(
    hypothesis: str,
    file_path: str,
    domain_model: Optional[Dict[str, Any]],
) -> List[str]:
    """Match a hypothesis against domain-model invariants.

    Returns list of matching invariant IDs. An invariant matches when
    its statement or negation shares significant terms with the
    hypothesis. The match is deliberately loose — the invariant's
    mechanical provenance (from the study pipeline) justifies the
    leniency.
    """
    if not domain_model or not hypothesis:
        return []
    invariants = domain_model.get("invariants", [])
    if not invariants:
        return []

    import re as _re
    hyp_lower = hypothesis.lower()
    hyp_words = set(_re.findall(r"[a-z_]\w{3,}", hyp_lower))
    if len(hyp_words) < 2:
        return []

    matched = []
    for inv in invariants:
        inv_id = inv.get("id", "")
        statement = (inv.get("statement", "") + " " + inv.get("negation", "")).lower()
        inv_words = set(_re.findall(r"[a-z_]\w{3,}", statement))
        if not inv_words:
            continue
        overlap = hyp_words & inv_words
        if len(overlap) >= 3 and len(overlap) / len(inv_words) >= 0.15:
            matched.append(inv_id)
    return matched


def _check_finding_gates(
    outcome: ReviewOutcome,
    *,
    audit_log: Optional[List[Dict[str, Any]]] = None,
    domain_model: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Check G1-G5 gates on a finding. Returns list of violations."""
    violations = []
    hypothesis = outcome.hypothesis or ""
    if outcome.review_result:
        hypothesis = outcome.review_result.get("hypothesis", hypothesis)

    evidence = outcome.evidence_tool or ""
    if outcome.review_result:
        evidence = outcome.review_result.get("evidence_tool", evidence)

    if not hypothesis or hypothesis.strip() == "":
        violations.append("G1: finding emitted without testable hypothesis")

    if _is_ungrounded_evidence(evidence):
        matched_invariants = _match_domain_model_invariants(
            hypothesis, outcome.file, domain_model,
        )
        if matched_invariants:
            inv_ids = ", ".join(matched_invariants)
            logger.info(
                "G2 bypassed for %s:%s — hypothesis matches "
                "domain-model invariant(s): %s",
                outcome.file, outcome.function, inv_ids,
            )
        else:
            violations.append("G2: finding emitted without tool-grounded evidence")

    # G3: NO-SELF-CRITIQUE — re-recording same function requires a sweep
    if audit_log is not None:
        key = f"{outcome.file}:{outcome.function}"
        prior_records = [
            e for e in audit_log
            if e.get("key") == key
            and e.get("action") in ("record", "orchestrator_review")
            and e.get("status") in ("finding", "suspicious")
        ]
        if prior_records and not outcome.evidence_tool:
            violations.append(
                "G3: re-recording without new tool evidence"
            )

    # G4: EVIDENCE-IN-ANNOTATION — findings require a non-empty body
    body = outcome.body or ""
    if outcome.status in ("finding", "suspicious") and not body.strip():
        violations.append(
            "G4: finding/suspicious with empty annotation body"
        )

    # G5: LANGUAGE-CWE — memory-corruption CWEs in memory-safe languages
    lang_mismatch = _check_language_cwe_mismatch(outcome)
    if lang_mismatch:
        violations.append(f"G5: {lang_mismatch}")

    return violations


class _ContentFilterError(Exception):
    """Raised when the LLM response is blocked by a content filter."""


_STATUS_SEVERITY = {"finding": 3, "suspicious": 2, "dormant": 1, "clean": 0, "error": -1}


def _multi_pass_review(
    review_fn: Callable,
    ctx: Dict[str, Any],
    config: OrchestratorConfig,
    passes: int,
) -> ReviewOutcome:
    """Run review_fn N times and merge hypotheses across passes.

    Delegates to multi_review.run_self_consistency when available,
    falling back to an inline loop. Takes the highest-severity
    outcome as the primary result, merges hypotheses across passes.
    """
    file_path = ctx.get("file", "")
    function_name = ctx.get("function", "")
    model = config.models[0] if config.models else "default"

    # Use multi_review substrate for cross-model consensus when
    # multiple distinct models are configured
    if config.multi_model and len(config.models) > 1:
        try:
            from .multi_review import run_audit_multi_review, consensus_status

            def context_fn(_file: str, _func: str) -> Dict[str, Any]:
                return ctx

            def adapted_review_fn(
                context: Dict[str, Any], model_name: str,
            ) -> Dict[str, Any]:
                outcome = review_fn(context, config)
                result = {
                    "file": outcome.file,
                    "function": outcome.function,
                    "status": outcome.status,
                    "body": outcome.body,
                    "hypothesis": outcome.hypothesis,
                    "evidence_tool": outcome.evidence_tool,
                    "cost_usd": outcome.cost_usd,
                    "model": outcome.model or model_name,
                    "duration_s": outcome.duration_s,
                }
                if outcome.hypotheses:
                    result["hypotheses"] = outcome.hypotheses
                if outcome.review_result:
                    result.update(outcome.review_result)
                return result

            refute_fn = None
            if config.adversarial:
                def refute_fn(finding: Dict[str, Any]) -> Dict[str, Any]:
                    refute_ctx = dict(ctx)
                    refute_ctx["adversarial_target"] = finding
                    outcome = review_fn(refute_ctx, config)
                    return {
                        "status": outcome.status,
                        "body": outcome.body,
                        "hypothesis": outcome.hypothesis,
                    }

            mr_result = run_audit_multi_review(
                file_path=file_path,
                function_name=function_name,
                models=config.models,
                context_fn=context_fn,
                review_fn=adapted_review_fn,
                refute_fn=refute_fn,
            )

            if not mr_result.items:
                return ReviewOutcome(
                    file=file_path, function=function_name,
                    status="error", body="multi-review produced no items",
                )

            primary = mr_result.items[0]
            total_cost = sum(
                r.get("cost_usd", 0)
                for raw_list in mr_result.per_model_raw.values()
                for r in raw_list
            )
            total_duration = max(
                (r.get("duration_s", 0)
                 for raw_list in mr_result.per_model_raw.values()
                 for r in raw_list),
                default=0,
            )
            return ReviewOutcome(
                file=primary.get("file", file_path),
                function=primary.get("function", function_name),
                status=(
                    consensus_status(mr_result)
                    or primary.get("status", "error")
                ),
                body=primary.get("body", ""),
                hypothesis=primary.get("hypothesis", ""),
                hypotheses=primary.get("hypotheses"),
                evidence_tool=primary.get("evidence_tool", ""),
                cost_usd=total_cost,
                model=primary.get("model", model),
                duration_s=total_duration,
                review_result=primary,
            )

        except (ImportError, Exception):
            logger.debug(
                "multi_review unavailable, falling back to inline loop",
                exc_info=True,
            )

    # Inline self-consistency: same model N times, best-of-N with
    # hypothesis dedup (used for single-model review_passes > 1)
    outcomes: List[ReviewOutcome] = []
    for _ in range(passes):
        try:
            outcome = review_fn(ctx, config)
        except _ContentFilterError:
            outcome = ReviewOutcome(
                file=file_path, function=function_name,
                status="error", body="blocked by content filter",
            )
        except Exception as exc:
            logger.warning(
                "review_fn pass failed for %s:%s: %s",
                file_path, function_name, exc,
            )
            outcome = ReviewOutcome(
                file=file_path, function=function_name,
                status="error", body=f"pass failed: {exc}",
            )
        outcomes.append(outcome)

    best = max(
        outcomes,
        key=lambda o: (
            _STATUS_SEVERITY.get(o.status, -1),
            len(o.hypotheses or []),
        ),
    )

    seen_mechanisms: set = set()
    merged_hypotheses: List[Dict[str, Any]] = []
    for o in outcomes:
        for h in (o.hypotheses or []):
            mech = h.get("mechanism", "")
            if mech and mech not in seen_mechanisms:
                seen_mechanisms.add(mech)
                merged_hypotheses.append(h)

    total_cost = sum(o.cost_usd for o in outcomes)
    total_duration = sum(o.duration_s for o in outcomes)

    return ReviewOutcome(
        file=best.file,
        function=best.function,
        status=best.status,
        body=best.body,
        hypothesis=best.hypothesis,
        hypotheses=merged_hypotheses or None,
        evidence_tool=best.evidence_tool,
        cost_usd=total_cost,
        model=best.model,
        duration_s=total_duration,
        review_result=best.review_result,
    )


_RECOVERABLE_ERROR_CLASSES = frozenset({"json_parse", "truncation", "api_error"})


def _classify_error(exc: Exception) -> str:
    msg = str(exc).lower()
    if "content filter" in msg or "blocked" in msg:
        return "content_filter"
    if "budget exceeded" in msg:
        return "budget"
    if "truncated" in msg or "output token limit" in msg:
        return "truncation"
    if isinstance(exc, json.JSONDecodeError):
        return "json_parse"
    if type(exc).__name__ == "ValidationError":
        return "json_parse"
    if any(k in msg for k in (
        "rate limit", "timeout", "502", "503", "504",
        "bad gateway", "overloaded", "quota exceeded",
        "server error",
    )):
        return "api_error"
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return "api_error"
    return "internal"


def _error_outcome(gap: Dict[str, Any], exc: Exception) -> ReviewOutcome:
    return ReviewOutcome(
        file=gap["file"],
        function=gap["name"],
        status="error",
        body=f"orchestrator: review_fn raised {type(exc).__name__}: {exc}",
        error_class=_classify_error(exc),
    )


_TRUNCATION_STRIP_KEYS = frozenset({
    "block_analysis", "sibling_ns", "type_constraints",
})


def _retry_error_outcomes(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    shared: Any,
    llm_client: Any,
    start_time: float,
    sarif_cache: Any,
) -> OrchestratorResult:
    """Retry recoverable error outcomes (json_parse, truncation, api_error)."""
    error_outcomes = [
        o for o in result.outcomes
        if o.status == "error" and o.error_class in _RECOVERABLE_ERROR_CLASSES
    ]
    if not error_outcomes:
        return result

    for outcome in error_outcomes:
        try:
            ctx = _build_context(
                config,
                {"file": outcome.file, "name": outcome.function},
                checklist, None,
            )
        except Exception:
            continue

        if outcome.error_class == "truncation":
            for key in _TRUNCATION_STRIP_KEYS:
                ctx.pop(key, None)
        ctx["error_retry"] = True

        try:
            new_outcome = review_fn(ctx, config)
        except Exception:
            continue

        result.error_retries += 1
        result.error_retry_recovered += 1
        result.errors -= 1
        if outcome.error_class in result.error_counts:
            result.error_counts[outcome.error_class] -= 1
            if result.error_counts[outcome.error_class] <= 0:
                del result.error_counts[outcome.error_class]
        idx = result.outcomes.index(outcome)
        result.outcomes[idx] = new_outcome
        result.reviewed -= 1
        _tally_outcome(result, new_outcome, append=False)
        result.cost_tracker.record_call(
            "error_retry", cost_usd=getattr(new_outcome, "cost_usd", 0.0),
        )

    return result


def _check_budget(
    config: OrchestratorConfig,
    start_time: float,
    result: OrchestratorResult,
) -> bool:
    """Return True when budget is exhausted."""
    if config.max_seconds:
        if time.monotonic() - start_time >= config.max_seconds:
            result.terminated_by = "max_seconds"
            return True
    if config.max_cost_usd and result.total_cost_usd >= config.max_cost_usd:
        result.terminated_by = "max_cost_usd"
        return True
    return False


def _tally_outcome(
    result: OrchestratorResult,
    outcome: ReviewOutcome,
    *,
    append: bool = True,
) -> None:
    with result._lock:
        if append:
            result.outcomes.append(outcome)
        result.reviewed += 1
        result.total_cost_usd += outcome.cost_usd
        if outcome.status == "finding":
            result.findings += 1
        elif outcome.status == "suspicious":
            result.suspicious += 1
        elif outcome.status == "clean":
            result.clean += 1
        elif outcome.status == "dormant":
            result.dormant += 1
        elif outcome.status == "dark":
            result.dormant += 1
        elif outcome.status == "error":
            result.errors += 1
            if outcome.error_class:
                result.error_counts[outcome.error_class] = (
                    result.error_counts.get(outcome.error_class, 0) + 1
                )


def _accumulate_observations(
    session_observations: List[Dict[str, str]],
    outcome: ReviewOutcome,
    gap: Dict[str, Any],
    *,
    sweep_pre_status: Optional[str] = None,
) -> None:
    """Extract LLM observations and add to session context.

    Also injects tool confirmation/refutation observations when
    sweep validation changed the outcome status.
    """
    source = f"{gap['file']}:{gap['name']}"

    if sweep_pre_status is not None:
        if outcome.status == "finding" and outcome.evidence_tool:
            session_observations.append({
                "source": source,
                "text": (
                    f"[tool-confirmed] {outcome.evidence_tool} confirmed: "
                    f"{outcome.hypothesis}"
                ),
                "kind": "tool_confirmation",
            })
        elif sweep_pre_status == "finding" and outcome.status == "suspicious":
            session_observations.append({
                "source": source,
                "text": (
                    f"[tool-refuted] hypothesis '{outcome.hypothesis}' "
                    f"was not confirmed by any mechanical tool — demoted"
                ),
                "kind": "tool_refutation",
            })

    raw = (outcome.review_result or {}).get("observations")
    if not raw or not isinstance(raw, list):
        return
    for obs in raw:
        if isinstance(obs, str) and len(obs) >= 10:
            session_observations.append({
                "source": source, "text": obs,
                "kind": "llm_observation",
            })


def _batch_trivial(
    workqueue: List[Dict[str, Any]],
    sloc_threshold: int,
) -> tuple:
    """Split workqueue into trivial batches and normal items.

    Functions with SLOC <= threshold are grouped by file into batches
    for combined review.  Returns (batches, remaining).
    """
    if sloc_threshold <= 0:
        return [], workqueue

    batches_by_file: Dict[str, List[Dict[str, Any]]] = {}
    remaining = []

    for gap in workqueue:
        sloc = gap.get("sloc", 0)
        if sloc > 0 and sloc <= sloc_threshold:
            batches_by_file.setdefault(gap["file"], []).append(gap)
        else:
            remaining.append(gap)

    batches = [items for items in batches_by_file.values() if len(items) >= 2]
    for items in batches_by_file.values():
        if len(items) < 2:
            remaining.extend(items)

    return batches, remaining


def _synthesis_hits_to_gaps(
    hits: List[Dict[str, Any]],
    checklist: Dict[str, Any],
    out_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Resolve Mode-2 sweep hits into reviewable gaps.

    Checker synthesis reports *sites* — ``{file, line, function: "",
    snippet}`` — because a codebase-wide rule matches text, not
    functions. The review loop is keyed on functions, so each site is
    resolved to the checklist function that encloses it.

    A site that resolves to no reviewable function (a top-level
    initializer, a macro, generated code, a checklist entry with no
    line span) cannot become a review task — but it is still tool
    signal, so it is written to ``unresolved-synthesis-hits.json``
    rather than discarded.

    Functions reviewed in an earlier round or run are deliberately NOT
    skipped: a synthesized checker encodes a pattern that was unknown
    when they were reviewed, which is exactly when re-review pays.
    """
    gaps: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    unresolved: List[Dict[str, Any]] = []

    for hit in hits:
        file_path = hit.get("file", "")
        try:
            line = int(hit.get("line") or 0)
        except (TypeError, ValueError):
            line = 0

        gap = gap_for_site(checklist, file_path, line) if line else None
        if gap is None:
            unresolved.append(hit)
            continue

        key = f"{gap['file']}:{gap['name']}"
        if key in seen:
            continue
        # Skip the seed's own function: the rule was synthesised *from*
        # it, so it is already a finding, not a new variant.
        origin_file = hit.get("origin_file", "")
        origin_function = hit.get("origin_function", "")
        if origin_function and key == f"{origin_file}:{origin_function}":
            continue
        seen.add(key)

        if hit.get("priority_score") is not None:
            gap["priority_score"] = hit["priority_score"]
        gap["from_synthesis"] = True
        if hit.get("snippet"):
            gap["synthesis_snippet"] = hit["snippet"]
        gaps.append(gap)

    if unresolved:
        logger.info(
            "synthesis pass: %d/%d hits did not resolve to a checklist "
            "function — recorded as unresolved sites",
            len(unresolved), len(hits),
        )
        if out_dir is not None:
            _write_unresolved_synthesis_hits(unresolved, out_dir)

    return gaps


def _write_unresolved_synthesis_hits(
    hits: List[Dict[str, Any]],
    out_dir: Path,
) -> None:
    """Persist synthesis sites that have no enclosing reviewable function."""
    path = out_dir / "unresolved-synthesis-hits.json"
    tmp = None
    # One non-fatal boundary around read, normalise, serialise and write.
    # This is a diagnostic artifact: a malformed, mis-encoded or
    # unserialisable one must never take the run down with it.
    try:
        existing: List[Dict[str, Any]] = []
        if path.is_file():
            try:
                prior = json.loads(
                    path.read_text(encoding="utf-8", errors="replace"),
                )
            except json.JSONDecodeError:
                prior = None
            # Tolerate any prior shape — a truncated write, a hand-edit,
            # a bare list — and replace what can't be understood.
            if isinstance(prior, dict) and isinstance(prior.get("hits"), list):
                existing = prior["hits"]
            elif isinstance(prior, list):
                existing = prior
            elif prior is not None:
                logger.debug("replacing malformed %s", path.name)

        existing = list(existing) + list(hits)
        payload = json.dumps(
            {"hits": existing, "count": len(existing)},
            indent=2, default=str,
        )

        fd, tmp = tempfile.mkstemp(dir=str(out_dir), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, str(path))
    except (OSError, UnicodeError, TypeError, ValueError):
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        logger.debug("could not persist unresolved synthesis hits", exc_info=True)


def _review_items(
    batch: List[Dict[str, Any]],
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    fuzz_coverage: Optional[Dict[str, Any]],
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
) -> List[ReviewOutcome]:
    """Review a group of trivial functions from the same file individually."""
    outcomes = []
    for gap in batch:
        ctx = _build_context(config, gap, checklist, context_map, evidence_index,
                             discovered_evidence=discovered_evidence,
                             blind=config.blind_first_pass)
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage, gap["file"], gap["name"],
            )
        ctx["batch_context"] = [
            f"{g['name']} (L{g.get('line_start', '?')}-{g.get('line_end', '?')})"
            for g in batch
        ]
        try:
            outcome = review_fn(ctx, config)
        except _ContentFilterError:
            outcome = ReviewOutcome(
                file=gap["file"],
                function=gap["name"],
                status="error",
                body="blocked by content filter",
            )
        except Exception as exc:
            logger.warning(
                "review_fn failed for %s:%s: %s",
                gap["file"], gap["name"], exc,
            )
            outcome = _error_outcome(gap, exc)

        if outcome.status == "finding":
            gate_violations = _check_finding_gates(outcome)
            if gate_violations:
                for v in gate_violations:
                    logger.warning(
                        "gate violation %s:%s: %s — demoted to suspicious",
                        outcome.file, outcome.function, v,
                    )
                outcome = _demote_outcome(
                    outcome,
                    f"[gate violation: {'; '.join(gate_violations)}]",
                )

        try:
            _commit_outcome(config, outcome, gap, batch=True)
        except Exception as exc:
            logger.warning(
                "commit failed for %s:%s: %s",
                gap["file"], gap["name"], exc,
            )
        outcomes.append(outcome)
    return outcomes


def _apply_reachability_gate(
    outcome: ReviewOutcome,
    ctx: Dict[str, Any],
    entry_points: set,
    config: OrchestratorConfig,
) -> ReviewOutcome:
    """Conservative post-review gate: demote findings only on hard evidence.

    Err toward false positives (keeping findings) rather than false negatives
    (suppressing real bugs). Only demotes when there is mechanical proof that
    the finding cannot be triggered.

    Demotion rules (all must have strong evidence):
      1. Dead code: function has no callers AND is not an entry point
         AND binary oracle says "absent" → dormant
      2. Dead code (source-only): no callers AND not an entry point
         AND not on any flow path → suspicious (not dormant — source
         analysis alone isn't proof)
    """
    key = f"{outcome.file}:{outcome.function}"
    role_ctx = ctx.get("role_context", {})
    role = role_ctx.get("role", "internal")
    on_flow = role_ctx.get("is_on_flow_path", False)
    has_caller_data = role_ctx.get("has_caller_data", False)
    callers = ctx.get("callers", [])

    is_entry = key in entry_points or role == "entry_point"
    is_sink = role == "sink"

    if is_sink:
        return outcome

    if config.binary_verdicts:
        verdict = config.binary_verdicts.get(outcome.function, "")
        if verdict == "absent" and not is_entry:
            logger.info(
                "reachability gate: %s demoted to dormant (binary: absent)",
                key,
            )
            return ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="dormant",
                body=(
                    f"[reachability gate: binary oracle says this function "
                    f"is absent from the compiled binary]\n\n{outcome.body}"
                ),
                hypothesis=outcome.hypothesis,
                hypotheses=outcome.hypotheses,
                evidence_tool=outcome.evidence_tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )

    if has_caller_data and not callers and not is_entry and not on_flow:
        logger.info(
            "reachability gate: %s demoted to suspicious "
            "(no callers, not entry point, not on flow path)",
            key,
        )
        return ReviewOutcome(
            file=outcome.file,
            function=outcome.function,
            status="suspicious",
            body=(
                f"[reachability gate: no visible callers and not an entry "
                f"point — finding may be valid but reachability is unproven]\n\n"
                f"{outcome.body}"
            ),
            hypothesis=outcome.hypothesis,
            hypotheses=outcome.hypotheses,
            evidence_tool=outcome.evidence_tool,
            cost_usd=outcome.cost_usd,
            model=outcome.model,
            duration_s=outcome.duration_s,
            review_result=outcome.review_result,
            line=outcome.line,
        )

    return outcome


_MEMORY_CWE = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125",
    "CWE-126", "CWE-127", "CWE-131", "CWE-134", "CWE-170",
    "CWE-190", "CWE-191", "CWE-193", "CWE-415", "CWE-416",
    "CWE-476", "CWE-787",
})
_MEMORY_SAFE_LANGS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".java", ".kt",
    ".scala", ".go", ".rs",
})


def _check_language_cwe_mismatch(
    outcome: ReviewOutcome,
) -> Optional[str]:
    """Detect CWE categories impossible in the file's language."""
    cwe = ""
    if outcome.review_result:
        cwe = (
            outcome.review_result.get("cwe_class")
            or outcome.review_result.get("cwe")
            or ""
        )
    if not cwe:
        return None
    cwe_upper = cwe.upper().strip()
    if cwe_upper not in _MEMORY_CWE:
        return None
    ext = Path(outcome.file).suffix.lower()
    if ext in _MEMORY_SAFE_LANGS:
        return (
            f"language-CWE mismatch: {cwe} (memory corruption) "
            f"claimed in {ext} file"
        )
    return None


def _run_prefilter_for_gap(
    config: OrchestratorConfig,
    gap: Dict[str, Any],
    ctx: Dict[str, Any],
) -> PrefilterResult:
    """Run the mechanical pre-filter on a single gap function."""
    source = _read_raw_source(
        config.target_path, gap["file"],
        gap.get("line_start", 0), gap.get("line_end"),
    )
    return run_prefilter(
        target_path=config.target_path,
        file_path=gap["file"],
        function_name=gap["name"],
        source=source,
        line_start=gap.get("line_start", 0),
        line_end=gap.get("line_end", 0),
        callers=ctx.get("callers"),
        callees=ctx.get("callees"),
        metadata=ctx.get("metadata"),
        sink_unreachable=ctx.get("sink_unreachable", False),
    )


def _read_raw_source(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: Optional[int],
) -> str:
    """Read raw source lines without line-number prefixes."""
    full_path = target_path / file_path
    if not full_path.exists():
        return ""
    try:
        lines = full_path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line_start - 1)
    end = line_end if line_end else min(start + 50, len(lines))
    return "\n".join(lines[start:end])


def _hypothesis_to_tool_chain(
    hypothesis: str,
    file_path: str,
    cwe: str = "",
) -> List[Dict[str, Any]]:
    """Build an ordered list of tools to try for a hypothesis.

    Each entry is ``{"type": "semgrep"|"smt"|"coccinelle"|"codeql",
    "config": {...}}``.  The chain is tried in order; the first
    confirmation wins, but errors/unavailability fall through to the
    next tool.  Multiple tools may match the same hypothesis — that's
    intentional for fallback coverage.

    CWE-based dispatch seeds the chain first (strongest, most stable
    signal), then string-matched tools augment with hypothesis-specific
    patterns.
    """
    chain: List[Dict[str, Any]] = []
    seen_types: set = set()

    if cwe:
        cwe_chain = _cwe_fallback_chain(cwe)
        for entry in cwe_chain:
            chain.append(entry)
            seen_types.add(entry["type"])

    semgrep_rule = _hypothesis_to_semgrep_rule(hypothesis, file_path)
    if semgrep_rule and "semgrep" not in seen_types:
        chain.append({"type": "semgrep", "config": {"rule": semgrep_rule}})
        seen_types.add("semgrep")
    elif not semgrep_rule and "semgrep" not in seen_types:
        try:
            from .sweep import mechanical_check_to_semgrep
            mc_pattern = mechanical_check_to_semgrep(hypothesis)
            if mc_pattern:
                chain.append({"type": "semgrep", "config": {"pattern": mc_pattern}})
                seen_types.add("semgrep")
        except ImportError:
            pass

    smt_verb = _hypothesis_to_smt_verb(hypothesis)
    if smt_verb and "smt" not in seen_types:
        chain.append({"type": "smt", "config": {"verb": smt_verb}})
        seen_types.add("smt")

    cocci_rule = _hypothesis_to_cocci_check(hypothesis)
    if cocci_rule and "coccinelle" not in seen_types:
        chain.append({"type": "coccinelle", "config": {"rule": cocci_rule}})
        seen_types.add("coccinelle")

    if cwe and "joern" not in seen_types:
        try:
            from .cwe_dispatch import joern_applicable, sinks_for_cwe
        except ImportError:
            pass
        else:
            if joern_applicable(cwe):
                sinks = sinks_for_cwe(cwe)
                if sinks:
                    chain.append({"type": "joern", "config": {"sinks": sinks}})
                    seen_types.add("joern")

    if cwe and "codeql" not in seen_types:
        try:
            from .cwe_dispatch import codeql_query_for_cwe
        except ImportError:
            pass
        else:
            codeql_query = codeql_query_for_cwe(cwe)
            if codeql_query:
                chain.append({"type": "codeql", "config": {"query": codeql_query}})

    return chain


def _cwe_fallback_chain(cwe: str) -> List[Dict[str, Any]]:
    """Generate tool chain from CWE dispatch when string matching fails."""
    chain: List[Dict[str, Any]] = []
    try:
        from .cwe_dispatch import (
            cocci_rule_for_cwe,
            codeql_query_for_cwe,
            joern_applicable,
            sinks_for_cwe,
            smt_verb_for_cwe,
        )
    except ImportError:
        return chain

    smt_verb = smt_verb_for_cwe(cwe)
    if smt_verb:
        chain.append({"type": "smt", "config": {"verb": smt_verb}})

    cocci_rule = cocci_rule_for_cwe(cwe)
    if cocci_rule:
        chain.append({"type": "coccinelle", "config": {"rule": cocci_rule}})

    codeql_query = codeql_query_for_cwe(cwe)
    if codeql_query:
        chain.append({"type": "codeql", "config": {"query": codeql_query}})

    if joern_applicable(cwe):
        sinks = sinks_for_cwe(cwe)
        if sinks:
            chain.append({"type": "joern", "config": {"sinks": sinks}})

    return chain


def _run_tool_chain(
    chain: List[Dict[str, Any]],
    *,
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    source: Optional[str],
    hypothesis: str,
    line_start: int = 0,
    sarif_cache: Optional[SarifCache] = None,
    tier_counters: Optional[Dict[str, "TierCounters"]] = None,
    evidence_index: Optional[Dict[str, "EvidenceRecord"]] = None,
    joern_server=None,
) -> List[str]:
    """Run tools from *chain* in order, collecting all confirmations.

    Returns a list of confirming tool IDs (e.g. ``["smt:check-oob",
    "coccinelle:missing_bounds_check"]``).  A tool that errors or
    whose dependency is missing is skipped (logged at debug) and the
    next tool in the chain is tried — this is the fallback behaviour.

    When *sarif_cache* is provided, semgrep sweeps check for prior
    SARIF results before spawning a subprocess.
    """
    confirmed: List[str] = []

    for entry in chain:
        tool_type = entry["type"]
        tool_cfg = entry["config"]

        try:
            if tool_type == "semgrep":
                if sarif_cache is not None:
                    cached = sarif_cache.lookup(
                        file_path, line_start,
                        line_start + 50 if line_start else 0,
                    )
                    if cached is not None:
                        if cached:
                            confirmed.append("sarif_cache:semgrep")
                            logger.debug(
                                "sarif_cache hit: %s:%s — %d prior results",
                                file_path, function_name, len(cached),
                            )
                        continue

                rule_path = tool_cfg["rule"]
                sweep = run_semgrep_sweep(
                    target_path=config.target_path,
                    file_path=file_path,
                    function_name=function_name,
                    rule_config=rule_path,
                    line_start=line_start,
                    line_end=line_start + 50 if line_start else 0,
                )
                if rule_path and os.path.basename(rule_path).startswith(
                    "audit_sweep_"
                ):
                    try:
                        os.unlink(rule_path)
                    except OSError:
                        pass
                if sweep.outcome == "confirmed":
                    confirmed.append(
                        f"semgrep:{sweep.rule_id or 'hypothesis'}"
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "semgrep", "confirmed")
                elif sweep.outcome == "error":
                    logger.debug(
                        "tool_chain semgrep error %s:%s: %s",
                        file_path, function_name, sweep.errors,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "semgrep", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "semgrep", "refuted")

            elif tool_type == "smt":
                smt_result = run_smt_verb_direct(
                    file_path=file_path,
                    function_name=function_name,
                    verb=tool_cfg["verb"],
                    source=source or "",
                    hypothesis=hypothesis,
                )
                if smt_result.outcome == "confirmed":
                    confirmed.append(f"smt:{tool_cfg['verb']}")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "smt", "confirmed")
                elif smt_result.outcome == "error":
                    logger.debug(
                        "tool_chain smt error %s:%s: %s",
                        file_path, function_name, smt_result.errors,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "smt", "errors")
                else:
                    if confirmed:
                        logger.info(
                            "smt refuted %s:%s — clearing %d prior "
                            "confirmations (%s)",
                            file_path, function_name,
                            len(confirmed), ", ".join(confirmed),
                        )
                        confirmed.clear()
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "smt", "refuted")

            elif tool_type == "coccinelle":
                cocci_result = run_consistency_check(
                    target_path=config.target_path,
                    function_name=function_name,
                    cocci_rule=tool_cfg["rule"],
                )
                if cocci_result.outcome == "confirmed":
                    confirmed.append(
                        f"coccinelle:{Path(tool_cfg['rule']).stem}"
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "coccinelle", "confirmed")
                elif cocci_result.outcome == "error":
                    logger.debug(
                        "tool_chain coccinelle error %s:%s: %s",
                        file_path, function_name, cocci_result.errors,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "coccinelle", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "coccinelle", "refuted")

            elif tool_type == "joern":
                key = f"{file_path}:{function_name}"
                pre_hit = False
                joern_hit = False
                if evidence_index and key in evidence_index:
                    rec = evidence_index[key]
                    if rec.all_joern_flows():
                        confirmed.append("joern:pre_sweep")
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "joern", "confirmed")
                        pre_hit = True
                        joern_hit = True

                if not pre_hit and joern_server is not None:
                    sinks = tool_cfg.get("sinks", [])
                    live_hits = _joern_live_query(
                        joern_server, function_name, sinks,
                    )
                    if live_hits:
                        confirmed.append("joern:live")
                        joern_hit = True
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "joern", "confirmed")
                    elif tier_counters:
                        _increment_tier_dict(tier_counters, "joern", "refuted")
                elif not pre_hit and tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "skipped")

                if joern_hit and joern_server is not None:
                    _enrich_joern_evidence(
                        evidence_index, key, function_name,
                        tool_cfg.get("sinks", []), joern_server,
                    )

            elif tool_type == "codeql":
                from .sweep import run_codeql_sweep
                codeql_result = run_codeql_sweep(
                    target_path=config.target_path,
                    file_path=file_path,
                    function_name=function_name,
                    query_path=tool_cfg["query"],
                    database_path=config.codeql_db_path,
                    line_start=line_start,
                    line_end=line_start + 50 if line_start else 0,
                )
                if codeql_result.outcome == "confirmed":
                    confirmed.append(
                        f"codeql:{Path(tool_cfg['query']).stem}"
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "confirmed")
                elif codeql_result.outcome == "error":
                    logger.debug(
                        "tool_chain codeql error %s:%s: %s",
                        file_path, function_name, codeql_result.errors,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "codeql", "refuted")

        except Exception as exc:
            logger.debug(
                "tool_chain %s exception %s:%s: %s",
                tool_type, file_path, function_name, exc,
            )

    return confirmed


_CWE_IMPLICIT_PRECONDITIONS: Dict[str, List[Dict[str, Any]]] = {
    "CWE-89": [{"check_type": "sink_reachable", "assumption": "SQL sink reachable from function"}],
    "CWE-78": [{"check_type": "sink_reachable", "assumption": "command execution sink reachable"}],
    "CWE-79": [{"check_type": "sink_reachable", "assumption": "HTML/JS output sink reachable"}],
    "CWE-22": [{"check_type": "sink_reachable", "assumption": "filesystem sink reachable"}],
}


def _check_preconditions(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    context_map: Optional[Dict[str, Any]],
) -> ReviewOutcome:
    """Verify LLM-stated preconditions mechanically.

    When the LLM emits status=finding with preconditions, run each
    precondition's specified check. If ANY precondition is contradicted,
    demote the finding to suspicious.

    When no preconditions are stated, synthesise minimal implicit ones
    from the CWE class (e.g., injection CWEs require a reachable sink).
    """
    review = outcome.review_result or {}
    preconditions = review.get("preconditions")
    if not preconditions:
        cwe = (review.get("cwe_class") or review.get("cwe") or "").upper().strip()
        implicit = _CWE_IMPLICIT_PRECONDITIONS.get(cwe)
        if implicit:
            preconditions = [
                {
                    **pc,
                    "location": {"file": outcome.file, "function": outcome.function},
                }
                for pc in implicit
            ]
        if not preconditions:
            return outcome

    try:
        from .precondition_check import verify_preconditions

        verdict = verify_preconditions(
            preconditions,
            target_path=config.target_path,
            context_map=context_map,
        )

        if verdict.any_contradicted:
            summary = verdict.contradiction_summary
            logger.info(
                "precondition gate: %s:%s demoted — %s",
                outcome.file, outcome.function, summary,
            )
            return _demote_outcome(
                outcome,
                f"[precondition contradicted: {summary}]",
            )

        for check in verdict.checks:
            logger.debug(
                "precondition %s:%s [%s] %s: %s",
                outcome.file, outcome.function,
                check.check_type, check.verdict, check.evidence,
            )

    except Exception:
        logger.debug(
            "precondition check failed for %s:%s",
            outcome.file, outcome.function, exc_info=True,
        )

    return outcome


def _sweep_validate(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    sarif_cache: Optional[SarifCache] = None,
    tier_counters: Optional[Dict[str, "TierCounters"]] = None,
    evidence_index: Optional[Dict[str, "EvidenceRecord"]] = None,
    joern_server=None,
) -> ReviewOutcome:
    """Post-LLM sweep validation: run mechanical checks on LLM findings.

    When the LLM says status=finding, attempt to validate the hypothesis
    with a mechanical tool before emitting. This is the G2 [TOOL-GROUNDED]
    gate enforced programmatically.

    Validation chain:
      1. If tool-confirmed evidence already present → pass through
      2. No hypothesis at all → demote to suspicious
      3. Run prefilter regex patterns on the source
      4. Run tool chain (Semgrep → SMT → Coccinelle → CodeQL) with fallback
      5. If nothing confirms, keep the finding but flag as ungrounded
    """
    review = outcome.review_result or {}
    hypothesis = review.get("hypothesis") or outcome.hypothesis or ""
    evidence_tool = review.get("evidence_tool") or outcome.evidence_tool or ""

    if _is_tool_confirmed(evidence_tool):
        return outcome

    if not hypothesis:
        logger.info(
            "sweep_validate: %s:%s finding has no hypothesis — demoting to suspicious",
            outcome.file, outcome.function,
        )
        return _demote_outcome(
            outcome,
            "[sweep validation: finding demoted — no testable hypothesis]",
        )

    source = _read_raw_source(
        config.target_path, outcome.file, outcome.line, None,
    )
    pf = run_prefilter(
        target_path=config.target_path,
        file_path=outcome.file,
        function_name=outcome.function,
        source=source,
        line_start=outcome.line,
    )

    if pf.hits:
        return _stamp_evidence(outcome, f"prefilter:{pf.hits[0].rule_id}")

    cwe = (outcome.review_result or {}).get("cwe_class") or (outcome.review_result or {}).get("cwe") or ""
    chain = _hypothesis_to_tool_chain(hypothesis, outcome.file, cwe=cwe)
    dispatched = {step.get("type") for step in chain if step.get("type")}
    confirmed = _run_tool_chain(
        chain,
        config=config,
        file_path=outcome.file,
        function_name=outcome.function,
        source=source,
        hypothesis=hypothesis,
        line_start=outcome.line,
        sarif_cache=sarif_cache,
        tier_counters=tier_counters,
        evidence_index=evidence_index,
        joern_server=joern_server,
    )

    outcome.tools_dispatched = dispatched
    if confirmed:
        tool_label = "+".join(confirmed)
        return _stamp_evidence(outcome, tool_label)

    # CodeQL bespoke dataflow validation (when LLM claims a source→sink
    # flow and no standard tool confirmed it)
    if config.codeql_db_path and "codeql" not in dispatched:
        try:
            from .codeql_validation import (
                extract_claims_from_review,
                validate_dataflow_claim,
            )
            claims = extract_claims_from_review(outcome.review_result or {})
            for claim in claims:
                vr = validate_dataflow_claim(
                    claim, db_path=Path(config.codeql_db_path),
                )
                if vr.confirmed:
                    return _stamp_evidence(outcome, "codeql:dataflow")
                if tier_counters:
                    label = "confirmed" if vr.confirmed else "refuted"
                    _increment_tier_dict(tier_counters, "codeql", label)
        except Exception:
            logger.debug(
                "codeql_validation failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )

    return outcome


def _run_clean_check_sweep(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    joern_server=None,
) -> Optional[str]:
    """Run a focused tool sweep for a clean verdict.

    Checks the evidence index for any flows the LLM may have missed.
    Returns a text description of discovered flows, or None.
    """
    key = f"{outcome.file}:{outcome.function}"

    if evidence_index:
        rec = evidence_index.get(key)
        if rec:
            parts = []
            flows = rec.all_joern_flows() if hasattr(rec, "all_joern_flows") else []
            for flow in flows[:3]:
                src = getattr(flow, "source_param", "?")
                sink = getattr(flow, "sink_call", "?")
                parts.append(
                    f"- Joern CPG: parameter `{src}` flows to `{sink}()`"
                )
            approx = getattr(rec, "taint_approx", None)
            if approx and getattr(approx, "dangerous_flows", None):
                params = getattr(approx, "params", [])
                for pidx, sinks in approx.dangerous_flows.items():
                    pname = params[pidx] if pidx < len(params) else f"arg{pidx}"
                    for sink_name, _ in sinks[:2]:
                        parts.append(
                            f"- Taint approx: `{pname}` flows to `{sink_name}()`"
                        )
            alerts = getattr(rec, "codeql_alerts", None)
            if alerts:
                for a in alerts[:3]:
                    rule = a.get("rule_id", "?")
                    line = a.get("line", "?")
                    parts.append(f"- CodeQL alert: {rule} at line {line}")
            semgrep = getattr(rec, "semgrep_hits", None)
            if semgrep:
                for h in semgrep[:3]:
                    rule = h.get("rule_id", "?")
                    parts.append(f"- Semgrep match: {rule}")

            if parts:
                return "\n".join(parts)

    return None


def _proactive_validate(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    dispatched_tools: Optional[set] = None,
    tier_counters: Optional[Dict[str, "TierCounters"]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    flow_traces: Optional[List[Dict[str, Any]]] = None,
    joern_server=None,
) -> ReviewOutcome:
    """Step 1e': proactive tool validation for findings/suspicious.

    Fires unconditionally — the LLM doesn't need to request tools.
    Uses CWE_TO_TOOL_DISPATCH to determine which tools apply.
    Skips tools already dispatched in step 1e.
    """
    if outcome.status not in ("finding", "suspicious"):
        return outcome

    review = outcome.review_result or {}
    cwe = review.get("cwe_class") or review.get("cwe") or ""
    if not cwe:
        return outcome

    dispatched = dispatched_tools or set()

    try:
        from .cwe_dispatch import (
            joern_applicable,
            sinks_for_cwe,
            smt_verb_for_cwe,
        )
    except ImportError:
        return outcome

    evidence_tool = review.get("evidence_tool") or outcome.evidence_tool or ""
    if _is_tool_confirmed(evidence_tool):
        return outcome

    confirmed_tools = []

    smt_verb = smt_verb_for_cwe(cwe)
    if smt_verb and "smt" not in dispatched:
        try:
            source_text = ""
            try:
                src_path = config.target_path / outcome.file
                if src_path.is_file():
                    source_text = src_path.read_text(errors="replace")
            except OSError:
                pass
            smt_result = run_smt_verb_direct(
                verb=smt_verb,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source_text,
                hypothesis=outcome.hypothesis or "",
            )
            if smt_result.outcome == "confirmed":
                confirmed_tools.append(f"smt:{smt_verb}")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "smt", "confirmed")
            elif tier_counters:
                _increment_tier_dict(tier_counters, "smt", "refuted")
        except Exception:
            logger.debug("proactive SMT failed for %s", cwe, exc_info=True)
            if tier_counters:
                _increment_tier_dict(tier_counters, "smt", "errors")

    if joern_applicable(cwe) and "joern" not in dispatched:
        sinks = sinks_for_cwe(cwe)
        pre_hit = False
        if sinks and evidence_index:
            key = f"{outcome.file}:{outcome.function}"
            rec = evidence_index.get(key)
            if rec and rec.all_joern_flows():
                confirmed_tools.append("joern:pre_sweep")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "confirmed")
                pre_hit = True

        if not pre_hit and sinks and joern_server is not None:
            live_hits = _joern_live_query(
                joern_server, outcome.function, sinks,
            )
            if live_hits:
                confirmed_tools.append("joern:live")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "confirmed")
            elif tier_counters:
                _increment_tier_dict(tier_counters, "joern", "refuted")

    if "codeql" not in dispatched and config.codeql_db_path:
        sinks = sinks_for_cwe(cwe)
        if sinks:
            try:
                from .sweep import run_codeql_sweep
                for sink in sinks[:2]:
                    codeql_result = run_codeql_sweep(
                        target_path=config.target_path,
                        file_path=outcome.file,
                        function_name=outcome.function,
                        query_path=f"cwe-{cwe.lower()}-{sink}",
                        database_path=config.codeql_db_path,
                        line_start=outcome.line,
                        line_end=outcome.line + 50 if outcome.line else 0,
                    )
                    if codeql_result.outcome == "confirmed":
                        confirmed_tools.append(f"codeql:{sink}")
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "codeql", "confirmed")
                        break
                    elif codeql_result.outcome == "error":
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "codeql", "errors")
                    elif tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "refuted")
            except Exception:
                logger.debug("proactive CodeQL failed for %s", cwe, exc_info=True)
                if tier_counters:
                    _increment_tier_dict(tier_counters, "codeql", "errors")

    is_c_target = outcome.file.endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"))
    if "coccinelle" not in dispatched and is_c_target:
        mechanism = review.get("mechanism") or ""
        cocci_rule = _hypothesis_to_cocci_check(mechanism) if mechanism else None
        if cocci_rule:
            try:
                cocci_result = run_consistency_check(
                    target_path=config.target_path,
                    function_name=outcome.function,
                    cocci_rule=cocci_rule,
                )
                if cocci_result.outcome == "confirmed":
                    confirmed_tools.append(f"coccinelle:{Path(cocci_rule).stem}")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "coccinelle", "confirmed")
                    if discovered_evidence and cocci_result.matches:
                        for match in cocci_result.matches:
                            m_file = match.get("file", "")
                            m_func = match.get("function", "")
                            if m_file and m_func:
                                _inject_discovered_evidence(
                                    discovered_evidence, m_file, m_func,
                                    "coccinelle",
                                    f"consistency violation at {m_file}:{match.get('line', '?')}",
                                )
                elif cocci_result.outcome == "error":
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "coccinelle", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "coccinelle", "refuted")
            except Exception:
                logger.debug("proactive Coccinelle failed for %s", cwe, exc_info=True)
                if tier_counters:
                    _increment_tier_dict(tier_counters, "coccinelle", "errors")

    # Path feasibility: check whether flow trace conditions are jointly
    # satisfiable (strengthens or refutes the finding's reachability claim)
    if flow_traces:
        try:
            from .path_feasibility import (
                check_path_feasibility,
                extract_conditions_from_flow_trace,
                extract_conditions_from_hypothesis,
            )
            all_conditions = []
            for trace in flow_traces:
                trace_file = trace.get("entry_point", {}).get("file", "")
                if trace_file == outcome.file or not trace_file:
                    all_conditions.extend(
                        extract_conditions_from_flow_trace(trace)
                    )
            if outcome.hypothesis:
                all_conditions.extend(
                    extract_conditions_from_hypothesis(outcome.hypothesis)
                )
            if all_conditions:
                feas = check_path_feasibility(all_conditions)
                if feas.feasible is True:
                    confirmed_tools.append("smt:path-feasible")
                elif feas.feasible is False:
                    logger.info(
                        "path infeasible for %s:%s — demoting",
                        outcome.file, outcome.function,
                    )
                    return _demote_outcome(
                        outcome,
                        "[path feasibility: conditions unsatisfiable]",
                    )
        except Exception:
            logger.debug(
                "path_feasibility failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )

    # Lifecycle-precondition check: detect context-drift bugs where a
    # state field is read without the guard that held at write time
    try:
        from core.analysis.lifecycle_audit_integration import (
            check_lifecycle_at_function,
            format_lifecycle_evidence,
        )
        source_text = ""
        try:
            src_path = config.target_path / outcome.file
            if src_path.is_file():
                source_text = src_path.read_text(errors="replace")
        except OSError:
            pass
        lc_findings = check_lifecycle_at_function(
            file_path=outcome.file,
            function_name=outcome.function,
            source=source_text,
            out_dir=config.out_dir,
        )
        if lc_findings:
            confirmed_tools.append("lifecycle")
            if tier_counters:
                _increment_tier_dict(tier_counters, "lifecycle", "confirmed")
            if discovered_evidence:
                evidence_text = format_lifecycle_evidence(lc_findings)
                if evidence_text:
                    _inject_discovered_evidence(
                        discovered_evidence, outcome.file, outcome.function,
                        "lifecycle", evidence_text,
                    )
    except ImportError:
        pass
    except Exception:
        logger.debug(
            "lifecycle check failed for %s:%s",
            outcome.file, outcome.function, exc_info=True,
        )

    if confirmed_tools:
        tool_label = "+".join(confirmed_tools)
        return _stamp_evidence(outcome, tool_label)

    return outcome


def _auto_synthesize_rules(
    result: OrchestratorResult,
    config: OrchestratorConfig,
) -> None:
    """Auto-synthesis: generate codebase-wide rules from confirmed findings.

    When >= 2 confirmed findings share the same CWE + mechanism, synthesize
    a checker rule and sweep the codebase for additional instances.
    Uses the same LLM-backed synthesis + tool selection as mid-loop.
    """
    from collections import Counter

    from .checker_synthesis import synthesize_and_sweep

    findings = [o for o in result.outcomes if o.status == "finding"]
    if len(findings) < 2:
        return

    cwe_mechanism_counts: Counter = Counter()
    cwe_mechanism_findings: Dict[str, List[ReviewOutcome]] = {}

    for f in findings:
        review = f.review_result or {}
        cwe = review.get("cwe_class") or review.get("cwe") or ""
        mechanism = review.get("mechanism") or ""
        if not cwe:
            continue
        key = f"{cwe}:{mechanism}" if mechanism else cwe
        cwe_mechanism_counts[key] += 1
        cwe_mechanism_findings.setdefault(key, []).append(f)

    seen_keys = {f"{o.file}:{o.function}" for o in result.outcomes}
    synthesis_count = 0

    for key, count in cwe_mechanism_counts.items():
        if count < 2:
            continue

        exemplars = cwe_mechanism_findings[key]
        synth = synthesize_and_sweep(
            exemplars[0], config, seen_keys,
            synthesis_count=synthesis_count,
        )
        if not synth:
            continue
        synthesis_count += 1
        logger.info(
            "auto-synthesized rule %s (%s) from %d %s findings, %d new hits",
            synth.rule_id, synth.tool, count, key, len(synth.hits),
        )



def _run_critique(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    sarif_cache: Optional[SarifCache] = None,
    joern_server=None,
) -> None:
    """Periodic tool-grounded re-evaluation of recent findings.

    Checks that findings still have valid tool evidence, and that
    suspicious items haven't gained new tool evidence since emission.
    Runs every critique_interval functions.
    """
    recent_findings = [
        o for o in result.outcomes[-config.critique_interval:]
        if o.status == "finding"
    ]

    for outcome in recent_findings:
        if not _is_tool_confirmed(outcome.evidence_tool):
            source = _read_raw_source(
                config.target_path, outcome.file, outcome.line, None,
            )
            pf = run_prefilter(
                target_path=config.target_path,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source,
                line_start=outcome.line,
            )
            if pf.hits:
                outcome.evidence_tool = f"critique:prefilter:{pf.hits[0].rule_id}"
                logger.info(
                    "critique: %s:%s gained evidence via %s",
                    outcome.file, outcome.function, outcome.evidence_tool,
                )

    recent_suspicious = [
        o for o in result.outcomes[-config.critique_interval:]
        if o.status == "suspicious" and o.hypothesis
    ]

    for outcome in recent_suspicious:
        if _has_refuting_counter(outcome):
            continue
        cwe = (outcome.review_result or {}).get("cwe_class") or (outcome.review_result or {}).get("cwe") or ""
        chain = _hypothesis_to_tool_chain(outcome.hypothesis, outcome.file, cwe=cwe)
        if not chain:
            continue
        source = _read_raw_source(
            config.target_path, outcome.file, outcome.line, None,
        )
        confirmed = _run_tool_chain(
            chain,
            config=config,
            file_path=outcome.file,
            function_name=outcome.function,
            source=source,
            hypothesis=outcome.hypothesis,
            line_start=outcome.line,
            sarif_cache=sarif_cache,
            tier_counters=result.tier_counters,
            joern_server=joern_server,
        )
        if confirmed:
            tool = "+".join(confirmed)
            idx = result.outcomes.index(outcome)
            result.outcomes[idx] = _promote_outcome(outcome, f"critique:{tool}")
            result.sweep_promoted += 1
            result.suspicious -= 1
            result.findings += 1
            logger.info(
                "critique: promoted %s:%s via %s",
                outcome.file, outcome.function, tool,
            )

    recent_clean = [
        o for o in result.outcomes[-config.critique_interval:]
        if o.status == "clean" and o.review_result
    ]
    for outcome in recent_clean:
        tool_evidence = (outcome.review_result or {}).get("tool_evidence", [])
        if not tool_evidence:
            continue
        for ev in tool_evidence:
            tool_name = ev.get("tool", "")
            rule_id = ev.get("rule_id", "")
            if tool_name and rule_id:
                new_hyp = f"Tool {tool_name} ({rule_id}) found something but was dismissed — recheck"
                chain = _hypothesis_to_tool_chain(new_hyp, outcome.file, cwe="")
                if chain:
                    source = _read_raw_source(
                        config.target_path, outcome.file, outcome.line, None,
                    )
                    confirmed = _run_tool_chain(
                        chain,
                        config=config,
                        file_path=outcome.file,
                        function_name=outcome.function,
                        source=source,
                        hypothesis=new_hyp,
                        line_start=outcome.line,
                        sarif_cache=sarif_cache,
                        tier_counters=result.tier_counters,
                        joern_server=joern_server,
                    )
                    if confirmed:
                        logger.info(
                            "critique: clean %s:%s has unresolved tool evidence from %s",
                            outcome.file, outcome.function, tool_name,
                        )
                    break


_MIN_SLOC_FOR_DEEPEN = 20


def _deepen_suspicious(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    fuzz_coverage: Optional[Dict[str, Any]],
    session_observations: List[Dict[str, str]],
    sarif_cache: Optional[Any],
    entry_points: set,
    start_time: float,
    on_progress: Optional[Callable],
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    audit_log: Optional[List[Dict[str, Any]]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    joern_server=None,
    project_learnings: Optional[List[Dict[str, str]]] = None,
) -> OrchestratorResult:
    """Re-review suspicious verdicts with enriched context.

    After the main pass, functions flagged as suspicious get a second
    look with: the accumulated session observations, their prior
    verdict, and an explicit prompt to try an alternative hypothesis.
    Only deepens functions above a minimum SLOC — tiny wrappers rarely
    sharpen on a second pass.
    """
    suspicious = [
        o for o in result.outcomes
        if o.status == "suspicious"
        and (o.review_result or {}).get("body")
        and not o.body.startswith("[gate violation:")
    ]
    if not suspicious:
        return result

    seen_hypotheses: Dict[str, str] = {}
    targets = []
    for o in suspicious:
        gap = _find_gap_in_checklist(checklist, o.file, o.function)
        if not gap:
            continue
        sloc = (gap.get("line_end", 0) or 0) - (gap.get("line_start", 0) or 0)
        has_evidence = bool(
            o.evidence_tool
            or (o.review_result or {}).get("tool_evidence")
        )
        key = f"{o.file}:{o.function}"
        hyp = (o.hypothesis or "").strip()[:200]
        if key in seen_hypotheses and hyp and hyp == seen_hypotheses[key]:
            continue
        if hyp:
            seen_hypotheses[key] = hyp
        if sloc < _MIN_SLOC_FOR_DEEPEN and not has_evidence:
            continue
        targets.append((o, gap))

    if not targets:
        return result

    logger.info(
        "deepen: %d suspicious verdicts to re-review", len(targets),
    )

    # Track outcomes to remove by identity so we can filter in one
    # pass after the loop instead of O(n) list.remove() per iteration.
    _outcomes_to_remove: set = set()

    for deepen_idx, (prior_outcome, gap) in enumerate(targets, 1):
        if _check_budget(config, start_time, result):
            break

        ctx = _build_context(
            config, gap, checklist, context_map, evidence_index,
            discovered_evidence=discovered_evidence,
        )
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage, gap["file"], gap["name"],
            )

        if config.enable_session_context and session_observations:
            ctx["session_observations"] = list(session_observations)
        if project_learnings:
            ctx["project_context"] = project_learnings

        if config.blind_first_pass:
            ctx["prior_verdict"] = {}
            if prior_outcome.hypothesis:
                ctx["prior_verdict"]["hypothesis"] = prior_outcome.hypothesis
        else:
            ctx["prior_verdict"] = {
                "status": prior_outcome.status,
                "body": prior_outcome.body,
            }
            if prior_outcome.hypothesis:
                ctx["prior_verdict"]["hypothesis"] = prior_outcome.hypothesis

        ctx["deepen"] = True

        try:
            outcome = review_fn(ctx, config)
        except Exception as exc:
            logger.warning(
                "deepen failed for %s:%s: %s",
                gap["file"], gap["name"], exc,
            )
            continue

        outcome.line = gap.get("line_start", 0)

        if outcome.status in ("finding", "suspicious"):
            if outcome.status == "finding":
                if config.sweep_validate_findings:
                    outcome = _sweep_validate(
                        outcome, config, sarif_cache,
                        tier_counters=result.tier_counters,
                        evidence_index=evidence_index,
                        joern_server=joern_server,
                    )
                if outcome.status == "finding":
                    outcome = _apply_reachability_gate(
                        outcome, ctx, entry_points, config,
                    )
                if outcome.status == "finding":
                    gate_violations = _check_finding_gates(
                        outcome, audit_log=audit_log,
                    )
                    if gate_violations:
                        for v in gate_violations:
                            logger.warning(
                                "gate violation %s:%s: %s — demoted to suspicious",
                                outcome.file, outcome.function, v,
                            )
                        outcome = _demote_outcome(
                            outcome,
                            f"[gate violation: {'; '.join(gate_violations)}]",
                        )

            _untally_outcome(result, prior_outcome)
            _outcomes_to_remove.add(id(prior_outcome))

            try:
                _commit_outcome(config, outcome, gap)
            except Exception as exc:
                logger.warning(
                    "commit failed for %s:%s: %s",
                    gap["file"], gap["name"], exc, exc_info=True,
                )

            _tally_outcome(result, outcome)

            if config.enable_session_context and outcome.review_result:
                _accumulate_observations(
                    session_observations, outcome, gap,
                    sweep_pre_status=prior_outcome.status,
                )

            logger.info(
                "deepen [%d/%d] %s:%s: %s -> %s",
                deepen_idx, len(targets),
                gap["file"], gap["name"],
                prior_outcome.status, outcome.status,
            )
        else:
            logger.info(
                "deepen [%d/%d] %s:%s: stayed %s",
                deepen_idx, len(targets),
                gap["file"], gap["name"], prior_outcome.status,
            )

    if _outcomes_to_remove:
        result.outcomes = [
            o for o in result.outcomes if id(o) not in _outcomes_to_remove
        ]

    return result


def _iterative_re_review(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    fuzz_coverage: Optional[Dict[str, Any]],
    entry_points: set,
    constraints: list,
    prop_config: Any,
    sarif_cache: Optional[SarifCache],
    start_time: float,
    on_progress: Optional[Callable],
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    audit_log: Optional[List[Dict[str, Any]]] = None,
    session_observations: Optional[List[Dict[str, str]]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    joern_server=None,
) -> OrchestratorResult:
    """Re-review callers of findings with propagated knowledge.

    After the initial pass, functions reviewed as clean might be
    vulnerable given knowledge about their callees discovered later.
    Each iteration re-reviews only callers of new findings from the
    previous iteration, injecting the callee finding as context.
    Converges when no new findings emerge.
    """
    if not config.propagate_constraints:
        return result

    reviewed_outcomes = {
        f"{o.file}:{o.function}": o for o in result.outcomes
    }

    MAX_RE_REVIEW_ITERATIONS = 5
    untallied_ids: set = set()
    iteration = 0
    logger.info("_iterative_re_review: entering loop, %d outcomes total", len(result.outcomes))
    while True:
        iteration += 1
        if iteration > MAX_RE_REVIEW_ITERATIONS:
            logger.warning(
                "re-review hit iteration cap (%d); stopping propagation",
                MAX_RE_REVIEW_ITERATIONS,
            )
            break
        new_findings = [
            o for o in result.outcomes
            if o.status in ("finding", "suspicious")
            and not getattr(o, "_propagated", False)
        ]
        logger.info(
            "_iterative_re_review: iteration %d, %d unpropagated findings/suspicious",
            iteration, len(new_findings),
        )
        if not new_findings:
            break

        for o in new_findings:
            o._propagated = True

        logger.info("_iterative_re_review: calling _find_re_review_targets")
        re_review_targets = _find_re_review_targets(
            new_findings, config, checklist, context_map, reviewed_outcomes,
        )
        logger.info("_iterative_re_review: got %d re-review targets", len(re_review_targets))

        if not re_review_targets:
            break

        if _check_budget(config, start_time, result):
            break

        logger.info(
            "re-review iteration %d: %d callers of %d findings",
            iteration, len(re_review_targets), len(new_findings),
        )

        for target in re_review_targets:
            if _check_budget(config, start_time, result):
                break

            gap = target["gap"]
            callee_findings = target["callee_findings"]

            ctx = _build_context(
                config, gap, checklist, context_map, evidence_index,
                discovered_evidence=discovered_evidence,
            )
            if fuzz_coverage:
                ctx["fuzz_coverage"] = _fuzz_coverage_for(
                    fuzz_coverage, gap["file"], gap["name"],
                )

            callee_ctx = []
            for f in callee_findings:
                entry = {
                    "file": f.file,
                    "function": f.function,
                    "hypothesis": f.hypothesis,
                    "body": f.body[:500],
                }
                if evidence_index:
                    callee_key = f"{f.file}:{f.function}"
                    callee_ev = evidence_index.get(callee_key)
                    if callee_ev and callee_ev.has_any_evidence():
                        entry["mechanical_evidence"] = format_evidence_prose(
                            callee_ev,
                        )
                callee_ctx.append(entry)
            ctx["callee_findings"] = callee_ctx

            old_key = f"{gap['file']}:{gap['name']}"
            prior = reviewed_outcomes.get(old_key)
            if prior:
                ctx["prior_verdict"] = {
                    "status": prior.status,
                    "body": prior.body,
                }

            try:
                outcome = review_fn(ctx, config)
            except _ContentFilterError:
                outcome = ReviewOutcome(
                    file=gap["file"],
                    function=gap["name"],
                    status="error",
                    body="blocked by content filter",
                )
            except Exception as exc:
                logger.warning(
                    "re-review failed for %s:%s: %s",
                    gap["file"], gap["name"], exc,
                )
                outcome = _error_outcome(gap, exc)

            outcome.line = gap.get("line_start", 0)

            if outcome.status == "finding" and config.sweep_validate_findings:
                outcome = _sweep_validate(
                    outcome, config, sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
                if outcome.status == "finding":
                    result.sweep_validated += 1
                else:
                    result.sweep_demoted += 1

            if outcome.status == "finding":
                outcome = _apply_reachability_gate(
                    outcome, ctx, entry_points, config,
                )

            if outcome.status == "finding":
                gate_violations = _check_finding_gates(
                    outcome, audit_log=audit_log,
                )
                if gate_violations:
                    outcome = _demote_outcome(
                        outcome,
                        f"[gate violation: {'; '.join(gate_violations)}]",
                    )

            try:
                _commit_outcome(config, outcome, gap)
            except Exception:
                logger.warning(
                    "commit failed for %s:%s",
                    gap["file"], gap["name"], exc_info=True,
                )

            if config.propagate_constraints and outcome.review_result:
                constraints = _extract_and_propagate(
                    outcome, constraints, checklist, entry_points,
                    prop_config, tier_counters=result.tier_counters,
                )

            old_key = f"{gap['file']}:{gap['name']}"
            old_outcome = reviewed_outcomes.get(old_key)
            if old_outcome and old_outcome in result.outcomes:
                idx = result.outcomes.index(old_outcome)
                if id(old_outcome) not in untallied_ids:
                    _untally_outcome(result, old_outcome)
                    untallied_ids.add(id(old_outcome))
                result.outcomes[idx] = outcome
                _tally_outcome(result, outcome, append=False)
            else:
                _tally_outcome(result, outcome)
            reviewed_outcomes[old_key] = outcome

            if config.enable_session_context and session_observations is not None and outcome.review_result:
                pre_status = old_outcome.status if old_outcome else None
                _accumulate_observations(
                    session_observations, outcome, gap,
                    sweep_pre_status=pre_status,
                )

            if on_progress:
                on_progress(result.reviewed, result.reviewed, outcome)

    if config.propagate_constraints and constraints:
        save_constraints(constraints, config.out_dir)

    return result


def _find_re_review_targets(
    findings: List[ReviewOutcome],
    config: OrchestratorConfig,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    reviewed_outcomes: Dict[str, ReviewOutcome],
) -> List[Dict[str, Any]]:
    """Find functions to re-review based on findings from the previous pass.

    Returns a list of dicts with 'gap' (checklist item) and
    'callee_findings' (the findings that triggered re-review).
    """
    targets: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        callers = _find_callers_from_inventory(
            config, finding.file, finding.function,
            finding.line, context_map,
        )
        for caller in callers:
            key = f"{caller['file']}:{caller['name']}"
            prior = reviewed_outcomes.get(key)
            if not prior or prior.status != "clean":
                continue

            if key not in targets:
                gap = _find_gap_in_checklist(
                    checklist, caller["file"], caller["name"],
                )
                if not gap:
                    continue
                targets[key] = {
                    "gap": gap,
                    "callee_findings": [],
                }
            targets[key]["callee_findings"].append(finding)

    return list(targets.values())


def _find_callers_from_inventory(
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    line: int,
    context_map: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Find 1-hop callers using the same logic as context._find_callers."""
    callers: List[Dict[str, Any]] = []
    if config.inventory:
        try:
            from core.analysis.reachability import (
                InternalFunction,
                callers_of,
            )
            target = InternalFunction(
                file_path=file_path, name=function_name, line=line,
            )
            result = callers_of(config.inventory, target, exclude_test_files=True)
            callers = [
                {"file": c.file_path, "name": c.name, "line_start": c.line}
                for c in result.all_callers
            ]
        except Exception:
            logger.warning(
                "inventory caller lookup failed for %s:%s",
                file_path, function_name, exc_info=True,
            )

    if context_map and not callers:
        seen = set()
        for edge in context_map.get("call_edges", []):
            if edge.get("callee") == function_name:
                ck = (edge.get("caller_file", ""), edge.get("caller", ""))
                if ck not in seen:
                    seen.add(ck)
                    callers.append({
                        "file": edge.get("caller_file", ""),
                        "name": edge.get("caller", ""),
                        "line_start": 0,
                    })
    return callers


def _find_gap_in_checklist(
    checklist: Dict[str, Any],
    file_path: str,
    function_name: str,
) -> Optional[Dict[str, Any]]:
    """Find a checklist item by file + function name."""
    for file_info in checklist.get("files", []):
        if file_info.get("path") != file_path:
            continue
        for item in file_info.get("items", file_info.get("functions", [])):
            if item.get("name") == function_name:
                return {
                    "file": file_path,
                    "name": function_name,
                    "line_start": item.get("line_start", 0),
                    "line_end": item.get("line_end"),
                }
    return None


def _untally_outcome(result: OrchestratorResult, outcome: ReviewOutcome) -> None:
    """Reverse a previously tallied outcome."""
    if outcome.status == "finding":
        result.findings -= 1
    elif outcome.status == "suspicious":
        result.suspicious -= 1
    elif outcome.status == "clean":
        result.clean -= 1
    elif outcome.status == "dormant":
        result.dormant -= 1
    elif outcome.status == "dark":
        result.dormant -= 1
    elif outcome.status == "error":
        result.errors -= 1
        if outcome.error_class and outcome.error_class in result.error_counts:
            result.error_counts[outcome.error_class] -= 1
    result.reviewed -= 1
    result.total_cost_usd -= outcome.cost_usd


_DISMISSIVE_COUNTERS = frozenset({
    "no plausible", "cannot construct", "no realistic",
    "no viable", "function is safe", "no vulnerability",
    "none", "n/a", "not applicable",
})


def _has_refuting_counter(outcome: ReviewOutcome) -> bool:
    """Check if any active hypothesis has a specific counter-argument.

    When the LLM marks a function as suspicious and provides a specific
    reason why the hypothesis does not reach finding level (e.g. "only
    exploitable if multi-threaded", "callers check the return value"),
    mechanical tools that match syntactic patterns should not override
    that judgment — they cannot reason about the architectural
    constraint the LLM identified.
    """
    hypotheses = (outcome.review_result or {}).get("hypotheses") or []
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        if h.get("confidence") == "refuted":
            continue
        counter = h.get("counter", "")
        if not counter or len(counter) < 20:
            continue
        lower = counter.lower().strip()
        if any(d in lower for d in _DISMISSIVE_COUNTERS):
            continue
        return True
    return False


_sink_guard_cache: Dict[str, str] = {}


def _check_sink_guarded_cached(function_name: str, joern_server) -> str:
    """Cache-wrapped sink guard check to avoid redundant Joern queries."""
    if function_name in _sink_guard_cache:
        return _sink_guard_cache[function_name]
    verdict = check_sink_guarded(function_name, joern_server)
    _sink_guard_cache[function_name] = verdict
    return verdict


def _promote_suspicious(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    sarif_cache: Optional[SarifCache] = None,
    checklist: Optional[Dict[str, Any]] = None,
    joern_server=None,
) -> None:
    """Post-loop pass: try sweep tools on suspicious items with hypotheses.

    If a mechanical tool confirms the hypothesis, promote to finding.
    Uses the tool chain with fallback — if the first-choice tool is
    unavailable or errors, the next tool in the chain is tried.
    Mutates result.outcomes in place and adjusts counters.
    No LLM calls — purely mechanical.

    Skips promotion when the LLM provided a specific counter-hypothesis
    explaining why the function should stay suspicious — syntactic tools
    cannot refute architectural constraints like threading models or
    caller-side bounds checks.
    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "suspicious":
            continue

        if outcome.body.startswith((
            "[sink-unreachability:",
            "[guarded-sink:", "[smt-infeasible:",
            "[entry-unreachability:", "[self-contradiction:",
        )) or (
            outcome.body.startswith("[gate violation:")
            and not _is_evidence_only_gate_demotion(outcome.body)
        ):
            logger.debug(
                "sweep skipped %s:%s — mechanical gate demotion is authoritative",
                outcome.file, outcome.function,
            )
            continue

        review = outcome.review_result or {}
        hypothesis = review.get("hypothesis") or outcome.hypothesis or ""
        if not hypothesis:
            continue

        if _has_refuting_counter(outcome):
            logger.debug(
                "sweep skipped %s:%s — LLM counter-hypothesis present",
                outcome.file, outcome.function,
            )
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path, outcome.file, outcome.line, line_end,
        )

        pf = run_prefilter(
            target_path=config.target_path,
            file_path=outcome.file,
            function_name=outcome.function,
            source=source,
            line_start=outcome.line,
        )
        if pf.hits:
            if line_end:
                pf.hits = [
                    h for h in pf.hits
                    if not h.line or outcome.line <= h.line <= line_end
                ]
            if pf.hits:
                tool = f"prefilter:{pf.hits[0].rule_id}"
                result.outcomes[i] = _promote_outcome(outcome, tool)
                result.sweep_promoted += 1
                result.suspicious -= 1
                result.findings += 1
                logger.info(
                    "sweep promoted %s:%s via %s",
                    outcome.file, outcome.function, tool,
                )
                continue

        cwe = (outcome.review_result or {}).get("cwe_class") or (outcome.review_result or {}).get("cwe") or ""
        chain = _hypothesis_to_tool_chain(hypothesis, outcome.file, cwe=cwe)
        confirmed = _run_tool_chain(
            chain,
            config=config,
            file_path=outcome.file,
            function_name=outcome.function,
            source=source,
            hypothesis=hypothesis,
            line_start=outcome.line,
            sarif_cache=sarif_cache,
            tier_counters=result.tier_counters,
            joern_server=joern_server,
        )

        if confirmed:
            if _check_sink_guarded_cached(outcome.function, joern_server) == "guarded":
                logger.info(
                    "sweep promotion blocked %s:%s via %s — all sink calls guarded",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue
            tool = "+".join(confirmed)
            result.outcomes[i] = _promote_outcome(outcome, tool)
            result.sweep_promoted += 1
            result.suspicious -= 1
            result.findings += 1
            logger.info(
                "sweep promoted %s:%s via %s",
                outcome.file, outcome.function, tool,
            )


def _promote_outcome(outcome: ReviewOutcome, tool: str) -> ReviewOutcome:
    """Promote a suspicious item to finding with tool evidence."""
    promoted = ReviewOutcome(
        file=outcome.file,
        function=outcome.function,
        status="finding",
        body=f"[sweep promoted via {tool}]\n\n{outcome.body}",
        hypothesis=outcome.hypothesis,
        hypotheses=outcome.hypotheses,
        evidence_tool=tool,
        cost_usd=outcome.cost_usd,
        model=outcome.model,
        duration_s=outcome.duration_s,
        review_result=outcome.review_result,
        line=outcome.line,
    )
    if promoted.review_result:
        promoted.review_result["evidence_tool"] = tool
    return promoted


_GATE_DEMOTED_PREFIXES = (
    "[gate violation:",
    "[self-contradiction:",
)

_STRUCTURAL_PREFILTER_RULES = frozenset({
    "post-loop-oob-write",
})


def _resolve_gate_demoted(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    sarif_cache: Optional[SarifCache] = None,
    checklist: Optional[Dict[str, Any]] = None,
    *,
    domain_model: Optional[Dict[str, Any]] = None,
    available_tools: Optional[Dict[str, bool]] = None,
) -> None:
    """Resolve gate-demoted suspicious outcomes.

    Gate demotions (G2 no-evidence, self-contradiction) catch LLM
    hallucinations.  But they leave the outcome as "suspicious" with no
    path to resolution — deepen and sweep both skip them.

    This pass checks whether ANY mechanical tool independently flags the
    same function.  If nothing corroborates the LLM's retracted claim:
    - If the vulnerability class IS tool-covered → resolved to clean
      (a tool could have found it but didn't — disconfirmed).
    - If the vulnerability class is NOT tool-covered → resolved to dark
      (no tool can detect this class — needs concrete verification).

    No LLM calls.
    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "suspicious":
            continue
        if not outcome.body.startswith(_GATE_DEMOTED_PREFIXES):
            continue

        if _has_mechanical_corroboration(outcome, config, sarif_cache, checklist,
                                        domain_model=domain_model):
            logger.debug(
                "gate-demoted %s:%s has mechanical corroboration — stays suspicious",
                outcome.file, outcome.function,
            )
            continue

        # Determine if the vulnerability class is tool-covered
        class_covered = True
        if available_tools is not None:
            try:
                from .tool_coverage import is_class_covered
                rr = outcome.review_result or {}
                class_covered = is_class_covered(
                    cwe_field=rr.get("cwe", ""),
                    mechanism=rr.get("mechanism", outcome.hypothesis or ""),
                    hypothesis=outcome.hypothesis or "",
                    available_tools=available_tools,
                )
            except Exception:
                logger.debug("tool_coverage check failed for %s:%s",
                             outcome.file, outcome.function, exc_info=True)

        if class_covered:
            resolved = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="clean",
                body=outcome.body,
                hypothesis=outcome.hypothesis,
                hypotheses=outcome.hypotheses,
                evidence_tool=outcome.evidence_tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )
            result.outcomes[i] = resolved
            result.suspicious -= 1
            result.clean += 1
            logger.info(
                "gate-resolved %s:%s → clean "
                "(no mechanical corroboration, class covered)",
                outcome.file, outcome.function,
            )
        else:
            resolved = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="dark",
                body=outcome.body,
                hypothesis=outcome.hypothesis,
                hypotheses=outcome.hypotheses,
                evidence_tool=outcome.evidence_tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )
            result.outcomes[i] = resolved
            result.suspicious -= 1
            result.dormant += 1
            logger.info(
                "gate-resolved %s:%s → dark "
                "(no mechanical corroboration, class not tool-covered)",
                outcome.file, outcome.function,
            )


def _try_block_level_context(
    gap: Dict[str, Any],
    ctx: Dict[str, Any],
    config: "OrchestratorConfig",
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
) -> Optional[str]:
    """Build block-level analysis context if the function qualifies.

    Returns formatted block context string, or None if the function
    doesn't need block-level review.
    """
    from .block_review import (
        build_block_review_plan,
        format_block_context,
        try_build_cfg,
    )

    full_path = config.target_path / gap["file"]
    try:
        raw_source = full_path.read_text(errors="replace") if full_path.exists() else ""
    except OSError:
        raw_source = ""

    cfg = try_build_cfg(
        gap["file"], gap["name"], config.target_path,
        source=raw_source,
    )
    if cfg is None:
        return None

    taint_approx = None
    if evidence_index:
        key = f"{gap['file']}:{gap['name']}"
        ev = evidence_index.get(key)
        if ev:
            taint_approx = ev.taint_approx

    from .prefilter import detect_language
    lang = detect_language(gap["file"])

    plan = build_block_review_plan(
        cfg,
        file_path=gap["file"],
        function_name=gap["name"],
        taint_approx=taint_approx,
        source=raw_source,
        cwe=gap.get("cwe", ""),
        language=lang,
    )
    if plan is None:
        return None

    logger.info(
        "block-level review for %s:%s (CC=%d, taint_branches=%d, "
        "paths_to_sink=%d, %d interesting blocks)",
        gap["file"], gap["name"],
        plan.profile.cyclomatic_complexity,
        plan.profile.taint_relevant_branches,
        plan.profile.path_to_sink_count,
        len(plan.blocks),
    )

    return format_block_context(plan)


def _constraints_for_function(
    constraints: list,
    file_path: str,
    function_name: str,
) -> List[Dict[str, str]]:
    """Find constraints relevant to a function being reviewed.

    Returns constraints where:
    - The constraint was emitted BY this function (direction=callers →
      callers must satisfy this)
    - The constraint targets this function (direction=callees →
      this function must satisfy what callers expect)
    - A constraint from a callee that this function calls
    """
    relevant = []
    key = f"{file_path}:{function_name}"

    for c in constraints:
        c_key = f"{c.file}:{c.function}"
        if c.status in ("refuted",):
            continue

        if c_key == key:
            relevant.append({
                "source": "self",
                "kind": c.kind,
                "target": c.target,
                "rule": c.rule,
                "violation": c.violation,
                "cwe": c.cwe,
                "direction": c.direction,
                "status": c.status,
            })
        elif c.direction == "callers" and c.function == function_name:
            relevant.append({
                "source": f"callee {c_key}",
                "kind": c.kind,
                "target": c.target,
                "rule": c.rule,
                "violation": c.violation,
                "cwe": c.cwe,
                "direction": c.direction,
                "status": c.status,
            })

    return relevant[:15]


def _review_flow_traces(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    joern_server=None,
    sarif_cache: Optional[SarifCache] = None,
) -> OrchestratorResult:
    """Post-loop pass: review entire source→sink flow traces as a unit.

    Individual function reviews catch per-function bugs. This pass catches
    composition bugs — where no single function is buggy but the combination
    of behaviors across a call chain creates a vulnerability (e.g., missing
    sanitization between a source function and a sink function, each of
    which looks correct in isolation).
    """
    if not config.out_dir:
        return result
    trace_files = sorted(config.out_dir.glob("flow-trace-*.json"))
    if not trace_files:
        return result

    reviewed_keys = {f"{o.file}:{o.function}" for o in result.outcomes}
    clean_keys = {
        f"{o.file}:{o.function}" for o in result.outcomes
        if o.status == "clean"
    }

    import json as _json
    traces_reviewed = 0
    for trace_file in trace_files[:10]:
        try:
            trace = _json.loads(trace_file.read_text())
        except (OSError, _json.JSONDecodeError):
            continue

        hops = trace.get("hops", [])
        source = trace.get("source", {})
        sink = trace.get("sink", {})
        if not hops or not source or not sink:
            continue

        hop_keys = []
        for hop in hops:
            hf = hop.get("file", "")
            hn = hop.get("name", "")
            if hf and hn:
                hop_keys.append(f"{hf}:{hn}")
        sf = source.get("file", "")
        sn = source.get("name", "")
        if sf and sn:
            hop_keys.insert(0, f"{sf}:{sn}")
        skf = sink.get("file", "")
        skn = sink.get("name", "")
        if skf and skn:
            hop_keys.append(f"{skf}:{skn}")

        all_clean = all(k in clean_keys for k in hop_keys if k in reviewed_keys)
        if not all_clean:
            continue

        hop_summaries = []
        for hop in hops:
            summary = {
                "file": hop.get("file", ""),
                "name": hop.get("name", ""),
                "line": hop.get("line", 0),
                "tainted_vars": hop.get("tainted_vars", []),
                "attacker_control": hop.get("attacker_control", ""),
            }
            if evidence_index:
                hkey = f"{hop.get('file', '')}:{hop.get('name', '')}"
                ev = evidence_index.get(hkey)
                if ev and ev.has_any_evidence():
                    summary["has_evidence"] = True
            hop_summaries.append(summary)

        flow_ctx = {
            "file": sf or skf,
            "function": f"flow:{source.get('name', '?')}→{sink.get('name', '?')}",
            "source": source.get("source", ""),
            "flow_trace": trace,
            "flow_hops": hop_summaries,
            "review_mode": "flow",
            "trace_id": trace.get("id", trace_file.stem),
        }

        try:
            outcome = review_fn(flow_ctx, config)
        except Exception as exc:
            logger.debug("flow trace review failed: %s", exc)
            continue

        if outcome.status in ("finding", "suspicious"):
            outcome.file = sf or skf
            outcome.function = f"flow:{source.get('name', '?')}→{sink.get('name', '?')}"
            outcome.line = source.get("line", 0)
            if outcome.status == "finding" and config.sweep_validate_findings:
                outcome = _sweep_validate(
                    outcome, config, sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
            _tally_outcome(result, outcome)
            traces_reviewed += 1
            logger.info(
                "flow-trace review: %s in %s",
                outcome.status, flow_ctx["function"],
            )

    if traces_reviewed:
        logger.info("flow-trace review: %d traces produced findings", traces_reviewed)
    return result


def _persist_findings(
    result: OrchestratorResult,
    config: OrchestratorConfig,
) -> None:
    """Write all findings to findings.json so they survive even without /validate."""
    findings_dicts = []
    for seq, outcome in enumerate(
        (o for o in result.outcomes if o.status == "finding"), start=1,
    ):
        finding: Dict[str, Any] = {
            "id": f"FIND-{seq:03d}",
            "file": outcome.file,
            "function": outcome.function,
            "line": outcome.line or 1,
            "title": outcome.hypothesis or f"Finding in {outcome.function}",
            "description": outcome.body,
            "severity": "medium",
            "source": "audit",
        }
        if outcome.evidence_tool:
            finding["evidence_tool"] = outcome.evidence_tool
        if outcome.hypothesis:
            finding["hypothesis"] = outcome.hypothesis
        findings_dicts.append(finding)

    if findings_dicts:
        write_findings(findings_dicts, config.out_dir)
        logger.info(
            "persisted %d finding(s) to findings.json", len(findings_dicts),
        )


def _persist_project_learnings(
    out_dir: Path,
    session_observations: List[Dict[str, str]],
    result: OrchestratorResult,
) -> None:
    """Save cross-run learnings from this audit to project context.

    Persists tool-confirmed observations as 'pattern' learnings and
    gate-demoted FP patterns as 'suppression' learnings.
    """
    from .project_context import Learning, load_project_context, save_project_context

    ctx = load_project_context(out_dir)
    added = 0

    for obs in session_observations:
        text = obs.get("text", "")
        if not text:
            continue
        source_fn = obs.get("source", "")
        if obs.get("tool_confirmed"):
            learning = Learning(
                text=text,
                category="pattern",
                source="llm",
                file=source_fn.rsplit(":", 1)[0] if ":" in source_fn else "",
                function=source_fn.rsplit(":", 1)[1] if ":" in source_fn else "",
            )
            if ctx.add(learning):
                added += 1

    for outcome in result.outcomes:
        if outcome.status != "suspicious":
            continue
        body = outcome.body or ""
        if "[self-contradiction:" in body or "[sink-unreachability:" in body:
            tag = body.split("[", 1)[1].split("]", 1)[0] if "[" in body else ""
            learning = Learning(
                text=f"Gate demoted {outcome.file}:{outcome.function}: {tag}",
                category="suppression",
                source="llm",
                file=outcome.file,
                function=outcome.function,
            )
            if ctx.add(learning):
                added += 1

    if added:
        try:
            save_project_context(ctx, out_dir)
            logger.info("persisted %d cross-run learnings to project context", added)
        except OSError:
            logger.debug("could not save project context", exc_info=True)


def _is_tool_confirmed(evidence_tool: str) -> bool:
    """Return True if evidence_tool was set by an actual tool run.

    A receipt is ``<namespace>:<detail>`` issued by ``_stamp_evidence``
    after the tool ran (or one of the bare dynamic/Frida tokens). A
    model-supplied value arrives namespaced as ``llm-claimed:…`` and is
    therefore never a receipt — see ``core.audit._util``.

    This is what stops a claimed ``evidence_tool`` from short-circuiting
    mechanical validation in ``_sweep_validate``.
    """
    return is_stamped_tool_evidence(evidence_tool)


def _stamp_evidence(outcome: ReviewOutcome, tool: str) -> ReviewOutcome:
    """Issue a tool receipt onto an outcome.

    This is the *only* way a value that satisfies ``_is_tool_confirmed``
    is created, and callers must have run the tool first. A label that
    isn't a well-formed receipt is still recorded (the annotation trail
    keeps it) but is logged loudly, because it means a new stamp
    namespace was added without registering it in
    ``_util.TOOL_EVIDENCE_NAMESPACES`` — which would silently downgrade
    real evidence to "not tool-confirmed".
    """
    if not is_stamped_tool_evidence(tool):
        logger.warning(
            "evidence stamp %r for %s:%s is not a recognised receipt "
            "(expected <namespace>:<detail>); register the namespace in "
            "core.audit._util.TOOL_EVIDENCE_NAMESPACES",
            tool, outcome.file, outcome.function,
        )
    outcome.evidence_tool = tool
    if outcome.review_result:
        outcome.review_result["evidence_tool"] = tool
    return outcome


def _has_mechanical_corroboration(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    sarif_cache: Optional["SarifCache"],
    checklist: Optional[Dict[str, Any]],
    *,
    domain_model: Optional[Dict[str, Any]] = None,
) -> bool:
    """Check if any mechanical tool independently flags this function.

    Used to bypass reasoning-chain gates (precondition checks) when
    code-level evidence already confirms the bug pattern.
    Domain-model invariants count as mechanical corroboration because
    they have provenance from the study pipeline.
    """
    gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
    line_end = gap.get("line_end") if gap else None

    if sarif_cache:
        hits = sarif_cache.lookup(
            outcome.file, outcome.line or 0, line_end or 0,
        )
        if hits:
            return True

    source = _read_raw_source(
        config.target_path, outcome.file, outcome.line, line_end,
    )
    pf = run_prefilter(
        target_path=config.target_path,
        file_path=outcome.file,
        function_name=outcome.function,
        source=source,
        line_start=outcome.line or 0,
    )
    if pf.hits:
        if line_end:
            pf.hits = [
                h for h in pf.hits
                if not h.line or outcome.line <= h.line <= line_end
            ]
        if pf.hits:
            return True

    if domain_model:
        hypothesis = outcome.hypothesis or ""
        if outcome.review_result:
            hypothesis = outcome.review_result.get("hypothesis", hypothesis)
        matched = _match_domain_model_invariants(
            hypothesis, outcome.file, domain_model,
        )
        if matched:
            logger.info(
                "mechanical corroboration via domain-model invariant "
                "for %s:%s — %s",
                outcome.file, outcome.function,
                ", ".join(matched),
            )
            return True

    return False


def _smt_demotion_reason(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    checklist: Dict[str, Any],
) -> Optional[str]:
    """Return a bracket-prefixed demotion reason if SMT proves overflow infeasible."""
    review = outcome.review_result or {}
    cwe = review.get("cwe_class") or review.get("cwe") or ""

    gap = _find_gap_in_checklist(checklist, outcome.file, outcome.function)
    if not gap:
        return None

    source = _read_raw_source(
        config.target_path, outcome.file,
        gap.get("line_start", 0), gap.get("line_end"),
    )
    if not source:
        return None

    try:
        from core.smt_solver.bounds_feasibility import check_bounds_infeasible
    except ImportError:
        return None

    if check_bounds_infeasible(source, cwe) is True:
        return (
            "[smt-infeasible: bounds conditions make overflow "
            "impossible (Z3 UNSAT)]"
        )
    return None



def _demote_outcome(outcome: ReviewOutcome, reason: str) -> ReviewOutcome:
    """Demote a finding to suspicious with a reason prefix."""
    return ReviewOutcome(
        file=outcome.file,
        function=outcome.function,
        status="suspicious",
        body=f"{reason}\n\n{outcome.body}",
        hypothesis=outcome.hypothesis,
        hypotheses=outcome.hypotheses,
        evidence_tool=outcome.evidence_tool,
        cost_usd=outcome.cost_usd,
        model=outcome.model,
        duration_s=outcome.duration_s,
        review_result=outcome.review_result,
        line=outcome.line,
    )


_HYPOTHESIS_SEMGREP_PATTERNS: Dict[str, str] = {
    "buffer overflow": "strcpy|sprintf|gets\\s*\\(|strcat",
    "sql injection": "SELECT.*%|INSERT.*%|UPDATE.*%|DELETE.*%",
    "command injection": "system\\s*\\(|popen\\s*\\(|exec[lv]p?e?\\s*\\(",
    "path traversal": "os\\.path\\.join|open\\s*\\(",
    "format string": "%s.*printf|printf\\s*\\(\\s*[a-zA-Z_]",
    "use after free": "free\\s*\\(",
    "double free": "free\\s*\\(",
    "xss": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "reflected": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
    "cross-site": "(snprintf|sprintf)\\s*\\([^)]*\"%s|write\\s*\\(.*\\+|response\\.write|res\\.send",
}


def _hypothesis_to_semgrep_rule(hypothesis: str, file_path: str) -> Optional[str]:
    """Generate a Semgrep YAML rule from a hypothesis string.

    Returns a path to a temp YAML file, or None if no rule can be derived.
    """
    import tempfile

    hyp_lower = hypothesis.lower()

    pattern = None
    rule_id = "hypothesis-check"
    for keyword, regex in _HYPOTHESIS_SEMGREP_PATTERNS.items():
        if keyword in hyp_lower:
            pattern = regex
            rule_id = keyword.replace(" ", "-")
            break

    if not pattern:
        return None

    lang = "c"
    if file_path.endswith(".py"):
        lang = "python"
    elif file_path.endswith((".js", ".ts")):
        lang = "javascript"
    elif file_path.endswith(".java"):
        lang = "java"
    elif file_path.endswith(".go"):
        lang = "go"
    elif file_path.endswith(".rs"):
        lang = "rust"

    rule_yaml = (
        f"rules:\n"
        f"  - id: audit-sweep-{rule_id}\n"
        f"    pattern-regex: '{pattern}'\n"
        f"    message: 'Hypothesis validation: {rule_id}'\n"
        f"    languages: [{lang}]\n"
        f"    severity: WARNING\n"
    )

    try:
        tmp = tempfile.NamedTemporaryFile(
            prefix="audit_sweep_", suffix=".yaml",
            mode="w", delete=False,
        )
        tmp.write(rule_yaml)
        tmp.close()
        return tmp.name
    except OSError:
        return None


_SMT_HYPOTHESIS_VERBS = [
    ("integer overflow leading to", "check-overflow-to-oob"),
    ("overflow to oob", "check-overflow-to-oob"),
    ("negative value", "check-negative-bypass"),
    ("bypass the size check", "check-negative-bypass"),
    ("bypass the resource limit", "check-negative-bypass"),
    ("out of bounds", "check-oob"),
    ("out-of-bounds", "check-oob"),
    ("buffer overflow", "check-oob"),
    ("integer underflow", "check-overflow"),
    ("integer overflow", "check-overflow"),
    ("overflow", "check-overflow"),
    ("underflow", "check-overflow"),
]


def _hypothesis_to_smt_verb(hypothesis: str) -> Optional[str]:
    """Map a hypothesis to an SMT solver verb."""
    import re
    hyp_lower = hypothesis.lower()
    for keyword, verb in _SMT_HYPOTHESIS_VERBS:
        if keyword in hyp_lower:
            return verb
    if re.search(r"negative.*bypass|bypass.*negative|signed.*unsigned", hyp_lower):
        return "check-negative-bypass"
    return None


_COCCI_RULES_DIR = Path(__file__).resolve().parents[2] / "engine" / "coccinelle" / "rules"


def _hypothesis_to_cocci_check(hypothesis: str) -> Optional[str]:
    """Map a hypothesis to a Coccinelle consistency-check rule.

    Returns the path to a .cocci rule file, or None.
    """
    if not _COCCI_RULES_DIR.is_dir():
        return None

    hyp_lower = hypothesis.lower()

    if "unchecked return" in hyp_lower or "return value" in hyp_lower:
        rule = _COCCI_RULES_DIR / "unchecked_return.cocci"
        if rule.exists():
            return str(rule)

    if "missing null check" in hyp_lower or "null check" in hyp_lower:
        rule = _COCCI_RULES_DIR / "missing_null_check.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "rcu_dereference", "rcu_read_lock", "rcu lock",
        "rcu grace period", "rcu protection",
    )):
        rule = _COCCI_RULES_DIR / "rcu_no_lock.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "lock held", "lock imbalance", "without unlock",
        "missing lock", "lock not released",
    )):
        rule = _COCCI_RULES_DIR / "lock_imbalance.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "copy_to_user", "info leak", "kernel memory to userspace",
        "not fully initialized", "leak uninitialized kernel memory",
        "padding", "copied to userspace",
    )):
        rule = _COCCI_RULES_DIR / "copy_to_user_uninit.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "uninitialized", "not initialized", "uninitialised",
        "indeterminate value",
    )):
        rule = _COCCI_RULES_DIR / "uninitialized_return.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "bounds check", "out of bounds", "out-of-bounds",
        "array index", "without validation",
    )):
        rule = _COCCI_RULES_DIR / "missing_bounds_check.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "toctou", "time-of-check", "double fetch",
        "read from user", "copy_from_user",
    )):
        rule = _COCCI_RULES_DIR / "double_fetch.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "list_del", "list corruption", "list_for_each",
        "unsafe list", "linked list",
    )):
        rule = _COCCI_RULES_DIR / "unsafe_list_del.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "uid truncat", "gid truncat", "truncating conversion",
        "narrowing", "__old_uid", "__old_gid",
    )):
        rule = _COCCI_RULES_DIR / "uid_truncation.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "resource leak", "memory leak", "not freed",
        "missing free", "leak on error",
    )):
        rule = _COCCI_RULES_DIR / "resource_leak_err.cocci"
        if rule.exists():
            return str(rule)

    if any(kw in hyp_lower for kw in (
        "race condition", "use-after-free", "use after free",
        "after unlock", "freed while", "after.*lock.*released",
        "concurrent", "non-atomic",
    )):
        rule = _COCCI_RULES_DIR / "use_after_unlock.cocci"
        if rule.exists():
            return str(rule)

    return None


_MAX_PROPAGATION_ROUNDS = 5


def _extract_and_propagate(
    outcome: ReviewOutcome,
    constraints: list,
    checklist: Dict[str, Any],
    entry_points: set,
    prop_config: PropagationConfig,
    tier_counters: Optional[Dict[str, "TierCounters"]] = None,
) -> list:
    """Extract constraints from a review and propagate iteratively.

    Loops until no new open constraints are generated or the round
    limit is reached, instead of the previous single-hop approach.
    """
    new_constraints = extract_constraints_from_review(
        outcome.review_result or {},
        outcome.file,
        outcome.function,
    )

    for c in new_constraints:
        constraints = merge_constraint(constraints, c)

    pending = list(open_constraints(new_constraints))
    rounds = 0

    while pending and rounds < _MAX_PROPAGATION_ROUNDS:
        rounds += 1
        next_pending = []

        for c in pending:
            try:
                result = propagate_one_hop(
                    c,
                    checklist=checklist,
                    entry_points=entry_points,
                    config=prop_config,
                    tier_counters=tier_counters,
                )
                if result.resolved and result.resolution == "refuted":
                    c.status = "refuted"
                elif result.resolved and result.resolution == "depth_limited":
                    c.status = "depth_limited"
                    c.depth_reached = prop_config.max_depth
                elif not result.resolved:
                    derived = getattr(result, "derived_constraints", [])
                    for dc in derived:
                        constraints = merge_constraint(constraints, dc)
                    new_open = list(open_constraints(derived))
                    next_pending.extend(new_open)
            except Exception:
                logger.debug(
                    "propagation failed for %s:%s",
                    c.file, c.function, exc_info=True,
                )

        pending = next_pending

    if rounds >= _MAX_PROPAGATION_ROUNDS and pending:
        logger.info(
            "constraint propagation hit round limit (%d) with %d open",
            _MAX_PROPAGATION_ROUNDS, len(pending),
        )

    return constraints


def _try_understand_bridge(config: OrchestratorConfig) -> Optional[Dict[str, Any]]:
    """Auto-import /understand context-map if one exists for this target."""
    try:
        from core.orchestration.understand_bridge import (
            find_understand_output,
            load_understand_context,
        )
        result_dir, stale = find_understand_output(
            config.out_dir,
            target_path=str(config.target_path),
        )
        if result_dir is None:
            return None
        logger.info(
            "understand_bridge: auto-importing context-map from %s", result_dir,
        )
        summary = load_understand_context(
            result_dir, config.out_dir, stale_files=stale,
        )
        if summary.get("context_map_loaded"):
            return load_context_map(config.out_dir)
    except Exception:
        logger.debug("understand_bridge import failed", exc_info=True)
    return None


def _recreate_coverage_from_annotations(
    coverage_records: List[Dict[str, Any]],
    annotations_dir: Path,
    checklist: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Re-create coverage entries from annotations when runs are cleaned.

    Annotations survive /project clean; coverage records don't. When an
    annotation exists for a function but no coverage record covers it,
    synthesize a coverage record so compute_gaps doesn't re-review it.
    """
    if not annotations_dir.is_dir():
        return coverage_records

    covered = set()
    for rec in coverage_records:
        for fa in rec.get("functions_analysed", []):
            covered.add((fa.get("file", ""), fa.get("function", "")))

    _META_STATUS_RE = re.compile(r"status=(\S+)")

    synthetic = []
    for ann_path in annotations_dir.rglob("*.md"):
        rel = ann_path.relative_to(annotations_dir)
        source_file = str(rel).removesuffix(".md")
        try:
            text = ann_path.read_text(errors="replace")
        except OSError:
            continue
        current_func = None
        current_status = "clean"
        for line in text.splitlines():
            if line.startswith("## ") and not line.startswith("## _"):
                if current_func and (source_file, current_func) not in covered:
                    synthetic.append({
                        "file": source_file,
                        "function": current_func,
                        "status": current_status,
                        "hash": None,
                    })
                    covered.add((source_file, current_func))
                current_func = line[3:].strip()
                current_status = "clean"
            elif current_func and line.startswith("<!-- meta:"):
                m = _META_STATUS_RE.search(line)
                if m:
                    current_status = m.group(1)
        if current_func and (source_file, current_func) not in covered:
            synthetic.append({
                "file": source_file,
                "function": current_func,
                "status": current_status,
                "hash": None,
            })
            covered.add((source_file, current_func))

    if synthetic:
        logger.info(
            "coverage: re-created %d records from surviving annotations",
            len(synthetic),
        )
        coverage_records = list(coverage_records)
        coverage_records.append({
            "tool": "audit",
            "functions_analysed": synthetic,
            "files_examined": sorted({s["file"] for s in synthetic}),
        })

    return coverage_records


def _load_variants(out_dir: Path) -> Set[str]:
    """Load variants.json from /understand --hunt if present.

    Returns a set of "file:function" keys that match known variant
    patterns, used to boost priority.
    """
    path = out_dir / "variants.json"
    if not path.exists():
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
        targets: Set[str] = set()
        for variant in data if isinstance(data, list) else data.get("variants", []):
            fp = variant.get("file", "")
            fn = variant.get("function", "")
            if fp and fn:
                targets.add(f"{fp}:{fn}")
        if targets:
            logger.info("variants: %d pattern-match targets loaded", len(targets))
        return targets
    except Exception:
        logger.debug("variants.json load failed", exc_info=True)
        return set()


def _load_coverage_records(out_dir: Path) -> List[Dict[str, Any]]:
    """Load coverage-record.json if present."""
    path = out_dir / "coverage-record.json"
    if not path.exists():
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return [data]
    except (json.JSONDecodeError, OSError):
        return []


def _load_exploit_feedback(config: OrchestratorConfig) -> FeedbackState:
    """Load exploit feedback state from the project or run directory."""
    candidates = [
        config.out_dir / "exploit-feedback.json",
        config.out_dir.parent / "exploit-feedback.json",
    ]
    for path in candidates:
        if path.is_file():
            state = load_feedback_state(path)
            if state.outcomes:
                return state
    return FeedbackState()


def _load_fuzz_coverage(out_dir: Path) -> Optional[Dict[str, Any]]:
    """Load fuzz coverage data if present.

    Fuzz coverage records which functions have been exercised by
    fuzzers.  This is a DIFFERENT kind of coverage than review
    coverage — a fuzzed function is not reviewed, and fuzzing
    doesn't mean safe.  But it's valuable context for the reviewer:
    "this function was fuzzed with X harness and survived N iterations"
    influences how deeply to look at input handling.
    """
    path = out_dir / "coverage-fuzz.json"
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _fuzz_coverage_for(
    fuzz_data: Dict[str, Any],
    file_path: str,
    function_name: str,
) -> Optional[Dict[str, Any]]:
    """Extract fuzz coverage for a specific function."""
    flat_key = f"{file_path}:{function_name}"
    if flat_key in fuzz_data:
        return fuzz_data[flat_key]
    file_data = fuzz_data.get("files", {}).get(file_path, {})
    func_data = file_data.get("functions", {}).get(function_name)
    if func_data:
        return func_data
    return None


# ── Evidence builders ──────────────────────────────────────────────


def _load_or_build_taint_approx(
    config: OrchestratorConfig,
) -> Optional[Dict[str, Any]]:
    """Load cached taint approximations or build and persist them."""
    if config.out_dir:
        cache_path = config.out_dir / "taint-approx.json"
        if cache_path.exists():
            try:
                from core.json import load_json
                cached = load_json(cache_path)
                if cached:
                    logger.info(
                        "taint_approx: loaded %d cached results", len(cached),
                    )
                    return cached
            except Exception:
                pass
    results = _build_taint_approx(config)
    if results and config.out_dir:
        try:
            from core.json import save_json
            save_json(config.out_dir / "taint-approx.json", results)
        except Exception:
            pass
    return results


def _build_taint_approx(
    config: OrchestratorConfig,
) -> Optional[Dict[str, Any]]:
    """Build tree-sitter taint approximations for all C/C++ files."""
    if not config.target_path or not config.target_path.is_dir():
        return None

    try:
        from core.analysis.taint_approx import (
            extract_taint_approx_c,
            extract_taint_approx_cpp,
        )
    except ImportError:
        return None

    results: Dict[str, Any] = {}
    c_exts = {".c", ".h"}
    cpp_exts = {".cc", ".cpp", ".cxx", ".hpp"}

    for path in config.target_path.rglob("*"):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in c_exts and suffix not in cpp_exts:
            continue

        try:
            content = path.read_text(errors="replace")
        except OSError:
            continue

        rel = str(path.relative_to(config.target_path))

        if suffix in c_exts:
            approxes = extract_taint_approx_c(content)
        else:
            approxes = extract_taint_approx_cpp(content)

        for func_name, approx in approxes.items():
            results[f"{rel}:{func_name}"] = approx

    if results:
        logger.info("taint_approx: %d functions analysed", len(results))
    return results or None


_C_EXTENSIONS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"})
_JOERN_STALL_FLOOR_S = 30


def _target_has_c_sources(target_path: Path) -> bool:
    """Check if target directory contains C/C++ source files."""
    if not target_path or not target_path.is_dir():
        return False
    for p in target_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in _C_EXTENSIONS:
            return True
    return False


_JOERN_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".scala", ".kt",
    ".go", ".rb", ".php",
})


def _target_has_joern_sources(target_path: Path) -> bool:
    """Check if target has non-C sources that Joern can parse."""
    if not target_path or not target_path.is_dir():
        return False
    for p in target_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in _JOERN_EXTENSIONS:
            return True
    return False


def _joern_available(overrides: Optional[Dict[str, Any]] = None) -> bool:
    """Check if Joern is installed, importable, and enabled in tuning."""
    if overrides and overrides.get("enabled") is False:
        return False
    try:
        from core.tuning import get_tuning
        if not get_tuning().joern_enabled:
            return False
    except Exception:
        pass
    try:
        from packages.joern.prereqs import is_available
        return is_available()
    except ImportError:
        return False


def _resolve_joern_evidence(
    config: OrchestratorConfig,
    on_joern_progress: Optional[Callable[[str], None]] = None,
    joern_server=None,
) -> tuple:
    """Resolve Joern evidence.

    Returns (joern_flows, joern_future). At most one is non-None;
    both are None when Joern is unavailable (graceful degradation).

    When a live Joern server is running, blocks and returns completed
    flows directly — server-mode pre-sweep is fast (~10-12s) and the
    LLM makes better initial judgments with flows in the prompt.

    Without a server, falls back to async (background thread) to
    avoid blocking the review loop on the slower subprocess path.
    """
    if not _joern_available(overrides=config.joern_overrides):
        return (None, None)

    if not (_target_has_c_sources(config.target_path)
            or _target_has_joern_sources(config.target_path)):
        return (None, None)

    def _progress(msg: str) -> None:
        logger.info(msg)
        if on_joern_progress:
            on_joern_progress(msg)

    if joern_server is not None and joern_server.is_alive():
        _progress("Joern pre-sweep (server mode, blocking)...")
        flows = _build_joern_evidence(config, _progress, joern_server)
        return (flows, None)

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="joern-cpg")
    future = executor.submit(
        _build_joern_evidence, config, _progress, joern_server,
    )
    executor.shutdown(wait=False)
    return (None, future)


def _re_review_joern_enriched(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    fuzz_coverage: Optional[Dict[str, Any]],
    evidence_index: Dict[str, EvidenceRecord],
    sarif_cache: Optional[SarifCache],
    entry_points: set,
    gaps_before_joern: List[Dict[str, Any]],
    start_time: float,
    on_progress: Optional[Callable],
    audit_log: Optional[List[Dict[str, Any]]] = None,
    session_observations: Optional[List[Dict[str, str]]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    joern_server=None,
) -> OrchestratorResult:
    """Re-review clean verdicts that now have Joern evidence.

    Functions reviewed before the Joern CPG build completed missed
    inter-procedural taint flows. Re-review only those that were
    marked clean AND now have Joern flows in the evidence index.
    """
    candidates = []
    for gap in gaps_before_joern:
        key = f"{gap['file']}:{gap['name']}"
        rec = evidence_index.get(key)
        if not rec or not rec.all_joern_flows():
            continue
        prior = next(
            (o for o in result.outcomes
             if o.file == gap["file"] and o.function == gap["name"]
             and o.status == "clean"),
            None,
        )
        if prior is not None:
            candidates.append((gap, prior))

    if not candidates:
        return result

    logger.info(
        "re-reviewing %d clean verdicts that gained Joern evidence",
        len(candidates),
    )

    for gap, prior_outcome in candidates:
        if _check_budget(config, start_time, result):
            break

        ctx = _build_context(config, gap, checklist, context_map, evidence_index,
                             discovered_evidence=discovered_evidence)
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage, gap["file"], gap["name"],
            )
        ctx["joern_re_review"] = True

        try:
            outcome = review_fn(ctx, config)
        except Exception as exc:
            logger.warning(
                "joern re-review failed for %s:%s: %s",
                gap["file"], gap["name"], exc,
            )
            continue

        outcome.line = gap.get("line_start", 0)

        if outcome.status in ("finding", "suspicious"):
            if outcome.status == "finding" and config.sweep_validate_findings:
                outcome = _sweep_validate(
                    outcome, config, sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
            if outcome.status == "finding":
                outcome = _apply_reachability_gate(
                    outcome, ctx, entry_points, config,
                )
            if outcome.status == "finding":
                gate_violations = _check_finding_gates(
                    outcome, audit_log=audit_log,
                )
                if gate_violations:
                    outcome = _demote_outcome(
                        outcome,
                        f"[gate violation: {'; '.join(gate_violations)}]",
                    )

            _untally_outcome(result, prior_outcome)
            idx = result.outcomes.index(prior_outcome)
            result.outcomes[idx] = outcome
            _tally_outcome(result, outcome, append=False)

            try:
                _commit_outcome(config, outcome, gap)
            except Exception:
                logger.warning(
                    "commit failed for %s:%s",
                    gap["file"], gap["name"], exc_info=True,
                )

            if config.enable_session_context and session_observations is not None and outcome.review_result:
                _accumulate_observations(
                    session_observations, outcome, gap,
                    sweep_pre_status=prior_outcome.status,
                )

            logger.info(
                "joern re-review %s:%s: clean -> %s",
                gap["file"], gap["name"], outcome.status,
            )

    return result


def _merge_joern_flows(
    joern_flows: Dict[str, list],
    evidence_index: Dict[str, EvidenceRecord],
    checklist: Dict[str, Any],
    sarif_cache: Optional[SarifCache],
) -> Dict[str, EvidenceRecord]:
    """Merge Joern taint flows into the evidence index."""
    merged = build_evidence_index(
        checklist=checklist,
        joern_flows=joern_flows,
        sarif_cache=sarif_cache,
    )
    from .safe_env import truncate_output
    for key, rec in merged.items():
        if key in evidence_index:
            existing = evidence_index[key]
            if rec.joern_flows and not existing.joern_flows:
                truncated, _note = truncate_output(rec.joern_flows, "joern")
                existing.joern_flows = truncated
        else:
            if rec.joern_flows:
                rec.joern_flows, _note = truncate_output(rec.joern_flows, "joern")
            evidence_index[key] = rec

    enriched = sum(1 for r in merged.values() if r.joern_flows)
    logger.info(
        "Joern evidence merged: %d functions enriched",
        enriched,
    )
    return evidence_index


def _drain_joern_future(
    future: Future,
    evidence_index: Dict[str, EvidenceRecord],
    checklist: Dict[str, Any],
    sarif_cache: Optional[SarifCache],
) -> Dict[str, EvidenceRecord]:
    """Drain a completed Joern future and merge flows into evidence_index."""
    try:
        joern_flows = future.result(timeout=0)
    except Exception:
        logger.warning("Joern background build failed", exc_info=True)
        return evidence_index

    if not joern_flows:
        return evidence_index

    return _merge_joern_flows(joern_flows, evidence_index, checklist, sarif_cache)


def _resolve_cpg_cache_dir(config: OrchestratorConfig) -> Optional[Path]:
    """Resolve the CPG cache directory for project-level reuse.

    With an active project: out_dir.parent IS the project dir, so the
    CPG at project_dir/joern-cpg/ is shared across /scan, /audit,
    /understand, /validate runs. Without a project: returns None and
    the CPG is built in a temporary directory (per-run only).
    """
    if not config.out_dir:
        return None
    project_dir = config.out_dir.parent
    if project_dir and project_dir != config.out_dir:
        return project_dir
    return None


def _import_sibling_joern_flows(
    config: OrchestratorConfig,
) -> Optional[Dict[str, list]]:
    """Step 0i: import Joern taint flows from sibling project runs."""
    siblings = _sibling_run_dirs(config.out_dir, target_path=config.target_path)
    if not siblings:
        return None
    imported: Dict[str, list] = {}
    for sibling_dir in siblings:
        flows_path = sibling_dir / "joern-flows.json"
        if not flows_path.exists():
            continue
        manifest_path = sibling_dir / ".raptor-run.json"
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
                sibling_hash = manifest.get("content_hash", "")
                if sibling_hash and hasattr(config, "content_hash"):
                    if sibling_hash != getattr(config, "content_hash", ""):
                        logger.debug(
                            "skipping stale joern-flows from %s (hash mismatch)",
                            sibling_dir.name,
                        )
                        continue
            except (json.JSONDecodeError, OSError):
                pass
        try:
            with open(flows_path) as f:
                flows_data = json.load(f)
            for key, flows in flows_data.items():
                imported.setdefault(key, []).extend(flows)
        except (json.JSONDecodeError, OSError):
            logger.debug("failed to import joern-flows from %s", sibling_dir.name)
    return imported if imported else None


def _sibling_run_dirs(
    out_dir: Path,
    *,
    target_path: Optional[Path] = None,
) -> List[Path]:
    """List sibling run directories under the same project.

    When *target_path* is provided, only includes siblings whose
    ``.raptor-run.json`` manifest records the same target — prevents
    cross-project contamination when runs share a generic parent
    directory like ``/tmp/`` or ``out/``.
    """
    project_dir = out_dir.parent
    if not project_dir or project_dir == out_dir:
        return []
    dirs = []
    for child in sorted(project_dir.iterdir()):
        if not child.is_dir() or child == out_dir:
            continue
        if target_path is not None:
            manifest = child / ".raptor-run.json"
            if manifest.exists():
                try:
                    with open(manifest) as f:
                        m = json.load(f)
                    sibling_target = m.get("target_path") or m.get("target", "")
                    if sibling_target and Path(sibling_target).resolve() != target_path.resolve():
                        continue
                except (json.JSONDecodeError, OSError):
                    continue
            else:
                continue
        dirs.append(child)
    return dirs



def _joern_tunables(overrides: Optional[Dict[str, Any]] = None):
    """Load JoernTunables from the central tuning config."""
    try:
        from packages.joern.tunables import JoernTunables
        return JoernTunables.from_tuning(overrides=overrides)
    except Exception:
        try:
            from packages.joern.tunables import JoernTunables
            return JoernTunables()
        except Exception:
            logger.debug("joern tunables unavailable", exc_info=True)
            return None


def _start_joern_server(config: OrchestratorConfig, tunables=None):
    """Start or reuse a persistent Joern server if Joern is available.

    Tries the lifecycle manager first (shared server across runs).
    Falls back to a per-run server if the lifecycle module is
    unavailable.

    Returns the server instance or None. Boot runs eagerly so the
    JVM is warm by the time the first query fires.
    """
    if not _joern_available(overrides=config.joern_overrides):
        return None

    if not (_target_has_c_sources(config.target_path)
            or _target_has_joern_sources(config.target_path)):
        return None

    try:
        from packages.joern.lifecycle import joern_acquire
        srv = joern_acquire(tunables)
        if srv is not None:
            return srv
    except Exception:
        logger.debug("joern lifecycle acquire failed; trying direct start",
                     exc_info=True)

    try:
        from packages.joern.server import JoernServer
    except ImportError:
        return None

    try:
        srv = JoernServer.from_tunables(tunables)
        srv.start()
        return srv
    except Exception:
        logger.debug("Joern server failed to start; using subprocess fallback",
                     exc_info=True)
        return None


def _stop_joern_server(server) -> None:
    """Stop the Joern server if it was started."""
    if server is None:
        return
    import threading

    def _do_stop():
        try:
            server.stop()
        except Exception:
            logger.debug("Joern server shutdown error", exc_info=True)

    t = threading.Thread(target=_do_stop, daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        logger.warning("Joern server stop timed out after 30s — abandoning")


def _joern_live_query(
    server,
    function_name: str,
    sinks: List[str],
    timeout: int = 30,
) -> List[Any]:
    """Fire a targeted taint query via the live Joern server.

    Queries whether any parameter of ``function_name`` flows to any
    of the given ``sinks``.  Returns the list of TaintFlow objects
    (empty = no flow found).  Each sink is tried independently;
    the first hit short-circuits.
    """
    from packages.joern.runner import _validate_substitution_value

    if not _validate_substitution_value(function_name):
        return []

    for sink in sinks:
        sink_name = sink.split(".")[-1] if "." in sink else sink
        if not _validate_substitution_value(sink_name):
            continue
        try:
            flows = server.run_taint_query(
                function_name, sink_name, timeout=timeout,
            )
            if flows:
                logger.info(
                    "joern live query: %s → %s = %d flow(s)",
                    function_name, sink_name, len(flows),
                )
                return flows
        except Exception:
            logger.debug(
                "joern live query failed: %s → %s",
                function_name, sink_name, exc_info=True,
            )

    return []


def _enrich_joern_evidence(
    evidence_index: Optional[Dict[str, Any]],
    key: str,
    function_name: str,
    sinks: List[str],
    joern_server,
) -> None:
    """Add unguarded-sink details and tainted arg indices to evidence."""
    if not evidence_index:
        return
    rec = evidence_index.get(key)
    if not rec:
        return

    from core.analysis.reachability_gates import (
        query_sink_arg_index,
        query_unguarded_sinks,
    )

    if not rec.joern_unguarded_sinks:
        unguarded = query_unguarded_sinks(function_name, joern_server)
        if unguarded:
            rec.joern_unguarded_sinks = unguarded

    if not rec.joern_sink_args:
        from packages.joern.runner import _validate_substitution_value
        for sink in sinks:
            sink_name = sink.split(".")[-1] if "." in sink else sink
            if not _validate_substitution_value(sink_name):
                continue
            args = query_sink_arg_index(function_name, sink_name, joern_server)
            if args:
                rec.joern_sink_args.extend(args)
        if rec.joern_sink_args:
            seen = set()
            deduped = []
            for a in rec.joern_sink_args:
                k = (a.get("sink"), a.get("arg_index"), a.get("source_param"))
                if k not in seen:
                    seen.add(k)
                    deduped.append(a)
            rec.joern_sink_args = deduped


def _build_joern_evidence(
    config: OrchestratorConfig,
    on_progress: Optional[Callable] = None,
    joern_server=None,
) -> Optional[Dict[str, list]]:
    """Run Joern pre-sweep (standard_sinks.sc) if available."""
    try:
        from .sweep import run_joern_pre_sweep
    except ImportError:
        return None

    tunables = _joern_tunables(overrides=config.joern_overrides)
    if tunables is None:
        return None
    cache_dir = _resolve_cpg_cache_dir(config)
    flows = run_joern_pre_sweep(
        config.target_path, {},
        cache_dir=cache_dir,
        on_progress=on_progress,
        stall_timeout=tunables.cpg_timeout_s,
        query_timeout=tunables.query_timeout_s,
        heap_mb=tunables.heap_mb,
        server=joern_server,
    )
    return flows or None


def _enrich_summaries_from_joern(
    joern_server,
    joern_flows: Dict[str, list],
    taint_summary_results: Dict[str, Any],
) -> None:
    """Run Joern summary batch for flow-involved methods and merge results.

    Extracts method names from taint flows, queries the Joern server for
    CPG-backed summaries (taint rules, preconditions, returns), converts
    them to ``FunctionSummary`` objects, and merges into
    ``taint_summary_results`` — overriding heuristic summaries with
    CPG-backed evidence.
    """
    try:
        from packages.joern.models import TaintFlow
        from core.analysis.summaries import (
            FunctionSummary, TaintRule, Precondition, ReturnCondition,
            EvidenceTier,
        )
    except ImportError:
        return

    methods: set[str] = set()
    file_for_method: dict[str, str] = {}
    for file_key, flow_list in joern_flows.items():
        for flow_dict in flow_list:
            try:
                flow = TaintFlow.from_dict(flow_dict) if isinstance(flow_dict, dict) else flow_dict
            except Exception:
                continue
            if flow.source_method:
                methods.add(flow.source_method)
                file_for_method.setdefault(flow.source_method, file_key)
            for step in getattr(flow, "steps", []):
                fn = getattr(step, "function", "")
                if fn:
                    methods.add(fn)
                    file_for_method.setdefault(fn, getattr(step, "file", file_key))

    if not methods:
        return

    try:
        summaries = joern_server.run_summary_batch(
            list(methods), timeout=60,
        )
    except Exception:
        logger.debug("joern summary batch failed", exc_info=True)
        return

    if not summaries:
        return

    merged = 0
    for method_name, js in summaries.items():
        file_path = file_for_method.get(method_name, "")
        key = f"{file_path}:{method_name}" if file_path else method_name

        fs = FunctionSummary(
            function=method_name,
            file=file_path,
            taint_rules=[
                TaintRule(
                    source_param=t, source_index=0,
                    sink_call="", sink_arg_index=0,
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for t in js.taint_rules
            ],
            preconditions=[
                Precondition(
                    param="", param_index=0,
                    conditions=[p],
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for p in js.preconditions
            ],
            returns=[
                ReturnCondition(
                    code=r,
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for r in js.returns
            ],
            evidence_tier=EvidenceTier.XREF_BACKED,
            source="joern_cpg",
            confidence="high",
        )

        existing = taint_summary_results.get(key)
        if existing is None or getattr(existing, "source", "") != "joern_cpg":
            taint_summary_results[key] = fs
            merged += 1

    if merged:
        logger.info("joern_summary_batch: merged %d CPG-backed summaries", merged)


def _codeql_pre_sweep(
    config: OrchestratorConfig,
    sarif_cache: SarifCache,
) -> None:
    """Step 0g: run standard CodeQL suites before the LLM loop.

    Generates SARIF and merges into the sarif_cache so per-function
    CodeQL alerts are available as pre-evidence.
    """
    try:
        from packages.codeql.query_runner import QueryRunner  # noqa: F401
    except ImportError:
        logger.debug("codeql runner not importable; skipping pre-sweep")
        return

    # TODO: wire QueryRunner to replace removed run_standard_queries
    pass


def _build_sink_results(
    config: OrchestratorConfig,
    taint_approx_results: Optional[Dict[str, Any]] = None,
    *,
    checklist: Optional[Dict[str, Any]] = None,
) -> Optional[Any]:
    """Run sink discovery on the target.

    Runs taxonomy-based discovery first, then supplements with
    project-specific sink heuristics (wrapper detection, naming
    patterns, side-effect analysis).
    """
    if not config.target_path or not config.target_path.is_dir():
        return None

    try:
        from core.inventory.sink_discovery import discover_sinks_for_target
        result = discover_sinks_for_target(config.target_path)
    except ImportError:
        return None
    except Exception:
        logger.debug("sink discovery failed", exc_info=True)
        return None

    call_graphs: Optional[Dict[str, Any]] = None
    if checklist:
        call_graphs = {}
        for fi in checklist.get("files", []):
            cg = fi.get("call_graph")
            if isinstance(cg, dict) and cg.get("calls"):
                call_graphs[fi["path"]] = cg

    try:
        from .sink_heuristics import discover_project_sinks, merge_discovered_sinks
        heuristic = discover_project_sinks(
            result,
            call_graphs=call_graphs,
            taint_approx=taint_approx_results,
        )
        if heuristic.discovered:
            merge_discovered_sinks(result, heuristic)
            logger.info(
                "sink_heuristics: %d project-specific sinks "
                "(wrapper=%d, naming=%d, side_effect=%d)",
                len(heuristic.discovered),
                heuristic.wrapper_count,
                heuristic.naming_count,
                heuristic.side_effect_count,
            )
            if config.out_dir:
                try:
                    import json as _json
                    hp = config.out_dir / "discovered-sinks.json"
                    hp.write_text(
                        _json.dumps(heuristic.to_dict(), indent=2) + "\n",
                    )
                except Exception:
                    pass
    except Exception:
        logger.debug("sink heuristics failed", exc_info=True)

    return result


def _build_taint_summary(
    config: OrchestratorConfig,
) -> Optional[Dict[str, Any]]:
    """Build taint summaries for all supported languages."""
    if not config.target_path or not config.target_path.is_dir():
        return None

    results: Dict[str, Any] = {}

    # Python — full CFG-based analysis
    try:
        from core.analysis.python_module_callgraph import build_python_module_callgraph
        from core.analysis.taint_summaries import build_taint_summaries

        for path in config.target_path.rglob("*.py"):
            if not path.is_file():
                continue
            try:
                cg = build_python_module_callgraph(path)
            except Exception:
                continue
            if cg is None:
                continue
            try:
                summaries = build_taint_summaries(cg, path)
            except Exception:
                continue
            rel = str(path.relative_to(config.target_path))
            for func_name, summary in summaries.items():
                results[f"{rel}:{func_name}"] = summary
    except ImportError:
        pass

    # Java, JavaScript/TypeScript, Go, Rust — regex-based extraction
    try:
        from core.analysis.taint_multi_lang import (
            extract_summaries_for_file,
            _LANG_EXTENSIONS,
        )
        multi_lang_count = 0
        for path in config.target_path.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _LANG_EXTENSIONS:
                continue
            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue
            if len(content) > 500_000:
                continue
            rel = str(path.relative_to(config.target_path))
            try:
                summaries = extract_summaries_for_file(content, rel)
            except Exception:
                continue
            for func_name, summary in summaries.items():
                results[f"{rel}:{func_name}"] = summary
                multi_lang_count += 1
        if multi_lang_count:
            logger.info(
                "taint_summary: %d multi-language functions analysed "
                "(Java/JS/Go/Rust)",
                multi_lang_count,
            )
    except ImportError:
        pass

    if results:
        py_count = sum(
            1 for k in results if k.rsplit(":", 1)[0].endswith(".py")
        )
        if py_count:
            logger.info("taint_summary: %d Python functions analysed", py_count)
    return results or None


# ── Adaptive propagation depth ────────────────────────────────────────


def _adaptive_max_depth(
    inventory: Optional[Dict[str, Any]],
    entry_points: set,
    operator_override: Optional[int] = None,
) -> int:
    """Compute propagation depth from call graph density."""
    if operator_override is not None:
        return operator_override

    if not inventory:
        return DEFAULT_MAX_DEPTH

    depths = _sample_entry_point_depths(inventory, entry_points)

    if not depths:
        return DEFAULT_MAX_DEPTH

    p90 = sorted(depths)[int(len(depths) * 0.9)]

    return max(5, min(p90 + 2, 15))


def _sample_entry_point_depths(
    inventory: Dict[str, Any],
    entry_points: set,
) -> List[int]:
    """BFS from each entry point, recording reachable function depths."""
    edges: Dict[str, List[str]] = {}
    for edge in inventory.get("call_edges", inventory.get("edges", [])):
        caller = edge.get("caller", "")
        callee = edge.get("callee", "")
        if caller and callee:
            edges.setdefault(caller, []).append(callee)

    if not edges:
        return []

    depths: List[int] = []
    for ep in list(entry_points)[:50]:
        name = ep.split(":")[-1] if ":" in ep else ep
        visited: set = set()
        queue = deque([(name, 0)])
        while queue:
            func, depth = queue.popleft()
            if func in visited:
                continue
            visited.add(func)
            depths.append(depth)
            for callee in edges.get(func, []):
                if callee not in visited and depth < 20:
                    queue.append((callee, depth + 1))

    return depths


# ── Tier-counter increments in tool chain ─────────────────────────────


def _read_function_source(
    target_path: Path, file_path: str, function_name: str,
) -> str:
    """Best-effort read of a function's source from the target."""
    full = target_path / file_path
    if not full.is_file():
        return ""
    try:
        text = full.read_text(errors="replace")
    except OSError:
        return ""
    if len(text) > 500_000:
        return ""
    return text



def _increment_tier_dict(
    tier_counters: Dict[str, "TierCounters"],
    tier: str,
    field: str,
    value: int = 1,
) -> None:
    """Increment a counter field on a tier_counters dict entry."""
    if tier in tier_counters:
        current = getattr(tier_counters[tier], field, 0)
        setattr(tier_counters[tier], field, current + value)


def _increment_tier(
    result: OrchestratorResult,
    tier: str,
    outcome_str: str,
) -> None:
    """Increment a tier counter based on tool outcome."""
    tc = result.tier_counters.get(tier)
    if tc is None:
        return
    if outcome_str == "confirmed":
        tc.confirmed += 1
    elif outcome_str == "refuted":
        tc.refuted += 1
    elif outcome_str == "error":
        tc.errors += 1
    else:
        tc.inconclusive += 1


def format_tier_diagnostics(
    tier_counters: Dict[str, TierCounters],
) -> str:
    """Format tier diagnostics as a human-readable table."""
    lines = ["Mechanical tier effectiveness:"]
    for name, tc in tier_counters.items():
        total = tc.confirmed + tc.refuted + tc.inconclusive + tc.errors
        if total == 0 and tc.skipped == 0:
            continue
        parts = []
        if tc.confirmed:
            parts.append(f"{tc.confirmed} confirmed")
        if tc.refuted:
            parts.append(f"{tc.refuted} refuted")
        if tc.inconclusive:
            parts.append(f"{tc.inconclusive} inconclusive")
        if tc.skipped:
            parts.append(f"{tc.skipped} skipped")
        if tc.errors:
            parts.append(f"{tc.errors} errors")
        if tc.wall_time_s > 0:
            wall_str = f"{tc.wall_time_s:.1f}s"
            if tc.cpg_build_s > 0:
                wall_str += f" (CPG build: {tc.cpg_build_s:.1f}s)"
            parts.append(wall_str)
        lines.append(f"  {name:16s} {', '.join(parts)}")
    return "\n".join(lines)


_MAX_DISCOVERED_PER_FUNCTION = 20


def _inject_discovered_evidence(
    discovered: Dict[str, Any],
    file_path: str,
    function_name: str,
    tool: str,
    hypothesis: str,
) -> None:
    """Add a mid-loop tool discovery to the discovered_evidence dict."""
    key = f"{file_path}:{function_name}"
    entries = discovered.setdefault(key, [])
    if len(entries) >= _MAX_DISCOVERED_PER_FUNCTION:
        entries.pop(0)
        logger.debug(
            "discovered_evidence cap (%d) reached for %s, oldest dropped",
            _MAX_DISCOVERED_PER_FUNCTION, key,
        )
    entries.append({
        "tool": tool,
        "text": f"{tool} confirmed: {hypothesis}" if hypothesis else f"{tool} confirmed",
    })


def write_tier_diagnostics(
    tier_counters: Dict[str, TierCounters],
    out_dir: Path,
) -> None:
    """Write tier-diagnostics.json to the output directory."""
    data = {}
    for name, tc in tier_counters.items():
        data[name] = {
            "confirmed": tc.confirmed,
            "refuted": tc.refuted,
            "inconclusive": tc.inconclusive,
            "skipped": tc.skipped,
            "errors": tc.errors,
            "wall_time_s": round(tc.wall_time_s, 2),
        }
        if tc.cpg_build_s > 0:
            data[name]["cpg_build_s"] = round(tc.cpg_build_s, 2)
    path = out_dir / "tier-diagnostics.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _iris_candidate_to_spec(candidate):
    """Convert an IRIS CandidateFunction to a TaintSpec via name heuristics."""
    from .iris_specs import TaintSpec
    from core.evidence import EvidenceTier
    name = candidate.function.lower()
    role = "propagator"
    if any(p in name for p in ("sanitize", "sanitise", "escape", "encode", "filter", "clean", "purify")):
        role = "sanitiser"
    elif any(p in name for p in ("read", "recv", "fetch", "load", "input", "get_user", "getenv")):
        role = "source"
    elif any(p in name for p in ("write", "send", "execute", "exec", "eval", "query", "system", "render", "emit")):
        role = "sink"
    return TaintSpec(
        function=candidate.function,
        file=candidate.file,
        role=role,
        confidence=0.6 if candidate.has_security_name else 0.4,
        evidence_tier=EvidenceTier.HEURISTIC,
    )


def _check_layer_disagreement(outcome, ctx, gap):
    """Check for mechanical/LLM/dynamic disagreement on this function.

    Builds layer claims from the evidence_index (mechanical) and the
    LLM's review_result, then delegates to layer_resolution.
    """
    try:
        from .layer_resolution import LayerClaim, LayerVerdict, resolve_disagreement
    except ImportError:
        return None

    review_result = getattr(outcome, "review_result", None) or {}
    if not review_result:
        return None

    mechanical_claim = None
    has_mech = ctx.get("mechanical_evidence") or ctx.get("_graded_mechanical")
    if has_mech:
        mech_reachable = not ctx.get("sink_unreachable", False)
        mechanical_claim = LayerClaim(
            layer=LayerVerdict.MECHANICAL,
            reachable=mech_reachable,
            has_flow=mech_reachable,
        )

    llm_finding = outcome.status in ("finding", "suspicious")
    llm_evasion = review_result.get("evasion_mechanism", "")
    llm_claim = LayerClaim(
        layer=LayerVerdict.LLM,
        reachable=llm_finding,
        has_flow=llm_finding,
        evasion_mechanism=llm_evasion,
    )

    dynamic_claim = None
    et = outcome.evidence_tool or ""
    if et.startswith("dynamic"):
        dynamic_claim = LayerClaim(
            layer=LayerVerdict.DYNAMIC,
            reachable=True,
            has_flow=et == "dynamic",
        )

    language = gap.get("language", "")
    return resolve_disagreement(
        gap.get("file", ""), gap.get("name", ""),
        mechanical=mechanical_claim,
        llm=llm_claim,
        dynamic=dynamic_claim,
        language=language,
    )


def _fuse_all_evidence(ctx: Dict[str, Any]) -> None:
    """Fuse mechanical, negative-space, typestate, postcondition, and spec evidence.

    Converts per-capability domain objects into GradedEvidence, then runs
    cross-source fusion to corroborate signals before the LLM review.
    Populates ctx["fused_evidence"] with the rendered text.
    """
    from .evidence_grade import Confidence, EvidenceSource, GradedEvidence
    from .evidence_fusion import format_fused_evidence, fuse_evidence

    mechanical = ctx.pop("_graded_mechanical", [])

    spec_ev: List[GradedEvidence] = []
    spec = ctx.get("inferred_spec")
    if spec:
        for pc in getattr(spec, "preconditions", []) or []:
            spec_ev.append(GradedEvidence(
                source=EvidenceSource.LLM_SPEC,
                confidence=Confidence.LOW,
                description=f"spec precondition: {pc}",
            ))
        for ns in getattr(spec, "negative_specs", []) or []:
            spec_ev.append(GradedEvidence(
                source=EvidenceSource.LLM_SPEC,
                confidence=Confidence.LOW,
                description=f"spec negative: {ns}",
            ))

    ns_ev: List[GradedEvidence] = []
    for finding in ctx.get("negative_space", []):
        desc = getattr(finding, "title", "") or getattr(finding, "expected", "")
        ns_ev.append(GradedEvidence(
            source=EvidenceSource.NEGATIVE_SPACE,
            confidence=Confidence.MEDIUM,
            description=desc,
            detail=getattr(finding, "evidence", None),
        ))

    contract_ev: List[GradedEvidence] = []
    for viol in ctx.get("postcondition_violations", []):
        desc = getattr(viol, "description", "") or str(viol)
        contract_ev.append(GradedEvidence(
            source=EvidenceSource.COCCINELLE,
            confidence=Confidence.MEDIUM,
            description=f"postcondition violation: {desc}",
        ))

    ts_ev: List[GradedEvidence] = []
    for viol in ctx.get("typestate_violations", []):
        desc = getattr(viol, "description", "") or str(viol)
        ts_ev.append(GradedEvidence(
            source=EvidenceSource.TYPESTATE,
            confidence=Confidence.MEDIUM,
            description=f"typestate: {desc}",
        ))

    total = len(mechanical) + len(spec_ev) + len(ns_ev) + len(contract_ev) + len(ts_ev)
    if total < 2:
        if mechanical:
            fused = fuse_evidence(mechanical, [], [], [], [])
            fused_text = format_fused_evidence(fused)
            if fused_text:
                ctx["fused_evidence"] = fused_text
        return

    fused = fuse_evidence(mechanical, spec_ev, ns_ev, contract_ev, ts_ev)
    fused_text = format_fused_evidence(fused)
    if fused_text:
        ctx["fused_evidence"] = fused_text


def _merge_validate_evidence(bridge_result, evidence_index):
    """Fold /validate feasibility verdicts into the evidence index."""
    if evidence_index is None:
        return
    for verdict in bridge_result.feasibility_verdicts:
        key = f"{verdict.get('file', '')}:{verdict.get('function', '')}"
        rec = evidence_index.get(key)
        if rec is None:
            continue
        existing = getattr(rec, "validate_verdicts", None)
        if existing is None:
            rec.validate_verdicts = []
        rec.validate_verdicts.append(verdict)


def _run_dark_verification(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    llm_client: Optional[Callable] = None,
) -> None:
    """Run dark-verification pass on dormant outcomes.

    For each outcome with status ``"dark"``, asks the LLM to generate
    a witness specification, then executes the witness mechanically.
    Confirmed witnesses upgrade the outcome to ``"finding"``; refuted
    witnesses downgrade to ``"clean"``.
    """
    if llm_client is None:
        return

    from .dark_verify import (
        build_witness_prompt,
        execute_witness,
        language_for_file,
        parse_witness_response,
    )

    dark_outcomes = [o for o in result.outcomes if o.status == "dark"]
    if not dark_outcomes:
        return

    records: List[Dict[str, Any]] = []

    for outcome in dark_outcomes:
        lang = language_for_file(outcome.file)
        if lang is None:
            continue

        prompt = build_witness_prompt(
            file=outcome.file,
            function=outcome.function,
            hypothesis=outcome.hypothesis,
            body=outcome.body,
            language=lang,
        )

        try:
            llm_response = llm_client(prompt, "")
        except Exception:
            continue

        spec = parse_witness_response(
            llm_response,
            finding_key=f"{outcome.file}:{outcome.function}",
            file=outcome.file,
            function=outcome.function,
            language=lang,
        )
        if spec is None:
            continue

        verify_result = execute_witness(spec, config.target_path)

        if verify_result.verdict == "confirmed":
            outcome.status = "finding"
            outcome.evidence_tool = "dark_verify"
            result.findings += 1
            result.dormant -= 1
        elif verify_result.verdict == "refuted":
            outcome.status = "clean"
            outcome.evidence_tool = "dark_verify"
            result.clean += 1
            result.dormant -= 1

        records.append({
            "file": outcome.file,
            "function": outcome.function,
            "status": outcome.status,
            "evidence_tool": outcome.evidence_tool,
            "verdict": verify_result.verdict,
            "match_detail": verify_result.match_detail,
        })

    if records:
        results_path = config.out_dir / "dark-verify-results.json"
        results_path.write_text(
            json.dumps(records, indent=2),
            encoding="utf-8",
        )
