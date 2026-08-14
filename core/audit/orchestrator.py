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
import tempfile
import subprocess
import sys
import threading as _threading
import time
from concurrent.futures import Future
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
    hydrate_live_gaps_for_detectors,
    load_checklist,
    load_context_map,
    write_gaps,
)
from .priority import (
    group_by_subsystem,
    load_flow_traces,
    load_fuzz_coverage as _load_fuzz_coverage_from_runs,
    load_tool_failures,
    score_functions,
)
from .propagation import PropagationConfig, propagate_one_hop
from .prefilter import PrefilterResult, run_prefilter
from .pipeline import ReviewMode, VerificationTier
from .shared_state import SharedState
from .topo_order import topological_sort as _topological_sort
from .triage import TriageBucket, classify_all, format_triage_summary
from .findings import write_findings
from .record import (
    append_audit_log,
    load_audit_log,
    _resolve_annotations_dir as _resolve_ann_dir,
)
from .sweep import (
    SarifCache,
    run_coccinelle_sweep,
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
    FeedbackState,
    load_feedback_state,
    format_feedback_summary,
    format_feedback_for_context,
)
from ._util import extract_context_map_set
from core.analysis.reachability_gates import (
    build_sink_reachable_set,
    check_sink_guarded,
    compute_demotion_verdict,
)

from .loaders import (
    load_variants as _load_variants,
    load_coverage_records as _load_coverage_records,
    load_exploit_feedback as _load_exploit_feedback_raw,
    load_fuzz_coverage as _load_fuzz_coverage,
    fuzz_coverage_for as _fuzz_coverage_for,
    load_or_build_taint_approx as _load_or_build_taint_approx_raw,
)
from .hypothesis_mapping import (
    hypothesis_to_semgrep_rule as _hypothesis_to_semgrep_rule,
    hypothesis_to_smt_verb as _hypothesis_to_smt_verb,
    hypothesis_to_cocci_check as _hypothesis_to_cocci_check,
)
from .diagnostics import (
    read_function_source as _read_function_source,
    increment_tier_dict as _increment_tier_dict,
    increment_tier as _increment_tier,
    format_tier_diagnostics,
    inject_discovered_evidence as _inject_discovered_evidence,
    write_tier_diagnostics,
    iris_candidate_to_spec as _iris_candidate_to_spec,
)
from .joern_backend import (
    joern_tunables as _joern_tunables,
    start_joern_server as _start_joern_server_raw,
    stop_joern_server as _stop_joern_server,
    joern_live_query as _joern_live_query,
    enrich_joern_evidence as _enrich_joern_evidence,
    enrich_summaries_from_joern as _enrich_summaries_from_joern,
    resolve_joern_evidence as _resolve_joern_evidence_raw,
    merge_joern_flows as _merge_joern_flows,
    drain_joern_future as _drain_joern_future,
    import_sibling_joern_flows as _import_sibling_joern_flows_raw,
    sibling_run_dirs as _sibling_run_dirs,
    adaptive_max_depth as _adaptive_max_depth,
)
from .codeql_backend import (
    codeql_pre_sweep as _codeql_pre_sweep_raw,
    build_sink_results as _build_sink_results_raw,
    build_taint_summary as _build_taint_summary_raw,
)

logger = logging.getLogger(__name__)

_shutdown_event = _threading.Event()


_active_target_path: Optional[Path] = None


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
    scope: Optional[str | list[str]] = None
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
    batch_sloc_threshold: int = 15
    propagate_constraints: bool = True
    binary_verdicts: Optional[Dict[str, str]] = None
    no_binary_oracle: bool = False
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
    functions: Optional[List[str]] = None
    joern_server: Optional[Any] = None  # pre-started server; caller owns lifecycle
    study_root: Optional[Path] = None  # full source root for study loop (when target_path is an excerpt)
    mode: ReviewMode = ReviewMode.SECURITY
    project_sinks: Optional[frozenset] = None  # IRIS-derived sink names for wrapper pre-filter


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
    verification_tier: str = "speculative"
    tools_dispatched: Optional[set] = field(default=None, repr=False)
    semantic_confidence: str = ""
    provenance_all_trusted: bool = False
    caller_attributed: bool = False
    attributed_caller: str = ""
    _propagated: bool = field(default=False, repr=False)

    _CONFIRMED_EVIDENCE = frozenset({
        "dark_verify:confirmed", "dynamic:crash", "frida:runtime",
    })

    def compute_tier(self) -> str:
        """Derive verification tier from evidence and tool dispatch state."""
        dispatched = self.tools_dispatched or set()

        if self.status == "clean":
            if dispatched:
                return VerificationTier.TOOL_BACKED.value
            return VerificationTier.SPECULATIVE.value

        if self.status not in ("finding", "suspicious"):
            return VerificationTier.SPECULATIVE.value
        if not self.evidence_tool:
            return VerificationTier.SPECULATIVE.value

        et_lower = self.evidence_tool.strip().lower()
        if et_lower in self._CONFIRMED_EVIDENCE:
            return VerificationTier.CONFIRMED.value
        tools = et_lower.split("+")
        if any(t.strip().endswith(":witness") for t in tools):
            return VerificationTier.CONFIRMED.value

        first_tool = et_lower.split("+")[0].strip()
        tool_name = first_tool.split(":")[0].strip()
        if tool_name in dispatched or any(
            tool_name in t for t in dispatched
        ):
            return VerificationTier.TOOL_BACKED.value
        return VerificationTier.LLM_ONLY.value


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
        "lifecycle": TierCounters(),
        "triage_skip": TierCounters(),
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
    sarif_clean_resolved: int = 0
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
        default_factory=_threading.Lock,
        repr=False,
    )


class _LockedOutcomes:
    """Thread-safe dict-like for reviewed_outcomes shared across workers."""

    __slots__ = ("_data", "_lock")

    def __init__(self) -> None:
        self._data: Dict[str, ReviewOutcome] = {}
        self._lock = _threading.Lock()

    def __setitem__(self, key: str, value: ReviewOutcome) -> None:
        with self._lock:
            self._data[key] = value

    def __getitem__(self, key: str) -> ReviewOutcome:
        with self._lock:
            return self._data[key]

    def get(self, key: str) -> Optional[ReviewOutcome]:
        with self._lock:
            return self._data.get(key)

    def keys(self) -> set:
        with self._lock:
            return set(self._data.keys())

    def __bool__(self) -> bool:
        return True


def _joern_target(config: OrchestratorConfig) -> Path:
    """Narrow the Joern CPG build target when scope allows it.

    When all scopes share a common prefix that exists as a subdirectory
    of target_path, return that subdirectory instead of the full repo
    root.  This avoids building a multi-GB CPG for an entire monorepo
    when only a small subtree is being audited.
    """
    if not config.scope:
        return config.target_path

    scopes = [config.scope] if isinstance(config.scope, str) else list(config.scope)
    if not scopes:
        return config.target_path

    parts_list = [Path(s).parts for s in scopes]
    common = []
    for segments in zip(*parts_list):
        if len(set(segments)) == 1:
            common.append(segments[0])
        else:
            break

    if not common:
        return config.target_path

    candidate = config.target_path / Path(*common)
    if candidate.is_dir():
        return candidate
    return config.target_path


def _get_dangerous_flows(approx) -> Optional[dict]:
    """Extract dangerous_flows from a TaintApprox object or dict.

    The taint-approx cache round-trips through JSON, so on a resumed
    run ``approx`` may be a plain dict instead of a ``TaintApprox``
    object.  Handle both uniformly.
    """
    if approx is None:
        return None
    if isinstance(approx, dict):
        return approx.get("dangerous_flows") or None
    return getattr(approx, "dangerous_flows", None) or None


def get_reviewed_set(out_dir: Path) -> set:
    """Load set of already-reviewed keys from audit log.

    Keys may be bare (file:name, legacy) or lined (file:name:line).
    Both forms are added so the workqueue filter matches either.

    Error statuses are excluded — they represent transient failures
    (budget exceeded, API error, truncation) and must be retried on
    the next run, not suppressed as "already reviewed".
    """
    reviewed = set()
    for entry in load_audit_log(out_dir):
        if entry.get("action") in ("record", "orchestrator_review"):
            if entry.get("status") == "error":
                continue
            key = entry.get("key", "")
            if key:
                reviewed.add(key)
                head, _, tail = key.rpartition(":")
                if head and tail.isdigit():
                    reviewed.add(head)
    return reviewed


def _line_near(line: int, target_lines: set, *, tolerance: int = 3) -> bool:
    """Check if *line* is within *tolerance* of any line in *target_lines*."""
    return any(abs(line - t) <= tolerance for t in target_lines)


def run_orchestrator(
    config: OrchestratorConfig,
    review_fn: Callable[[Dict[str, Any], OrchestratorConfig], ReviewOutcome],
    *,
    on_progress: Optional[Callable[[int, int, ReviewOutcome], None]] = None,
    prep_cache: Optional[dict] = None,
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
    if prep_cache is None or not prep_cache.get("_caches_cleared"):
        _sink_guard_cache.clear()
        _file_lines_cache.clear()
        if prep_cache is not None:
            prep_cache["_caches_cleared"] = True
    result = OrchestratorResult()
    _jt = _joern_tunables(overrides=config.joern_overrides)
    if _jt is not None:
        joern_timeout_s = _jt.cpg_timeout_s + _jt.query_timeout_s
    else:
        joern_timeout_s = 600

    _caller_owns_joern = config.joern_server is not None
    if _caller_owns_joern:
        joern_server = config.joern_server
        _joern_lifecycle = False
    else:
        _joern_path = _joern_target(config)
        joern_server = _start_joern_server_raw(
            _joern_path, config.joern_overrides, _jt,
        )
        _joern_lifecycle = (
            joern_server is not None
            and hasattr(joern_server, "_proc")
            and joern_server._proc is None
        )
    try:
        return _run_audit_body(
            config,
            review_fn,
            on_progress,
            result=result,
            start_time=start_time,
            joern_server=joern_server,
            joern_timeout_s=joern_timeout_s,
            prep_cache=prep_cache,
        )
    finally:
        from core.analysis.reach_audit import set_joern_server

        set_joern_server(None)
        if _caller_owns_joern:
            pass
        elif _joern_lifecycle:
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
    graph=None,
    reviewed_outcomes=None,
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
    with shared._evidence_lock:
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
    call_edge_index = shared.call_edge_index
    checklist_index = shared.checklist_index
    mechanical_findings = shared.mechanical_findings
    inject_resolver = shared.inject_resolver
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
    gap_key_lined = f"{gap_key}:{gap.get('line_start', 0)}"

    # ── Chain re-review: un-tally the prior outcome ──────────────────
    _prior_outcome = None
    if gap.get("force_review") and reviewed_outcomes:
        _prior_outcome = reviewed_outcomes.get(gap_key)
        if _prior_outcome is not None:
            with result._lock:
                try:
                    result.outcomes.remove(_prior_outcome)
                except ValueError:
                    pass
            _untally_outcome(result, _prior_outcome)

    # ── Triage skip ───────────────────────────────────────────────────
    triage = triage_results.get(gap_key_lined) or triage_results.get(gap_key)
    if triage and triage.bucket == TriageBucket.SKIP and not gap.get("force_review"):
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
            evidence_tool="triage:classifier",
        )
        outcome.line = gap.get("line_start", 0)
        with result._lock:
            result.prefilter_skipped += 1
        try:
            if collector is not None:
                collector.submit(outcome, gap)
            else:
                _commit_outcome(config, outcome, gap)
        except Exception as exc:
            logger.warning(
                "commit failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
        _tally_outcome(result, outcome)
        if reviewed_outcomes is not None:
            reviewed_outcomes[gap_key] = outcome
        if on_progress:
            on_progress(review_idx, total, outcome)
        return outcome

    # ── Dead-code gate (G7): skip LLM for provably dead functions ────
    _dead_reason = _dead_code_reason(gap)
    if not _dead_reason and config.binary_verdicts:
        _fn_name = gap.get("name", "")
        _bo_verdict = config.binary_verdicts.get(_fn_name, "")
        _is_header_inline = (
            gap["file"].endswith(".h")
            and "static" in gap.get("source", "")[:200]
        )
        if (
            _bo_verdict == "absent"
            and gap_key not in entry_points
            and not _is_header_inline
        ):
            _dead_reason = "binary_oracle_absent (not present in compiled binary)"
    if _dead_reason:
        outcome = ReviewOutcome(
            file=gap["file"],
            function=gap["name"],
            status="dormant",
            body=(
                f"[dead-code gate: {_dead_reason}] "
                f"Function is in provably dead code — skipped LLM review."
            ),
            evidence_tool="reachability:dead_code",
        )
        outcome.line = gap.get("line_start", 0)
        try:
            if collector is not None:
                collector.submit(outcome, gap)
            else:
                _commit_outcome(config, outcome, gap)
        except Exception as exc:
            logger.warning(
                "commit failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
        _tally_outcome(result, outcome)
        if reviewed_outcomes is not None:
            reviewed_outcomes[gap_key] = outcome
        if on_progress:
            on_progress(review_idx, total, outcome)
        return outcome

    # ── SAGE: pre-compute source hash for hypothesis recall/store ────
    try:
        from core.sage.hooks import compute_finding_source_hash

        line_start = gap.get("line_start", 0)
        if line_start:
            src_hash = compute_finding_source_hash(
                config.target_path / gap["file"],
                line_start,
            )
            if src_hash:
                gap["_sage_source_hash"] = src_hash
    except Exception:
        pass

    # ── SAGE: recall prior hypothesis verdict → skip if clean/dormant ─
    if not config.force and not gap.get("force_review") and gap.get("_sage_source_hash"):
        try:
            from core.sage.hooks import recall_audit_hypothesis_verdict

            prior = recall_audit_hypothesis_verdict(
                repo_path=str(config.target_path),
                file_path=gap["file"],
                function=gap["name"],
                source_hash=gap["_sage_source_hash"],
            )
        except Exception:
            prior = None
        if prior and prior.get("status") in ("clean", "dormant"):
            prior_status = prior["status"]
            prior_tool = prior.get("tool", "")
            outcome = ReviewOutcome(
                file=gap["file"],
                function=gap["name"],
                status=prior_status,
                body=(
                    f"[SAGE recall: prior {prior_status} verdict with "
                    f"matching source hash] Skipped LLM review."
                ),
                evidence_tool=f"sage:recall:{prior_tool}"
                if prior_tool
                else "sage:recall",
            )
            outcome.line = gap.get("line_start", 0)
            with result._lock:
                result.prefilter_skipped += 1
            try:
                if collector is not None:
                    collector.submit(outcome, gap)
                else:
                    _commit_outcome(config, outcome, gap)
            except Exception as exc:
                logger.warning(
                    "commit failed for %s:%s: %s",
                    gap["file"],
                    gap["name"],
                    exc,
                )
            _tally_outcome(result, outcome)
            if reviewed_outcomes is not None:
                reviewed_outcomes[gap_key] = outcome
            if on_progress:
                on_progress(review_idx, total, outcome)
            return outcome

    # ── Build context ─────────────────────────────────────────────────
    ctx = _build_context(
        config,
        gap,
        checklist,
        context_map,
        evidence_index,
        discovered_evidence=discovered_evidence,
        blind=config.blind_first_pass,
    )

    if triage:
        ctx["triage_bucket"] = triage.bucket.value
        ctx["triage_token_budget"] = triage.token_budget

    gap_key_mech = gap_key
    mech_list = []
    if mechanical_findings and gap_key_mech in mechanical_findings:
        mech_list = list(mechanical_findings[gap_key_mech])
    if inject_resolver and inject_resolver.available:
        inject_findings = inject_resolver.resolve(
            gap["file"], gap["name"],
            gap.get("line_start", 0), gap.get("line_end"),
        )
        if inject_findings:
            mech_list = mech_list + inject_findings
    if mech_list:
        ctx["mechanical_detector_findings"] = mech_list

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
                ctx["source"],
                gap["file"],
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
                ctx["source"],
                gap.get("name", ""),
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
                        lib_info["library"],
                        lib_info["version"],
                        ce_name,
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
                violations = enforce_callee_contracts(
                    gap, ctx["callee_summaries"], source
                )
                if violations:
                    ctx["contract_violations"] = violations
        except ImportError:
            pass

    gap_with_source = gap
    if not gap.get("source") and ctx.get("source"):
        gap_with_source = {**gap, "source": ctx["source"]}

    try:
        from .spec_inference import infer_spec_mechanical

        summaries_for_spec = None
        if ctx.get("callee_summaries"):
            summaries_for_spec = {
                f"{getattr(s, 'file', '')}:{getattr(s, 'function', '')}": s
                for s in ctx["callee_summaries"]
            }
        spec = infer_spec_mechanical(
            gap_with_source,
            checklist=checklist,
            tests=discovered_tests or None,
            summaries=summaries_for_spec,
        )
        if spec and spec.intent:
            ctx["inferred_spec"] = spec
            if spec.preconditions and ctx.get("source"):
                try:
                    from .contracts import enforce_callee_contracts, ContractContext

                    spec_contracts = [
                        ContractContext(
                            callee_function=gap.get("name", ""),
                            callee_file=gap.get("file", ""),
                            preconditions=spec.preconditions,
                            source="spec_inference",
                        )
                    ]
                    existing = ctx.get("callee_contracts", [])
                    ctx["callee_contracts"] = existing + spec_contracts
                except ImportError:
                    pass

            if spec.preconditions and ctx.get("callers"):
                try:
                    from .spec_inference import (
                        verify_preconditions_at_call_sites,
                    )
                    verifications = verify_preconditions_at_call_sites(
                        spec, ctx["callers"],
                    )
                    if verifications:
                        ctx["precondition_verifications"] = verifications
                except Exception:
                    logger.debug(
                        "precondition verification failed for %s:%s",
                        gap.get("file"), gap.get("name"),
                        exc_info=True,
                    )
    except Exception:
        logger.debug(
            "spec_inference failed for %s:%s",
            gap.get("file"),
            gap.get("name"),
            exc_info=True,
        )

    if not ctx.get("inferred_spec") or not ctx["inferred_spec"].intent:
        role_ctx = gap.get("role_context", {})
        is_high_value = (
            role_ctx.get("role") in ("entry_point", "sink")
            or gap.get("priority_score", 0) >= 0.7
        )
        if is_high_value and gap_with_source.get("source"):
            try:
                from .spec_inference import infer_spec_with_llm_sync

                llm_spec = infer_spec_with_llm_sync(
                    gap_with_source,
                    mechanical_spec=ctx.get("inferred_spec"),
                )
                if llm_spec and llm_spec.intent:
                    ctx["inferred_spec"] = llm_spec
            except Exception:
                logger.debug(
                    "llm spec_inference failed for %s:%s",
                    gap.get("file"),
                    gap.get("name"),
                    exc_info=True,
                )

    if typestate_models and ctx.get("source"):
        try:
            from core.analysis.typestate import check_typestate_violations

            ts_violations = check_typestate_violations(
                ctx["source"],
                typestate_models,
            )
            if ts_violations:
                ctx["typestate_violations"] = ts_violations
        except Exception:
            logger.debug(
                "typestate check failed for %s:%s",
                gap.get("file"),
                gap.get("name"),
                exc_info=True,
            )

    if conventions:
        strategies = gap.get("strategies", set())
        if isinstance(strategies, (list, tuple)):
            strategies = set(strategies)
        ns_findings = []
        for strat in strategies or {"general"}:
            ns_findings.extend(
                check_negative_space(gap_with_source, conventions, strat)
            )

        # Match on identity, not prose. NegativeSpaceFinding carries
        # file/function, so substring-searching the function name in
        # `evidence` only misroutes: duplicate names across files, and
        # prefixes like handle_user / handle_user_admin.
        gap_file, gap_name = gap.get("file", ""), gap.get("name", "")
        func_sibling_ns = [
            f
            for f in sibling_ns_findings
            if (f.file, f.function) == (gap_file, gap_name)
        ]
        ns_findings.extend(func_sibling_ns)

        if ns_findings:
            ctx["negative_space"] = ns_findings
            evidence_key = f"{gap['file']}:{gap['name']}"
            if evidence_key in evidence_index:
                with shared._evidence_lock:
                    evidence_index[evidence_key].negative_space = ns_findings

    func_name = gap.get("name", "")
    func_file = gap.get("file", "")

    if shared.capability_displacements:
        func_displacements = [
            d for d in shared.capability_displacements
            if func_file == d.file
        ]
        if func_displacements:
            try:
                from .dispatch_table import format_displacement_context
                _dc = format_displacement_context(func_displacements)
                if _dc:
                    ctx["capability_displacement"] = _dc
            except Exception:
                pass

    if shared.struct_accessor_index:
        try:
            from .struct_accessor_index import (
                get_co_accessors,
                format_co_accessor_context,
            )
            co_groups = get_co_accessors(
                shared.struct_accessor_index, func_name, func_file,
            )
            _cac = format_co_accessor_context(co_groups)
            if _cac:
                ctx["co_accessor_analysis"] = _cac
        except Exception:
            pass

    sib_viols = [
        v
        for v in sibling_postcond_violations
        if v.function == func_name and v.file == func_file
    ]
    if sib_viols:
        ctx.setdefault("postcondition_violations", []).extend(sib_viols)

    if fuzz_coverage:
        ctx["fuzz_coverage"] = _fuzz_coverage_for(
            fuzz_coverage,
            gap["file"],
            gap["name"],
        )

    if gap_key in widely_used_keys:
        ctx["widely_used"] = True
    if gap_key in variant_targets:
        ctx["variant_match"] = True
    if sarif_cache:
        sarif_hits = sarif_cache.lookup(gap["file"])
        if sarif_hits is not None and not sarif_hits:
            ctx["codeql_no_alerts"] = True
    if gap.get("_race_protected"):
        ctx["race_protected"] = gap["_race_protection_detail"]
    if gap.get("_smt_pre_evidence"):
        ctx["smt_pre_evidence"] = gap["_smt_pre_evidence"]

    if config.enable_session_context and session_observations:
        with shared._observations_lock:
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
            shared.constraints,
            gap["file"],
            gap["name"],
        )
        if relevant:
            ctx["active_constraints"] = relevant

    # ── Chain findings from connected functions ──────────────────────
    if reviewed_outcomes and (call_edge_index or call_edges):
        chain = _collect_chain_findings(
            gap_key, call_edges, reviewed_outcomes,
            call_edge_index=call_edge_index,
        )
        if chain:
            ctx["chain_findings"] = chain

    # ── Prefilter ─────────────────────────────────────────────────────
    pf_result = None
    if config.prefilter:
        pf_result = _run_prefilter_for_gap(config, gap, ctx, domain_model)
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
                evidence_tool="prefilter:skip",
            )
            outcome.line = gap.get("line_start", 0)
            with result._lock:
                result.prefilter_skipped += 1
            try:
                if collector is not None:
                    collector.submit(outcome, gap)
                else:
                    _commit_outcome(config, outcome, gap)
            except Exception as exc:
                logger.warning(
                    "commit failed for %s:%s: %s",
                    gap["file"],
                    gap["name"],
                    exc,
                )
            _tally_outcome(result, outcome)
            if reviewed_outcomes is not None:
                reviewed_outcomes[gap_key] = outcome
            if on_progress:
                on_progress(review_idx, total, outcome)
            return outcome

        if pf_result.hits:
            with result._lock:
                result.prefilter_hits += len(pf_result.hits)
            if not config.blind_first_pass:
                ctx["prefilter_results"] = pf_result

    # ── Block-level context ───────────────────────────────────────────
    try:
        block_ctx = _try_block_level_context(
            gap,
            ctx,
            config,
            evidence_index,
        )
        if block_ctx:
            ctx["block_analysis"] = block_ctx
    except Exception:
        logger.debug(
            "block-level analysis failed for %s:%s",
            gap["file"],
            gap["name"],
            exc_info=True,
        )

    # ── Intra-function sibling analysis ─────────────────────────────
    try:
        from .intra_function import analyse_intra_function, format_intra_function_context
        _ifsa = analyse_intra_function(ctx.get("source", ""))
        _ifsa_ctx = format_intra_function_context(_ifsa)
        if _ifsa_ctx:
            ctx["intra_function_analysis"] = _ifsa_ctx
    except Exception:
        pass

    _fuse_all_evidence(ctx)

    # ── LLM review ────────────────────────────────────────────────────
    review_start = time.monotonic()
    if config.review_passes > 1:
        outcome = _multi_pass_review(
            review_fn,
            ctx,
            config,
            config.review_passes,
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
                gap["file"],
                gap["name"],
                exc,
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
        and any(h.rule_id in _STRUCTURAL_PREFILTER_RULES for h in pf_result.hits)
    ):
        hit = next(
            h for h in pf_result.hits if h.rule_id in _STRUCTURAL_PREFILTER_RULES
        )
        outcome.status = "suspicious"
        outcome.body = (
            f"[prefilter override: {hit.rule_id}] "
            f"LLM ruled clean but mechanical detector flagged "
            f"a structural bug: {hit.message}"
        )
        logger.warning(
            "prefilter override %s:%s: %s (LLM said clean)",
            gap["file"],
            gap["name"],
            hit.rule_id,
        )

    # ── Anti-self-refutation gate (promotion: clean → suspicious) ────
    if outcome.status == "clean":
        try:
            from .refutation import rescue_self_refuted

            rv = rescue_self_refuted(outcome)
            if rv is not None:
                append_audit_log(config.out_dir, {
                    "action": "refutation_gate",
                    "gate": rv.gate,
                    "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
                    "file": outcome.file,
                    "function": outcome.function,
                    "reason": rv.reason,
                    "demote_to": rv.demote_to,
                    "original_status": outcome.status,
                    "applied": True,
                })
                logger.info(
                    "anti-self-refutation %s:%s — %s → %s",
                    outcome.file, outcome.function,
                    rv.reason, rv.demote_to,
                )
                outcome.status = rv.demote_to
                outcome.body = (
                    f"[{rv.gate}: {rv.reason}]\n\n" + outcome.body
                )
        except Exception:
            logger.debug(
                "anti-self-refutation error for %s:%s",
                outcome.file, outcome.function,
                exc_info=True,
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
                with result._lock:
                    result.clean_checks += 1
                cc_flows = _run_clean_check_sweep(
                    outcome,
                    config,
                    evidence_index,
                    joern_server,
                )
                if cc_flows:
                    cc_prompt = build_clean_check_prompt(ctx, cc_flows)
                    cc_ctx = dict(ctx)
                    cc_ctx["clean_check"] = cc_prompt
                    try:
                        revised = review_fn(cc_ctx, config)
                        if revised.status != "clean":
                            outcome = _merge_clean(outcome, revised)
                            with result._lock:
                                result.clean_check_rescues += 1
                            logger.info(
                                "clean-check rescue %s:%s → %s",
                                gap["file"],
                                gap["name"],
                                outcome.status,
                            )
                    except Exception:
                        logger.debug(
                            "clean-check review failed for %s:%s",
                            gap["file"],
                            gap["name"],
                            exc_info=True,
                        )
        except ImportError:
            logger.warning(
                "refinement module unavailable — clean-check rescue disabled",
            )

    # ── Sweep validation ──────────────────────────────────────────────
    pre_sweep_status = outcome.status
    if outcome.status == "finding" and config.sweep_validate_findings:
        outcome = _sweep_validate(
            outcome,
            config,
            sarif_cache,
            tier_counters=result.tier_counters,
            evidence_index=evidence_index,
            joern_server=joern_server,
        )
        with result._lock:
            if outcome.status == "finding":
                result.sweep_validated += 1
            else:
                result.sweep_demoted += 1

    # ── Proactive validation ──────────────────────────────────────────
    if outcome.status in ("finding", "suspicious") and not config.blind_first_pass:
        outcome = _proactive_validate(
            outcome,
            config,
            evidence_index,
            tier_counters=result.tier_counters,
            dispatched_tools=outcome.tools_dispatched,
            discovered_evidence=discovered_evidence,
            flow_traces=flow_traces,
            joern_server=joern_server,
        )
        if outcome.evidence_tool:
            with shared._evidence_lock:
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
                dispatch_suggestion,
                merge_outcomes as _merge_refined,
                RefinementContext,
                should_refine as _should_refine,
            )

            bucket_val = triage.bucket.value if triage else "investigate"
            ref_round = 0
            prev_suggestion = ""
            while _should_refine(
                outcome,
                bucket_val,
                round_number=ref_round,
                max_refinements=config.max_refinements,
            ) and not _check_budget(config, start_time, result):
                ref_round += 1
                with result._lock:
                    result.refinement_rounds += 1

                prior_review = outcome.review_result or {}
                suggestion = prior_review.get("tool_query_suggestion", "")

                if suggestion and suggestion != prev_suggestion:
                    new_results = dispatch_suggestion(
                        suggestion, outcome, ctx, config,
                    )
                    prev_suggestion = suggestion
                else:
                    new_results = []

                tool_results = collect_tool_results(
                    outcome,
                    evidence_index=evidence_index,
                )
                tool_results.extend(new_results)

                ref_ctx = RefinementContext(
                    prior_hypothesis=outcome.hypothesis or "",
                    prior_status=outcome.status,
                    tool_results=tool_results,
                    tools_dispatched=outcome.tools_dispatched or set(),
                    round_number=ref_round,
                    tool_query_suggestion=suggestion,
                )
                ref_prompt = build_refinement_prompt(ctx, ref_ctx)
                ref_review_ctx = dict(ctx)
                ref_review_ctx["refinement"] = ref_prompt
                try:
                    refined = review_fn(ref_review_ctx, config)
                except Exception:
                    logger.debug(
                        "refinement review failed for %s:%s round %d",
                        gap["file"],
                        gap["name"],
                        ref_round,
                        exc_info=True,
                    )
                    break
                outcome = _merge_refined(outcome, refined)
                logger.debug(
                    "refinement round %d for %s:%s → %s",
                    ref_round,
                    gap["file"],
                    gap["name"],
                    outcome.status,
                )

                if outcome.status != ref_ctx.prior_status:
                    break
        except ImportError:
            pass

    # ── Provenance annotation ────────────────────────────────────────
    if provenance_map and gap_key_mech in provenance_map:
        prov_entries = provenance_map[gap_key_mech]
        if prov_entries and all(
            e.get("trust", "") == "trusted" for e in prov_entries
        ):
            outcome.provenance_all_trusted = True

    # ── Reachability gate ─────────────────────────────────────────────
    if outcome.status == "finding":
        outcome = _apply_reachability_gate(
            outcome,
            ctx,
            entry_points,
            config,
        )

    # ── Speculative race gate ────────────────────────────────────────
    if outcome.status in ("finding", "suspicious"):
        outcome = _apply_speculative_race_demotion(outcome)

    # ── Caller attribution annotation ──────────────────────────────
    if outcome.status in ("finding", "suspicious"):
        outcome = _apply_caller_attribution(outcome, ctx.get("callers", []))

    # ── Finding gates ─────────────────────────────────────────────────
    if outcome.status == "finding":
        gate_violations = _check_finding_gates(
            outcome,
            audit_log=audit_log,
            domain_model=domain_model,
            mode=config.mode,
        )
        if gate_violations:
            for v in gate_violations:
                logger.warning(
                    "gate violation %s:%s: %s — demoted to suspicious",
                    outcome.file,
                    outcome.function,
                    v,
                )
            outcome = _demote_outcome(
                outcome,
                f"[gate violation: {'; '.join(gate_violations)}]",
            )

    # ── Semantic confidence classification ──────────────────────────
    if outcome.status in ("finding", "suspicious") and not outcome.semantic_confidence:
        try:
            from .semantic_confidence import classify_semantic_confidence
            _sc = classify_semantic_confidence(
                outcome.hypothesis or "",
                ctx.get("source", ""),
                line_start=gap.get("line_start", 0),
            )
            if _sc == "high":
                outcome.semantic_confidence = "high"
        except Exception:
            pass

    # ── Refutation gates ──────────────────────────────────────────────
    # Cheap mechanical checks that kill false-positive hypotheses.
    # Runs after G2 finding gates, before suspicious-demotion.
    if outcome.status in ("finding", "suspicious"):
        try:
            from .refutation import refute_hypothesis

            rv = refute_hypothesis(
                outcome,
                domain_model=domain_model,
                checklist=checklist,
                config=config,
                joern_server=joern_server,
            )
            if rv is not None:
                append_audit_log(config.out_dir, {
                    "action": "refutation_gate",
                    "gate": rv.gate,
                    "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
                    "file": outcome.file,
                    "function": outcome.function,
                    "reason": rv.reason,
                    "demote_to": rv.demote_to,
                    "original_status": outcome.status,
                    "applied": True,
                })
                logger.info(
                    "refutation gate [%s] %s:%s — %s → %s",
                    rv.gate, outcome.file, outcome.function,
                    rv.reason, rv.demote_to,
                )
                outcome = _demote_outcome(
                    outcome, f"[{rv.gate}: {rv.reason}]",
                )
                outcome.status = rv.demote_to
        except Exception:
            logger.debug(
                "refutation gate error for %s:%s",
                outcome.file, outcome.function,
                exc_info=True,
            )

    # ── Suspicious demotion gate ────────────────────────────────────
    # Runs AFTER finding gates (G2) so that finding→suspicious demotions
    # are also caught.
    # Suspicious without verification evidence demotes to clean.
    # Only active when Joern is running (cross-function verifiers need
    # the CPG to confirm interprocedural bugs that intra-function
    # SMT/Coccinelle can't reach).
    if (
        outcome.status == "suspicious"
        and joern_server is not None
        and not _is_verification_evidence_for_gate(outcome)
    ):
        outcome.status = "clean"
        outcome.body = (
            "[suspicious-demotion: no verification evidence "
            "with Joern available]\n\n" + outcome.body
        )

    # ── Dynamic validation ────────────────────────────────────────────
    if config.dynamic_validation and outcome.status == "finding":
        try:
            from .dynamic_sweep import should_run_dynamic, run_dynamic_sweep

            if should_run_dynamic(outcome, config):
                dyn_result = run_dynamic_sweep(outcome, ctx, config)
                if dyn_result and dyn_result.evidence_strength == "sanitizer":
                    outcome.evidence_tool = "dynamic:sanitizer"
                elif dyn_result and dyn_result.evidence_strength == "crash":
                    outcome.evidence_tool = "dynamic:crash"
                elif dyn_result and dyn_result.evidence_strength == "refuted":
                    outcome = _demote_outcome(outcome, "[dynamic: refuted]")
        except Exception:
            logger.debug(
                "dynamic sweep failed for %s:%s",
                gap.get("file"),
                gap.get("name"),
                exc_info=True,
            )

        # Frida runs as a second opinion when the dynamic sweep produced only
        # a bare crash ("dynamic:crash") — that's weak evidence and Frida may
        # upgrade it to runtime-confirmed. Skip only when the sanitiser already
        # confirmed ("dynamic:sanitizer").
        if outcome.status == "finding" and outcome.evidence_tool != "dynamic:sanitizer":
            try:
                from .frida_observe import should_run_frida, run_frida_observation

                if should_run_frida(outcome, config):
                    frida_result = run_frida_observation(outcome, ctx, config)
                    if frida_result and frida_result.evidence_strength == "confirmed":
                        outcome.evidence_tool = "frida:runtime"
            except Exception:
                logger.debug(
                    "Frida observation failed for %s:%s",
                    gap.get("file"),
                    gap.get("name"),
                    exc_info=True,
                )

    # ── Mid-loop synthesis ────────────────────────────────────────────
    if outcome.status == "finding" and _is_tool_confirmed(outcome.evidence_tool or ""):
        try:
            from .checker_synthesis import synthesize_and_sweep

            seen_keys = (reviewed_set or set()) | {
                f"{g['file']}:{g['name']}" for g in (workqueue or [])
            }
            synth = synthesize_and_sweep(
                outcome,
                config,
                seen_keys,
                synthesis_count=result.synthesis_amplified,
            )
            if synth and synth.cost_usd:
                result.cost_tracker.record_call(
                    "checker_synthesis", cost_usd=synth.cost_usd,
                )
                with result._lock:
                    result.total_cost_usd += synth.cost_usd
            if synth and synth.hits:
                for hit in synth.hits:
                    hit.setdefault("priority_score", 0.8)
                    shared.synthesis_queue.append(hit)
                with result._lock:
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
                    len(synth.hits),
                    outcome.file,
                    outcome.function,
                )
        except Exception:
            logger.debug(
                "mid-loop synthesis failed for %s:%s",
                outcome.file,
                outcome.function,
                exc_info=True,
            )

    # ── Publish outcome before chain injection ─────────────────────────
    # The outcome, taint summaries, and constraints must be visible
    # before chain injection pushes neighbours onto the ready queue —
    # otherwise a concurrent worker can pop the re-queued neighbour
    # and call _collect_chain_findings before our outcome is stored.
    if reviewed_outcomes is not None:
        reviewed_outcomes[gap_key] = outcome

    if outcome.review_result and taint_summary_results is not None:
        from core.analysis.summaries import (
            summary_from_review_result,
            propagate_taint_upward,
        )

        llm_summary = summary_from_review_result(
            outcome.function,
            outcome.file,
            outcome.review_result,
        )
        if llm_summary:
            with shared._taint_lock:
                key = f"{outcome.file}:{outcome.function}"
                if key not in taint_summary_results:
                    taint_summary_results[key] = llm_summary

                for edge in call_edges or []:
                    callee_name = edge.get("callee", "")
                    if callee_name != outcome.function:
                        continue
                    caller_key = f"{edge['caller_file']}:{edge['caller']}"
                    caller_sum = taint_summary_results.get(caller_key)
                    if caller_sum:
                        call_args = edge.get("args", [])
                        propagate_taint_upward(llm_summary, caller_sum, call_args)

    if config.propagate_constraints and outcome.review_result:
        with shared._constraints_lock:
            shared.constraints = _extract_and_propagate(
                outcome,
                shared.constraints,
                checklist,
                entry_points,
                prop_config,
                tier_counters=result.tier_counters,
            )

    # ── Mid-loop chain injection ────────────────────────────────────────
    # Only chain-inject from findings (tool-grounded evidence).
    # Suspicious-only verdicts are LLM guesses; chain-following from
    # guesses cascades nil-deref and other FP hypotheses across the
    # call graph, flipping correct clean verdicts to suspicious.
    if outcome.status == "finding" and graph is not None:
        try:
            finding_prio = gap.get("priority_score", 0.0) + _CHAIN_PRIORITY_BOOST
            _inject_chain_targets(
                outcome,
                graph,
                call_edges,
                checklist,
                reviewed_outcomes=reviewed_outcomes,
                finding_priority=finding_prio,
                call_edge_index=call_edge_index,
                checklist_index=checklist_index,
            )
        except Exception:
            logger.debug(
                "chain injection failed for %s:%s",
                gap.get("file"),
                gap.get("name"),
                exc_info=True,
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
            gap["file"],
            gap["name"],
            exc,
        )

    _tally_outcome(result, outcome)

    # ── Post-commit tracking ──────────────────────────────────────────
    review_result = getattr(outcome, "review_result", None)
    if review_result and review_result.get("reading_list"):
        sq = getattr(shared, "study_queue", None)
        if sq is not None:
            for rl_item in review_result["reading_list"]:
                if isinstance(rl_item, dict) and rl_item.get("question"):
                    sq.enqueue(StudyRequest(
                        question=rl_item["question"],
                        source_file=gap["file"],
                        source_function=gap["name"],
                        priority=rl_item.get("priority", "normal"),
                        resolution=rl_item.get("resolution", "identifier"),
                        context=rl_item.get("context", ""),
                    ))

    if live_classifications is not None and outcome.review_result:
        try:
            from .live_classifications import extract_from_outcome as _extract_live
            with shared._live_lock:
                _extract_live(outcome, gap, live_classifications)
        except Exception:
            logger.debug(
                "live classification extraction failed for %s:%s",
                gap.get("file", ""),
                gap.get("name", ""),
                exc_info=True,
            )

    if (
        pf_result
        and pf_result.hits
        and checker_library
        and checker_library.all_entries()
    ):
        is_tp = outcome.status in ("finding", "suspicious")
        for hit in pf_result.hits:
            checker_library.record_match(hit.rule_id, is_tp)

    disagree = _check_layer_disagreement(outcome, ctx, gap)
    if disagree is not None:
        if layer_disagreements is not None:
            layer_disagreements.append(disagree)

    if config.enable_session_context and outcome.review_result:
        with shared._observations_lock:
            _accumulate_observations(
                session_observations, outcome, gap,
                sweep_pre_status=pre_sweep_status,
            )

    # ── SAGE: chain re-review status change observation ──────────────
    if _prior_outcome is not None and outcome.status != _prior_outcome.status:
        source = f"{gap['file']}:{gap['name']}"
        obs = (
            f"[chain re-review] {source}: "
            f"{_prior_outcome.status} → {outcome.status} "
            f"after neighbour finding provided chain context"
        )
        if outcome.hypothesis:
            obs += f" (hypothesis: {outcome.hypothesis[:200]})"
        _sage_store_observation(obs, "chain_status_change", source)

    if (
        config.critique_interval > 0
        and review_idx > 0
        and review_idx % config.critique_interval == 0
    ):
        _run_critique(result, config, sarif_cache, joern_server=joern_server)

    if on_progress:
        on_progress(review_idx, total, outcome)

    return outcome


def _compute_audit_prep(config, *, joern_server=None, on_progress=None):
    """Compute all mode-independent prep for the audit loop.

    Returns a dict of prep results, or None if checklist is missing.
    In ensemble mode, this is called once and the result shared across
    both passes — all computation here is mode-independent.
    """
    checklist = load_checklist(config.out_dir)
    if not checklist:
        logger.error("no checklist.json in %s", config.out_dir)
        return None

    context_map = load_context_map(config.out_dir)
    if context_map is None:
        context_map = _try_understand_bridge(config)
    if context_map is None:
        context_map = {}
    if "call_edges" not in context_map:
        from core.orchestration.context_map_callgraph import enrich_with_call_edges

        edge_count = enrich_with_call_edges(
            context_map,
            checklist=checklist,
        )
        if edge_count:
            logger.debug("bootstrapped %d call edges from checklist", edge_count)
    flow_traces = load_flow_traces(config.out_dir)

    variant_targets = _load_variants(config.out_dir)

    sarif_cache = SarifCache.from_directory(config.out_dir)

    if config.codeql_db_path and not sarif_cache:
        _codeql_pre_sweep_raw(config.codeql_db_path, config.out_dir, sarif_cache)

    sarif_clean_files: Set[str] = set()
    if sarif_cache:
        from .sweep import _normalize_sarif_path

        _sarif_alerted_files = set(sarif_cache._by_file.keys())
        for _fi in checklist.get("files", []):
            _fp = _fi.get("path", "")
            if not _fp:
                continue
            if _normalize_sarif_path(_fp) not in _sarif_alerted_files:
                sarif_clean_files.add(_fp)
        if sarif_clean_files:
            logger.info(
                "sarif_clean: %d / %d checklist files have zero SARIF alerts",
                len(sarif_clean_files),
                len(sarif_clean_files) + len(_sarif_alerted_files),
            )

    taint_approx_results = _load_or_build_taint_approx_raw(
        config.target_path, config.out_dir,
        scope=config.scope,
    )
    taint_summary_results = _build_taint_summary_raw(
        config.target_path, scope=config.scope,
    )
    sink_results = _build_sink_results_raw(
        config.target_path,
        taint_approx_results,
        checklist=checklist,
        out_dir=config.out_dir,
        scope=config.scope,
    )

    if sink_results is not None and "sinks" not in context_map:
        from core.orchestration.context_map_sinks import _populate_sinks_array

        _populate_sinks_array(context_map, sink_results)

    joern_future: Optional[Future] = None
    joern_flows: Optional[Dict[str, list]] = None

    imported_joern = _import_sibling_joern_flows_raw(
        config.out_dir, target_path=config.target_path
    )

    cm_sinks = context_map.get("sink_details", []) if context_map else None

    from .binary_bridge import load_binary_bridge

    if config.no_binary_oracle:
        binary_bridge_early = None
    else:
        binary_bridge_early = load_binary_bridge(
            config.out_dir,
            target_path=config.target_path,
        )

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
        scope=config.scope,
    )

    try:
        from .validate_bridge import import_validate_evidence

        _bridge_project = (
            Path(config.out_dir).parent
            if config.out_dir and (Path(config.out_dir) / ".raptor-run.json").exists()
            else None
        )
        bridge_result = import_validate_evidence(
            config.out_dir,
            config.target_path,
            project_dir=_bridge_project,
        )
        if bridge_result and (
            bridge_result.feasibility_verdicts or bridge_result.runtime_evidence
        ):
            _merge_validate_evidence(bridge_result, evidence_index)
            logger.info(
                "validate bridge: imported %d feasibility verdicts,"
                " %d runtime evidence items",
                len(bridge_result.feasibility_verdicts),
                len(bridge_result.runtime_evidence),
            )
    except Exception:
        logger.debug("validate bridge import failed", exc_info=True)

    try:
        from .binary_layer0 import (
            scan_function as layer0_scan,
            format_layer0_summary,
            Layer0Result,
        )

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
    tool_capabilities = {
        "joern": joern_server is not None,
        "binary": binary_bridge_early is not None,
        "codeql": config.codeql_db_path is not None,
        "semgrep": caps.semgrep,
        "coccinelle": caps.coccinelle,
        "r2": caps.r2,
        "frida": caps.frida,
        "ghidra": caps.ghidra,
    }
    degradation_report = assess_degradation(tool_capabilities)
    if degradation_report.degraded:
        logger.info(
            "degradation: %d tools degraded to fallback\n%s",
            len(degradation_report.degraded),
            format_degradation_report(degradation_report),
        )

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
                context_map,
                threat_model=config.threat_model,
            )
            security_decision_keys = build_security_decision_set(context_map)
            feeds_security_keys = frozenset(
                build_feeds_security_map(context_map).keys(),
            )
            if provenance_map:
                logger.info(
                    "mechanical gates: provenance map covers %d functions, "
                    "%d security-decision points",
                    len(provenance_map),
                    len(security_decision_keys),
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
    fuzz_coverage = _load_fuzz_coverage(config.out_dir)

    _project_dir = (
        Path(config.out_dir).parent
        if config.out_dir and (Path(config.out_dir) / ".raptor-run.json").exists()
        else None
    )
    gaps = compute_gaps(
        checklist,
        [] if config.force else coverage_records,
        context_map=context_map,
        strategy_filter=config.strategy_filter,
        scope=config.scope,
        fuzz_coverage=fuzz_coverage,
        out_dir=None if config.force else config.out_dir,
        project_dir=None if config.force else _project_dir,
    )

    _joern_last_activity = [time.monotonic()]

    if gaps:

        def _joern_progress_cb(msg: str) -> None:
            _joern_last_activity[0] = time.monotonic()
            if on_progress:
                placeholder = ReviewOutcome(
                    file="",
                    function="",
                    status="clean",
                    body=msg,
                )
                on_progress(-1, 0, placeholder)

        joern_flows, joern_future = _resolve_joern_evidence_raw(
            _joern_target(config),
            joern_overrides=config.joern_overrides,
            on_joern_progress=_joern_progress_cb,
            joern_server=joern_server,
            out_dir=config.out_dir,
        )

        if joern_flows is not None:
            evidence_index = _merge_joern_flows(
                joern_flows,
                evidence_index,
                checklist,
                sarif_cache,
            )
            if joern_server is not None and taint_summary_results is not None:
                _enrich_summaries_from_joern(
                    joern_server,
                    joern_flows,
                    taint_summary_results,
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
            gaps,
            taint_chain_callees=taint_chain_callees,
        )
        if iris_candidates:
            iris_taint_specs = [_iris_candidate_to_spec(c) for c in iris_candidates]
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

    project_sinks = None
    try:
        from core.iris.api import get_project_sinks
        project_sinks = get_project_sinks(out_dir=config.out_dir)
        if project_sinks:
            logger.info("IRIS: loaded %d project sinks for wrapper pre-filter", len(project_sinks))
    except Exception:
        logger.debug("IRIS sink loading skipped", exc_info=True)

    if config.include_stale:
        ann_dir = config.annotations_dir or _resolve_ann_dir(config.out_dir)
        gaps = _merge_stale(gaps, ann_dir, config.target_path)

    prior_constraints = load_constraints(config.out_dir)
    open_keys = (
        {f"{c.file}:{c.function}" for c in open_constraints(prior_constraints)}
        if prior_constraints
        else None
    )

    sibling_dirs = _sibling_run_dirs(config.out_dir, target_path=config.target_path)
    tool_failures = load_tool_failures(sibling_dirs) if sibling_dirs else None
    fuzz_cov_files = (
        _load_fuzz_coverage_from_runs(sibling_dirs) if sibling_dirs else None
    )

    from .strategy_stats import load_strategy_weights

    strat_weights = load_strategy_weights(
        config.out_dir, target_path=config.target_path
    )

    gaps = score_functions(
        gaps,
        context_map=context_map,
        flow_traces=flow_traces,
        threat_model=config.threat_model,
        open_constraint_keys=open_keys,
        tool_failures=tool_failures,
        fuzz_coverage=fuzz_cov_files,
        strategy_weights=strat_weights,
        binary_bridge=binary_bridge_early,
    )

    if config.budget and config.budget > 0:
        gaps = gaps[: config.budget]

    entry_points = extract_context_map_set(context_map, "entry_points")

    try:
        from .ops_struct import collect_ops_entry_points

        _ops_srcs: Dict[str, str] = {}
        for gap in gaps:
            fp = gap.get("file", "")
            if fp and fp not in _ops_srcs:
                try:
                    sp = config.target_path / fp
                    if sp.is_file():
                        _ops_srcs[fp] = sp.read_text(errors="replace")
                except Exception:
                    pass
        _ops_eps = collect_ops_entry_points(_ops_srcs)
        if _ops_eps:
            entry_points = entry_points | _ops_eps
            logger.info(
                "ops-struct reachability: %d indirect entry points added",
                len(_ops_eps),
            )
    except Exception:
        logger.debug("ops-struct entry point extraction failed", exc_info=True)

    sinks_set = extract_context_map_set(context_map, "sinks")
    trust_boundary_set = extract_context_map_set(
        context_map,
        "trust_boundaries",
        nested_key="functions",
    )
    joern_flow_keys = (
        frozenset(k for k, rec in evidence_index.items() if rec.all_joern_flows())
        if evidence_index
        else frozenset()
    )
    sink_unreachable_keys = (
        frozenset(k for k, rec in evidence_index.items() if rec.sink_unreachable)
        if evidence_index
        else frozenset()
    )
    dangerous_callee_keys = (
        frozenset(
            k
            for k, rec in evidence_index.items()
            if rec.has_any_evidence() and not rec.sink_unreachable
        )
        if evidence_index
        else frozenset()
    )
    priority_scores = {
        f"{g['file']}:{g['name']}": g.get("priority_score", 0.0) for g in gaps
    }
    try:
        from core.concepts.audit_bridge import domain_key_files
        _kf = domain_key_files(config.out_dir)
        if _kf:
            _boosted = 0
            for key, score in priority_scores.items():
                file_path = key.rsplit(":", 1)[0]
                if file_path in _kf:
                    priority_scores[key] = score + _KEY_FILE_PRIORITY_BOOST
                    _boosted += 1
            if _boosted:
                logger.info("key_files boost: %d functions boosted", _boosted)
    except Exception:
        logger.debug("key_files boost failed", exc_info=True)
    taint_path_keys = frozenset(
        k
        for k, approx in (taint_approx_results or {}).items()
        if getattr(approx, "has_any_dangerous_flow", lambda: False)()
        or getattr(approx, "direct_flows", None)
    )
    from .triage import detect_generated_files

    generated_files = set(detect_generated_files(gaps, target_path=config.target_path))
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

    detector_gaps = hydrate_live_gaps_for_detectors(
        [g for g in gaps if not g.get("dead")],
        Path(config.target_path),
    )
    conventions = discover_conventions(detector_gaps)
    if conventions:
        logger.info(
            "negative-space: discovered %d security conventions",
            len(conventions),
        )

    from core.analysis.peer_groups import resolve_peer_groups

    gap_func_dicts = [
        {
            "name": g.get("name", ""),
            "file": g.get("file", ""),
            "line": g.get("line", 0),
            "source": g.get("source", ""),
        }
        for g in gaps
        if g.get("name")
    ]
    peer_groups = resolve_peer_groups(
        gap_func_dicts,
        joern_server=joern_server,
        checklist=checklist,
    )

    sibling_ns_findings = (
        check_sibling_negative_space(
            detector_gaps, conventions, peer_groups=peer_groups,
        ) if conventions else []
    )
    if sibling_ns_findings:
        logger.info(
            "sibling analysis: %d asymmetry findings across peer groups",
            len(sibling_ns_findings),
        )

    try:
        from .dispatch_table import check_capability_displacement
        capability_displacements = check_capability_displacement(detector_gaps)
        if capability_displacements:
            logger.info(
                "dispatch-table analysis: %d capability displacement(s)",
                len(capability_displacements),
            )
    except Exception:
        capability_displacements = []
        logger.debug("dispatch-table analysis skipped", exc_info=True)

    try:
        from .struct_accessor_index import build_index_from_source
        struct_accessor_index = build_index_from_source(detector_gaps)
        if struct_accessor_index:
            logger.info(
                "struct-accessor index: %d fields tracked across functions",
                len(struct_accessor_index),
            )
    except Exception:
        struct_accessor_index = {}
        logger.debug("struct-accessor index skipped", exc_info=True)

    from .postcondition_verify import (
        check_sibling_ordering,
        check_sibling_sanitizer_strength,
    )

    sibling_postcond_violations = []
    for pg in peer_groups:
        pg_gaps = [
            g
            for g in gaps
            if any(
                s.function == g.get("name") and s.file == g.get("file")
                for s in pg.siblings
            )
        ]
        sibling_postcond_violations.extend(check_sibling_ordering(pg_gaps))
        sibling_postcond_violations.extend(check_sibling_sanitizer_strength(pg_gaps))

    if sibling_postcond_violations:
        logger.info(
            "sibling postcondition: %d ordering/strength violations",
            len(sibling_postcond_violations),
        )

    semantic_findings: List[Dict[str, Any]] = []
    try:
        from .sibling_analysis import check_semantic_consistency

        source_map = {
            f"{g['file']}:{g['name']}": {"source": g.get("source", "")}
            for g in gaps
            if g.get("source")
        }
        semantic_findings = check_semantic_consistency(peer_groups, source_map)
        if semantic_findings:
            logger.info(
                "semantic consistency: %d outliers across peer groups",
                len(semantic_findings),
            )
    except Exception:
        logger.debug("semantic consistency check failed", exc_info=True)

    mechanical_findings: Dict[str, List[Dict[str, Any]]] = {}
    guard_clean_keys: set[str] = set()
    try:
        mechanical_findings, guard_clean_keys = _run_mechanical_detectors(
            gaps,
            config,
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
            logger.info(
                "wrote %d mechanical findings to %s",
                sum(len(v) for v in mechanical_findings.values()),
                mech_path,
            )
        except Exception:
            logger.debug("failed to persist mechanical findings", exc_info=True)

    call_edges = context_map.get("call_edges", []) if context_map else []
    widely_used_keys = set()
    try:
        from .priority import detect_widely_used
        widely_used_keys = detect_widely_used(checklist)
    except Exception:
        logger.debug("detect_widely_used failed", exc_info=True)

    return {
        "checklist": checklist,
        "context_map": context_map,
        "flow_traces": flow_traces,
        "variant_targets": variant_targets,
        "sarif_cache": sarif_cache,
        "sarif_clean_files": sarif_clean_files,
        "taint_approx_results": taint_approx_results,
        "taint_summary_results": taint_summary_results,
        "sink_results": sink_results,
        "evidence_index": evidence_index,
        "binary_bridge_early": binary_bridge_early,
        "caps": caps,
        "project_sinks": project_sinks,
        "joern_flows": joern_flows,
        "joern_future": joern_future,
        "joern_last_activity": _joern_last_activity,
        "iris_taint_specs": iris_taint_specs,
        "prior_constraints": prior_constraints,
        "open_keys": open_keys,
        "strat_weights": strat_weights,
        "gaps": gaps,
        "entry_points": entry_points,
        "sinks_set": sinks_set,
        "trust_boundary_set": trust_boundary_set,
        "joern_flow_keys": joern_flow_keys,
        "sink_unreachable_keys": sink_unreachable_keys,
        "dangerous_callee_keys": dangerous_callee_keys,
        "priority_scores": priority_scores,
        "taint_path_keys": taint_path_keys,
        "triage_results": triage_results,
        "conventions": conventions,
        "sibling_ns_findings": sibling_ns_findings,
        "peer_groups": peer_groups,
        "sibling_postcond_violations": sibling_postcond_violations,
        "capability_displacements": capability_displacements,
        "struct_accessor_index": struct_accessor_index,
        "semantic_findings": semantic_findings,
        "mechanical_findings": mechanical_findings,
        "guard_clean_keys": guard_clean_keys,
        "detector_gaps": detector_gaps,
        "provenance_map": provenance_map,
        "security_decision_keys": security_decision_keys,
        "feeds_security_keys": feeds_security_keys,
        "checker_library": checker_library,
        "summary_cache": summary_cache,
        "discovered_tests": discovered_tests,
        "typestate_models": typestate_models,
        "coverage_records": coverage_records,
        "fuzz_coverage": fuzz_coverage,
        "tool_failures": tool_failures,
        "fuzz_cov_files": fuzz_cov_files,
        "widely_used_keys": widely_used_keys,
        "call_edges": call_edges,
        "tool_capabilities": tool_capabilities,
    }


def _run_audit_body(
    config,
    review_fn,
    on_progress,
    *,
    result,
    start_time,
    joern_server,
    joern_timeout_s,
    prep_cache=None,
):
    """Inner orchestrator body, always wrapped in try/finally for server cleanup."""
    global _active_target_path
    _active_target_path = config.target_path

    if joern_server is not None:
        from core.analysis.reach_audit import set_joern_server

        set_joern_server(joern_server)

    # --- Ensemble prep cache: first pass computes, second reuses ---
    _prep = None
    _prep_event = None
    if prep_cache is not None:
        _prep_lock = prep_cache.setdefault("_lock", _threading.Lock())
        _prep_event = prep_cache.setdefault("_event", _threading.Event())

        _role = "compute"
        with _prep_lock:
            if prep_cache.get("_ready"):
                _role = "reuse"
            elif prep_cache.get("_computing"):
                _role = "wait"
            else:
                prep_cache["_computing"] = True

        if _role == "reuse":
            from copy import deepcopy
            _prep = deepcopy(prep_cache["_prep"])
            logger.info("ensemble prep: reusing cached prep from first pass")
        elif _role == "wait":
            _prep_event.wait(timeout=600)
            if prep_cache.get("_prep") is not None:
                from copy import deepcopy
                _prep = deepcopy(prep_cache["_prep"])
                logger.info("ensemble prep: reusing cached prep (waited)")

    if _prep is None:
        try:
            _prep = _compute_audit_prep(
                config, joern_server=joern_server, on_progress=on_progress,
            )
        finally:
            if _prep_event is not None:
                if _prep is not None:
                    prep_cache["_prep"] = _prep
                    prep_cache["_ready"] = True
                _prep_event.set()
        if _prep is None:
            result.terminated_by = "no_checklist"
            return result

    checklist = _prep["checklist"]
    context_map = _prep["context_map"]
    flow_traces = _prep["flow_traces"]
    variant_targets = _prep["variant_targets"]
    sarif_cache = _prep["sarif_cache"]
    sarif_clean_files = _prep.get("sarif_clean_files", set())
    taint_approx_results = _prep["taint_approx_results"]
    taint_summary_results = _prep["taint_summary_results"]
    evidence_index = _prep["evidence_index"]
    caps = _prep["caps"]
    config.caps = caps
    if _prep.get("project_sinks") is not None:
        config.project_sinks = _prep["project_sinks"]
    joern_future = _prep["joern_future"]
    _joern_last_activity = _prep["joern_last_activity"]
    iris_taint_specs = _prep["iris_taint_specs"]
    prior_constraints = _prep["prior_constraints"]
    gaps = _prep["gaps"]
    entry_points = _prep["entry_points"]
    sinks_set = _prep["sinks_set"]
    trust_boundary_set = _prep.get("trust_boundary_set", set())
    priority_scores = _prep["priority_scores"]
    triage_results = _prep["triage_results"]
    conventions = _prep["conventions"]
    sibling_ns_findings = _prep["sibling_ns_findings"]
    peer_groups = _prep["peer_groups"]
    sibling_postcond_violations = _prep["sibling_postcond_violations"]
    capability_displacements = _prep.get("capability_displacements", [])
    struct_accessor_index = _prep.get("struct_accessor_index", {})
    semantic_findings = _prep["semantic_findings"]
    mechanical_findings = _prep["mechanical_findings"]
    guard_clean_keys = _prep.get("guard_clean_keys", set())
    provenance_map = _prep["provenance_map"]
    security_decision_keys = _prep["security_decision_keys"]
    feeds_security_keys = _prep["feeds_security_keys"]
    checker_library = _prep["checker_library"]
    summary_cache = _prep["summary_cache"]
    discovered_tests = _prep["discovered_tests"]
    typestate_models = _prep["typestate_models"]
    fuzz_coverage = _prep["fuzz_coverage"]
    widely_used_keys = _prep["widely_used_keys"]
    call_edges = _prep["call_edges"]
    tool_capabilities = _prep["tool_capabilities"]

    # Per-pass: persist gaps and build workqueue
    if mechanical_findings and config.out_dir:
        try:
            mech_path = config.out_dir / "mechanical-findings.json"
            mech_path.write_text(json.dumps(mechanical_findings, indent=2))
        except Exception:
            logger.debug("failed to persist mechanical findings", exc_info=True)

    write_gaps(gaps, config.out_dir)

    reviewed_set = (
        set()
        if config.force
        else get_reviewed_set(config.out_dir)
        if config.resume
        else set()
    )
    audit_log = load_audit_log(config.out_dir) if config.resume else []

    workqueue = []
    fn_filter = None
    if config.functions:
        fn_filter_simple: set[str] = set()
        fn_filter_lined: dict[str, set[int]] = {}
        for spec in config.functions:
            head, _, tail = spec.rpartition(":")
            if head and tail.isdigit():
                fn_filter_lined.setdefault(head, set()).add(int(tail))
            else:
                fn_filter_simple.add(spec)
        fn_filter = (fn_filter_simple, fn_filter_lined)

    guard_clean_resolved = 0
    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        if key in reviewed_set:
            result.skipped += 1
            continue
        if (
            key in guard_clean_keys
            and key not in entry_points
            and key not in sinks_set
            and key not in trust_boundary_set
            and not gap.get("force_review")
        ):
            outcome = ReviewOutcome(
                file=gap["file"],
                function=gap["name"],
                status="clean",
                body=(
                    "[guard-sufficiency: all sinks properly guarded] "
                    "Mechanical detectors confirmed all sink guards are "
                    "sufficient — skipped LLM review."
                ),
                evidence_tool="mechanical:guard_sufficiency",
            )
            outcome.line = gap.get("line_start", 0)
            try:
                _commit_outcome(config, outcome, gap)
            except Exception as exc:
                logger.warning(
                    "commit failed for guard-clean %s: %s", key, exc,
                )
            _tally_outcome(result, outcome)
            result.prefilter_skipped += 1
            guard_clean_resolved += 1
            continue
        if fn_filter is not None:
            simple, lined = fn_filter
            line = gap.get("line_start", 0)
            meta = gap.get("metadata") or {}
            cls = meta.get("class_name")
            qual_key = f"{gap['file']}:{cls}.{gap['name']}" if cls else key
            in_simple = key in simple or qual_key in simple
            in_lined = (
                _line_near(line, lined.get(key, set()))
                or _line_near(line, lined.get(qual_key, set()))
            )
            if not in_simple and not in_lined:
                result.skipped += 1
                continue
            gap["force_review"] = True

        if (
            sarif_clean_files
            and not gap.get("force_review")
            and gap["file"] in sarif_clean_files
            and key not in entry_points
            and key not in sinks_set
            and key not in trust_boundary_set
            and not (mechanical_findings and mechanical_findings.get(key))
        ):
            _sloc = gap.get("sloc") or (
                gap.get("line_end", 0) - gap.get("line_start", 0)
            )
            if 0 < _sloc <= 20:
                _sc_outcome = ReviewOutcome(
                    file=gap["file"],
                    function=gap["name"],
                    status="clean",
                    body=(
                        "[sarif-clean gate] File has zero CodeQL alerts, "
                        "function has no mechanical findings, SLOC <= 20, "
                        "and function is not an entry point, sink, or "
                        "trust boundary. Resolved without LLM review."
                    ),
                    evidence_tool="sarif:no_alerts",
                )
                _sc_outcome.line = gap.get("line_start", 0)
                try:
                    _commit_outcome(config, _sc_outcome, gap)
                except Exception:
                    logger.debug(
                        "commit failed for sarif-clean %s", key, exc_info=True,
                    )
                _tally_outcome(result, _sc_outcome)
                result.sarif_clean_resolved += 1
                continue

        workqueue.append(gap)
    if guard_clean_resolved:
        logger.info(
            "guard-clean resolution: resolved %d functions as clean "
            "without LLM review",
            guard_clean_resolved,
        )

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
        wq_priority = {
            f"{g['file']}:{g['name']}": priority_scores.get(
                f"{g['file']}:{g['name']}", g.get("priority_score", 0.0),
            )
            for g in workqueue
        }
        topo_order = _topological_sort(topo_adj, priority_scores=wq_priority)
        topo_rank = {k: i for i, k in enumerate(topo_order)}

        workqueue.sort(
            key=lambda g: topo_rank.get(f"{g['file']}:{g['name']}", len(topo_order)),
        )
        logger.info(
            "topo_order: reordered %d functions using %d call edges",
            len(workqueue),
            len(call_edges),
        )

    if config.subsystem_depth > 0:
        subsystem_groups = group_by_subsystem(
            workqueue,
            depth=config.subsystem_depth,
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

    batched, workqueue = _batch_trivial(workqueue, config.batch_sloc_threshold)

    batched_count = sum(len(b) for b in batched)

    # --- Pre-loop SMT screen: lock in mechanical verdicts before LLM ---
    if config.sweep_validate_findings:
        workqueue = _pre_loop_smt_screen(
            workqueue, config, result, checklist,
        )

    total = len(workqueue) + batched_count
    logger.info(
        "orchestrator: %d functions to review (%d skipped, %d batched as trivial)",
        total,
        result.skipped,
        batched_count,
    )

    # Pre-loop LLM summary pass removed: the workqueue is topo-sorted
    # (callees before callers), so callee summaries are produced by the
    # main review loop via summary_from_review_result() before the
    # caller is reviewed. This saves up to 80 LLM calls.

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
    joern_submit_time = time.monotonic() if joern_future is not None else None

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
            project_learnings,
            checklist=checklist,
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
                    n_con,
                    n_inv,
                )
    except Exception:
        logger.debug("domain model load failed", exc_info=True)

    try:
        n_inv_matches = _run_invariant_prescreening(
            domain_model, config, gaps, mechanical_findings,
        )
        if n_inv_matches:
            logger.info(
                "invariant prescreening: %d match(es) injected", n_inv_matches,
            )
            if config.out_dir:
                try:
                    mech_path = config.out_dir / "mechanical-findings.json"
                    mech_path.write_text(
                        json.dumps(mechanical_findings, indent=2),
                    )
                except Exception:
                    pass
    except Exception:
        logger.debug("invariant prescreening failed", exc_info=True)

    feedback_state = _load_exploit_feedback_raw(
        config.out_dir, load_feedback_state, FeedbackState
    )
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
            logger.info(
                "fp_feedback: loaded %d FP patterns from annotations + journal",
                len(fp_patterns),
            )
        if not fp_patterns and config.out_dir:
            fp_patterns = load_fp_patterns(config.out_dir)
    except Exception:
        logger.debug("fp_feedback: load failed", exc_info=True)

    inject_resolver = _InjectModeResolver(config, joern_server=joern_server)

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
        capability_displacements=capability_displacements,
        struct_accessor_index=struct_accessor_index,
        peer_groups=peer_groups,
        semantic_findings=semantic_findings,
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
    shared.inject_resolver = inject_resolver
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
            "auto workers: model=%s → max_workers=%d",
            model,
            resolved_workers,
        )
    else:
        resolved_workers = config.max_workers
    executor_config = ExecutorConfig(max_workers=resolved_workers)

    layer_disagreements: List[Any] = []

    # --- Glance batches (parallel) ---
    if batched:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _review_batch(batch):
            return _review_items(
                batch,
                config,
                review_fn,
                checklist,
                context_map,
                fuzz_coverage,
                evidence_index,
                discovered_evidence=discovered_evidence,
                domain_model=domain_model,
            ), batch

        review_idx = 0
        with ThreadPoolExecutor(max_workers=resolved_workers) as pool:
            futures = [pool.submit(_review_batch, b) for b in batched]
            for fut in as_completed(futures):
                if _check_budget(config, start_time, result):
                    break
                batch_outcomes, batch = fut.result()
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
            new_index = _drain_joern_future(
                jf,
                evidence_index,
                checklist,
                sarif_cache,
            )
            with shared._evidence_lock:
                evidence_index = new_index
                shared.evidence_index = evidence_index
            joern_state["future"] = None
        elif jf is not None:
            idle_s = time.monotonic() - _joern_last_activity[0]
            if idle_s > joern_timeout_s:
                logger.warning(
                    "Joern stalled (%.0fs since last activity) — cancelling",
                    idle_s,
                )
                jf.cancel()
                joern_state["future"] = None
                joern_state["submit_time"] = None

        if joern_state["future"] is not None:
            shared.reviewed_before_joern.append(gap)

    # --- Main executor pass ---
    graph = TaskGraph.from_workqueue(workqueue, call_edges)
    reviewed_outcomes = _LockedOutcomes()

    # --- Shared concurrency throttle ---
    # A single AdaptiveThrottle gates all LLM calls across Thread A
    # (review executor) and Thread B (study consumer).  429 broadcasts
    # from any provider reach both consumers via the throttle registry.
    from core.llm.throttle import AdaptiveThrottle
    from core.llm.concurrency import read_throttle_cooldown_s

    throttle = AdaptiveThrottle(
        resolved_workers,
        cooldown_s=read_throttle_cooldown_s(),
    )

    # --- Start incremental study consumer (Thread B) ---
    _C_STUDY_SUFFIXES = frozenset(
        (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"),
    )
    _has_c_files = any(
        Path(g["file"]).suffix.lower() in _C_STUDY_SUFFIXES
        for g in workqueue
    )
    study_queue: StudyQueue | None = None
    study_consumer_thread: _threading.Thread | None = None
    concept_index_ref: list = [ConceptIndex.empty()]
    if _has_c_files and config.out_dir:
        study_queue = StudyQueue()
        shared.study_queue = study_queue
        study_consumer_thread = _threading.Thread(
            target=_study_consumer,
            args=(
                study_queue,
                config,
                shared,
                review_fn,
                reviewed_outcomes,
                result,
            ),
            kwargs=dict(
                checklist=checklist,
                context_map=context_map,
                evidence_index=evidence_index,
                sarif_cache=sarif_cache,
                entry_points=entry_points,
                start_time=start_time,
                on_progress=on_progress,
                audit_log=audit_log,
                session_observations=session_observations,
                discovered_evidence=discovered_evidence,
                joern_server=joern_server,
                collector=collector,
                throttle=throttle,
                concept_index_ref=concept_index_ref,
            ),
            daemon=True,
            name="study-consumer",
        )
        study_consumer_thread.start()
        logger.info("study-consumer: started")

    executor_stats = run_executor_sync(
        graph,
        review_fn,
        shared,
        config,
        result,
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
        reviewed_outcomes=reviewed_outcomes,
        throttle=throttle,
        study_queue=study_queue,
        concept_index_ref=concept_index_ref,
    )
    joern_future = joern_state["future"]
    if executor_stats.budget_stopped and not result.terminated_by:
        result.terminated_by = "llm_budget_exceeded"

    # --- Drain study consumer ---
    if study_queue is not None:
        study_queue.signal_producer_done()
    if study_consumer_thread is not None:
        study_consumer_thread.join(timeout=600)
        if study_consumer_thread.is_alive():
            logger.warning("study-consumer: did not drain within 600s")

    # --- Concept discovery: mine outcomes for invariants ---
    try:
        if not executor_stats.budget_stopped:
            _run_concept_discovery(
                reviewed_outcomes, config, shared, gaps,
                mechanical_findings, reviewed_set,
            )
    except Exception:
        logger.debug("concept discovery failed", exc_info=True)

    # --- Synthesis queue second pass ---
    #
    # Optional enrichment, so it must never cost the run its results.
    # Everything here runs after the main review loop but *before* the
    # state sync-back and the single one-shot ``collector.flush()``
    # below, so any exception raised in resolution, graph construction
    # or the executor would discard the run's findings and its buffered
    # audit log. Degrade to "second pass skipped" instead: the main pass
    # has already earned its output.
    try:
        if shared.synthesis_queue and not executor_stats.budget_stopped:
            synth_hits = list(shared.synthesis_queue)
            shared.synthesis_queue.clear()
            synth_gaps = _synthesis_hits_to_gaps(
                synth_hits,
                checklist,
                config.out_dir,
            )
            logger.info(
                "synthesis pass: %d targets from mid-loop synthesis "
                "(%d hits resolved to reviewable functions)",
                len(synth_hits),
                len(synth_gaps),
            )
        else:
            synth_gaps = []

        if synth_gaps:
            synth_graph = TaskGraph.from_workqueue(synth_gaps, call_edges)
            run_executor_sync(
                synth_graph,
                review_fn,
                shared,
                config,
                result,
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
    except Exception as exc:
        logger.warning(
            "synthesis second pass failed (%s: %s) — keeping main-pass "
            "results and flushing buffered state",
            type(exc).__name__,
            exc,
            exc_info=True,
        )

    throttle.close()

    # --- Sync mutable state back from SharedState ---
    constraints = shared.constraints
    evidence_index = shared.evidence_index
    session_observations = shared.session_observations
    discovered_evidence = shared.discovered_evidence
    reviewed_before_joern = shared.reviewed_before_joern

    if collector is not None:
        collector.flush()

    # --- Callee-contract propagation (#6): re-review callers whose
    #     callee assumption was contradicted by the callee's review ---
    try:
        contract_re = _callee_contract_requeue(
            result, config, review_fn,
            checklist=checklist,
            context_map=context_map,
            fuzz_coverage=fuzz_coverage,
            evidence_index=evidence_index,
            discovered_evidence=discovered_evidence,
            session_observations=session_observations,
            joern_server=joern_server,
            start_time=start_time,
            on_progress=on_progress,
            max_workers=resolved_workers,
        )
        if contract_re:
            logger.info(
                "callee-contract propagation: re-reviewed %d callers",
                contract_re,
            )
    except Exception:
        logger.debug(
            "callee-contract propagation failed", exc_info=True,
        )

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
                joern_future,
                evidence_index,
                checklist,
                sarif_cache,
            )
        joern_future = None

    if config.propagate_constraints and constraints:
        save_constraints(constraints, config.out_dir)

    if reviewed_before_joern:
        result = _re_review_joern_enriched(
            result,
            config,
            review_fn,
            checklist,
            context_map,
            fuzz_coverage,
            evidence_index,
            sarif_cache,
            entry_points,
            reviewed_before_joern,
            start_time,
            on_progress,
            audit_log=audit_log,
            session_observations=session_observations,
            discovered_evidence=discovered_evidence,
            joern_server=joern_server,
            max_workers=resolved_workers,
        )

    if config.deepen_suspicious:
        result = _deepen_suspicious(
            result,
            config,
            review_fn,
            checklist,
            context_map,
            fuzz_coverage,
            session_observations,
            sarif_cache,
            entry_points,
            start_time,
            on_progress,
            evidence_index,
            audit_log=audit_log,
            discovered_evidence=discovered_evidence,
            joern_server=joern_server,
            project_learnings=project_learnings,
            max_workers=resolved_workers,
        )

    if config.deepen_suspicious:
        logger.debug("entering post-deepen mechanical sweep")
        sink_reachable = build_sink_reachable_set(context_map)
        new_outcomes = []
        for outcome in result.outcomes:
            if outcome.status == "finding":
                corroborated = _has_mechanical_corroboration(
                    outcome,
                    config,
                    sarif_cache,
                    checklist,
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
                            outcome,
                            config,
                            checklist,
                        )
                    if reason is not None:
                        logger.info(
                            "gate: %s:%s demoted — %s",
                            outcome.file,
                            outcome.function,
                            reason,
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
        logger.debug("exited post-deepen mechanical sweep")

    logger.debug("entering _iterative_re_review")
    result = _iterative_re_review(
        result,
        config,
        review_fn,
        checklist,
        context_map,
        fuzz_coverage,
        entry_points,
        constraints,
        prop_config,
        sarif_cache,
        start_time,
        on_progress,
        evidence_index,
        audit_log=audit_log,
        session_observations=session_observations,
        discovered_evidence=discovered_evidence,
        joern_server=joern_server,
        max_workers=resolved_workers,
    )
    logger.debug("exited _iterative_re_review")

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
                        (
                            o
                            for o in result.outcomes
                            if o.file == gap["file"] and o.function == gap["name"]
                        ),
                        None,
                    )
                    if prior and prior.status == "clean":
                        live_sink_targets.append(gap)
            if live_sink_targets:
                effective_ls_workers = max(1, resolved_workers)
                logger.info(
                    "live-sink re-queue: %d functions to re-review at DEEP_DIVE depth (workers=%d)",
                    len(live_sink_targets),
                    effective_ls_workers,
                )
                sorted_sinks = sorted(live_classifications.sinks)
                ls_prepared = []
                for target_gap in live_sink_targets:
                    ctx = _build_context(
                        config,
                        target_gap,
                        checklist,
                        context_map,
                        evidence_index,
                        discovered_evidence=discovered_evidence,
                    )
                    ctx["live_sinks"] = sorted_sinks
                    ctx["triage_bucket"] = "DEEP_DIVE"
                    prior = next(
                        (
                            o
                            for o in result.outcomes
                            if o.file == target_gap["file"]
                            and o.function == target_gap["name"]
                        ),
                        None,
                    )
                    ls_prepared.append((len(ls_prepared), target_gap, prior, ctx))

                def _do_ls_review(item):
                    idx, _gap, _prior, ctx = item
                    try:
                        outcome = review_fn(ctx, config)
                        return (idx, outcome, None)
                    except Exception as exc:
                        return (idx, None, exc)

                if effective_ls_workers <= 1:
                    ls_raw = []
                    for item in ls_prepared:
                        if _check_budget(config, start_time, result):
                            break
                        ls_raw.append(_do_ls_review(item))
                else:
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    ls_raw = []
                    with ThreadPoolExecutor(max_workers=effective_ls_workers) as pool:
                        ls_futs = {
                            pool.submit(_do_ls_review, item): item
                            for item in ls_prepared
                        }
                        for fut in as_completed(ls_futs):
                            if _check_budget(config, start_time, result):
                                for f in ls_futs:
                                    f.cancel()
                                break
                            ls_raw.append(fut.result())

                for idx, outcome, exc in sorted(ls_raw, key=lambda r: r[0]):
                    _, target_gap, prior, _ctx = ls_prepared[idx]
                    if exc is not None:
                        logger.warning(
                            "live-sink re-review failed for %s:%s: %s",
                            target_gap["file"],
                            target_gap["name"],
                            exc,
                        )
                        continue
                    if prior is not None:
                        _untally_outcome(result, prior)
                        try:
                            result.outcomes.remove(prior)
                        except ValueError:
                            pass
                    _tally_outcome(result, outcome)
                    if collector is not None:
                        collector.submit(outcome, target_gap)
                    else:
                        _commit_outcome(config, outcome, target_gap)
        except Exception:
            logger.debug("live-sink expansion failed", exc_info=True)

    if config.sweep_validate_findings:
        pre_sweep = {
            (o.file, o.function): o.status for o in result.outcomes
        }
        logger.debug("entering _promote_suspicious")
        _promote_suspicious(
            result, config, sarif_cache, checklist, joern_server=joern_server
        )
        logger.debug("exited _promote_suspicious")

        logger.debug("entering _promote_clean_refuted")
        _promote_clean_refuted(
            result, config, checklist, joern_server=joern_server,
        )
        logger.debug("exited _promote_clean_refuted")

        logger.debug("entering _demote_self_contradictions")
        _demote_self_contradictions(result)
        logger.debug("exited _demote_self_contradictions")

        logger.debug("entering _promote_hypothesis_inconsistent")
        _promote_hypothesis_inconsistent(result)
        logger.debug("exited _promote_hypothesis_inconsistent")

        # Run refutation gates on newly-promoted suspicious outcomes.
        # Hypothesis-consistency promotes clean→suspicious when the LLM
        # had high-confidence race/leak hypotheses but said "clean".
        # The per-function refutation gate (line ~1398) missed these
        # because they were clean at that point.
        try:
            from .refutation import refute_hypothesis

            for i, outcome in enumerate(result.outcomes):
                if outcome.status != "suspicious":
                    continue
                if "[hypothesis-consistency:" not in outcome.body:
                    continue
                rv = refute_hypothesis(
                    outcome,
                    domain_model=domain_model,
                    checklist=checklist,
                    config=config,
                    joern_server=joern_server,
                )
                if rv is not None:
                    append_audit_log(config.out_dir, {
                        "action": "refutation_gate_post_promote",
                        "gate": rv.gate,
                        "file": outcome.file,
                        "function": outcome.function,
                        "reason": rv.reason,
                        "demote_to": rv.demote_to,
                        "original_status": "suspicious",
                    })
                    logger.info(
                        "refutation gate (post-promote) [%s] %s:%s — %s → %s",
                        rv.gate, outcome.file, outcome.function,
                        rv.reason, rv.demote_to,
                    )
                    result.outcomes[i] = _demote_outcome(
                        outcome, f"[{rv.gate}: {rv.reason}]",
                    )
                    result.outcomes[i].status = rv.demote_to
                    result.suspicious -= 1
                    result.clean += 1
        except Exception:
            logger.debug(
                "refutation gate (post-promote) error",
                exc_info=True,
            )

        logger.debug("entering _promote_smt_clean")
        _promote_smt_clean(result, config, checklist)
        logger.debug("exited _promote_integer_narrowing")

        for outcome in result.outcomes:
            key = (outcome.file, outcome.function)
            old_status = pre_sweep.get(key)
            if old_status and old_status != outcome.status:
                entry = {
                    "action": "sweep_promotion",
                    "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
                    "status": outcome.status,
                    "prior_status": old_status,
                    "evidence_tool": outcome.evidence_tool or "",
                    "model": outcome.model or "",
                    "cost_usd": 0.0,
                    "duration_s": 0.0,
                    "hypothesis": outcome.hypothesis or "",
                }
                append_audit_log(config.out_dir, entry)

    try:
        from .propagation import propagate_confidence
        edge_index = shared.call_edge_index if shared else {}
        check_index = shared.checklist_index if shared else {}
        conf_demotions = propagate_confidence(
            result.outcomes, edge_index, check_index,
        )
        for d in conf_demotions:
            entry = {
                "action": "sweep_promotion",
                "key": f"{d.file}:{d.function}:0",
                "status": "clean",
                "prior_status": "suspicious",
                "evidence_tool": "confidence_propagation",
                "model": "",
                "cost_usd": 0.0,
                "duration_s": 0.0,
                "hypothesis": d.reason,
            }
            append_audit_log(config.out_dir, entry)
        if conf_demotions:
            logger.info(
                "confidence propagation: %d demotions", len(conf_demotions),
            )
    except Exception:
        logger.debug("confidence propagation failed", exc_info=True)

    logger.debug("entering _resolve_gate_demoted")
    _resolve_gate_demoted(
        result,
        config,
        sarif_cache,
        checklist,
        domain_model=domain_model,
        available_tools=tool_capabilities,
    )
    logger.debug("exited _resolve_gate_demoted")

    logger.debug("entering _auto_synthesize_rules")
    _auto_synthesize_rules(result, config)
    logger.debug("exited _auto_synthesize_rules")

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
                    len(graduated),
                    engine_rules_dir,
                )
        except Exception:
            logger.debug("rule graduation failed", exc_info=True)

    if layer_disagreements and config.out_dir:
        try:
            from .layer_resolution import (
                write_disagreements,
                format_disagreement_summary,
                LayerVerdict,
            )

            write_disagreements(layer_disagreements, config.out_dir)
            logger.info(format_disagreement_summary(layer_disagreements))

            mechanical_wins = [
                d for d in layer_disagreements
                if d.winner == LayerVerdict.MECHANICAL
            ]
            if mechanical_wins and not _check_budget(config, start_time, result):
                result = _re_review_disagreements(
                    mechanical_wins,
                    result,
                    config,
                    review_fn,
                    checklist,
                    context_map,
                    evidence_index,
                    start_time,
                    on_progress,
                    audit_log=audit_log,
                    session_observations=session_observations,
                    discovered_evidence=discovered_evidence,
                    joern_server=joern_server,
                    max_workers=resolved_workers,
                )
        except Exception:
            logger.debug("layer disagreement persistence failed", exc_info=True)

    result = _review_flow_traces(
        result,
        config,
        review_fn,
        checklist,
        evidence_index=evidence_index,
        joern_server=joern_server,
        sarif_cache=sarif_cache,
        domain_model=domain_model,
        audit_log=audit_log,
        start_time=start_time,
    )

    if result.findings > 0:
        logger.debug("entering _persist_findings")
        _persist_findings(result, config)

    if iris_taint_specs and joern_server is not None and result.findings > 0:
        try:
            from .iris_specs import compile_joern_config

            requery_cfg = compile_joern_config(iris_taint_specs)
            if requery_cfg.strip():
                try:
                    requery_hits = _joern_live_query(
                        joern_server,
                        requery_cfg,
                        [],
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
            gaps,
            taint_chain_callees=taint_chain_callees_post,
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

                    confirmed = [
                        h.get("key", "") for h in (hits or []) if h.get("flows")
                    ]
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
                _iris_model = config.models[0] if config.models and config.models[0] != "default" else None
                iris_llm = LLMClient(pinned_model=_iris_model) if _iris_model else LLMClient()
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
                joern_tool_runner,
                codeql_tool_runner,
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
                    len(refined_specs),
                    len(history),
                )
                if config.out_dir:
                    spec_path = config.out_dir / "iris-taint-specs-refined.json"
                    spec_path.write_text(specs_to_json(refined_specs))

            if assumptions:
                logger.info(
                    "iris.synthesise: %d assumptions from %d sink/sanitiser specs",
                    len(assumptions),
                    sum(1 for s in refined_specs if s.role in ("sink", "sanitiser")),
                )

            if bypass_findings:
                logger.info(
                    "IRIS bypass: %d bypass findings",
                    len(bypass_findings),
                )
                if config.out_dir:
                    bp_path = config.out_dir / "iris-bypass-findings.json"
                    bp_path.write_text(
                        json.dumps(
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
                        )
                    )
    except Exception:
        logger.debug("IRIS refinement/bypass failed", exc_info=True)

    if result.findings >= 2 and config.out_dir:
        try:
            from .attacker_synthesis import (
                synthesize_chains,
                write_attack_chains,
                format_chains_summary,
            )

            chains = synthesize_chains(result.outcomes, context_map)
            if chains:
                write_attack_chains(chains, config.out_dir)
                logger.info(format_chains_summary(chains))
        except Exception:
            logger.debug("attacker synthesis failed", exc_info=True)

    post_loop_findings: list[dict] = []
    generated: list = []

    try:
        from .taint_specs import check_stored_taint, check_config_dependent

        for tf in check_stored_taint(gaps, target_path=config.target_path):
            post_loop_findings.append(tf.to_dict())
        for tf in check_config_dependent(gaps, target_path=config.target_path):
            post_loop_findings.append(tf.to_dict())
    except Exception:
        logger.debug("taint-spec post-loop checks failed", exc_info=True)

    try:
        from core.iris.synthesise import (
            stored_taint_assumptions,
            config_provenance_assumptions,
        )

        heuristic_assumptions = stored_taint_assumptions(
            gaps
        ) + config_provenance_assumptions(gaps)
        heuristic_with_enforcers = [a for a in heuristic_assumptions if a.enforced_by]
        if heuristic_with_enforcers and bypass_runner is not None:
            heuristic_bypasses = bypass_runner(heuristic_with_enforcers)
            for bf in heuristic_bypasses:
                post_loop_findings.append(
                    {
                        "check": f"iris_{bf.assumption.bug_class or 'bypass'}",
                        "title": (
                            f"IRIS bypass: {bf.caller_function}"
                            f" skips {bf.missing_enforcer}"
                        ),
                        "description": (
                            f"Caller {bf.caller_file}:{bf.caller_function} reaches "
                            f"{bf.assumption.target} without {bf.missing_enforcer}"
                        ),
                        "file": bf.caller_file,
                        "function": bf.caller_function,
                        "cwe": bf.assumption.bug_class or "",
                        "confidence": "medium",
                    }
                )
    except Exception:
        logger.debug("IRIS heuristic assumption bypass failed", exc_info=True)

    try:
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

        tp = Path(config.target_path)
        ns_vocab = None
        try:
            from .condition_smt import DomainVocabulary
            ns_vocab = DomainVocabulary.from_domain_model(domain_model)
        except Exception:
            pass
        for nf in check_resource_exhaustion(
            gaps, target_path=tp, domain_vocab=ns_vocab,
        ):
            post_loop_findings.append(nf.to_dict())
        for nf in check_protocol_ambiguity(gaps, target_path=tp):
            post_loop_findings.append(nf.to_dict())
        for nf in check_missing_app_features(gaps, target_path=tp):
            post_loop_findings.append(nf.to_dict())
        for nf in check_signal_safety(
            gaps, target_path=tp, domain_vocab=ns_vocab,
        ):
            post_loop_findings.append(nf.to_dict())
        for nf in check_ub_patterns(gaps, target_path=tp):
            post_loop_findings.append(nf.to_dict())
        for nf in check_side_channels(gaps, target_path=tp):
            post_loop_findings.append(nf.to_dict())
        for nf in check_multi_process(gaps, target_path=tp):
            post_loop_findings.append(nf.to_dict())
        for nf in check_deployment_assumptions(gaps, target_path=tp):
            post_loop_findings.append(nf.to_dict())
        for nf in check_lock_ordering(
            gaps, target_path=tp, domain_vocab=ns_vocab,
        ):
            post_loop_findings.append(nf.to_dict())
    except Exception:
        logger.debug("negative-space post-loop checks failed", exc_info=True)

    try:
        from .postcondition_verify import verify_postconditions

        pc_result = verify_postconditions(
            gaps,
            taint_summary_results or {},
        )
        if pc_result.violations:
            for v in pc_result.violations:
                post_loop_findings.append(v.to_dict())
            logger.info(
                "postcondition: %d violations from %d postconditions",
                len(pc_result.violations),
                pc_result.functions_with_postconditions,
            )
    except Exception:
        logger.debug("postcondition verification failed", exc_info=True)

    try:
        from .triage import detect_generated_files

        generated = detect_generated_files(gaps, target_path=config.target_path)
    except Exception:
        logger.debug("generated-file detection failed", exc_info=True)

    if post_loop_findings:
        logger.info(
            "Post-loop pattern checks: %d findings",
            len(post_loop_findings),
        )
    if generated:
        logger.info(
            "%d generated files detected — review depth reduced",
            len(generated),
        )

    if config.out_dir and (post_loop_findings or generated):
        try:
            pl_path = config.out_dir / "post-loop-findings.json"
            pl_path.write_text(
                json.dumps(
                    {
                        "findings": post_loop_findings,
                        "generated_files": generated,
                        "finding_count": len(post_loop_findings),
                    },
                    indent=2,
                )
            )
        except Exception:
            logger.debug("post-loop findings write failed", exc_info=True)

    for plf in post_loop_findings:
        plf_file = plf.get("file", "")
        plf_func = plf.get("function", "")
        if plf_file and plf_func:
            plf_status = "suspicious"
            try:
                from .collector import append_journal_for_outcome

                class _PlfOutcome:
                    pass

                _o = _PlfOutcome()
                _o.file = plf_file
                _o.function = plf_func
                _o.status = plf_status
                _o.body = f"[mechanical] {plf.get('description', '')}"
                _o.model = None
                _o.hypothesis = None
                _o.hypotheses = None
                _o.evidence_tool = None
                _o.tools_dispatched = None
                _o.review_result = {"cwe": plf.get("cwe", "")}
                _o.cost_usd = None
                _o.duration_s = None
                append_journal_for_outcome(
                    out_dir=config.out_dir,
                    target_path=config.target_path,
                    run_id=(config.out_dir.name if config.out_dir else ""),
                    outcome=_o,
                    gap={
                        "line_start": plf.get("line_start", 0),
                        "line_end": plf.get("line_end"),
                        "strategies": ["post-loop-mechanical"],
                    },
                    checked_by=["audit:post-loop"],
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "post-loop journal append failed for %s:%s",
                    plf_file,
                    plf_func,
                    exc_info=True,
                )

    if config.validate and result.findings > 0:
        from .validate import validate_findings

        result = validate_findings(
            result,
            target_path=config.target_path,
            out_dir=config.out_dir,
        )

    try:
        result = _retry_error_outcomes(
            result,
            config,
            review_fn,
            checklist,
            None,
            None,
            start_time,
            sarif_cache,
        )
    except Exception:
        logger.debug("error retry pass failed", exc_info=True)

    try:
        from core.llm.client import LLMClient
        _dark_model = config.models[0] if config.models and config.models[0] != "default" else None
        _dark_client = LLMClient(pinned_model=_dark_model) if _dark_model else LLMClient()
        _run_dark_verification(
            result,
            config,
            llm_client=lambda p, s: (
                _dark_client.generate(
                    p,
                    system_prompt=s or None,
                ).content
            ),
        )
    except Exception:
        logger.debug("dark verification pass failed", exc_info=True)

    # --- Phase 2: security impact classification (bug_first mode) ---
    if config.mode.has_security_phase:
        _run_phase2(result, config)

    result.total_duration_s = time.monotonic() - start_time

    # --- Collector flush: write all buffered state to disk ---
    if collector is not None:
        try:
            collector.flush()
        except Exception:
            logger.debug("collector flush failed", exc_info=True)

    _persist_project_learnings(
        config.out_dir,
        session_observations,
        result,
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
                    finding["evidence_chain"].append(
                        {
                            "source": "dynamic:exploit_confirmed",
                            "confidence": "high",
                            "description": "exploit confirmation from /exploit run",
                        }
                    )
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
            from .measurement import (
                load_ground_truth,
                evaluate_run,
                write_evaluation,
                format_evaluation,
            )

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
                load_planted_bugs,
                match_findings_to_bugs,
                build_matrix,
                format_matrix_report,
                write_matrix,
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
                                det.bug_id,
                                det.detected,
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
            logger.info(
                "summaries: wrote %d entries to summaries.json", len(summaries_out)
            )
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
                len(unsandboxed),
                ", ".join(unsandboxed),
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


def _run_invariant_prescreening(
    domain_model: dict[str, Any] | None,
    config: "OrchestratorConfig",
    gaps: list[dict[str, Any]],
    mechanical_findings: Dict[str, List[Dict[str, Any]]],
) -> int:
    """Run compiled invariant rules from the domain model as pre-screening.

    Finds invariants with ``mechanical_rule`` set, locates the rule files
    in ``checkers/`` directories, runs them against the target, and injects
    matches into *mechanical_findings* keyed by ``file:function``.

    Returns the number of matches injected.
    """
    if not domain_model:
        return 0
    invariants = domain_model.get("invariants", [])
    compiled = [
        inv for inv in invariants
        if isinstance(inv, dict) and inv.get("mechanical_rule")
    ]
    if not compiled:
        return 0

    checkers_dirs = []
    if config.out_dir:
        checkers_dirs.append(config.out_dir / "checkers")
        checkers_dirs.append(config.out_dir.parent / "concepts" / "checkers")
        checkers_dirs.append(config.out_dir.parent / "checkers")

    file_func_index: dict[str, list[tuple[str, int, int]]] = {}
    for g in gaps:
        fp = g.get("file", "")
        fn = g.get("name", "")
        ls = g.get("line_start", 0)
        le = g.get("line_end", 0)
        if fp and fn and isinstance(ls, int) and isinstance(le, int):
            file_func_index.setdefault(fp, []).append((fn, ls, le))

    def _match_function(file: str, line: int) -> str | None:
        entries = file_func_index.get(file)
        if not entries:
            return None
        for fn, ls, le in entries:
            if ls <= line <= le:
                return fn
        return None

    from packages.checker_synthesis.models import SynthesisedRule
    from packages.checker_synthesis.synthesise import _run_engine

    total = 0
    for inv in compiled:
        rule_id = inv["mechanical_rule"]
        engine = "coccinelle" if ".coccinelle." in rule_id else "semgrep"
        ext = ".cocci" if engine == "coccinelle" else ".yml"
        filename = f"{rule_id}{ext}"

        rule_path = None
        for d in checkers_dirs:
            candidate = d / filename
            if candidate.is_file():
                rule_path = candidate
                break
        if rule_path is None:
            continue

        try:
            body = rule_path.read_text(encoding="utf-8")
        except OSError:
            continue

        rule = SynthesisedRule(engine=engine, rule_id=rule_id, body=body)
        matches, errors = _run_engine(rule, rule_path, config.target_path)
        if errors:
            logger.debug(
                "invariant prescreening %s: %s", rule_id, "; ".join(errors[:2]),
            )

        inv_stmt = inv.get("statement", rule_id)
        for m in matches:
            func = _match_function(m.file, m.line)
            if not func:
                continue
            key = f"{m.file}:{func}"
            mechanical_findings.setdefault(key, []).append({
                "file": m.file,
                "function": func,
                "detector": "invariant_rule",
                "line": m.line,
                "description": f"invariant violation ({rule_id}): {inv_stmt}",
            })
            total += 1

    return total


def _run_concept_discovery(
    reviewed_outcomes: "_LockedOutcomes",
    config: "OrchestratorConfig",
    shared: "SharedState",
    gaps: list[dict[str, Any]],
    mechanical_findings: Dict[str, List[Dict[str, Any]]],
    reviewed_set: set,
) -> None:
    """Mine review outcomes for recurring patterns, compile into rules.

    1. Cluster findings by CWE
    2. Extract invariant candidates from clusters of 2+
    3. Compile into Semgrep/Coccinelle rules (LLM call)
    4. Run prescreening and inject hits into mechanical_findings
    """
    from .concept_discovery import (
        candidates_to_model_entries,
        discover_invariants,
    )

    snapshot = dict(reviewed_outcomes)
    if not snapshot:
        return

    dm = shared.domain_model
    candidates = discover_invariants(snapshot, dm)
    if not candidates:
        return

    logger.info(
        "concept discovery: %d invariant candidate(s) from %d outcomes",
        len(candidates), len(snapshot),
    )

    entries = candidates_to_model_entries(candidates)

    if dm is None:
        dm = {"concepts": [], "invariants": [], "contracts": []}
    existing_ids = {
        inv.get("id") for inv in dm.get("invariants", [])
        if isinstance(inv, dict)
    }
    new_entries = [e for e in entries if e["id"] not in existing_ids]
    if not new_entries:
        return

    dm.setdefault("invariants", []).extend(new_entries)
    shared.domain_model = dm

    if config.out_dir:
        try:
            import json as _json

            dm_path = config.out_dir / "domain-model.json"
            dm_path.write_text(
                _json.dumps(dm, indent=2) + "\n", encoding="utf-8",
            )
        except Exception:
            logger.debug("concept discovery: domain model write failed", exc_info=True)

    from core.llm.client import LLMClient
    from core.llm.task_types import TaskType

    _model = (
        config.models[0]
        if config.models and config.models[0] != "default"
        else None
    )
    client = LLMClient(pinned_model=_model) if _model else LLMClient()

    def _llm(prompt, schema, system_prompt):
        try:
            data, _ = client.generate_structured(
                prompt=prompt,
                schema=schema,
                system_prompt=system_prompt,
                task_type=TaskType.AUDIT,
            )
            return data
        except Exception as exc:
            logger.debug("concept discovery LLM call failed: %s", exc)
            return None

    from core.concepts.compiler import compile_invariant
    from core.concepts.model import Invariant
    from packages.checker_synthesis.languages import fallback_engine

    compiled_count = 0
    for entry in new_entries:
        inv = Invariant(
            id=entry["id"],
            statement=entry["statement"],
            negation=entry["negation"],
            description=entry.get("description", ""),
            confidence=entry.get("confidence", "observed"),
            relevant_cwes=entry.get("relevant_cwes", []),
            evidence=entry.get("evidence", []),
        )

        engine = "semgrep"
        for ev in inv.evidence:
            ev_file = ev.split(":")[0].strip() if ":" in ev else ""
            if ev_file:
                from packages.checker_synthesis.languages import detect_engine

                detected = detect_engine(ev_file)
                if detected:
                    engine = detected
                    break

        cr = compile_invariant(inv, engine, _llm, config.out_dir or Path("."))
        if not cr.success:
            alt = fallback_engine(engine)
            if alt:
                cr = compile_invariant(
                    inv, alt, _llm, config.out_dir or Path("."),
                )

        if cr.success:
            entry["mechanical_rule"] = cr.rule_id
            compiled_count += 1

    if compiled_count:
        logger.info(
            "concept discovery: compiled %d/%d invariant(s)",
            compiled_count, len(new_entries),
        )
        n = _run_invariant_prescreening(dm, config, gaps, mechanical_findings)
        if n:
            logger.info(
                "concept discovery prescreening: %d new match(es)", n,
            )


class _InjectModeResolver:
    """Lazy per-function inject-mode detector evaluation.

    Instead of running check_lock_domain and uninit_leak on every function
    upfront (which blocks the pipeline for minutes), this resolver computes
    inject-mode findings on-demand when a function is about to be
    LLM-reviewed.  Results are cached so repeated lookups are free.
    """

    def __init__(
        self,
        config: "OrchestratorConfig",
        joern_server: Any = None,
    ) -> None:
        self._config = config
        self._joern_server = joern_server
        self._cache: Dict[str, List[Dict[str, Any]]] = {}

        self._check_lock_domain = None
        self._check_uninit_leak = None
        self._check_callback_cross = None
        self._vocab = None

        try:
            from .condition_smt import (
                DomainVocabulary,
                check_lock_domain,
            )
            self._check_lock_domain = check_lock_domain
            dm = None
            try:
                from .journal import load_domain_model
                dm = load_domain_model(config.out_dir)
            except Exception:
                pass
            self._vocab = DomainVocabulary.from_domain_model(dm)
        except Exception:
            logger.debug("inject resolver: check_lock_domain unavailable", exc_info=True)

        try:
            from .uninit_detector import detect_uninit_leak
            self._check_uninit_leak = detect_uninit_leak
        except Exception:
            logger.debug("inject resolver: uninit_detector unavailable", exc_info=True)

        if joern_server is not None:
            try:
                from .callback_lifetime import check_callback_lifetime_cross
                self._check_callback_cross = check_callback_lifetime_cross
            except Exception:
                logger.debug("inject resolver: callback_lifetime unavailable", exc_info=True)

        self._available = (
            self._check_lock_domain is not None
            or self._check_uninit_leak is not None
            or self._check_callback_cross is not None
        )

    @property
    def available(self) -> bool:
        return self._available

    def resolve(
        self, file: str, function: str, line_start: int, line_end: Optional[int],
    ) -> List[Dict[str, Any]]:
        """Return inject-mode findings for a single function (cached)."""
        key = f"{file}:{function}"
        if key in self._cache:
            return self._cache[key]

        findings: List[Dict[str, Any]] = []
        if not self._available:
            self._cache[key] = findings
            return findings

        src = _read_raw_source(self._config.target_path, file, line_start, line_end)
        if not src:
            self._cache[key] = findings
            return findings

        is_c = any(file.endswith(ext) for ext in _C_EXTS)
        is_go = file.endswith(".go")

        if self._check_lock_domain is not None and (is_c or is_go):
            try:
                ldr = self._check_lock_domain(src, self._vocab)
                if ldr.mismatch_found:
                    findings.append({
                        "file": file,
                        "function": function,
                        "detector": "smt:check-lock-domain",
                        "line": line_start,
                        "description": (
                            f"lock-domain mismatch: field `{ldr.field}` "
                            f"accessed under `{ldr.lock1}` (L{ldr.access1_line}) "
                            f"and `{ldr.lock2}` (L{ldr.access2_line})"
                        ),
                    })
            except Exception:
                logger.debug(
                    "check_lock_domain inject failed for %s:%s",
                    file, function, exc_info=True,
                )

        if self._check_uninit_leak is not None and is_c:
            try:
                for uleak in self._check_uninit_leak(
                    src, function,
                    joern_server=self._joern_server,
                ):
                    findings.append({
                        "file": file,
                        "function": function,
                        "detector": f"uninit_leak:{uleak.tier}",
                        "line": uleak.line,
                        "description": uleak.description,
                    })
            except Exception:
                logger.debug(
                    "uninit_leak inject failed for %s:%s",
                    file, function, exc_info=True,
                )

        if self._check_callback_cross is not None and is_c:
            try:
                clr = self._check_callback_cross(
                    self._joern_server, file, function,
                )
                if clr.violation_found:
                    for v in clr.violations:
                        findings.append({
                            "file": file,
                            "function": function,
                            "detector": "callback_lifetime_cross",
                            "line": v.register_line or line_start,
                            "description": v.reasoning,
                        })
                    if not clr.violations:
                        findings.append({
                            "file": file,
                            "function": function,
                            "detector": "callback_lifetime_cross",
                            "line": line_start,
                            "description": clr.reasoning,
                        })
            except Exception:
                logger.debug(
                    "callback_lifetime_cross inject failed for %s:%s",
                    file, function, exc_info=True,
                )

        self._cache[key] = findings
        return findings


def _run_mechanical_detectors(
    gaps: List[Dict[str, Any]],
    config: OrchestratorConfig,
    context_map: Optional[Dict[str, Any]] = None,
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    joern_server: Any = None,
) -> tuple[Dict[str, List[Dict[str, Any]]], set[str]]:
    """Run pre-loop mechanical detectors over all source files.

    Returns a tuple of:
      1. Findings keyed by "file:function".  Each value is a list of
         finding dicts with keys: file, function, detector, line, description.
      2. A set of "file:function" keys that are mechanically clean — all
         sinks had sufficient guards with no detector findings.

    Design ref: ~/design/audit.md lines 782-813.
    """
    mechanical_findings: Dict[str, List[Dict[str, Any]]] = {}
    guard_clean_keys: set[str] = set()
    _guarded_funcs: set[str] = set()
    _sufficient_funcs: dict[str, bool] = {}
    _decorative_funcs: set[str] = set()
    _smt_insufficient_funcs: set[str] = set()
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
        return mechanical_findings, guard_clean_keys

    def _add(file: str, func: str, detector: str, line: int, description: str) -> None:
        nonlocal total
        key = f"{file}:{func}"
        mechanical_findings.setdefault(key, []).append(
            {
                "file": file,
                "function": func,
                "detector": detector,
                "line": line,
                "description": description,
            }
        )
        total += 1

    sinks_set: frozenset[str] = frozenset()
    if context_map:
        from .gaps import extract_context_map_set

        sinks_set = frozenset(extract_context_map_set(context_map, "sinks"))

    # --- L0/L1/L2/L3: condition chain (parallelised per file) ---
    guard_cache: Dict[str, list] = {}
    _extract_sg = None
    _assess_guards = None
    _check_bindings = None
    _check_sufficiency = None
    _check_pf = None
    _check_sm = None
    _cpg_verify = None

    try:
        from .condition_extraction import extract_sink_guards as _extract_sg
        from .condition_adequacy import assess_file_guards as _assess_guards
        from .condition_binding import check_all_bindings as _check_bindings
    except Exception:
        logger.debug("mechanical: condition chain import failed", exc_info=True)

    try:
        from .condition_smt import (
            check_all_sufficiency as _check_sufficiency,
            check_path_feasibility as _check_pf,
            check_signed_mismatch as _check_sm,
        )
    except Exception:
        logger.debug("mechanical: condition_smt import failed", exc_info=True)

    if joern_server is not None:
        try:
            from .condition_cpg import verify_guard_relevance_cpg as _cpg_verify
        except Exception:
            logger.debug("mechanical: condition_cpg import failed", exc_info=True)

    def _guards_for(fp, src):
        if fp not in guard_cache:
            if _extract_sg is not None:
                try:
                    guard_cache[fp] = _extract_sg(
                        src, fp, sink_names=sinks_set or None,
                    )
                except Exception:
                    guard_cache[fp] = []
            else:
                guard_cache[fp] = []
        return guard_cache[fp]

    def _process_file_conditions(fp, src):
        findings = []
        guards = _guards_for(fp, src)
        if not guards:
            return findings

        for sg in guards:
            if sg.guards:
                gkey = f"{fp}:{sg.sink_function}"
                _guarded_funcs.add(gkey)
                if gkey not in _sufficient_funcs:
                    _sufficient_funcs[gkey] = True

        if _assess_guards is not None:
            try:
                adequacy_results, asymmetries = _assess_guards(guards)
                for sg, ar in zip(guards, adequacy_results):
                    v = ar.verdict
                    if hasattr(v, "value"):
                        v = v.value
                    gkey = f"{fp}:{sg.sink_function}"
                    if v != "sufficient":
                        _sufficient_funcs[gkey] = False
                    if v in ("irrelevant", "insufficient", "unknown"):
                        notes = "; ".join(ar.notes) if ar.notes else ""
                        findings.append((
                            fp, sg.sink_function, f"guard_{v}",
                            sg.sink_line,
                            f"{v} guard for {ar.sink_api}: {notes}",
                        ))
                for asym in asymmetries:
                    findings.append((
                        fp, asym.sink_function, "sink_guard_asymmetry",
                        asym.unguarded_line,
                        f"asymmetric guarding of {asym.sink_api}: "
                        f"guarded at L{asym.guarded_line}, "
                        f"unguarded at L{asym.unguarded_line}",
                    ))
            except Exception:
                logger.debug("condition adequacy failed for %s", fp, exc_info=True)

        if _check_bindings is not None:
            try:
                binding_analyses = _check_bindings(src, guards)
                for sg, ba in zip(guards, binding_analyses):
                    if ba.all_guards_decorative:
                        gkey = f"{fp}:{sg.sink_function}"
                        _decorative_funcs.add(gkey)
                        findings.append((
                            fp, sg.sink_function, "unbound_guard",
                            sg.sink_line,
                            f"all {ba.decorative_guard_count} guard(s) "
                            f"decorative for {ba.sink_api}",
                        ))
            except Exception:
                logger.debug("condition binding failed for %s", fp, exc_info=True)

        # SMT first — proven-sufficient guards skip the expensive CPG round
        _smt_cleared = set()
        if _check_sufficiency is not None:
            try:
                smt_per_guard = _check_sufficiency(guards)
                for idx, (sg, results) in enumerate(zip(guards, smt_per_guard)):
                    has_insufficient = False
                    for sr in results:
                        if sr.feasible is True:
                            has_insufficient = True
                            gkey = f"{fp}:{sg.sink_function}"
                            _smt_insufficient_funcs.add(gkey)
                            detail = sr.reasoning or ""
                            if sr.concrete_values:
                                vals = ", ".join(
                                    f"{k}={v}" for k, v in sr.concrete_values.items()
                                )
                                detail = f"{detail} ({vals})" if detail else vals
                            detector = "insufficient_guard_smt"
                            if sr.witness:
                                detector += ":witness"
                                detail += f" witness={sr.witness}"
                            findings.append((
                                fp, sg.sink_function, detector,
                                sg.sink_line,
                                f"SMT: guard '{sr.guard_text}' insufficient "
                                f"for {sg.sink_api}: {detail}",
                            ))
                    if not has_insufficient:
                        _smt_cleared.add(idx)
            except Exception:
                logger.debug("condition_smt failed for %s", fp, exc_info=True)

        if _cpg_verify is not None:
            try:
                for idx, sg in enumerate(guards):
                    if idx in _smt_cleared:
                        continue
                    cpg_results = _cpg_verify(sg, joern_server=joern_server)
                    for cr in cpg_results:
                        if cr.data_dep_bound is False and cr.dominates_sink is False:
                            findings.append((
                                fp, sg.sink_function, "decorative_guard_cpg",
                                sg.sink_line,
                                f"CPG: guard '{cr.guard_text}' neither "
                                f"on data-dep path nor dominates sink "
                                f"{cr.sink_api}",
                            ))
            except Exception:
                logger.debug("condition_cpg failed for %s", fp, exc_info=True)

        if _check_pf is not None:
            try:
                for sg in guards:
                    if sg.guards:
                        pfr = _check_pf(sg.guards)
                        if pfr.feasible is False:
                            detector = "dead_path_smt"
                            desc = (
                                f"SMT: path to {sg.sink_api} is infeasible "
                                f"({pfr.reasoning})"
                            )
                            if pfr.witness:
                                detector += ":witness"
                                desc += f" witness={pfr.witness}"
                            findings.append((fp, sg.sink_function, detector, sg.sink_line, desc))

                    if _check_sm is not None:
                        for guard in sg.guards:
                            if not guard.resolvable:
                                continue
                            smr = _check_sm(guard)
                            if smr.mismatch:
                                detector = "signed_mismatch_smt"
                                desc = f"SMT: {smr.reasoning}"
                                if smr.witness:
                                    detector += ":witness"
                                    desc += f" witness={smr.witness}"
                                findings.append((fp, sg.sink_function, detector, sg.sink_line, desc))
            except Exception:
                logger.debug("condition_smt L3b failed for %s", fp, exc_info=True)

        return findings

    if _extract_sg is not None:
        from concurrent.futures import ThreadPoolExecutor

        file_items = list(source_texts.items())
        with ThreadPoolExecutor(max_workers=min(8, len(file_items) or 1)) as pool:
            futures = {
                pool.submit(_process_file_conditions, fp, src): fp
                for fp, src in file_items
            }
            for fut in futures:
                try:
                    for finding_tuple in fut.result():
                        _add(*finding_tuple)
                except Exception:
                    fp = futures[fut]
                    logger.debug("condition chain failed for %s", fp, exc_info=True)

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
            _add(
                sc.file,
                sc.function,
                "sentinel_collapse",
                sc.line,
                f"{sc.write_value} coerced via {sc.read_coercion}: {sc.semantic_loss}",
            )
    except Exception:
        logger.debug("mechanical: sentinel_collapse failed", exc_info=True)

    try:
        from .fail_open_detector import detect_fail_open_patterns

        for fo in detect_fail_open_patterns(source_texts, call_graphs):
            _add(fo.file, fo.function, "fail_open", fo.line, fo.description)
    except Exception:
        logger.debug("mechanical: fail_open failed", exc_info=True)

    try:
        from .pattern_completeness import detect_pattern_gaps

        for pg in detect_pattern_gaps(source_texts):
            _add(
                pg.file,
                pg.function,
                "pattern_gap",
                pg.line,
                f"{pg.gap_type}: {pg.pattern} — {pg.suggestion}",
            )
    except Exception:
        logger.debug("mechanical: pattern_completeness failed", exc_info=True)

    try:
        from .callsite_consistency import detect_callsite_deviations

        for cd in detect_callsite_deviations(
            source_texts, joern_server=joern_server,
        ):
            _add(
                cd.file,
                cd.enclosing_function,
                "callsite_deviation",
                cd.line,
                f"{cd.callee}: {cd.discarded_count}/{cd.total_sites} "
                f"sites discard return value",
            )
    except Exception:
        logger.debug("mechanical: callsite_consistency failed", exc_info=True)

    try:
        from .transform_sequence import detect_transform_order_violations

        for tv in detect_transform_order_violations(source_texts):
            _add(
                tv.file,
                tv.function,
                "transform_order",
                tv.line,
                f"{tv.violation} — fix: {tv.fix}",
            )
    except Exception:
        logger.debug("mechanical: transform_sequence failed", exc_info=True)

    try:
        from .value_space_checker import detect_value_space_mismatches

        for vm in detect_value_space_mismatches(source_texts, call_graphs):
            unhandled = ", ".join(vm.unhandled[:5])
            _add(
                vm.consumer_file,
                vm.consumer_function,
                "value_space_mismatch",
                0,
                f"producer {vm.producer_function} emits values "
                f"not handled by consumer: [{unhandled}]",
            )
    except Exception:
        logger.debug("mechanical: value_space_checker failed", exc_info=True)

    try:
        from .type_confusion import detect_type_confusion

        for tcf in detect_type_confusion(source_texts, call_graphs, joern_server):
            subtypes_str = ", ".join(getattr(tcf, "overriding_subtypes", [])[:3])
            _add(
                tcf.file,
                tcf.function,
                "type_confusion",
                tcf.line,
                f"deserialised object reaches virtual dispatch "
                f"of {getattr(tcf, 'overridden_method', '?')}() — "
                f"subtypes [{subtypes_str}] override this method",
            )
    except Exception:
        logger.debug("mechanical: type_confusion failed", exc_info=True)

    try:
        from .callback_lifetime import check_callback_lifetime_local

        for fp, src in source_texts.items():
            if not any(fp.endswith(ext) for ext in _C_EXTS):
                continue
            for gap in gaps:
                if gap.get("file") != fp:
                    continue
                func_name = gap.get("name", "")
                line_start = gap.get("line_start", 0)
                line_end = gap.get("line_end")
                func_src = _read_raw_source(
                    config.target_path, fp, line_start, line_end,
                )
                if not func_src:
                    continue
                clr = check_callback_lifetime_local(func_src)
                if clr.violation_found:
                    desc = clr.reasoning
                    detector = "callback_lifetime_local"
                    if clr.rcu_kfree_mismatch:
                        detector = "rcu_kfree_mismatch"
                    _add(fp, func_name, detector, line_start, desc)
    except Exception:
        logger.debug("mechanical: callback_lifetime failed", exc_info=True)

    # --- Standing Coccinelle templates ---
    try:
        from packages.coccinelle.runner import (
            is_available as _cocci_avail,
            run_rule as _run_cocci_rule,
        )

        raptor_dir = Path(os.environ["RAPTOR_DIR"])
        rules_dir = raptor_dir / "engine" / "coccinelle" / "rules"
        if _cocci_avail() and rules_dir.is_dir() and config.target_path:
            from .cwe_dispatch import CWE_TO_TOOL_DISPATCH

            standing_rules: set[str] = set()
            for entry in CWE_TO_TOOL_DISPATCH.values():
                cocci_name = entry.get("cocci")
                if cocci_name:
                    rule_path = rules_dir / cocci_name
                    if rule_path.is_file():
                        standing_rules.add(str(rule_path))
            if standing_rules:
                c_files = [
                    config.target_path / fp
                    for fp in source_texts
                    if any(fp.endswith(ext) for ext in _C_EXTS)
                ]
                for c_file in c_files:
                    if not c_file.is_file():
                        continue
                    for rule_path_str in sorted(standing_rules):
                        sr = _run_cocci_rule(
                            c_file, Path(rule_path_str),
                            no_includes=True, timeout=60,
                        )
                        for match in sr.matches:
                            f_file = match.file or str(c_file)
                            f_line = match.line or 0
                            f_rule = sr.rule or Path(rule_path_str).stem
                            try:
                                rel = str(
                                    Path(f_file).relative_to(config.target_path)
                                )
                            except ValueError:
                                rel = ""
                            func_name = ""
                            for gap in gaps:
                                if gap.get("file") != rel:
                                    continue
                                gs = gap.get("line_start", 0)
                                ge = gap.get("line_end", gs + 9999)
                                if gs <= f_line <= (ge or gs + 9999):
                                    func_name = gap.get("name", "")
                                    break
                            if func_name:
                                desc = match.message or str(match)
                                _add(
                                    rel, func_name,
                                    f"cocci:{f_rule}", f_line, desc,
                                )
    except Exception:
        logger.debug("mechanical: standing_cocci failed", exc_info=True)

    # inject-mode detectors moved to lazy evaluation — see _InjectModeResolver

    if total:
        unique_funcs = len(mechanical_findings)
        logger.info(
            "mechanical detectors: %d findings across %d unique functions",
            total,
            unique_funcs,
        )

    for gkey in _guarded_funcs:
        if (
            _sufficient_funcs.get(gkey, False)
            and gkey not in _decorative_funcs
            and gkey not in _smt_insufficient_funcs
            and gkey not in mechanical_findings
        ):
            guard_clean_keys.add(gkey)

    if guard_clean_keys:
        logger.info(
            "guard-clean resolution: %d functions with all sinks properly "
            "guarded",
            len(guard_clean_keys),
        )

    return mechanical_findings, guard_clean_keys


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
                "found %d stale annotation(s) for re-review",
                len(stale_items),
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
                or (rec.taint_approx and _get_dangerous_flows(rec.taint_approx))
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

    ctx["review_mode"] = config.mode

    return ctx


def _commit_outcome(
    config: OrchestratorConfig,
    outcome: ReviewOutcome,
    gap: Dict[str, Any],
    *,
    batch: bool = False,
) -> None:
    """Write the review result to review-journal.jsonl.

    Journal is the sole LLM review store. ``record_review`` (which
    wrote ``coverage-audit.json``) and ``mark_checked`` (which
    stamped ``checked_by`` on the checklist) were removed at Phase-3
    completion — both duplicated state the journal already carries.
    Coverage-store LLM signal is imported from the journal at run
    completion; consumers wanting per-function verdict/context read
    the journal directly.
    """
    checked_by = ["audit"]
    if outcome.model:
        checked_by.append(outcome.model)

    from .collector import append_journal_for_outcome

    # ``run_id`` derived from the run-dir basename to match Collector's
    # convention (see Collector construction ~orchestrator.py:1810).
    # Without this every ``_commit_outcome`` journal entry would carry
    # an empty ``run_id``, breaking cross-run queries and the project
    # index's provenance.
    run_id = config.out_dir.name if config.out_dir else ""
    append_journal_for_outcome(
        out_dir=config.out_dir,
        target_path=config.target_path,
        run_id=run_id,
        outcome=outcome,
        gap=gap,
        checked_by=checked_by,
    )

    outcome.verification_tier = outcome.compute_tier()

    line_start = gap.get("line_start", 0)
    entry: Dict[str, Any] = {
        "action": "orchestrator_review",
        "key": f"{outcome.file}:{outcome.function}:{line_start}",
        "status": outcome.status,
        "verification_tier": outcome.verification_tier,
        "model": outcome.model,
        "cost_usd": outcome.cost_usd,
        "duration_s": outcome.duration_s,
    }
    if outcome.hypothesis:
        entry["hypothesis"] = outcome.hypothesis
    if outcome.hypotheses:
        entry["hypotheses"] = outcome.hypotheses
    rr = outcome.review_result or {}
    if rr.get("counter_hypothesis"):
        entry["counter_hypothesis"] = rr["counter_hypothesis"]
    if outcome.evidence_tool:
        entry["evidence_tool"] = outcome.evidence_tool
    if outcome.review_result and outcome.review_result.get("preconditions"):
        entry["preconditions"] = outcome.review_result["preconditions"]
    if outcome.review_result and outcome.review_result.get("intent_trace"):
        entry["intent_trace"] = outcome.review_result["intent_trace"]
    if rr.get("relies_on"):
        entry["relies_on"] = rr["relies_on"]
    strategies = gap.get("strategies")
    if strategies:
        entry["strategies"] = strategies
    if batch:
        entry["batch"] = True
    append_audit_log(config.out_dir, entry)

    # ── SAGE: store hypothesis verdict ───────────────────────────────
    src_hash = gap.get("_sage_source_hash", "")
    if src_hash and outcome.status != "error" and outcome.hypothesis:
        try:
            from core.sage.hooks import store_audit_hypothesis_verdict

            evidence = outcome.evidence_tool or ""
            if gap.get("force_review"):
                evidence = f"{evidence}+chain_context" if evidence else "chain_context"
            store_audit_hypothesis_verdict(
                repo_path=str(config.target_path),
                file_path=outcome.file,
                function=outcome.function,
                hypothesis=outcome.hypothesis,
                status=outcome.status,
                evidence_tool=evidence,
                source_hash=src_hash,
            )
        except Exception:
            logger.debug(
                "SAGE hypothesis store failed for %s:%s",
                outcome.file,
                outcome.function,
                exc_info=True,
            )


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


def _resolve_hypothesis(outcome: ReviewOutcome) -> str:
    """Extract the best hypothesis string from the review result.

    Prefers the singular ``hypothesis`` field.  When it is empty, falls
    back to the highest-confidence entry in the ``hypotheses`` array.
    """
    review = outcome.review_result or {}
    hyp = review.get("hypothesis") or outcome.hypothesis or ""
    if hyp and hyp.strip():
        return hyp

    hypotheses = review.get("hypotheses") or []
    _RANK = {"high": 0, "medium": 1, "low": 2, "refuted": 3}
    best = None
    best_rank = 999
    for entry in hypotheses:
        if not isinstance(entry, dict):
            continue
        mechanism = entry.get("mechanism") or ""
        if not mechanism.strip():
            continue
        confidence = entry.get("confidence", "low")
        rank = _RANK.get(confidence, 2)
        if rank < best_rank:
            best = mechanism
            best_rank = rank
    return best or ""


def _check_finding_gates(
    outcome: ReviewOutcome,
    *,
    audit_log: Optional[List[Dict[str, Any]]] = None,
    domain_model: Optional[Dict[str, Any]] = None,
    mode: ReviewMode = ReviewMode.SECURITY,
) -> List[str]:
    """Check G1-G5 gates on a finding. Returns list of violations."""
    from .evidence_grade import is_tool_evidence

    violations = []
    hypothesis = _resolve_hypothesis(outcome)

    evidence = outcome.evidence_tool or ""
    if not evidence and outcome.review_result:
        evidence = _sanitize_llm_et(
            outcome.review_result.get("evidence_tool", ""),
        )

    if not hypothesis or hypothesis.strip() == "":
        violations.append("G1: finding emitted without testable hypothesis")

    if not is_tool_evidence(evidence):
        matched_invariants = _match_domain_model_invariants(
            hypothesis,
            outcome.file,
            domain_model,
        )
        if matched_invariants:
            inv_ids = ", ".join(matched_invariants)
            logger.info(
                "G2 bypassed for %s:%s — hypothesis matches "
                "domain-model invariant(s): %s",
                outcome.file,
                outcome.function,
                inv_ids,
            )
        else:
            violations.append("G2: finding emitted without tool-grounded evidence")

    # G3: NO-SELF-CRITIQUE — re-recording same function requires a sweep
    if audit_log is not None:
        key = f"{outcome.file}:{outcome.function}"
        prior_records = [
            e
            for e in audit_log
            if e.get("key") == key
            and e.get("action") in ("record", "orchestrator_review")
            and e.get("status") in ("finding", "suspicious")
        ]
        if prior_records and not outcome.evidence_tool:
            violations.append("G3: re-recording without new tool evidence")

    # G4: EVIDENCE-IN-ANNOTATION — findings require a non-empty body
    body = outcome.body or ""
    if outcome.status in ("finding", "suspicious") and not body.strip():
        violations.append("G4: finding/suspicious with empty annotation body")

    # G5: LANGUAGE-CWE — memory-corruption CWEs in memory-safe languages
    # Skipped in quality mode (no security classification)
    if mode != ReviewMode.QUALITY:
        lang_mismatch = _check_language_cwe_mismatch(outcome)
        if lang_mismatch:
            violations.append(f"G5: {lang_mismatch}")

    return violations


class _ContentFilterError(Exception):
    """Raised when the LLM response is blocked by a content filter."""


_STATUS_SEVERITY = {
    "finding": 3,
    "suspicious": 2,
    "dormant": 1,
    "clean": 0,
    "error": -1,
}


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
                context: Dict[str, Any],
                model_name: str,
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
                    file=file_path,
                    function=function_name,
                    status="error",
                    body="multi-review produced no items",
                )

            primary = mr_result.items[0]
            total_cost = sum(
                r.get("cost_usd", 0)
                for raw_list in mr_result.per_model_raw.values()
                for r in raw_list
            )
            total_duration = max(
                (
                    r.get("duration_s", 0)
                    for raw_list in mr_result.per_model_raw.values()
                    for r in raw_list
                ),
                default=0,
            )
            return ReviewOutcome(
                file=primary.get("file", file_path),
                function=primary.get("function", function_name),
                status=(consensus_status(mr_result) or primary.get("status", "error")),
                body=primary.get("body", ""),
                hypothesis=primary.get("hypothesis", ""),
                hypotheses=primary.get("hypotheses"),
                evidence_tool=_sanitize_llm_et(primary.get("evidence_tool", "")),
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
                file=file_path,
                function=function_name,
                status="error",
                body="blocked by content filter",
            )
        except Exception as exc:
            logger.warning(
                "review_fn pass failed for %s:%s: %s",
                file_path,
                function_name,
                exc,
            )
            outcome = ReviewOutcome(
                file=file_path,
                function=function_name,
                status="error",
                body=f"pass failed: {exc}",
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
        for h in o.hypotheses or []:
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
        evidence_tool=_sanitize_llm_et(best.evidence_tool),
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
    if any(
        k in msg
        for k in (
            "rate limit",
            "timeout",
            "502",
            "503",
            "504",
            "bad gateway",
            "overloaded",
            "quota exceeded",
            "server error",
        )
    ):
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


_TRUNCATION_STRIP_KEYS = frozenset(
    {
        "block_analysis",
        "sibling_ns",
        "type_constraints",
    }
)


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
        o
        for o in result.outcomes
        if o.status == "error" and o.error_class in _RECOVERABLE_ERROR_CLASSES
    ]
    if not error_outcomes:
        return result

    for outcome in error_outcomes:
        if _check_budget(config, start_time, result):
            break

        try:
            ctx = _build_context(
                config,
                {"file": outcome.file, "name": outcome.function},
                checklist,
                None,
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
        if new_outcome.status != "error":
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
            "error_retry",
            cost_usd=getattr(new_outcome, "cost_usd", 0.0),
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
    if config.max_cost_usd:
        with result._lock:
            if result.total_cost_usd >= config.max_cost_usd:
                result.terminated_by = "max_cost_usd"
                return True
    return False


@dataclass
class StudyRequest:
    """A single reading-list item produced by a review."""
    question: str
    source_file: str
    source_function: str
    priority: str = "normal"
    resolution: str = "identifier"
    context: str = ""


class StudyQueue:
    """Thread-safe producer-consumer queue for study requests.

    Supports concept-level tracking for the suppression gate:
    pending_concepts() returns concepts currently awaiting study;
    mark_studied() moves them to the studied set and wakes the
    executor via an asyncio.Event bridge.
    """

    def __init__(self) -> None:
        self._queue: list[StudyRequest] = []
        self._lock = _threading.Lock()
        self._not_empty = _threading.Condition(_threading.Lock())
        self._producer_done = False
        self._pending_concepts: set[str] = set()
        self._studied_concepts: set[str] = set()
        self._consumer_done = False
        self._loop: Any = None
        self._study_event: Any = None

    def enqueue(self, item: StudyRequest) -> None:
        concept = _extract_concept_from_question(item.question)
        with self._not_empty:
            self._queue.append(item)
            if concept:
                self._pending_concepts.add(concept.lower())
            self._not_empty.notify()

    def dequeue_batch(
        self, max_items: int = 15, timeout: float = 30.0,
    ) -> list[StudyRequest]:
        with self._not_empty:
            if not self._queue and not self._producer_done:
                self._not_empty.wait(timeout=timeout)
            batch = self._queue[:max_items]
            del self._queue[:max_items]
            return batch

    def signal_producer_done(self) -> None:
        with self._not_empty:
            self._producer_done = True
            self._not_empty.notify_all()

    def is_done(self) -> bool:
        with self._not_empty:
            return self._producer_done and not self._queue

    def pending_concepts(self) -> frozenset:
        with self._not_empty:
            return frozenset(self._pending_concepts)

    def mark_studied(self, concepts: set) -> None:
        with self._not_empty:
            self._pending_concepts -= concepts
            self._studied_concepts |= concepts
        self._notify_executor()

    def signal_consumer_done(self) -> None:
        with self._not_empty:
            self._consumer_done = True
            self._pending_concepts.clear()
        self._notify_executor()

    @property
    def consumer_done(self) -> bool:
        return self._consumer_done

    def set_event_loop(self, loop: Any, event: Any) -> None:
        self._study_event = event
        self._loop = loop

    def _notify_executor(self) -> None:
        loop = self._loop
        event = self._study_event
        if loop is None or event is None:
            return
        if not loop.is_running():
            return
        try:
            loop.call_soon_threadsafe(event.set)
        except RuntimeError:
            pass


class ConceptIndex:
    """Maps concept names to the functions that reference them.

    Built from checklist source bodies intersected with known
    type/struct/macro names.  Immutable after construction.
    """

    def __init__(
        self,
        concept_to_fns: dict[str, set[str]],
        fn_to_concepts: dict[str, set[str]],
    ) -> None:
        self._concept_to_fns = concept_to_fns
        self._fn_to_concepts = fn_to_concepts

    def concepts_for(self, file: str, name: str) -> frozenset:
        key = f"{file}:{name}"
        return frozenset(self._fn_to_concepts.get(key, ()))

    def functions_for(self, concept: str) -> frozenset:
        return frozenset(self._concept_to_fns.get(concept.lower(), ()))

    @classmethod
    def empty(cls) -> ConceptIndex:
        return cls({}, {})

    @classmethod
    def build(
        cls,
        checklist: dict,
        known_types: set[str] | None = None,
        *,
        cardinality_cap_pct: float = 0.05,
        cardinality_cap_abs: int = 20,
    ) -> ConceptIndex:
        import re as _re

        items = checklist.get("items", [])
        if not items:
            return cls.empty()

        types_lower = {t.lower() for t in known_types} if known_types else set()
        if not types_lower:
            return cls.empty()

        cap = min(
            int(len(items) * cardinality_cap_pct),
            cardinality_cap_abs,
        )
        cap = max(cap, 1)

        concept_to_fns: dict[str, set[str]] = {}
        fn_to_concepts: dict[str, set[str]] = {}

        ident_re = _re.compile(r'\b[A-Za-z_]\w{2,}\b')

        for item in items:
            source = item.get("source", "")
            if not source:
                continue
            fn_key = f"{item['file']}:{item['name']}"
            tokens = {t.lower() for t in ident_re.findall(source)}
            matched = tokens & types_lower
            for concept in matched:
                concept_to_fns.setdefault(concept, set()).add(fn_key)
                fn_to_concepts.setdefault(fn_key, set()).add(concept)

        to_drop = [
            c for c, fns in concept_to_fns.items()
            if len(fns) > cap
        ]
        for c in to_drop:
            for fn_key in concept_to_fns.pop(c):
                s = fn_to_concepts.get(fn_key)
                if s:
                    s.discard(c)

        return cls(concept_to_fns, fn_to_concepts)


_STUDY_MAX_RE_REVIEWS = 50
_STUDY_RE_REVIEW_PER_CYCLE = 10
_STUDY_MAX_STALE_BATCHES = 3


def _dedup_batch(
    batch: list[StudyRequest],
    seen_concepts: set,
    domain_model: dict | None,
) -> list[StudyRequest]:
    """Remove items whose concept is already studied or in-flight."""
    known = set(seen_concepts)
    if domain_model:
        for concept in domain_model.get("concepts", []):
            known.add(concept.get("name", "").lower())
        for inv in domain_model.get("invariants", []):
            known.add(inv.get("subject", "").lower())

    fresh: list[StudyRequest] = []
    for item in batch:
        concept = _extract_concept_from_question(item.question)
        if concept and concept.lower() not in known:
            known.add(concept.lower())
            fresh.append(item)
        elif not concept:
            fresh.append(item)
    return fresh


def _extract_concept_from_question(question: str) -> str | None:
    """Pull the key identifier from a reading-list question.

    Handles patterns like "what is sk_buff?", "how does skb_put work?",
    "Does process_heartbeat validate payload_len against out_cap?".
    """
    import re as _re
    m = _re.search(
        r"(?:what is|how does|does)\s+[`'\"]?(\w+)[`'\"]?",
        question,
        _re.IGNORECASE,
    )
    return m.group(1) if m else None


def _study_consumer(
    study_queue: StudyQueue,
    config: OrchestratorConfig,
    shared: SharedState,
    review_fn: Callable,
    reviewed_outcomes: _LockedOutcomes,
    result: OrchestratorResult,
    *,
    checklist: dict,
    context_map: dict | None,
    evidence_index: dict,
    sarif_cache: SarifCache | None,
    entry_points: set,
    start_time: float,
    on_progress: Callable | None,
    audit_log: list | None = None,
    session_observations: list | None = None,
    discovered_evidence: dict | None = None,
    joern_server: Any = None,
    collector: Any = None,
    throttle: Any = None,
    concept_index_ref: list | None = None,
) -> None:
    """Thread B: consume study requests, study in-process, re-review."""
    study_list_built = False
    study_list_path: Path | None = None
    re_review_count = 0
    stale_batches = 0
    seen_concepts: set[str] = set()

    try:
        _study_consumer_loop(
            study_queue, config, shared, review_fn, reviewed_outcomes,
            result,
            checklist=checklist,
            context_map=context_map,
            evidence_index=evidence_index,
            sarif_cache=sarif_cache,
            entry_points=entry_points,
            start_time=start_time,
            on_progress=on_progress,
            audit_log=audit_log,
            session_observations=session_observations,
            discovered_evidence=discovered_evidence,
            joern_server=joern_server,
            collector=collector,
            throttle=throttle,
            concept_index_ref=concept_index_ref,
            state={
                "study_list_built": study_list_built,
                "study_list_path": study_list_path,
                "re_review_count": re_review_count,
                "stale_batches": stale_batches,
                "seen_concepts": seen_concepts,
            },
        )
    finally:
        study_queue.signal_consumer_done()


def _study_consumer_loop(
    study_queue: StudyQueue,
    config: OrchestratorConfig,
    shared: SharedState,
    review_fn: Callable,
    reviewed_outcomes: _LockedOutcomes,
    result: OrchestratorResult,
    *,
    checklist: dict,
    context_map: dict | None,
    evidence_index: dict,
    sarif_cache: SarifCache | None,
    entry_points: set,
    start_time: float,
    on_progress: Callable | None,
    audit_log: list | None = None,
    session_observations: list | None = None,
    discovered_evidence: dict | None = None,
    joern_server: Any = None,
    collector: Any = None,
    throttle: Any = None,
    concept_index_ref: list | None = None,
    state: dict | None = None,
) -> None:
    """Inner loop for _study_consumer (separated for try/finally)."""
    st = state or {}
    study_list_built = st.get("study_list_built", False)
    study_list_path = st.get("study_list_path")
    re_review_count = st.get("re_review_count", 0)
    stale_batches = st.get("stale_batches", 0)
    seen_concepts = st.get("seen_concepts", set())

    while not study_queue.is_done():
        # The consumer runs its own LLM calls (study-prep, Phase 2/3
        # batches, re-reviews) — without this gate it kept working
        # long past max_seconds/max_cost (observed 27min against a
        # 900s cap) because only the main review loop checked budget.
        if _check_budget(config, start_time, result):
            logger.info(
                "study-consumer: run budget exhausted (%s) — stopping",
                result.terminated_by,
            )
            break
        batch = study_queue.dequeue_batch(max_items=15, timeout=30.0)
        if not batch:
            continue

        dm = shared.domain_model
        fresh = _dedup_batch(batch, seen_concepts, dm)
        if not fresh:
            continue

        if not config.out_dir:
            continue

        # Flush to reading-list.json (Thread B is sole writer)
        try:
            from core.concepts.audit_bridge import queue_reading_list_item

            for req in fresh:
                queue_reading_list_item(
                    config.out_dir,
                    question=req.question,
                    source_file=req.source_file,
                    source_function=req.source_function,
                    priority=req.priority,
                    resolution=req.resolution,
                    context=req.context,
                )
        except Exception:
            logger.warning(
                "study-consumer: flush to reading-list failed",
                exc_info=True,
            )
            continue

        # Study-prep: run once, cache study-list + parsed data
        if not study_list_built:
            study_target = str(config.study_root or config.target_path)
            prep_cmd = [
                sys.executable,
                str(
                    Path(__file__).resolve().parents[2]
                    / "libexec"
                    / "raptor-study-prep"
                ),
                study_target,
                str(config.out_dir),
            ]
            rl_path = config.out_dir / "reading-list.json"
            if rl_path.is_file():
                prep_cmd.extend(["--reading-list", str(rl_path)])
            if config.models and config.models[0] != "default":
                prep_cmd.extend(["--model", config.models[0]])

            from core.config import RaptorConfig

            study_env = RaptorConfig.get_safe_env()
            study_env["_RAPTOR_TRUSTED"] = "1"
            try:
                prep_result = subprocess.run(
                    prep_cmd,
                    env=study_env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if prep_result.returncode != 0:
                    logger.warning(
                        "study-consumer: prep failed (exit %d): %s",
                        prep_result.returncode,
                        (prep_result.stderr or "").strip()[:200],
                    )
                    continue
            except subprocess.TimeoutExpired:
                logger.warning("study-consumer: prep timed out")
                continue
            except Exception:
                logger.warning("study-consumer: prep error", exc_info=True)
                continue

            study_list_path = config.out_dir / "study-list.json"
            if not study_list_path.is_file():
                logger.warning(
                    "study-consumer: no study-list.json after prep",
                )
                continue
            study_list_built = True

            # Build ConceptIndex from study-prep type data
            if concept_index_ref is not None:
                _build_concept_index_from_prep(
                    concept_index_ref, checklist, config.out_dir,
                )

        # Study-run: in-process, scoped to this batch's reading-list.
        n_before = len(dm.get("concepts", [])) if dm else 0
        try:
            from core.concepts.study import run_study
            from core.llm.client import LLMClient

            study_model = (
                config.models[0]
                if config.models and config.models[0] != "default"
                else None
            )
            study_client = LLMClient(pinned_model=study_model)
            try:
                if throttle is not None:
                    with throttle.acquire_sync():
                        run_study(
                            study_list_path,
                            config.out_dir,
                            study_client,
                        )
                else:
                    run_study(
                        study_list_path,
                        config.out_dir,
                        study_client,
                    )
            finally:
                # The study client's spend previously vanished: the
                # report's Cost line AND the --max-cost gate read
                # result.total_cost_usd, so a run under-reported (and
                # under-enforced) by every Phase 2/3 study call —
                # observed $2.87 reported vs $6.16 scorecard actual.
                # finally: partial spend from a failed run still counts.
                spent = getattr(study_client, "total_cost", 0.0) or 0.0
                if spent:
                    with result._lock:
                        result.total_cost_usd += spent
                    result.cost_tracker.record_call(
                        "study", cost_usd=spent,
                    )
        except Exception:
            logger.warning(
                "study-consumer: study-run failed", exc_info=True,
            )
            continue

        # Reload domain model
        try:
            from .journal import load_domain_model

            new_dm = load_domain_model(config.out_dir)
            if new_dm:
                shared.domain_model = new_dm
                if collector is not None:
                    collector.invalidate_domain_model_cache()
        except Exception:
            logger.debug("study-consumer: domain model reload failed",
                         exc_info=True)

        n_after = len(shared.domain_model.get("concepts", [])
                       ) if shared.domain_model else 0

        # Mark studied concepts so the suppression gate can release
        batch_concepts = set()
        for req in fresh:
            c = _extract_concept_from_question(req.question)
            if c:
                batch_concepts.add(c.lower())
        if batch_concepts:
            study_queue.mark_studied(batch_concepts)

        # Starvation guard
        if n_after == n_before:
            stale_batches += 1
            if stale_batches >= _STUDY_MAX_STALE_BATCHES:
                logger.info(
                    "study-consumer: %d stale batches, stopping",
                    stale_batches,
                )
                break
        else:
            stale_batches = 0

        seen_concepts.update(
            c.get("name", "").lower()
            for c in (shared.domain_model or {}).get("concepts", [])
        )

        # Compute new concepts for broader re-review
        new_concept_names: set[str] = set()
        if n_after > n_before and shared.domain_model:
            all_concepts = {
                c.get("name", "").lower()
                for c in shared.domain_model.get("concepts", [])
            }
            new_concept_names = all_concepts - seen_concepts
            seen_concepts.update(all_concepts)

        if re_review_count >= _STUDY_MAX_RE_REVIEWS:
            logger.info(
                "study-consumer: re-review cap (%d) reached",
                _STUDY_MAX_RE_REVIEWS,
            )
            continue

        # Collect re-review candidates: originating functions +
        # broader concept-scoped functions from ConceptIndex
        source_keys = {
            f"{r.source_file}:{r.source_function}" for r in fresh
        }

        ci = (concept_index_ref[0]
              if concept_index_ref and concept_index_ref[0]
              else None)
        if ci and new_concept_names:
            for concept in new_concept_names:
                source_keys |= set(ci.functions_for(concept))

        already_reviewed = source_keys & reviewed_outcomes.keys()
        if not already_reviewed:
            continue

        cycle_cap = min(
            _STUDY_RE_REVIEW_PER_CYCLE,
            _STUDY_MAX_RE_REVIEWS - re_review_count,
        )
        budget = min(len(already_reviewed), cycle_cap)

        # Prioritise: suspicious first, then the rest
        suspicious = sorted(
            k for k in already_reviewed
            if _is_suspicious_outcome(k, reviewed_outcomes)
        )
        rest = sorted(already_reviewed - set(suspicious))
        to_review = (suspicious + rest)[:budget]

        reading_list_fns = set(to_review)
        result = _re_review_study_enriched(
            result,
            config,
            review_fn,
            checklist,
            context_map,
            evidence_index,
            sarif_cache,
            entry_points,
            reading_list_fns,
            start_time,
            on_progress,
            audit_log=audit_log,
            session_observations=session_observations,
            discovered_evidence=discovered_evidence,
            joern_server=joern_server,
            max_workers=min(4, budget),
            throttle=throttle,
        )
        re_review_count += len(to_review)

        # Resolve batch items in reading-list
        try:
            from core.concepts.reading_list import ReadingList

            rl = ReadingList.load(config.out_dir / "reading-list.json")
            for req in fresh:
                for item in rl.pending():
                    if item.get("question") == req.question:
                        rl.resolve(
                            item["id"],
                            concept_id=_extract_concept_from_question(
                                req.question,
                            ),
                        )
                        break
            rl.save(config.out_dir / "reading-list.json")
        except Exception:
            logger.debug(
                "study-consumer: reading-list resolve failed",
                exc_info=True,
            )

    logger.info(
        "study-consumer: done (re-reviews=%d, stale_batches=%d)",
        re_review_count,
        stale_batches,
    )


def _is_suspicious_outcome(key: str, outcomes: _LockedOutcomes) -> bool:
    """Check if a reviewed function has a suspicious verdict."""
    try:
        outcome = outcomes.get(key)
        if outcome and hasattr(outcome, "status"):
            return outcome.status == "suspicious"
    except Exception:
        pass
    return False


def _build_concept_index_from_prep(
    concept_index_ref: list,
    checklist: dict,
    out_dir: Path,
) -> None:
    """Build ConceptIndex after study-prep, using its type data."""
    try:
        import json

        study_list_path = out_dir / "study-list.json"
        if not study_list_path.is_file():
            return
        with open(study_list_path) as f:
            study_list = json.load(f)
        type_names: set[str] = set()
        if isinstance(study_list, dict):
            idents = study_list.get("identifiers", "")
            if isinstance(idents, str) and idents:
                for name in idents.split(","):
                    name = name.strip()
                    if len(name) > 2:
                        type_names.add(name)
            for item in study_list.get("items", []):
                if isinstance(item, dict):
                    name = item.get("name", "")
                    if name and len(name) > 2:
                        type_names.add(name)
        elif isinstance(study_list, list):
            for item in study_list:
                if isinstance(item, dict):
                    name = item.get("name", "")
                    if name and len(name) > 2:
                        type_names.add(name)
        if not type_names:
            return

        target_path = checklist.get("target_path", "")
        enriched = _flatten_checklist_with_source(checklist, target_path)
        if not enriched:
            return
        idx = ConceptIndex.build({"items": enriched}, type_names)
        concept_index_ref[0] = idx
        logger.info(
            "study-consumer: built ConceptIndex "
            "(%d concepts, %d functions)",
            len(idx._concept_to_fns),
            len(idx._fn_to_concepts),
        )
    except Exception:
        logger.debug(
            "study-consumer: ConceptIndex build failed",
            exc_info=True,
        )


def _flatten_checklist_with_source(
    checklist: dict,
    target_path: str,
) -> list[dict]:
    """Flatten files[].items[] and read source bodies from disk."""
    from pathlib import Path as _Path

    base = _Path(target_path) if target_path else None
    result: list[dict] = []
    src_cache: dict[str, list[str]] = {}

    for fi in checklist.get("files", []):
        rel_path = fi.get("path", "")
        if not rel_path:
            continue
        for item in fi.get("items", []):
            name = item.get("name", "")
            if not name:
                continue
            source = ""
            if base is not None:
                ls = item.get("line_start")
                le = item.get("line_end")
                if ls and le:
                    if rel_path not in src_cache:
                        src_file = base / rel_path
                        try:
                            src_cache[rel_path] = (
                                src_file.read_text(errors="replace")
                                .splitlines()
                            )
                        except OSError:
                            src_cache[rel_path] = []
                    lines = src_cache[rel_path]
                    source = "\n".join(lines[ls - 1:le])
            result.append({
                "file": rel_path,
                "name": name,
                "source": source,
            })
    return result


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


def _sage_store_observation(text: str, kind: str, source: str) -> None:
    """Best-effort store of a tool-confirmed observation to SAGE."""
    try:
        from core.sage.hooks import store_audit_observation

        store_audit_observation(
            repo_path=str(_active_target_path or ""),
            observation=text,
            kind=kind,
            source_function=source,
        )
    except Exception:
        pass


_MAX_OBSERVATION_LEN = 500


def _sanitise_observation(text: str) -> str:
    """Sanitise an LLM-generated observation before re-injection.

    Observations flow into subsequent prompts.  A target with an
    injection payload could influence the LLM to emit observations
    that carry the payload forward.
    """
    from .prompt_defence import sanitise_for_prompt, scan_for_injection

    cleaned = sanitise_for_prompt(text, content_type="comment")
    if len(cleaned) > _MAX_OBSERVATION_LEN:
        cleaned = cleaned[:_MAX_OBSERVATION_LEN] + "…"
    warnings = scan_for_injection(cleaned, location="session_observation")
    if warnings:
        logger.warning(
            "injection pattern in observation (dropped): %s",
            cleaned[:80],
        )
        return ""
    return cleaned


def _accumulate_observations(
    session_observations: List[Dict[str, str]],
    outcome: ReviewOutcome,
    gap: Dict[str, Any],
    *,
    sweep_pre_status: Optional[str] = None,
) -> None:
    """Extract LLM observations and add to session context.

    Also injects tool confirmation/refutation observations when
    sweep validation changed the outcome status. Tool-confirmed and
    tool-refuted observations are also stored to SAGE for cross-target
    transfer via the methodology domain.
    """
    source = f"{gap['file']}:{gap['name']}"

    if sweep_pre_status is not None:
        if outcome.status == "finding" and _is_tool_confirmed(
            outcome.evidence_tool or ""
        ):
            obs_text = (
                f"[tool-confirmed] {outcome.evidence_tool} confirmed: "
                f"{_sanitise_observation(outcome.hypothesis or '')}"
            )
            session_observations.append(
                {
                    "source": source,
                    "text": obs_text,
                    "kind": "tool_confirmation",
                }
            )
            _sage_store_observation(obs_text, "tool_confirmation", source)
        elif sweep_pre_status == "finding" and outcome.status == "suspicious":
            obs_text = (
                f"[tool-refuted] hypothesis '{_sanitise_observation(outcome.hypothesis or '')}' "
                f"was not confirmed by any mechanical tool — demoted"
            )
            session_observations.append(
                {
                    "source": source,
                    "text": obs_text,
                    "kind": "tool_refutation",
                }
            )
            _sage_store_observation(obs_text, "tool_refutation", source)

    raw = (outcome.review_result or {}).get("observations")
    if not raw or not isinstance(raw, list):
        return
    for obs in raw:
        if isinstance(obs, str) and len(obs) >= 10:
            cleaned = _sanitise_observation(obs)
            if not cleaned:
                continue
            session_observations.append({
                "source": source, "text": cleaned,
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
            len(unresolved),
            len(hits),
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
            indent=2,
            default=str,
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
    domain_model: Optional[Dict[str, Any]] = None,
) -> List[ReviewOutcome]:
    """Review a group of trivial functions from the same file individually."""
    outcomes = []
    for gap in batch:
        dead_reason = _dead_code_reason(gap)
        if dead_reason:
            outcome = ReviewOutcome(
                file=gap["file"],
                function=gap["name"],
                status="dormant",
                body=(
                    f"[dead-code gate: {dead_reason}] "
                    f"Function is in provably dead code — skipped LLM review."
                ),
                evidence_tool="reachability:dead_code",
            )
            outcome.line = gap.get("line_start", 0)
            try:
                _commit_outcome(config, outcome, gap, batch=True)
            except Exception as exc:
                logger.warning(
                    "commit failed for %s:%s: %s",
                    gap["file"],
                    gap["name"],
                    exc,
                )
            outcomes.append(outcome)
            continue

        ctx = _build_context(
            config,
            gap,
            checklist,
            context_map,
            evidence_index,
            discovered_evidence=discovered_evidence,
            blind=config.blind_first_pass,
        )
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage,
                gap["file"],
                gap["name"],
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
                gap["file"],
                gap["name"],
                exc,
            )
            outcome = _error_outcome(gap, exc)

        if outcome.status == "finding":
            gate_violations = _check_finding_gates(outcome, mode=config.mode)
            if gate_violations:
                for v in gate_violations:
                    logger.warning(
                        "gate violation %s:%s: %s — demoted to suspicious",
                        outcome.file,
                        outcome.function,
                        v,
                    )
                outcome = _demote_outcome(
                    outcome,
                    f"[gate violation: {'; '.join(gate_violations)}]",
                )

        # ── Refutation gates (batch path) ─────────────────────────
        if outcome.status in ("finding", "suspicious"):
            try:
                from .refutation import refute_hypothesis

                rv = refute_hypothesis(
                    outcome,
                    domain_model=domain_model,
                    checklist=checklist,
                    config=config,
                )
                if rv is not None:
                    append_audit_log(config.out_dir, {
                        "action": "refutation_gate",
                        "gate": rv.gate,
                        "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
                        "file": outcome.file,
                        "function": outcome.function,
                        "reason": rv.reason,
                        "demote_to": rv.demote_to,
                        "original_status": outcome.status,
                        "applied": True,
                        "batch": True,
                    })
                    logger.info(
                        "refutation gate [%s] %s:%s — %s → %s (batch)",
                        rv.gate, outcome.file, outcome.function,
                        rv.reason, rv.demote_to,
                    )
                    outcome = _demote_outcome(
                        outcome, f"[{rv.gate}: {rv.reason}]",
                    )
                    outcome.status = rv.demote_to
            except Exception:
                logger.debug(
                    "refutation gate error for %s:%s (batch)",
                    gap.get("file"), gap.get("name"),
                    exc_info=True,
                )

        # ── Anti-self-refutation (batch path) ────────────────────
        if outcome.status == "clean":
            try:
                from .refutation import rescue_self_refuted

                rv = rescue_self_refuted(outcome)
                if rv is not None:
                    append_audit_log(config.out_dir, {
                        "action": "refutation_gate",
                        "gate": rv.gate,
                        "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
                        "file": outcome.file,
                        "function": outcome.function,
                        "reason": rv.reason,
                        "demote_to": rv.demote_to,
                        "original_status": outcome.status,
                        "applied": True,
                        "batch": True,
                    })
                    logger.info(
                        "anti-self-refutation %s:%s — %s → %s (batch)",
                        outcome.file, outcome.function,
                        rv.reason, rv.demote_to,
                    )
                    outcome.status = rv.demote_to
                    outcome.body = (
                        f"[{rv.gate}: {rv.reason}]\n\n" + outcome.body
                    )
            except Exception:
                logger.debug(
                    "anti-self-refutation error for %s:%s (batch)",
                    gap.get("file"), gap.get("name"),
                    exc_info=True,
                )

        try:
            _commit_outcome(config, outcome, gap, batch=True)
        except Exception as exc:
            logger.warning(
                "commit failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
        outcomes.append(outcome)
    return outcomes


def _dead_code_reason(gap: Dict[str, Any]) -> Optional[str]:
    """Return a human-readable reason if the gap is provably dead code,
    else None. Checks flags propagated from the checklist by compute_gaps."""
    if gap.get("lexical_dead"):
        return "lexical_dead (inside always-false guard)"
    if gap.get("module_aborts_on_load"):
        return "module_aborts_on_load (file aborts before function binds)"
    if gap.get("build_excluded"):
        return "build_excluded (file excluded from compilation)"
    return None


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
        _is_header_inline = (
            outcome.file.endswith(".h")
            and "static" in (ctx.get("source", "") or "")[:200]
        )
        _has_tool_evidence = bool(
            outcome.evidence_tool
            and outcome.evidence_tool != "reachability:dead_code"
        )
        if (
            verdict == "absent"
            and not is_entry
            and not _is_header_inline
            and not _has_tool_evidence
        ):
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


_RACE_KW = ("race condition", "toctou", "time-of-check", "time of check",
            "concurrent", "concurrently", "data race", "deadlock", "livelock")

_RACE_EVIDENCE_PREFIX = ("smt:", "coccinelle:", "semgrep:", "codeql:", "joern:",
                         "sarif:", "prefilter:lock", "prefilter:race")

_PROTECTION_RE = re.compile(
    r"\b(?:protected\s+by|under\s+lock|held\s+(?:by\s+)?lock|rcu_read_lock"
    r"|single[_-]threaded|init[_-]only|seriali[sz]ed\s+by"
    r"|mutex[_\s]held|spin_lock|sequential[_\s]init)\b",
    re.I,
)

_NEGATION_BEFORE_RE = re.compile(
    r"\b(?:not|no|without|lacks?|missing|absent|never)\b",
    re.I,
)


def _apply_speculative_race_demotion(outcome: ReviewOutcome) -> ReviewOutcome:
    """Demote evidence-free race hypotheses.

    finding → suspicious when race keywords present but no tool evidence.
    suspicious → clean when the body names a concrete protection mechanism
    (negation-aware: "not protected by" does NOT count).
    """
    hyp = (outcome.hypothesis or "").lower()
    if not any(kw in hyp for kw in _RACE_KW):
        return outcome

    ev = outcome.evidence_tool or ""
    if ev and any(ev.startswith(p) for p in _RACE_EVIDENCE_PREFIX):
        return outcome

    key = f"{outcome.file}:{outcome.function}"

    if outcome.status == "finding":
        logger.info(
            "speculative race gate: %s demoted finding → suspicious "
            "(race hypothesis without tool evidence)",
            key,
        )
        outcome.status = "suspicious"

    if outcome.status == "suspicious":
        body = (outcome.body or "").lower()
        m = _PROTECTION_RE.search(body)
        if m:
            before = body[max(0, m.start() - 30):m.start()]
            if not _NEGATION_BEFORE_RE.search(before):
                logger.info(
                    "speculative race gate: %s demoted suspicious → clean "
                    "(protection mechanism: %s)",
                    key,
                    m.group(0),
                )
                outcome.status = "clean"

    return outcome


def _apply_caller_attribution(
    outcome: ReviewOutcome,
    callers: list,
) -> ReviewOutcome:
    """Tag findings that describe a bug in a caller, not the reviewed function."""
    if outcome.status not in ("finding", "suspicious"):
        return outcome
    if not callers:
        return outcome

    text = f"{outcome.hypothesis or ''} {outcome.body or ''}".lower()
    if not text.strip():
        return outcome

    for c in callers:
        name = c.get("name", "")
        if not name or len(name) < 3:
            continue
        if name.lower() in text:
            outcome.caller_attributed = True
            outcome.attributed_caller = name
            logger.info(
                "caller attribution: %s:%s references caller %s",
                outcome.file, outcome.function, name,
            )
            break

    return outcome


_MEMORY_CWE = frozenset(
    {
        "CWE-119",
        "CWE-120",
        "CWE-121",
        "CWE-122",
        "CWE-125",
        "CWE-126",
        "CWE-127",
        "CWE-131",
        "CWE-134",
        "CWE-170",
        "CWE-190",
        "CWE-191",
        "CWE-193",
        "CWE-415",
        "CWE-416",
        "CWE-476",
        "CWE-787",
    }
)
_MEMORY_SAFE_LANGS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".rb",
        ".java",
        ".kt",
        ".scala",
        ".go",
        ".rs",
    }
)


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
        return f"language-CWE mismatch: {cwe} (memory corruption) claimed in {ext} file"
    return None


def _run_prefilter_for_gap(
    config: OrchestratorConfig,
    gap: Dict[str, Any],
    ctx: Dict[str, Any],
    domain_model: Optional[Dict[str, Any]] = None,
) -> PrefilterResult:
    """Run the mechanical pre-filter on a single gap function."""
    from .condition_smt import DomainVocabulary

    source = _read_raw_source(
        config.target_path,
        gap["file"],
        gap.get("line_start", 0),
        gap.get("line_end"),
    )
    vocab = DomainVocabulary.from_domain_model(domain_model) if domain_model else None
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
        project_sinks=config.project_sinks,
        domain_vocab=vocab,
    )


_file_lines_cache: Dict[str, Optional[list]] = {}


def _read_raw_source(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: Optional[int],
) -> str:
    """Read raw source lines without line-number prefixes."""
    cache_key = str(target_path / file_path)
    if cache_key not in _file_lines_cache:
        full_path = target_path / file_path
        if not full_path.exists():
            _file_lines_cache[cache_key] = None
        else:
            try:
                _file_lines_cache[cache_key] = full_path.read_text(
                    errors="replace",
                ).splitlines()
            except OSError:
                _file_lines_cache[cache_key] = None
    lines = _file_lines_cache[cache_key]
    if lines is None:
        return ""
    start = max(0, line_start - 1)
    end = line_end if line_end is not None else min(start + 50, len(lines))
    return "\n".join(lines[start:end])


_R2_ABI_TABLES: Dict[str, List[str]] = {
    "amd64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "win64": ["rcx", "rdx", "r8", "r9"],
    # x86-32: r2 lifts cdecl stack pushes into register-assignment
    # pseudo-code (eax = arg1), so these match r2's output, not the
    # hardware ABI.  For true fastcall the order is ecx, edx; for r2
    # cdecl lifting the order varies — we accept all three as possible
    # arg carriers and collect whichever appear before a call.
    "x86": ["eax", "ecx", "edx"],
    "aarch64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "arm": ["r0", "r1", "r2", "r3"],
    "sparc": ["o0", "o1", "o2", "o3", "o4", "o5"],
    "sparc64": ["o0", "o1", "o2", "o3", "o4", "o5"],
    "mips": ["a0", "a1", "a2", "a3"],
    "ppc": ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"],
    "riscv": ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
}

_R2_ARG_REGS_BY_ABI: Dict[str, frozenset] = {}
for _abi, _regs in _R2_ABI_TABLES.items():
    _all = set(_regs)
    if _abi == "amd64":
        _all.update(["r8d", "r9d", "edi", "esi", "edx", "ecx"])
    elif _abi == "aarch64":
        _all.update([f"w{i}" for i in range(8)])
    _R2_ARG_REGS_BY_ABI[_abi] = frozenset(_all)


def _detect_r2_abi(source: str) -> Optional[str]:
    """Detect calling convention from register names in r2 output.

    Checks most-specific first to avoid false matches (e.g. ARM r0-r3
    overlap with PPC r3-r10, MIPS a0-a3 overlap with RISC-V a0-a7).
    """
    tokens = set(source.split())
    is_pe = ".dll_" in source
    if tokens & {"rdi", "rsi"}:
        return "amd64"
    if is_pe and tokens & {"rcx", "rdx", "r8", "r9"}:
        return "win64"
    if tokens & {"rcx", "rdx", "r8", "r9"} and not (tokens & {"rdi", "rsi"}):
        return "win64" if is_pe else "amd64"
    if tokens & {"x0", "x1", "x2", "x3"}:
        return "aarch64"
    if tokens & {"o0", "o1", "o2", "o3"} and not (tokens & {"rdi", "rsi", "x0"}):
        return "sparc64" if tokens & {"xcc", "icc"} else "sparc"
    if tokens & {"a0", "a1", "a2", "a3"}:
        if tokens & {"a4", "a5", "a6", "a7"}:
            return "riscv"
        return "mips"
    if tokens & {"r3", "r4", "r5", "r6"} and tokens & {"r7", "r8", "r9", "r10"}:
        return "ppc"
    if tokens & {"r0", "r1", "r2", "r3"} and not (tokens & {"rdi", "rsi"}):
        return "arm"
    if tokens & {"eax", "ecx", "edx"} and not (tokens & {"rdi", "rsi", "r8"}):
        return "x86"
    return None


def _normalise_r2_decompilation(source: str) -> str:
    """Convert r2 lifted-assembly pseudocode into C-like calls.

    r2 emits ``rdi = arg1 ; sym.imp.printf ()`` instead of
    ``printf(arg1)``.  Semgrep patterns like ``printf($ARG)``
    can't match the register-assignment style, so we reconstruct
    the call with its argument(s) inlined.

    Supports x86_64, x86, AArch64, ARM, SPARC, SPARC64, MIPS,
    PowerPC, and RISC-V calling conventions — the ABI is
    auto-detected from register names in the source.
    """
    import re

    abi = _detect_r2_abi(source)
    if abi is None:
        return source

    arg_order = list(_R2_ABI_TABLES[abi])
    if abi == "amd64":
        arg_order.extend(["r8d", "r9d", "edi", "esi", "edx", "ecx"])
    elif abi == "aarch64":
        arg_order.extend([f"w{i}" for i in range(8)])
    arg_regs = _R2_ARG_REGS_BY_ABI[abi]

    lines = source.splitlines()
    out: list[str] = []

    _ANY_REG = re.compile(
        r"^\s*(\w+)\s*=\s*(.+?)(?:\s*//.*)?$",
    )
    # ELF PLT: sym.imp.printf          Mach-O: sym.imp._printf
    # PE:      sym.imp.MSVCRT.dll_printf  /  sym.imp.ucrtbase.dll_printf
    # Direct:  sym.printf
    _CALL = re.compile(
        r"^\s*sym(?:\.imp)?\.(?:[\w.]+\.dll_|_)?(\w+)\s*\(.*?\)\s*(?://.*)?$",
    )
    _LABEL_OR_COMMENT = re.compile(r"^\s*(//|loc_|$)")

    reg_vals: dict[str, str] = {}
    arg_vals: dict[str, str] = {}

    for line in lines:
        m_call = _CALL.match(line)
        if m_call:
            func_name = m_call.group(1)
            args = []
            for reg in arg_order:
                if reg in arg_vals:
                    args.append(arg_vals[reg])
            if args:
                indent = line[: len(line) - len(line.lstrip())]
                call_line = f"{indent}{func_name}({', '.join(args)});"
                out.append(call_line)
            else:
                out.append(line)
            arg_vals.clear()
            continue

        m_reg = _ANY_REG.match(line)
        if m_reg:
            reg, val = m_reg.group(1), m_reg.group(2).strip()
            if reg in arg_regs:
                resolved = reg_vals.get(val, val)
                arg_vals[reg] = resolved
            else:
                reg_vals[reg] = val
            out.append(line)
            continue

        if _LABEL_OR_COMMENT.match(line):
            out.append(line)
            continue

        out.append(line)

    return "\n".join(out)


def _write_decompilation_tmpfile(
    decompilation: str,
    function_name: str,
) -> Optional[Path]:
    """Write decompilation to a temp directory so Semgrep can read it."""
    if not decompilation or decompilation.startswith("("):
        return None
    try:
        normalised = _normalise_r2_decompilation(decompilation)
        tmp_dir = Path(tempfile.mkdtemp(prefix="raptor_decomp_"))
        (tmp_dir / f"{function_name}.c").write_text(
            normalised, encoding="utf-8",
        )
        return tmp_dir
    except OSError:
        logger.debug("failed to write decompilation tmpfile", exc_info=True)
        return None


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
    target_path_override: Optional[Path] = None,
    domain_vocab: Any = None,
) -> List[str]:
    """Run tools from *chain* in order, collecting all confirmations.

    Returns a list of confirming tool IDs (e.g. ``["smt:check-oob",
    "coccinelle:missing_bounds_check"]``).  A tool that errors or
    whose dependency is missing is skipped (logged at debug) and the
    next tool in the chain is tried — this is the fallback behaviour.

    When *sarif_cache* is provided, semgrep sweeps check for prior
    SARIF results before spawning a subprocess.
    """
    effective_target = target_path_override or config.target_path
    confirmed: List[str] = []

    if domain_vocab is None and config.out_dir:
        try:
            from .condition_smt import DomainVocabulary
            from .journal import load_domain_model
            dm = load_domain_model(config.out_dir)
            if dm:
                domain_vocab = DomainVocabulary.from_domain_model(dm)
        except Exception:
            pass

    for entry in chain:
        tool_type = entry["type"]
        tool_cfg = entry["config"]

        try:
            if tool_type == "semgrep":
                if sarif_cache is not None:
                    cached = sarif_cache.lookup(
                        file_path,
                        line_start,
                        line_start + 50 if line_start else 0,
                    )
                    if cached is not None:
                        if cached:
                            confirmed.append("sarif_cache:semgrep")
                            logger.debug(
                                "sarif_cache hit: %s:%s — %d prior results",
                                file_path,
                                function_name,
                                len(cached),
                            )
                        continue

                rule_path = tool_cfg["rule"]
                try:
                    sweep = run_semgrep_sweep(
                        target_path=effective_target,
                        file_path=file_path,
                        function_name=function_name,
                        rule_config=rule_path,
                        line_start=line_start,
                        line_end=line_start + 50 if line_start else 0,
                    )
                finally:
                    if rule_path and os.path.basename(rule_path).startswith("audit_sweep_"):
                        try:
                            os.unlink(rule_path)
                        except OSError:
                            pass
                if sweep.outcome == "confirmed":
                    confirmed.append(f"semgrep:{sweep.rule_id or 'hypothesis'}")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "semgrep", "confirmed")
                elif sweep.outcome == "error":
                    logger.debug(
                        "tool_chain semgrep error %s:%s: %s",
                        file_path,
                        function_name,
                        sweep.errors,
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
                        file_path,
                        function_name,
                        smt_result.errors,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "smt", "errors")
                else:
                    smt_confirmations = [c for c in confirmed if c.startswith("smt:")]
                    if smt_confirmations:
                        logger.info(
                            "smt refuted %s:%s — clearing %d smt confirmations (%s); keeping %d pattern-match confirmations",
                            file_path,
                            function_name,
                            len(smt_confirmations),
                            ", ".join(smt_confirmations),
                            len(confirmed) - len(smt_confirmations),
                        )
                        confirmed[:] = [c for c in confirmed if not c.startswith("smt:")]
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "smt", "refuted")

            elif tool_type == "coccinelle":
                if tool_cfg.get("cross_file"):
                    cocci_result = run_consistency_check(
                        target_path=effective_target,
                        function_name=function_name,
                        cocci_rule=tool_cfg["rule"],
                        domain_vocab=domain_vocab,
                    )
                else:
                    cocci_result = run_coccinelle_sweep(
                        target_path=effective_target,
                        file_path=file_path,
                        function_name=function_name,
                        cocci_rule=tool_cfg["rule"],
                        line_start=line_start if line_start else None,
                        line_end=None,
                        domain_vocab=domain_vocab,
                    )
                if cocci_result.outcome == "confirmed":
                    confirmed.append(f"coccinelle:{Path(tool_cfg['rule']).stem}")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "coccinelle", "confirmed")
                elif cocci_result.outcome == "error":
                    logger.debug(
                        "tool_chain coccinelle error %s:%s: %s",
                        file_path,
                        function_name,
                        cocci_result.errors,
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
                        joern_server,
                        function_name,
                        sinks,
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
                        evidence_index,
                        key,
                        function_name,
                        tool_cfg.get("sinks", []),
                        joern_server,
                    )

            elif tool_type == "codeql":
                from .sweep import run_codeql_sweep

                codeql_result = run_codeql_sweep(
                    target_path=effective_target,
                    file_path=file_path,
                    function_name=function_name,
                    query_path=tool_cfg["query"],
                    database_path=config.codeql_db_path,
                    line_start=line_start,
                    line_end=line_start + 50 if line_start else 0,
                )
                if codeql_result.outcome == "confirmed":
                    confirmed.append(f"codeql:{Path(tool_cfg['query']).stem}")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "confirmed")
                elif codeql_result.outcome == "error":
                    logger.debug(
                        "tool_chain codeql error %s:%s: %s",
                        file_path,
                        function_name,
                        codeql_result.errors,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "codeql", "refuted")

        except Exception as exc:
            logger.debug(
                "tool_chain %s exception %s:%s: %s",
                tool_type,
                file_path,
                function_name,
                exc,
            )

    return confirmed


_CWE_IMPLICIT_PRECONDITIONS: Dict[str, List[Dict[str, Any]]] = {
    "CWE-89": [
        {
            "check_type": "sink_reachable",
            "assumption": "SQL sink reachable from function",
        }
    ],
    "CWE-78": [
        {
            "check_type": "sink_reachable",
            "assumption": "command execution sink reachable",
        }
    ],
    "CWE-79": [
        {"check_type": "sink_reachable", "assumption": "HTML/JS output sink reachable"}
    ],
    "CWE-22": [
        {"check_type": "sink_reachable", "assumption": "filesystem sink reachable"}
    ],
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
                outcome.file,
                outcome.function,
                summary,
            )
            return _demote_outcome(
                outcome,
                f"[precondition contradicted: {summary}]",
            )

        for check in verdict.checks:
            logger.debug(
                "precondition %s:%s [%s] %s: %s",
                outcome.file,
                outcome.function,
                check.check_type,
                check.verdict,
                check.evidence,
            )

    except Exception:
        logger.debug(
            "precondition check failed for %s:%s",
            outcome.file,
            outcome.function,
            exc_info=True,
        )

    return outcome


def _sweep_validate(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    sarif_cache: Optional[SarifCache] = None,
    tier_counters: Optional[Dict[str, "TierCounters"]] = None,
    evidence_index: Optional[Dict[str, "EvidenceRecord"]] = None,
    joern_server=None,
    source_override: Optional[str] = None,
    is_binary: bool = False,
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
         — for binary targets, use decompiler Semgrep + Frida auto-launch
      5. If nothing confirms, keep the finding but flag as ungrounded

    Parameters
    ----------
    source_override:
        Pre-loaded source/decompilation text. Skips file read when set.
    is_binary:
        True when reviewing a binary target (routes to binary tool chain).
    """
    review = outcome.review_result or {}
    hypothesis = _resolve_hypothesis(outcome)
    raw_et = review.get("evidence_tool") or outcome.evidence_tool or ""
    if _is_tool_confirmed(raw_et):
        return outcome
    evidence_tool = _sanitize_llm_et(raw_et)

    if not hypothesis:
        logger.info(
            "sweep_validate: %s:%s finding has no hypothesis — demoting to suspicious",
            outcome.file,
            outcome.function,
        )
        return _demote_outcome(
            outcome,
            "[sweep validation: finding demoted — no testable hypothesis]",
        )

    is_binary = is_binary or outcome.file.startswith("binary:")
    if source_override is not None:
        source = source_override
    else:
        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            None,
        )

    _decomp_tmp_dir: Optional[Path] = None
    effective_file = outcome.file
    if is_binary and source:
        _decomp_tmp_dir = _write_decompilation_tmpfile(
            source, outcome.function,
        )
        if _decomp_tmp_dir is not None:
            effective_file = f"{outcome.function}.c"

    try:
        if not is_binary:
            pf = run_prefilter(
                target_path=config.target_path,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source,
                line_start=outcome.line,
                project_sinks=config.project_sinks,
            )

            if pf.hits:
                return _stamp_evidence(outcome, f"prefilter:{pf.hits[0].rule_id}")

        cwe = (
            (outcome.review_result or {}).get("cwe_class")
            or (outcome.review_result or {}).get("cwe")
            or ""
        )
        chain = _hypothesis_to_tool_chain(hypothesis, effective_file, cwe=cwe)

        if is_binary:
            try:
                from .binary_verification import decompiler_rules_for_hypothesis
                for rule_path in decompiler_rules_for_hypothesis(hypothesis, cwe):
                    chain.append({"type": "semgrep", "config": {"rule": str(rule_path)}})
            except ImportError:
                pass

        dispatched = {step.get("type") for step in chain if step.get("type")}

        confirmed = _run_tool_chain(
            chain,
            config=config,
            file_path=effective_file,
            function_name=outcome.function,
            source=source,
            hypothesis=hypothesis,
            line_start=0 if is_binary else outcome.line,
            sarif_cache=sarif_cache,
            tier_counters=tier_counters,
            evidence_index=evidence_index,
            joern_server=joern_server,
            target_path_override=_decomp_tmp_dir if is_binary and _decomp_tmp_dir else None,
        )

        # Frida auto-launch — last resort for binary targets.
        # Requires explicit opt-in (config.dynamic_validation) because
        # it executes the real binary on the host.
        if is_binary and not confirmed and getattr(config, "dynamic_validation", False):
            binary_path = getattr(config, "_binary_path", None)
            if binary_path:
                try:
                    from .binary_verification import auto_launch_and_observe, can_auto_launch
                    if can_auto_launch(binary_path):
                        frida_result = auto_launch_and_observe(
                            binary_path=Path(binary_path),
                            function_name=outcome.function,
                        )
                        if frida_result and frida_result.get("evidence_strength") == "confirmed":
                            confirmed.append("frida:runtime")
                            dispatched.add("frida_auto")
                            if tier_counters:
                                _increment_tier_dict(tier_counters, "frida", "confirmed")
                except ImportError:
                    pass

        outcome.tools_dispatched = dispatched
        if confirmed:
            high_prec = [t for t in confirmed if not _is_detection_only(t)]
            if high_prec:
                tool_label = "+".join(high_prec)
                return _stamp_evidence(outcome, tool_label)
    finally:
        if _decomp_tmp_dir is not None:
            import shutil
            shutil.rmtree(_decomp_tmp_dir, ignore_errors=True)

    # CodeQL bespoke dataflow validation (when LLM claims a source→sink
    # flow and no standard tool confirmed it)
    if not is_binary and config.codeql_db_path and "codeql" not in dispatched:
        try:
            from .codeql_validation import (
                extract_claims_from_review,
                validate_dataflow_claim,
            )

            claims = extract_claims_from_review(outcome.review_result or {})
            for claim in claims:
                vr = validate_dataflow_claim(
                    claim,
                    db_path=Path(config.codeql_db_path),
                )
                if vr.confirmed:
                    return _stamp_evidence(outcome, "codeql:dataflow")
                if tier_counters:
                    if vr.confirmed is None:
                        _increment_tier_dict(tier_counters, "codeql", "errors")
                    else:
                        _increment_tier_dict(tier_counters, "codeql", "refuted")
        except Exception:
            logger.debug(
                "codeql_validation failed for %s:%s",
                outcome.file,
                outcome.function,
                exc_info=True,
            )

    # SMT integer-overflow disproof — last mechanical check before
    # falling through with ungrounded evidence.  If the hypothesis
    # mentions integer overflow/underflow/wraparound and Z3 can show
    # the overflow is infeasible (UNSAT), demote to clean.  If SAT
    # (overflow IS feasible), stamp supporting evidence.
    _OVERFLOW_KW = ("overflow", "underflow", "wraparound", "integer")
    hyp_lower = hypothesis.lower()
    if (
        outcome.status in ("finding", "suspicious")
        and any(kw in hyp_lower for kw in _OVERFLOW_KW)
        and not _is_tool_confirmed(evidence_tool)
    ):
        try:
            from .condition_smt import disprove_integer_overflow

            smt_result = disprove_integer_overflow(hypothesis, source or "")
            if smt_result.disproved is True:
                logger.info(
                    "sweep_validate: %s:%s overflow disproved "
                    "(Z3 UNSAT) — demoting to clean",
                    outcome.file,
                    outcome.function,
                )
                outcome = ReviewOutcome(
                    file=outcome.file,
                    function=outcome.function,
                    status="clean",
                    body=(
                        "[smt-disproof: integer overflow impossible (Z3 UNSAT)]\n\n"
                        + (outcome.body or "")
                    ),
                    hypothesis=outcome.hypothesis,
                    hypotheses=outcome.hypotheses,
                    evidence_tool="smt:disproof:unsat",
                    cost_usd=outcome.cost_usd,
                    model=outcome.model,
                    duration_s=outcome.duration_s,
                    review_result=outcome.review_result,
                    line=outcome.line,
                )
                if outcome.review_result:
                    outcome.review_result["evidence_tool"] = "smt:disproof:unsat"
                return outcome
            elif smt_result.disproved is False:
                logger.info(
                    "sweep_validate: %s:%s overflow feasible "
                    "(Z3 SAT) — stamping supporting evidence",
                    outcome.file,
                    outcome.function,
                )
                return _stamp_evidence(outcome, "smt:disproof:sat")
        except Exception:
            logger.debug(
                "disprove_integer_overflow failed for %s:%s",
                outcome.file,
                outcome.function,
                exc_info=True,
            )

    outcome.evidence_tool = evidence_tool
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
                parts.append(f"- Joern CPG: parameter `{src}` flows to `{sink}()`")
            approx = getattr(rec, "taint_approx", None)
            df = _get_dangerous_flows(approx) if approx else None
            if df:
                params = (
                    getattr(approx, "params", None)
                    or (approx.get("params") if isinstance(approx, dict) else None)
                    or []
                )
                for pidx, sinks in df.items():
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

    try:
        from .cwe_dispatch import (
            infer_cwe_from_hypothesis,
            joern_applicable,
            sinks_for_cwe,
            smt_verb_for_cwe,
        )

        _has_cwe_dispatch = True
    except ImportError:
        _has_cwe_dispatch = False
        infer_cwe_from_hypothesis = None

    if not cwe and _has_cwe_dispatch and infer_cwe_from_hypothesis:
        cwe = infer_cwe_from_hypothesis(outcome.hypothesis or "") or ""

    if not cwe:
        return outcome

    dispatched = dispatched_tools or set()

    raw_et = review.get("evidence_tool") or outcome.evidence_tool or ""
    if _is_tool_confirmed(raw_et):
        return outcome
    evidence_tool = _sanitize_llm_et(raw_et)

    confirmed_tools = []

    smt_verb = smt_verb_for_cwe(cwe) if _has_cwe_dispatch else None
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

    if _has_cwe_dispatch and joern_applicable(cwe) and "joern" not in dispatched:
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
                joern_server,
                outcome.function,
                sinks,
            )
            if live_hits:
                confirmed_tools.append("joern:live")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "confirmed")
            elif tier_counters:
                _increment_tier_dict(tier_counters, "joern", "refuted")

    if _has_cwe_dispatch and "codeql" not in dispatched and config.codeql_db_path:
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
                cocci_result = run_coccinelle_sweep(
                    target_path=config.target_path,
                    file_path=outcome.file,
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
                                    discovered_evidence,
                                    m_file,
                                    m_func,
                                    "coccinelle",
                                    "consistency violation at"
                                    f" {m_file}:{match.get('line', '?')}",
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

    # Cross-function verification (Joern CPG): interprocedural checks
    # that intra-function SMT/Coccinelle can't reach.
    if joern_server is not None and "cross_function" not in dispatched:
        try:
            from .cross_function_verify import cross_function_verify
            xf_result = cross_function_verify(
                function_name=outcome.function,
                file_path=outcome.file,
                hypothesis=outcome.hypothesis or "",
                server=joern_server,
            )
            if xf_result is not None and xf_result.verified:
                confirmed_tools.append(f"joern:xf:{xf_result.verifier_name}")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern_xf", "confirmed")
                if discovered_evidence:
                    _inject_discovered_evidence(
                        discovered_evidence,
                        outcome.file,
                        outcome.function,
                        f"joern:xf:{xf_result.verifier_name}",
                        xf_result.evidence,
                    )
            elif tier_counters and xf_result is not None:
                _increment_tier_dict(tier_counters, "joern_xf", "refuted")
        except Exception:
            logger.debug(
                "cross-function verify failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            if tier_counters:
                _increment_tier_dict(tier_counters, "joern_xf", "errors")

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
                    all_conditions.extend(extract_conditions_from_flow_trace(trace))
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
                        outcome.file,
                        outcome.function,
                    )
                    return _demote_outcome(
                        outcome,
                        "[path feasibility: conditions unsatisfiable]",
                    )
        except Exception:
            logger.debug(
                "path_feasibility failed for %s:%s",
                outcome.file,
                outcome.function,
                exc_info=True,
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
                        discovered_evidence,
                        outcome.file,
                        outcome.function,
                        "lifecycle",
                        evidence_text,
                    )
    except ImportError:
        pass
    except Exception:
        logger.debug(
            "lifecycle check failed for %s:%s",
            outcome.file,
            outcome.function,
            exc_info=True,
        )

    if confirmed_tools:
        tool_label = "+".join(confirmed_tools)
        return _stamp_evidence(outcome, tool_label)

    outcome.evidence_tool = evidence_tool
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
            exemplars[0],
            config,
            seen_keys,
            synthesis_count=synthesis_count,
        )
        if not synth:
            continue
        synthesis_count += 1
        logger.info(
            "auto-synthesized rule %s (%s) from %d %s findings, %d new hits",
            synth.rule_id,
            synth.tool,
            count,
            key,
            len(synth.hits),
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
        o for o in result.outcomes[-config.critique_interval :] if o.status == "finding"
    ]

    for outcome in recent_findings:
        if not _is_tool_confirmed(outcome.evidence_tool):
            source = _read_raw_source(
                config.target_path,
                outcome.file,
                outcome.line,
                None,
            )
            pf = run_prefilter(
                target_path=config.target_path,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source,
                line_start=outcome.line,
                project_sinks=config.project_sinks,
            )
            if pf.hits:
                outcome.evidence_tool = f"critique:prefilter:{pf.hits[0].rule_id}"
                logger.info(
                    "critique: %s:%s gained evidence via %s",
                    outcome.file,
                    outcome.function,
                    outcome.evidence_tool,
                )

    recent_suspicious = [
        o
        for o in result.outcomes[-config.critique_interval :]
        if o.status == "suspicious" and o.hypothesis
    ]

    for outcome in recent_suspicious:
        if _has_refuting_counter(outcome):
            continue
        cwe = (
            (outcome.review_result or {}).get("cwe_class")
            or (outcome.review_result or {}).get("cwe")
            or ""
        )
        chain = _hypothesis_to_tool_chain(outcome.hypothesis, outcome.file, cwe=cwe)
        if not chain:
            continue
        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            None,
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
                outcome.file,
                outcome.function,
                tool,
            )

    recent_clean = [
        o
        for o in result.outcomes[-config.critique_interval :]
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
                new_hyp = (
                    f"Tool {tool_name} ({rule_id})"
                    " found something but was dismissed"
                    " — recheck"
                )
                chain = _hypothesis_to_tool_chain(new_hyp, outcome.file, cwe="")
                if chain:
                    source = _read_raw_source(
                        config.target_path,
                        outcome.file,
                        outcome.line,
                        None,
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
                            "critique: clean %s:%s has unresolved"
                            " tool evidence from %s",
                            outcome.file,
                            outcome.function,
                            tool_name,
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
    max_workers: int = 1,
) -> OrchestratorResult:
    """Re-review suspicious verdicts with enriched context.

    After the main pass, functions flagged as suspicious get a second
    look with: the accumulated session observations, their prior
    verdict, and an explicit prompt to try an alternative hypothesis.
    Only deepens functions above a minimum SLOC — tiny wrappers rarely
    sharpen on a second pass.

    When max_workers > 1, LLM calls are dispatched in parallel via
    ThreadPoolExecutor.  Post-processing (sweep, gates, tally) runs
    in the main thread as futures complete.
    """
    suspicious = [
        o
        for o in result.outcomes
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
            o.evidence_tool or (o.review_result or {}).get("tool_evidence")
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

    effective_workers = max(1, max_workers)
    logger.info(
        "deepen: %d suspicious verdicts to re-review (workers=%d)",
        len(targets),
        effective_workers,
    )

    # Track outcomes to remove by identity so we can filter in one
    # pass after the loop instead of O(n) list.remove() per iteration.
    _outcomes_to_remove: set = set()

    # --- Build all contexts up-front so they snapshot session_observations ---
    prepared: list = []
    for deepen_idx, (prior_outcome, gap) in enumerate(targets, 1):
        ctx = _build_context(
            config,
            gap,
            checklist,
            context_map,
            evidence_index,
            discovered_evidence=discovered_evidence,
        )
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage,
                gap["file"],
                gap["name"],
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
        prepared.append((deepen_idx, prior_outcome, gap, ctx))

    def _do_review(item):
        idx, _prior, gap, ctx = item
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:
            return (idx, None, exc)

    if effective_workers <= 1:
        raw_results = []
        for item in prepared:
            if _check_budget(config, start_time, result):
                break
            raw_results.append(_do_review(item))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        raw_results = []
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_item = {
                pool.submit(_do_review, item): item for item in prepared
            }
            for fut in as_completed(future_to_item):
                if _check_budget(config, start_time, result):
                    for f in future_to_item:
                        f.cancel()
                    break
                raw_results.append(fut.result())

    # --- Process results (always in main thread) ---
    idx_to_prepared = {item[0]: item for item in prepared}
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, prior_outcome, gap, ctx = idx_to_prepared[idx]

        if exc is not None:
            logger.warning(
                "deepen failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
            continue

        outcome.line = gap.get("line_start", 0)

        # Accept the deepen verdict when it's non-clean, OR when
        # the clean came from a structured demotion (all-refuted or
        # rationale-consistency) rather than a bare LLM flip-flop.
        _rr = outcome.review_result or {}
        _deepen_dominated = outcome.status == "clean" and not (
            _rr.get("all_refuted_demotion")
            or _rr.get("rationale_consistency_demotion")
        )

        if _deepen_dominated:
            logger.info(
                "deepen [%d/%d] %s:%s: stayed %s (clean without structured basis)",
                idx,
                len(targets),
                gap["file"],
                gap["name"],
                prior_outcome.status,
            )
        else:
            if outcome.status == "finding":
                if config.sweep_validate_findings:
                    outcome = _sweep_validate(
                        outcome,
                        config,
                        sarif_cache,
                        tier_counters=result.tier_counters,
                        evidence_index=evidence_index,
                        joern_server=joern_server,
                    )
                if outcome.status == "finding":
                    outcome = _apply_reachability_gate(
                        outcome,
                        ctx,
                        entry_points,
                        config,
                    )
                if outcome.status == "finding":
                    gate_violations = _check_finding_gates(
                        outcome,
                        audit_log=audit_log,
                        mode=config.mode,
                    )
                    if gate_violations:
                        for v in gate_violations:
                            logger.warning(
                                "gate violation %s:%s: %s — demoted to suspicious",
                                outcome.file,
                                outcome.function,
                                v,
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
                    gap["file"],
                    gap["name"],
                    exc,
                    exc_info=True,
                )

            _tally_outcome(result, outcome)

            if config.enable_session_context and outcome.review_result:
                _accumulate_observations(
                    session_observations,
                    outcome,
                    gap,
                    sweep_pre_status=prior_outcome.status,
                )

            logger.info(
                "deepen [%d/%d] %s:%s: %s -> %s",
                idx,
                len(targets),
                gap["file"],
                gap["name"],
                prior_outcome.status,
                outcome.status,
            )

    if _outcomes_to_remove:
        result.outcomes = [
            o for o in result.outcomes if id(o) not in _outcomes_to_remove
        ]

    return result


def _re_review_disagreements(
    disagreements,
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    evidence_index: Optional[Dict[str, EvidenceRecord]],
    start_time: float,
    on_progress: Optional[Callable],
    *,
    audit_log: Optional[List[Dict[str, Any]]] = None,
    session_observations: Optional[List[Dict[str, str]]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    joern_server=None,
    max_workers: int = 1,
) -> OrchestratorResult:
    """Re-review functions where the mechanical layer overruled the LLM.

    When a mechanical tool found a flow/reachability signal but the LLM
    called the function clean, inject the disagreement verdict into the
    context and ask the LLM to reconsider with the mechanical evidence
    explicitly surfaced.
    """
    outcome_by_key = {f"{o.file}:{o.function}": o for o in result.outcomes}
    gap_by_key = _gap_index(checklist)

    prepared = []
    for d in disagreements:
        key = f"{d.file}:{d.function}"
        prior = outcome_by_key.get(key)
        if prior is None or prior.status not in ("clean",):
            continue

        gap = gap_by_key.get(key)
        if gap is None:
            continue

        ctx = _build_context(
            config, gap, checklist, context_map,
            evidence_index,
            discovered_evidence=discovered_evidence,
        )
        ctx["disagreement_override"] = {
            "resolution": d.resolution,
            "mechanical_reachable": (
                d.mechanical_claim.reachable
                if d.mechanical_claim else None
            ),
            "mechanical_has_flow": (
                d.mechanical_claim.has_flow
                if d.mechanical_claim else None
            ),
        }
        ctx["prior_verdict"] = {
            "status": prior.status,
            "body": prior.body,
        }
        prepared.append((len(prepared), key, prior, ctx))

    if not prepared:
        return result

    effective_workers = max(1, max_workers)
    logger.info(
        "disagreement re-review: %d candidates (workers=%d)",
        len(prepared),
        effective_workers,
    )

    def _do_review(item):
        idx, _key, _prior, ctx = item
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:
            return (idx, None, exc)

    if effective_workers <= 1:
        raw_results = []
        for item in prepared:
            if _check_budget(config, start_time, result):
                break
            raw_results.append(_do_review(item))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        raw_results = []
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_item = {
                pool.submit(_do_review, item): item for item in prepared
            }
            for fut in as_completed(future_to_item):
                if _check_budget(config, start_time, result):
                    for f in future_to_item:
                        f.cancel()
                    break
                raw_results.append(fut.result())

    re_reviewed = 0
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, key, prior, _ctx = prepared[idx]

        if exc is not None:
            logger.debug(
                "disagreement re-review failed for %s", key, exc_info=True,
            )
            continue

        re_reviewed += 1
        if outcome.status != prior.status:
            logger.info(
                "disagreement re-review %s: %s → %s",
                key, prior.status, outcome.status,
            )
            for i, o in enumerate(result.outcomes):
                if f"{o.file}:{o.function}" == key:
                    result.outcomes[i] = outcome
                    _untally_outcome(result, prior)
                    _tally_outcome(result, outcome)
                    break

    if re_reviewed:
        logger.info(
            "disagreement re-review: %d functions reconsidered", re_reviewed,
        )
    return result


def _gap_index(checklist: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build file:function → gap dict from checklist."""
    index: Dict[str, Dict[str, Any]] = {}
    for item in checklist.get("files", []):
        for func in item.get("items", item.get("functions", [])):
            key = f"{item.get('file', '')}:{func.get('name', '')}"
            index[key] = {
                "file": item.get("file", ""),
                "name": func.get("name", ""),
                "line": func.get("line", 0),
                "line_start": func.get("line_start", 0),
                "line_end": func.get("line_end", 0),
                "source": func.get("source", ""),
                "language": item.get("language", ""),
            }
    return index


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
    max_workers: int = 1,
) -> OrchestratorResult:
    """Re-review callers of findings with propagated knowledge.

    After the initial pass, functions reviewed as clean might be
    vulnerable given knowledge about their callees discovered later.
    Each iteration re-reviews only callers of new findings from the
    previous iteration, injecting the callee finding as context.
    Converges when no new findings emerge.

    Within each iteration, LLM calls are dispatched in parallel when
    max_workers > 1.  Post-processing runs in the main thread.
    Iterations themselves remain sequential (each depends on the
    previous iteration's findings).
    """
    if not config.propagate_constraints:
        return result

    reviewed_outcomes = {f"{o.file}:{o.function}": o for o in result.outcomes}

    MAX_RE_REVIEW_ITERATIONS = 5
    untallied_ids: set = set()
    effective_workers = max(1, max_workers)
    iteration = 0
    logger.debug(
        "_iterative_re_review: entering loop, %d outcomes total", len(result.outcomes)
    )
    while True:
        iteration += 1
        if iteration > MAX_RE_REVIEW_ITERATIONS:
            logger.warning(
                "re-review hit iteration cap (%d); stopping propagation",
                MAX_RE_REVIEW_ITERATIONS,
            )
            break
        new_findings = [
            o
            for o in result.outcomes
            if o.status in ("finding", "suspicious")
            and not getattr(o, "_propagated", False)
        ]
        logger.debug(
            "_iterative_re_review: iteration %d, %d unpropagated findings/suspicious",
            iteration,
            len(new_findings),
        )
        if not new_findings:
            break

        for o in new_findings:
            o._propagated = True

        logger.debug("_iterative_re_review: calling _find_re_review_targets")
        re_review_targets = _find_re_review_targets(
            new_findings,
            config,
            checklist,
            context_map,
            reviewed_outcomes,
        )
        logger.debug(
            "_iterative_re_review: got %d re-review targets", len(re_review_targets)
        )

        if not re_review_targets:
            break

        if _check_budget(config, start_time, result):
            break

        logger.info(
            "re-review iteration %d: %d callers of %d findings (workers=%d)",
            iteration,
            len(re_review_targets),
            len(new_findings),
            effective_workers,
        )

        # --- Build all contexts up-front for this iteration ---
        prepared = []
        for target in re_review_targets:
            gap = target["gap"]
            callee_findings = target["callee_findings"]

            ctx = _build_context(
                config,
                gap,
                checklist,
                context_map,
                evidence_index,
                discovered_evidence=discovered_evidence,
            )
            if fuzz_coverage:
                ctx["fuzz_coverage"] = _fuzz_coverage_for(
                    fuzz_coverage,
                    gap["file"],
                    gap["name"],
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
            prepared.append((len(prepared), gap, ctx))

        def _do_review(item):
            idx, gap, ctx = item
            try:
                outcome = review_fn(ctx, config)
                return (idx, outcome, None)
            except _ContentFilterError:
                outcome = ReviewOutcome(
                    file=gap["file"],
                    function=gap["name"],
                    status="error",
                    body="blocked by content filter",
                )
                return (idx, outcome, None)
            except Exception as exc:
                return (idx, None, exc)

        if effective_workers <= 1:
            raw_results = []
            for item in prepared:
                if _check_budget(config, start_time, result):
                    break
                raw_results.append(_do_review(item))
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            raw_results = []
            with ThreadPoolExecutor(max_workers=effective_workers) as pool:
                future_to_item = {
                    pool.submit(_do_review, item): item for item in prepared
                }
                for fut in as_completed(future_to_item):
                    if _check_budget(config, start_time, result):
                        for f in future_to_item:
                            f.cancel()
                        break
                    raw_results.append(fut.result())

        # --- Process results in main thread ---
        idx_to_prepared = {item[0]: item for item in prepared}
        for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
            _, gap, ctx = idx_to_prepared[idx]

            if exc is not None:
                logger.warning(
                    "re-review failed for %s:%s: %s",
                    gap["file"],
                    gap["name"],
                    exc,
                )
                outcome = _error_outcome(gap, exc)

            outcome.line = gap.get("line_start", 0)

            if outcome.status == "finding" and config.sweep_validate_findings:
                outcome = _sweep_validate(
                    outcome,
                    config,
                    sarif_cache,
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
                    outcome,
                    ctx,
                    entry_points,
                    config,
                )

            if outcome.status == "finding":
                gate_violations = _check_finding_gates(
                    outcome,
                    audit_log=audit_log,
                    mode=config.mode,
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
                    gap["file"],
                    gap["name"],
                    exc_info=True,
                )

            if config.propagate_constraints and outcome.review_result:
                constraints = _extract_and_propagate(
                    outcome,
                    constraints,
                    checklist,
                    entry_points,
                    prop_config,
                    tier_counters=result.tier_counters,
                )

            old_key = f"{gap['file']}:{gap['name']}"
            old_outcome = reviewed_outcomes.get(old_key)
            if old_outcome and old_outcome in result.outcomes:
                oi = result.outcomes.index(old_outcome)
                if id(old_outcome) not in untallied_ids:
                    _untally_outcome(result, old_outcome)
                    untallied_ids.add(id(old_outcome))
                result.outcomes[oi] = outcome
                _tally_outcome(result, outcome, append=False)
            else:
                _tally_outcome(result, outcome)
            reviewed_outcomes[old_key] = outcome

            if (
                config.enable_session_context
                and session_observations is not None
                and outcome.review_result
            ):
                pre_status = old_outcome.status if old_outcome else None
                _accumulate_observations(
                    session_observations,
                    outcome,
                    gap,
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
            config,
            finding.file,
            finding.function,
            finding.line,
            context_map,
        )
        for caller in callers:
            key = f"{caller['file']}:{caller['name']}"
            prior = reviewed_outcomes.get(key)
            if not prior or prior.status != "clean":
                continue

            if key not in targets:
                gap = _find_gap_in_checklist(
                    checklist,
                    caller["file"],
                    caller["name"],
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
                file_path=file_path,
                name=function_name,
                line=line,
            )
            result = callers_of(config.inventory, target, exclude_test_files=True)
            callers = [
                {"file": c.file_path, "name": c.name, "line_start": c.line}
                for c in result.all_callers
            ]
        except Exception:
            logger.warning(
                "inventory caller lookup failed for %s:%s",
                file_path,
                function_name,
                exc_info=True,
            )

    if context_map and not callers:
        seen = set()
        for edge in context_map.get("call_edges", []):
            if edge.get("callee") == function_name:
                ck = (edge.get("caller_file", ""), edge.get("caller", ""))
                if ck not in seen:
                    seen.add(ck)
                    callers.append(
                        {
                            "file": edge.get("caller_file", ""),
                            "name": edge.get("caller", ""),
                            "line_start": 0,
                        }
                    )
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


def _run_phase2(result, config) -> None:
    """Phase 2 security classification + Phase 2b chaining (bug_first mode)."""
    from core.llm.client import LLMClient as _P2Client

    _p2_model = (
        config.models[0]
        if config.models and config.models[0] != "default"
        else None
    )
    _p2_client = _P2Client(pinned_model=_p2_model) if _p2_model else _P2Client()

    classifications = {}
    try:
        from .security_classifier import classify_security_impact
        classifications = classify_security_impact(
            result.outcomes, config.out_dir, _p2_client,
            model_name=_p2_model,
        )
        if classifications:
            logger.info(
                "Phase 2: %d outcomes classified for security impact",
                len(classifications),
            )
            p2_path = config.out_dir / "phase2-classifications.json"
            p2_path.write_text(
                json.dumps(classifications, indent=2),
                encoding="utf-8",
            )
    except Exception:
        logger.debug("Phase 2 classification failed", exc_info=True)

    try:
        from .chain_detector import find_chain_candidates, evaluate_chains
        candidates = find_chain_candidates(
            result.outcomes, config.out_dir, classifications,
        )
        if candidates:
            logger.info(
                "Phase 2b: %d chain candidates to evaluate",
                len(candidates),
            )
            chains = evaluate_chains(
                candidates, _p2_client, model_name=_p2_model,
            )
            if chains:
                chains_path = config.out_dir / "bug-chains.json"
                chains_path.write_text(
                    json.dumps(chains, indent=2),
                    encoding="utf-8",
                )
                for chain in chains:
                    bug_a_func = chain["bug_a"].rsplit(":", 1)[-1]
                    chain_outcome = ReviewOutcome(
                        file=chain["bug_a"].rsplit(":", 1)[0],
                        function=bug_a_func,
                        status="finding",
                        body=chain.get("chain_description", ""),
                        hypothesis=chain.get("chain_description", ""),
                        evidence_tool="chain_detector",
                        review_result={
                            "chain": True,
                            "bug_a": chain["bug_a"],
                            "bug_b": chain["bug_b"],
                            "primitive": chain.get("primitive", ""),
                            "confidence": chain.get("confidence", "medium"),
                        },
                    )
                    result.outcomes.append(chain_outcome)
                    result.findings += 1
                logger.info("Phase 2b: %d chains confirmed", len(chains))
    except Exception:
        logger.debug("Phase 2b chaining failed", exc_info=True)


_KEY_FILE_PRIORITY_BOOST = 5.0
_CHAIN_PRIORITY_BOOST = 5.0
_MAX_CHAIN_INJECTIONS_PER_FINDING = 10
_MAX_CHAIN_CONTEXT_ITEMS = 5


def _collect_chain_findings(
    fn_key: str,
    call_edges: list,
    reviewed_outcomes: Dict[str, ReviewOutcome],
    call_edge_index: Optional[Dict[str, list]] = None,
) -> List[Dict[str, str]]:
    """Collect findings from 1-hop neighbours for chain context.

    Returns a list of dicts suitable for the ``chain_findings`` context
    section — callers and callees that were already reviewed and found
    vulnerable or suspicious.

    When *call_edge_index* is provided (built once at loop setup),
    only edges involving *fn_key* are examined instead of the full
    edge list.
    """
    edges = call_edge_index.get(fn_key, ()) if call_edge_index else call_edges
    chain: List[Dict[str, str]] = []
    seen: set = set()
    for edge in edges:
        caller_bare = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
        callee_file = edge.get("callee_file") or edge.get("caller_file", "")
        callee_bare = f"{callee_file}:{edge.get('callee', '')}"

        neighbour = None
        direction = ""
        if caller_bare == fn_key:
            neighbour = callee_bare
            direction = "callee"
        elif callee_bare == fn_key:
            neighbour = caller_bare
            direction = "caller"

        if neighbour is None or neighbour in seen:
            continue
        seen.add(neighbour)

        prior = reviewed_outcomes.get(neighbour)
        if prior and prior.status in ("finding", "suspicious"):
            entry: Dict[str, str] = {
                "function": f"{prior.file}:{prior.function}",
                "status": prior.status,
                "direction": direction,
            }
            if prior.hypothesis:
                entry["hypothesis"] = prior.hypothesis
            if prior.body:
                entry["body"] = prior.body[:300]
            if prior.evidence_tool:
                entry["evidence_tool"] = prior.evidence_tool
            chain.append(entry)
            if len(chain) >= _MAX_CHAIN_CONTEXT_ITEMS:
                break
    return chain


def _inject_chain_targets(
    outcome: ReviewOutcome,
    graph,
    call_edges: list,
    checklist: Dict[str, Any],
    reviewed_outcomes: Optional[Dict[str, ReviewOutcome]] = None,
    finding_priority: float = 0.0,
    call_edge_index: Optional[Dict[str, list]] = None,
    checklist_index: Optional[Dict[tuple, dict]] = None,
) -> int:
    """Inject callers and callees of a confirmed finding into the TaskGraph.

    When a finding is confirmed mid-loop, its immediate neighbours in the
    call graph should be reviewed next (or re-prioritised if already queued):

    - **Callers** that might pass unsanitised input to the vulnerable function.
    - **Callees** that consume corrupted output from the vulnerable function.

    Returns the number of tasks injected or reprioritised.
    """
    if graph is None:
        return 0

    fn_bare = f"{outcome.file}:{outcome.function}"
    edges = call_edge_index.get(fn_bare, ()) if call_edge_index else call_edges
    if not edges:
        return 0
    injected = 0

    for edge in edges:
        if injected >= _MAX_CHAIN_INJECTIONS_PER_FINDING:
            break

        caller_bare = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
        callee_file = edge.get("callee_file") or edge.get("caller_file", "")
        callee_bare = f"{callee_file}:{edge.get('callee', '')}"

        target_bare = None
        if callee_bare == fn_bare:
            target_bare = caller_bare
        elif caller_bare == fn_bare:
            target_bare = callee_bare

        if target_bare is None:
            continue

        if reviewed_outcomes:
            prior = reviewed_outcomes.get(target_bare)
            if prior is not None:
                # Already reviewed — skip entirely. Re-reviewing clean
                # functions with chain context injects false premises
                # ("what if the caller passes nil?") that flip correct
                # verdicts to suspicious.
                continue

        t_file, t_name = target_bare.split(":", 1)
        if checklist_index is not None:
            gap = checklist_index.get((t_file, t_name))
            if gap is not None:
                gap = dict(gap)
            else:
                gap = None
        else:
            gap = _find_gap_in_checklist(checklist, t_file, t_name)
        if not gap:
            continue

        gap["force_review"] = True
        key = f"{t_file}:{t_name}:{gap.get('line_start', 0)}"
        if graph.inject_task(key, gap, finding_priority, requeue=True):
            injected += 1

    if injected:
        logger.info(
            "chain injection: %d targets from %s:%s",
            injected, outcome.file, outcome.function,
        )
    return injected


def _untally_outcome(result: OrchestratorResult, outcome: ReviewOutcome) -> None:
    """Reverse a previously tallied outcome."""
    with result._lock:
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


_DISMISSIVE_COUNTERS = frozenset(
    {
        "no plausible",
        "cannot construct",
        "no realistic",
        "no viable",
        "function is safe",
        "no vulnerability",
        "none",
        "n/a",
        "not applicable",
    }
)


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
        if (h.get("confidence") or "").lower() == "refuted":
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

        if outcome.body.startswith(
            (
                "[gate violation:",
                "[sink-unreachability:",
                "[guarded-sink:",
                "[smt-infeasible:",
                "[entry-unreachability:",
                "[self-contradiction:",
            )
        ):
            logger.debug(
                "sweep skipped %s:%s — mechanical gate demotion is authoritative",
                outcome.file,
                outcome.function,
            )
            continue

        review = outcome.review_result or {}
        hypothesis = review.get("hypothesis") or outcome.hypothesis or ""
        if not hypothesis:
            continue

        if _has_refuting_counter(outcome):
            logger.debug(
                "sweep skipped %s:%s — LLM counter-hypothesis present",
                outcome.file,
                outcome.function,
            )
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )

        pf = run_prefilter(
            target_path=config.target_path,
            file_path=outcome.file,
            function_name=outcome.function,
            source=source,
            line_start=outcome.line,
            project_sinks=config.project_sinks,
        )
        if pf.hits:
            if line_end:
                pf.hits = [
                    h
                    for h in pf.hits
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
                    outcome.file,
                    outcome.function,
                    tool,
                )
                continue

        cwe = (
            (outcome.review_result or {}).get("cwe_class")
            or (outcome.review_result or {}).get("cwe")
            or ""
        )
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
            high_prec = [
                t for t in confirmed
                if not _is_detection_only(t)
            ]
            if not high_prec:
                logger.info(
                    "sweep promotion blocked %s:%s — only detection-role "
                    "rules (%s)",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue
            if _check_sink_guarded_cached(outcome.function, joern_server) == "guarded":
                logger.info(
                    "sweep promotion blocked %s:%s via %s — all sink calls guarded",
                    outcome.file,
                    outcome.function,
                    "+".join(confirmed),
                )
                continue
            tool = "+".join(high_prec)
            result.outcomes[i] = _promote_outcome(outcome, tool)
            result.sweep_promoted += 1
            result.suspicious -= 1
            result.findings += 1
            logger.info(
                "sweep promoted %s:%s via %s",
                outcome.file,
                outcome.function,
                tool,
            )


def _is_detection_only(tool_id: str) -> bool:
    """Check if a tool confirmation is from a detection-only rule.

    Detection rules surface candidates but are too imprecise to promote
    a finding's status without LLM agreement.  The role is read from
    metadata: ``// @role:`` in coccinelle rules, ``_SMT_VERB_ROLES``
    for SMT verbs.

    Only stock library rules (in engine/coccinelle/rules/) are checked;
    dynamically-generated per-hypothesis rules are always allowed to
    promote because they target the specific hypothesis.
    """
    if tool_id.startswith("coccinelle:"):
        rule_name = tool_id.split("coccinelle:", 1)[1]
        rule_path = os.path.join(
            os.environ.get("RAPTOR_DIR", "."),
            "engine", "coccinelle", "rules", f"{rule_name}.cocci",
        )
        if not os.path.isfile(rule_path):
            return False
        from core.audit.sweep import get_rule_role
        return get_rule_role(rule_path) == "detection"

    if tool_id.startswith("smt:"):
        verb = tool_id.split("smt:", 1)[1]
        from core.audit.sweep import get_smt_verb_role
        return get_smt_verb_role(verb) == "detection"

    return False


_ARITHMETIC_RE = __import__("re").compile(
    r"[\w\])\s]"
    r"\s*[+\-*]\s*"
    r"[\w(]"
)


def _source_has_arithmetic(source: str) -> bool:
    """Check if source contains binary arithmetic operators (+, -, *).

    Skips comments and string literals to avoid matching prose that
    mentions arithmetic.  Used to gate SMT overflow checks — without
    actual arithmetic in the source, the check is vacuously true.
    """
    import re
    cleaned = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'',
                     " ", source, flags=re.DOTALL)
    return bool(_ARITHMETIC_RE.search(cleaned))


def _promote_clean_refuted(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
    joern_server=None,
) -> None:
    """Post-loop pass: SMT-verify refuted hypotheses on clean outcomes.

    When the LLM generates an arithmetic hypothesis (overflow, underflow,
    OOB) then refutes it, the refutation may be wrong.  SMT can settle
    the dispute mechanically.  Only SMT is used — Coccinelle and Semgrep
    match syntactic patterns that fire on safe code and would introduce
    false positives.
    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        hypotheses = getattr(outcome, "hypotheses", None) or []
        if not hypotheses and outcome.review_result:
            hypotheses = outcome.review_result.get("hypotheses") or []

        refuted = [
            h for h in hypotheses
            if isinstance(h, dict) and (h.get("confidence") or "").lower() == "refuted"
        ]
        if not refuted:
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        if outcome.line == 0 and gap:
            outcome.line = gap.get("line_start", 0)

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )

        cwe = ""
        if outcome.review_result:
            cwe = (
                outcome.review_result.get("cwe_class")
                or outcome.review_result.get("cwe")
                or ""
            )

        for h in refuted:
            mechanism = h.get("mechanism", "")
            if not mechanism:
                continue
            smt_verb = None
            if cwe:
                try:
                    from .cwe_dispatch import smt_verb_for_cwe
                    smt_verb = smt_verb_for_cwe(cwe)
                except ImportError:
                    pass
            if not smt_verb:
                smt_verb = _hypothesis_to_smt_verb(mechanism)
            if not smt_verb:
                continue

            from core.audit.sweep import get_smt_verb_role
            if get_smt_verb_role(smt_verb) == "detection":
                logger.debug(
                    "clean-refuted skipped %s:%s — %s is detection-role "
                    "(cannot override LLM clean)",
                    outcome.file, outcome.function, smt_verb,
                )
                continue

            _VACUOUS_VERBS = (
                "check-overflow", "check-oob", "check-overflow-to-oob",
            )
            if smt_verb in _VACUOUS_VERBS:
                logger.debug(
                    "clean-refuted skipped %s:%s — %s is vacuous without "
                    "source-level guards",
                    outcome.file, outcome.function, smt_verb,
                )
                continue

            chain = [{"type": "smt", "config": {"verb": smt_verb}}]
            confirmed = _run_tool_chain(
                chain,
                config=config,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source,
                hypothesis=mechanism,
                line_start=outcome.line,
                joern_server=joern_server,
            )
            if not confirmed:
                continue

            if _check_sink_guarded_cached(outcome.function, joern_server) == "guarded":
                logger.info(
                    "clean-refuted promotion blocked %s:%s via %s — guarded",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue

            tool = "+".join(confirmed)
            result.outcomes[i] = _promote_outcome(
                outcome, f"clean-refuted:{tool}",
            )
            result.sweep_promoted += 1
            result.clean -= 1
            result.findings += 1
            logger.info(
                "clean-refuted promoted %s:%s via %s (LLM refuted, SMT confirmed)",
                outcome.file, outcome.function, tool,
            )
            break


_C_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx"})


def _pre_loop_smt_screen(
    workqueue: list,
    config: "OrchestratorConfig",
    result: OrchestratorResult,
    checklist: Optional[Dict[str, Any]] = None,
) -> list:
    """Run SMT checks before the LLM loop.

    Functions with a confirmed SMT finding are recorded as outcomes
    immediately and removed from the workqueue so they never reach the
    (expensive) LLM review.  Returns the filtered workqueue.
    """
    try:
        from .condition_smt import (
            DomainVocabulary,
            check_auth_bypass,
            check_lock_discipline,
            check_resource_leak,
            check_null_propagation,
            check_integer_narrowing,
            check_early_release,
            check_toctou,
        )
    except Exception:
        return workqueue

    _extract_sg = None
    _check_pf = None
    try:
        from .condition_extraction import extract_sink_guards as _extract_sg
        from .condition_smt import check_path_feasibility as _check_pf
    except Exception:
        pass

    dm = None
    try:
        from .journal import load_domain_model
        dm = load_domain_model(config.out_dir)
    except Exception:
        pass
    vocab = DomainVocabulary.from_domain_model(dm)

    kept: list = []
    screened = 0

    for gap in workqueue:
        file_path = gap["file"]
        func_name = gap["name"]
        line_start = gap.get("line_start", 0)
        line_end = gap.get("line_end")

        is_c = any(file_path.endswith(ext) for ext in _C_EXTS)
        is_go = file_path.endswith(".go")
        is_c_or_go = is_c or is_go

        source = _read_raw_source(
            config.target_path, file_path, line_start, line_end,
        )
        if not source:
            kept.append(gap)
            continue

        tool_hit = ""
        try:
            abr = check_auth_bypass(source)
            if abr.bypass_found:
                tool_hit = "smt:check-auth-bypass"
                if abr.witness:
                    tool_hit += ":witness"
        except Exception:
            pass

        if not tool_hit and is_c:
            try:
                ldr = check_lock_discipline(source, vocab)
                if ldr.violation_found:
                    tool_hit = "smt:check-lock-discipline"
                    if ldr.witness:
                        tool_hit += ":witness"
            except Exception:
                pass

        if not tool_hit and is_c:
            try:
                rlr = check_resource_leak(source, vocab)
                if rlr.leak_found:
                    tool_hit = "smt:check-resource-leak"
                    if rlr.witness:
                        tool_hit += ":witness"
            except Exception:
                pass

        if not tool_hit and is_c:
            try:
                npr = check_null_propagation(source, vocab)
                if npr.null_deref_found:
                    tool_hit = "smt:check-null-propagation"
            except Exception:
                pass

        if not tool_hit and is_c_or_go:
            try:
                inr = check_integer_narrowing(source)
                if inr.narrowing_found:
                    tool_hit = "smt:check-integer-narrowing"
                    if inr.witness:
                        tool_hit += ":witness"
            except Exception:
                pass

        if not tool_hit and is_c_or_go:
            try:
                err = check_early_release(source, vocab)
                if err.early_release_found:
                    tool_hit = "smt:check-early-release"
            except Exception:
                pass

        if not tool_hit and is_c:
            try:
                from .callback_lifetime import check_callback_lifetime_local
                clr = check_callback_lifetime_local(source)
                if clr.violation_found:
                    tool_hit = "smt:check-callback-lifetime"
            except Exception:
                pass

        # check-lock-domain: too noisy for hard-classify (FP on
        # aead_check_key).  Runs in inject-mode via _run_mechanical_detectors
        # instead — results go to the LLM as context, not as verdicts.

        if not tool_hit and is_c:
            try:
                ttr = check_toctou(source)
                if ttr.toctou_found:
                    tool_hit = "smt:check-toctou"
            except Exception:
                pass

        if tool_hit:
            gap["_smt_pre_evidence"] = tool_hit
            screened += 1
            logger.info(
                "pre-loop SMT screen: %s:%s → evidence injected: %s",
                file_path, func_name, tool_hit,
            )
            kept.append(gap)
            continue

        if is_c and _extract_sg is not None and _check_pf is not None:
            try:
                guards = _extract_sg(source, file_path)
                if guards:
                    all_infeasible = True
                    for sg in guards:
                        if not sg.guards:
                            all_infeasible = False
                            break
                        pfr = _check_pf(sg.guards)
                        if pfr.feasible is not False:
                            all_infeasible = False
                            break
                    if all_infeasible:
                        outcome = ReviewOutcome(
                            file=file_path,
                            function=func_name,
                            status="dormant",
                            body=(
                                "[pre-loop SMT screen: all sink paths "
                                "infeasible] Z3 proved every path to a "
                                "dangerous sink is unreachable."
                            ),
                            evidence_tool="smt:dead-path",
                            line=line_start,
                        )
                        result.outcomes.append(outcome)
                        result.dormant += 1
                        result.reviewed += 1
                        screened += 1
                        logger.info(
                            "pre-loop SMT screen: %s:%s → dormant "
                            "(all sink paths infeasible)",
                            file_path, func_name,
                        )
                        continue
            except Exception:
                pass

        if is_c and not tool_hit:
            try:
                from .condition_smt import check_race_protection
                rpr = check_race_protection(source, vocab)
                if rpr.protected:
                    gap["_race_protected"] = True
                    gap["_race_protection_detail"] = rpr.reasoning
            except Exception:
                pass

        kept.append(gap)

    if screened:
        logger.info(
            "pre-loop SMT screen: %d evidence injections, %d remain for LLM",
            screened, len(kept),
        )

    return kept


def _promote_smt_clean(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
) -> None:
    """Consolidated post-loop pass: run SMT checks on clean outcomes.

    Single source read per function instead of separate passes.
    Includes Go-capable checks (integer_narrowing, early_release,
    lock_domain) alongside C-only checks.
    """
    try:
        from .condition_smt import (
            DomainVocabulary,
            check_auth_bypass,
            check_lock_discipline,
            check_resource_leak,
            check_null_propagation,
            check_integer_narrowing,
            check_early_release,
            check_lock_domain,
        )
    except Exception:
        return

    dm = None
    try:
        from .journal import load_domain_model
        dm = load_domain_model(config.out_dir)
    except Exception:
        pass
    vocab = DomainVocabulary.from_domain_model(dm)

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        is_c = any(outcome.file.endswith(ext) for ext in _C_EXTS)
        is_c_or_go = is_c or outcome.file.endswith(".go")

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        if outcome.line == 0 and gap:
            logger.warning(
                "smt-clean: %s:%s has outcome.line=0, using gap line_start=%d",
                outcome.file, outcome.function, gap.get("line_start", 0),
            )
            outcome.line = gap.get("line_start", 0)

        source = _read_raw_source(
            config.target_path, outcome.file, outcome.line, line_end,
        )
        if not source:
            continue

        tool_hit = ""

        try:
            abr = check_auth_bypass(source)
            if abr.bypass_found:
                tool_hit = "smt:check-auth-bypass"
                if abr.witness:
                    tool_hit += ":witness"
        except Exception:
            logger.debug(
                "auth_bypass_smt failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )

        if not tool_hit and is_c:
            try:
                ldr = check_lock_discipline(source, vocab)
                if ldr.violation_found:
                    tool_hit = "smt:check-lock-discipline"
                    if ldr.witness:
                        tool_hit += ":witness"
            except Exception:
                logger.debug(
                    "lock_discipline_smt failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if not tool_hit and is_c:
            try:
                rlr = check_resource_leak(source, vocab)
                if rlr.leak_found:
                    tool_hit = "smt:check-resource-leak"
                    if rlr.witness:
                        tool_hit += ":witness"
            except Exception:
                logger.debug(
                    "resource_leak_smt failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if not tool_hit and is_c:
            try:
                npr = check_null_propagation(source, vocab)
                if npr.null_deref_found:
                    tool_hit = "smt:check-null-propagation"
            except Exception:
                logger.debug(
                    "null_propagation_smt failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if not tool_hit and is_c_or_go:
            try:
                inr = check_integer_narrowing(source)
                if inr.narrowing_found:
                    tool_hit = "smt:check-integer-narrowing"
                    if inr.witness:
                        tool_hit += ":witness"
            except Exception:
                logger.debug(
                    "integer_narrowing_smt failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if not tool_hit and is_c_or_go:
            try:
                err = check_early_release(source, vocab)
                if err.early_release_found:
                    tool_hit = "smt:check-early-release"
            except Exception:
                logger.debug(
                    "early_release_smt failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if not tool_hit and is_c:
            try:
                from .callback_lifetime import check_callback_lifetime_local
                clr = check_callback_lifetime_local(source)
                if clr.violation_found:
                    tool_hit = "smt:check-callback-lifetime"
            except Exception:
                logger.debug(
                    "callback_lifetime failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if not tool_hit and is_c_or_go:
            try:
                ldr2 = check_lock_domain(source, vocab)
                if ldr2.mismatch_found:
                    tool_hit = "smt:check-lock-domain"
            except Exception:
                logger.debug(
                    "lock_domain_smt failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

        if tool_hit:
            result.outcomes[i] = _promote_outcome(outcome, tool_hit)
            result.sweep_promoted += 1
            result.clean -= 1
            result.findings += 1
            logger.info(
                "smt-clean promoted %s:%s via %s",
                outcome.file, outcome.function, tool_hit,
            )


def _promote_auth_bypass(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
) -> None:
    """Post-loop pass: proactive auth bypass detection on clean outcomes.

    Scans every clean outcome for the early-return-before-auth-check
    pattern.  When found, promotes clean → finding with SMT evidence.
    This catches auth bugs the LLM missed entirely.
    """
    try:
        from .condition_smt import check_auth_bypass
    except Exception:
        return

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        if outcome.line == 0 and gap:
            outcome.line = gap.get("line_start", 0)

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )
        if not source:
            continue

        try:
            abr = check_auth_bypass(source)
        except Exception:
            logger.debug(
                "auth_bypass_smt failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue

        if not abr.bypass_found:
            continue

        tool = "smt:check-auth-bypass"
        if abr.witness:
            tool += ":witness"
        result.outcomes[i] = _promote_outcome(outcome, tool)
        result.sweep_promoted += 1
        result.clean -= 1
        result.findings += 1
        logger.info(
            "auth-bypass promoted %s:%s — %s",
            outcome.file, outcome.function, abr.reasoning,
        )


def _promote_lock_discipline(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
) -> None:
    """Post-loop pass: proactive lock discipline detection on clean outcomes.

    Scans every clean outcome for lock-acquire-without-release-on-return
    patterns.  When found, promotes clean -> finding with SMT evidence.
    Only applies to C/C++ files (kernel-style locking).
    """
    _LOCK_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx"})
    try:
        from .condition_smt import check_lock_discipline
    except Exception:
        return

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        if not any(outcome.file.endswith(ext) for ext in _LOCK_EXTS):
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )
        if not source:
            continue

        try:
            ldr = check_lock_discipline(source)
        except Exception:
            logger.debug(
                "lock_discipline_smt failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue

        if not ldr.violation_found:
            continue

        tool = "smt:check-lock-discipline"
        if ldr.witness:
            tool += ":witness"
        result.outcomes[i] = _promote_outcome(outcome, tool)
        result.sweep_promoted += 1
        result.clean -= 1
        result.findings += 1
        logger.info(
            "lock-discipline promoted %s:%s — %s",
            outcome.file, outcome.function, ldr.reasoning,
        )


def _promote_resource_leak(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
) -> None:
    """Post-loop pass: proactive resource leak detection on clean outcomes.

    Scans every clean C/C++ outcome for alloc-without-free-on-error-path
    patterns.  When found, promotes clean -> finding with SMT evidence.
    """
    _LEAK_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx"})
    try:
        from .condition_smt import check_resource_leak
    except Exception:
        return

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        if not any(outcome.file.endswith(ext) for ext in _LEAK_EXTS):
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )
        if not source:
            continue

        try:
            rlr = check_resource_leak(source)
        except Exception:
            logger.debug(
                "resource_leak_smt failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue

        if not rlr.leak_found:
            continue

        tool = "smt:check-resource-leak"
        if rlr.witness:
            tool += ":witness"
        result.outcomes[i] = _promote_outcome(outcome, tool)
        result.sweep_promoted += 1
        result.clean -= 1
        result.findings += 1
        logger.info(
            "resource-leak promoted %s:%s — %s",
            outcome.file, outcome.function, rlr.reasoning,
        )


def _promote_null_propagation(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
    domain_model: Optional[Dict[str, Any]] = None,
) -> None:
    """Post-loop pass: proactive null propagation detection on clean outcomes.

    Scans every clean C/C++ outcome for pointer-from-nullable-source
    used without null check before first dereference.
    """
    _NULL_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx"})
    try:
        from .condition_smt import DomainVocabulary, check_null_propagation
    except Exception:
        return
    vocab = DomainVocabulary.from_domain_model(domain_model) if domain_model else None

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        if not any(outcome.file.endswith(ext) for ext in _NULL_EXTS):
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )
        if not source:
            continue

        try:
            npr = check_null_propagation(source, vocab)
        except Exception:
            logger.debug(
                "null_propagation_smt failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue

        if not npr.null_deref_found:
            continue

        tool = "smt:check-null-propagation"
        result.outcomes[i] = _promote_outcome(outcome, tool)
        result.sweep_promoted += 1
        result.clean -= 1
        result.findings += 1
        logger.info(
            "null-propagation promoted %s:%s — %s",
            outcome.file, outcome.function, npr.reasoning,
        )


def _promote_integer_narrowing(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: Optional[Dict[str, Any]] = None,
) -> None:
    """Post-loop pass: proactive integer narrowing detection on clean outcomes.

    Scans every clean C/C++ outcome for implicit integer narrowing without
    bounds checking.  Only applies to C/C++ (Go/Python/Rust/Java have
    built-in overflow safety or explicit conversions).
    """
    _NARROW_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx"})
    try:
        from .condition_smt import check_integer_narrowing
    except Exception:
        return

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        if not any(outcome.file.endswith(ext) for ext in _NARROW_EXTS):
            continue

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )
        if not source:
            continue

        try:
            inr = check_integer_narrowing(source)
        except Exception:
            logger.debug(
                "integer_narrowing_smt failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue

        if not inr.narrowing_found:
            continue

        tool = "smt:check-integer-narrowing"
        if inr.witness:
            tool += ":witness"
        result.outcomes[i] = _promote_outcome(outcome, tool)
        result.sweep_promoted += 1
        result.clean -= 1
        result.findings += 1
        logger.info(
            "integer-narrowing promoted %s:%s — %s",
            outcome.file, outcome.function, inr.reasoning,
        )


def _demote_self_contradictions(result: OrchestratorResult) -> None:
    """Demote suspicious outcomes where every hypothesis is refuted.

    When the LLM marks all hypotheses as refuted yet still returns
    'suspicious' with no tool evidence, the verdict is self-
    contradictory.  Verified safe: all corpus TPs with no evidence
    have at least one unrefuted hypothesis.
    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "suspicious":
            continue
        if outcome.evidence_tool:
            continue

        hypotheses = outcome.hypotheses or []
        if not hypotheses and outcome.review_result:
            hypotheses = outcome.review_result.get("hypotheses") or []
        if not hypotheses:
            continue

        all_refuted = all(
            isinstance(h, dict)
            and (h.get("confidence") or "").lower() == "refuted"
            for h in hypotheses
        )
        if not all_refuted:
            continue

        result.outcomes[i] = ReviewOutcome(
            file=outcome.file,
            function=outcome.function,
            status="clean",
            body=f"[self-contradiction: all {len(hypotheses)} hypotheses refuted]\n\n{outcome.body}",
            hypothesis=outcome.hypothesis,
            hypotheses=outcome.hypotheses,
            evidence_tool="",
            cost_usd=outcome.cost_usd,
            model=outcome.model,
            duration_s=outcome.duration_s,
            review_result=outcome.review_result,
            line=outcome.line,
        )
        result.suspicious -= 1
        result.clean += 1
        logger.info(
            "self-contradiction demotion: %s:%s — all %d hypotheses refuted",
            outcome.file, outcome.function, len(hypotheses),
        )


def _promote_hypothesis_inconsistent(result: OrchestratorResult) -> None:
    """Promote clean outcomes whose own hypotheses contradict the verdict.

    Mirror of ``_demote_self_contradictions``.  When the LLM returns
    'clean' but retains at least one hypothesis at high or medium confidence,
    the verdict is inconsistent with the
    analysis — the model described a plausible bug then second-guessed
    itself under context pressure.  Promote to suspicious so the sweep
    pass can attempt mechanical verification.

    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        if outcome.body.startswith("[suspicious-demotion:"):
            continue

        hypotheses = outcome.hypotheses or []
        if not hypotheses and outcome.review_result:
            hypotheses = outcome.review_result.get("hypotheses") or []
        if not hypotheses:
            continue

        unrefuted = [
            h for h in hypotheses
            if isinstance(h, dict)
            and (h.get("confidence") or "").lower() in ("high", "medium")
        ]
        if not unrefuted:
            continue

        best = unrefuted[0]
        mechanism = best.get("mechanism", "")[:120]
        result.outcomes[i] = ReviewOutcome(
            file=outcome.file,
            function=outcome.function,
            status="suspicious",
            body=(
                f"[hypothesis-consistency: {len(unrefuted)} unrefuted "
                f"hypothesis(es) at high/medium confidence]\n\n"
                f"{outcome.body}"
            ),
            hypothesis=outcome.hypothesis,
            hypotheses=outcome.hypotheses,
            evidence_tool="",
            cost_usd=outcome.cost_usd,
            model=outcome.model,
            duration_s=outcome.duration_s,
            review_result=outcome.review_result,
            line=outcome.line,
        )
        result.clean -= 1
        result.suspicious += 1
        logger.info(
            "hypothesis-consistency promotion: %s:%s — %d unrefuted "
            "high-confidence hypothesis(es) despite clean verdict (%s)",
            outcome.file, outcome.function, len(unrefuted), mechanism,
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

_STRUCTURAL_PREFILTER_RULES = frozenset(
    {
        "post-loop-oob-write",
    }
)


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

        if _has_mechanical_corroboration(
            outcome, config, sarif_cache, checklist, domain_model=domain_model
        ):
            ev = outcome.evidence_tool or ""
            if outcome.provenance_all_trusted and "smt" not in ev:
                logger.info(
                    "gate-demoted %s:%s has corroboration but all inputs "
                    "trusted — provenance overrides detection-only evidence",
                    outcome.file,
                    outcome.function,
                )
            else:
                logger.debug(
                    "gate-demoted %s:%s has mechanical corroboration "
                    "— stays suspicious",
                    outcome.file,
                    outcome.function,
                )
                continue

        # Determine if the vulnerability class is tool-covered
        class_covered = False
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
                logger.warning(
                    "tool_coverage check failed for %s:%s",
                    outcome.file,
                    outcome.function,
                    exc_info=True,
                )

        if class_covered:
            if outcome.semantic_confidence == "high":
                logger.info(
                    "gate-resolved %s:%s → stays suspicious "
                    "(semantic_confidence=high rescues from clean demotion)",
                    outcome.file,
                    outcome.function,
                )
                continue

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
                outcome.file,
                outcome.function,
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
                outcome.file,
                outcome.function,
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
        gap["file"],
        gap["name"],
        config.target_path,
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
        gap["file"],
        gap["name"],
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
            relevant.append(
                {
                    "source": "self",
                    "kind": c.kind,
                    "target": c.target,
                    "rule": c.rule,
                    "violation": c.violation,
                    "cwe": c.cwe,
                    "direction": c.direction,
                    "status": c.status,
                }
            )
        elif c.direction == "callers" and c.function == function_name:
            relevant.append(
                {
                    "source": f"callee {c_key}",
                    "kind": c.kind,
                    "target": c.target,
                    "rule": c.rule,
                    "violation": c.violation,
                    "cwe": c.cwe,
                    "direction": c.direction,
                    "status": c.status,
                }
            )

    return relevant[:15]


def _review_flow_traces(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    evidence_index: Optional[Dict[str, EvidenceRecord]] = None,
    joern_server=None,
    sarif_cache: Optional[SarifCache] = None,
    domain_model=None,
    audit_log: Optional[list] = None,
    start_time: float = 0.0,
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
        f"{o.file}:{o.function}" for o in result.outcomes if o.status == "clean"
    }

    import json as _json

    traces_reviewed = 0
    for trace_file in trace_files[:10]:
        if start_time and _check_budget(config, start_time, result):
            break

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
                    outcome,
                    config,
                    sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
            if outcome.status == "finding":
                gate_violations = _check_finding_gates(
                    outcome, audit_log=audit_log,
                    domain_model=domain_model,
                    mode=config.mode,
                )
                if gate_violations:
                    outcome = _demote_outcome(
                        outcome,
                        f"[gate violation: {'; '.join(gate_violations)}]",
                    )
            _tally_outcome(result, outcome)
            traces_reviewed += 1
            logger.info(
                "flow-trace review: %s in %s",
                outcome.status,
                flow_ctx["function"],
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
        (o for o in result.outcomes if o.status == "finding"),
        start=1,
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
            "persisted %d finding(s) to findings.json",
            len(findings_dicts),
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

    Delegates to evidence_grade.is_tool_evidence which checks canonical
    stamps (dynamic, frida, semgrep, etc.) and namespaced prefixes
    (prefilter:, critique:, sweep:).  LLM-suggested values like
    "Semgrep" or "CodeQL" do not pass.
    """
    from .evidence_grade import is_tool_evidence

    return is_tool_evidence(evidence_tool)


def _sanitize_llm_et(raw: str) -> str:
    """Strip LLM-supplied evidence_tool so it cannot pass _is_tool_confirmed."""
    from .evidence_grade import sanitize_llm_evidence_tool

    return sanitize_llm_evidence_tool(raw)


def _is_verification_evidence_for_gate(outcome: ReviewOutcome) -> bool:
    """Check if outcome has verification-grade evidence (for demotion gate).

    Returns True when the outcome carries evidence strong enough to
    prevent the suspicious→clean demotion.  Delegates to the pipeline's
    _is_verification_evidence which handles role checks.
    """
    ev = outcome.evidence_tool or ""
    if not ev:
        review = outcome.review_result or {}
        ev = review.get("evidence_tool", "")
    if not ev:
        return False
    from .pipeline import _is_verification_evidence
    for part in ev.split("+"):
        if _is_verification_evidence(part.strip()):
            return True
    return False


def _stamp_evidence(outcome: ReviewOutcome, tool: str) -> ReviewOutcome:
    """Stamp evidence_tool onto an outcome."""
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
            outcome.file,
            outcome.line or 0,
            line_end or 0,
        )
        if hits:
            return True

    source = _read_raw_source(
        config.target_path,
        outcome.file,
        outcome.line,
        line_end,
    )
    pf = run_prefilter(
        target_path=config.target_path,
        file_path=outcome.file,
        function_name=outcome.function,
        source=source,
        line_start=outcome.line or 0,
        project_sinks=config.project_sinks,
    )
    if pf.hits:
        if line_end:
            pf.hits = [
                h for h in pf.hits if not h.line or outcome.line <= h.line <= line_end
            ]
        if pf.hits:
            return True

    if domain_model:
        hypothesis = outcome.hypothesis or ""
        if outcome.review_result:
            hypothesis = outcome.review_result.get("hypothesis", hypothesis)
        matched = _match_domain_model_invariants(
            hypothesis,
            outcome.file,
            domain_model,
        )
        if matched:
            logger.info(
                "mechanical corroboration via domain-model invariant for %s:%s — %s",
                outcome.file,
                outcome.function,
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
        config.target_path,
        outcome.file,
        gap.get("line_start", 0),
        gap.get("line_end"),
    )
    if not source:
        return None

    try:
        from core.smt_solver.bounds_feasibility import check_bounds_infeasible
    except ImportError:
        return None

    if check_bounds_infeasible(source, cwe) is True:
        return "[smt-infeasible: bounds conditions make overflow impossible (Z3 UNSAT)]"

    # Fallback: hypothesis-driven overflow disproof via condition_smt.
    hypothesis = _resolve_hypothesis(outcome)
    if hypothesis:
        try:
            from .condition_smt import disprove_integer_overflow

            smt_result = disprove_integer_overflow(hypothesis, source)
            if smt_result.disproved is True:
                return "[smt-disproof: integer overflow impossible (Z3 UNSAT)]"
        except Exception:
            logger.debug(
                "disprove_integer_overflow fallback failed for %s:%s",
                outcome.file,
                outcome.function,
                exc_info=True,
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
                    c.file,
                    c.function,
                    exc_info=True,
                )

        pending = next_pending

    if rounds >= _MAX_PROPAGATION_ROUNDS and pending:
        logger.info(
            "constraint propagation hit round limit (%d) with %d open",
            _MAX_PROPAGATION_ROUNDS,
            len(pending),
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
            "understand_bridge: auto-importing context-map from %s",
            result_dir,
        )
        summary = load_understand_context(
            result_dir,
            config.out_dir,
            stale_files=stale,
        )
        if summary.get("context_map_loaded"):
            return load_context_map(config.out_dir)
    except Exception:
        logger.debug("understand_bridge import failed", exc_info=True)
    return None


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
    max_workers: int = 1,
) -> OrchestratorResult:
    """Re-review clean verdicts that now have Joern evidence.

    Functions reviewed before the Joern CPG build completed missed
    inter-procedural taint flows. Re-review only those that were
    marked clean AND now have Joern flows in the evidence index.

    When max_workers > 1, LLM calls are dispatched in parallel via
    ThreadPoolExecutor.  Post-processing runs in the main thread.
    """
    candidates = []
    for gap in gaps_before_joern:
        key = f"{gap['file']}:{gap['name']}"
        rec = evidence_index.get(key)
        if not rec or not rec.all_joern_flows():
            continue
        prior = next(
            (
                o
                for o in result.outcomes
                if o.file == gap["file"]
                and o.function == gap["name"]
                and o.status == "clean"
            ),
            None,
        )
        if prior is not None:
            candidates.append((gap, prior))

    if not candidates:
        return result

    if _check_budget(config, start_time, result):
        logger.info(
            "joern re-review skipped: run budget exhausted (%s)",
            result.terminated_by,
        )
        return result

    effective_workers = max(1, max_workers)
    logger.info(
        "re-reviewing %d clean verdicts that gained Joern evidence (workers=%d)",
        len(candidates),
        effective_workers,
    )

    # --- Build all contexts up-front ---
    prepared = []
    for gap, prior_outcome in candidates:
        ctx = _build_context(
            config,
            gap,
            checklist,
            context_map,
            evidence_index,
            discovered_evidence=discovered_evidence,
        )
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage,
                gap["file"],
                gap["name"],
            )
        ctx["joern_re_review"] = True
        prepared.append((len(prepared), gap, prior_outcome, ctx))

    def _do_review(item):
        idx, _gap, _prior, ctx = item
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:
            return (idx, None, exc)

    if effective_workers <= 1:
        raw_results = []
        for item in prepared:
            if _check_budget(config, start_time, result):
                break
            raw_results.append(_do_review(item))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        raw_results = []
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_item = {
                pool.submit(_do_review, item): item for item in prepared
            }
            for fut in as_completed(future_to_item):
                if _check_budget(config, start_time, result):
                    for f in future_to_item:
                        f.cancel()
                    break
                raw_results.append(fut.result())

    # --- Process results in main thread ---
    idx_to_prepared = {item[0]: item for item in prepared}
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, gap, prior_outcome, ctx = idx_to_prepared[idx]

        if exc is not None:
            logger.warning(
                "joern re-review failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
            continue

        outcome.line = gap.get("line_start", 0)

        if outcome.status in ("finding", "suspicious"):
            if outcome.status == "finding" and config.sweep_validate_findings:
                outcome = _sweep_validate(
                    outcome,
                    config,
                    sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
            if outcome.status == "finding":
                outcome = _apply_reachability_gate(
                    outcome,
                    ctx,
                    entry_points,
                    config,
                )
            if outcome.status == "finding":
                gate_violations = _check_finding_gates(
                    outcome,
                    audit_log=audit_log,
                    mode=config.mode,
                )
                if gate_violations:
                    outcome = _demote_outcome(
                        outcome,
                        f"[gate violation: {'; '.join(gate_violations)}]",
                    )

            _untally_outcome(result, prior_outcome)
            oi = result.outcomes.index(prior_outcome)
            result.outcomes[oi] = outcome
            _tally_outcome(result, outcome, append=False)

            try:
                _commit_outcome(config, outcome, gap)
            except Exception:
                logger.warning(
                    "commit failed for %s:%s",
                    gap["file"],
                    gap["name"],
                    exc_info=True,
                )

            if (
                config.enable_session_context
                and session_observations is not None
                and outcome.review_result
            ):
                _accumulate_observations(
                    session_observations,
                    outcome,
                    gap,
                    sweep_pre_status=prior_outcome.status,
                )

            logger.info(
                "joern re-review %s:%s: clean -> %s",
                gap["file"],
                gap["name"],
                outcome.status,
            )

    return result


def _callee_contract_requeue(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    *,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    fuzz_coverage: Optional[Dict[str, Any]],
    evidence_index: Dict[str, Any],
    discovered_evidence: Optional[Dict[str, Any]] = None,
    session_observations: Optional[List[Dict[str, str]]] = None,
    joern_server=None,
    start_time: float = 0.0,
    on_progress: Optional[Callable] = None,
    max_workers: int = 1,
) -> int:
    """Re-review callers whose callee assumptions were contradicted.

    Scans outcomes for ``relies_on`` references.  When a callee was
    reviewed and found to have a finding/suspicious status, any caller
    that assumed the callee was safe is re-reviewed with the callee's
    actual result injected as context.

    Returns the count of callers re-reviewed.
    """
    callee_outcomes: Dict[str, ReviewOutcome] = {}
    for o in result.outcomes:
        callee_outcomes[o.function] = o
        callee_outcomes[f"{o.file}:{o.function}"] = o

    candidates: List[tuple] = []
    for o in result.outcomes:
        if o.status != "clean":
            continue
        rr = o.review_result or {}
        relies_on = rr.get("relies_on") or []
        if not relies_on:
            continue
        for dep in relies_on:
            callee_name = dep.get("callee", "")
            assumption = dep.get("assumption", "")
            if not callee_name:
                continue
            co = callee_outcomes.get(callee_name)
            if co is None and ":" not in callee_name:
                co = next(
                    (v for k, v in callee_outcomes.items()
                     if k.endswith(f":{callee_name}")),
                    None,
                )
            if co is not None and co.status in ("finding", "suspicious"):
                co_ev = getattr(co, "evidence_tool", "") or ""
                if not co_ev or co_ev.startswith(("prefilter:", "llm-claimed:")):
                    continue
                candidates.append((o, callee_name, assumption, co))
                break

    if not candidates:
        return 0

    logger.info(
        "callee-contract: %d callers relied on callees with findings",
        len(candidates),
    )

    effective_workers = max(1, max_workers)
    prepared = []
    cl = checklist if isinstance(checklist, dict) else {}
    cl_entries = [
        {**item, "file": fi.get("path", "")}
        for fi in cl.get("files", [])
        for item in fi.get("items", [])
    ] if cl else []
    for caller_outcome, callee_name, assumption, callee_outcome in candidates:
        gap = next(
            (
                e for e in cl_entries
                if e.get("file") == caller_outcome.file
                and e.get("name") == caller_outcome.function
            ),
            None,
        )
        if gap is None:
            gap = {
                "file": caller_outcome.file,
                "name": caller_outcome.function,
                "line_start": caller_outcome.line,
            }
        ctx = _build_context(
            config, gap, checklist, context_map,
            evidence_index,
            discovered_evidence=discovered_evidence,
        )
        if fuzz_coverage:
            ctx["fuzz_coverage"] = _fuzz_coverage_for(
                fuzz_coverage,
                gap["file"],
                gap["name"],
            )
        ctx["callee_contract_violation"] = {
            "callee": callee_name,
            "assumption": assumption,
            "callee_status": callee_outcome.status,
            "callee_hypothesis": callee_outcome.hypothesis or "",
        }
        ctx["force_review"] = True
        prepared.append((len(prepared), gap, caller_outcome, ctx))

    def _do_review(item):
        idx, _gap, _prior, ctx = item
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:
            return (idx, None, exc)

    if effective_workers <= 1:
        raw_results = [_do_review(item) for item in prepared]
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        raw_results = []
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            futs = {pool.submit(_do_review, item): item
                    for item in prepared}
            for fut in as_completed(futs):
                raw_results.append(fut.result())

    re_reviewed = 0
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, gap, prior_outcome, _ctx = prepared[idx]
        if exc is not None:
            logger.warning(
                "callee-contract re-review failed for %s:%s: %s",
                gap.get("file", "?"), gap.get("name", "?"), exc,
            )
            continue
        outcome.line = gap.get("line_start", 0)
        if outcome.status in ("finding", "suspicious"):
            _untally_outcome(result, prior_outcome)
            try:
                oi = result.outcomes.index(prior_outcome)
                result.outcomes[oi] = outcome
            except ValueError:
                result.outcomes.append(outcome)
            _tally_outcome(result, outcome, append=False)
            try:
                _commit_outcome(config, outcome, gap)
            except Exception:
                logger.debug(
                    "commit failed for callee-contract re-review %s:%s",
                    gap.get("file"), gap.get("name"), exc_info=True,
                )
            logger.info(
                "callee-contract: %s:%s clean -> %s (callee %s has %s)",
                gap.get("file"), gap.get("name"),
                outcome.status,
                _ctx.get("callee_contract_violation", {}).get("callee"),
                _ctx.get("callee_contract_violation", {}).get("callee_status"),
            )
            re_reviewed += 1

    return re_reviewed


def _re_review_study_enriched(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: Dict[str, Any],
    context_map: Optional[Dict[str, Any]],
    evidence_index: Dict[str, EvidenceRecord],
    sarif_cache: Optional[SarifCache],
    entry_points: set,
    reading_list_functions: set,
    start_time: float,
    on_progress: Optional[Callable],
    audit_log: Optional[List[Dict[str, Any]]] = None,
    session_observations: Optional[List[Dict[str, str]]] = None,
    discovered_evidence: Optional[Dict[str, Any]] = None,
    joern_server=None,
    max_workers: int = 1,
    throttle: Any = None,
) -> OrchestratorResult:
    """Re-review functions that queued reading-list items.

    Now with enriched domain knowledge.

    After the study loop resolves reading-list questions into domain-model
    concepts/invariants, the functions that originally needed that knowledge
    are re-reviewed with the enriched context injected via domain_model_context().

    When max_workers > 1, LLM calls are dispatched in parallel via
    ThreadPoolExecutor.  Post-processing runs in the main thread.
    When *throttle* is provided, each LLM call acquires a slot first.
    """
    candidates = []
    for key in reading_list_functions:
        parts = key.split(":", 1)
        if len(parts) != 2:
            continue
        file_path, func_name = parts

        prior = next(
            (
                o
                for o in result.outcomes
                if o.file == file_path and o.function == func_name
            ),
            None,
        )
        if prior is None:
            continue

        gap = {
            "file": file_path,
            "name": func_name,
            "line_start": getattr(prior, "line", 0),
        }
        candidates.append((gap, prior))

    if not candidates:
        return result

    if _check_budget(config, start_time, result):
        logger.info(
            "study re-review skipped: run budget exhausted (%s)",
            result.terminated_by,
        )
        return result

    effective_workers = max(1, max_workers)
    logger.info(
        "re-reviewing %d functions with enriched domain knowledge (workers=%d)",
        len(candidates),
        effective_workers,
    )

    # --- Build all contexts up-front ---
    prepared = []
    for gap, prior_outcome in candidates:
        ctx = _build_context(
            config,
            gap,
            checklist,
            context_map,
            evidence_index,
            discovered_evidence=discovered_evidence,
        )
        ctx["study_re_review"] = True
        ctx["prior_verdict"] = {
            "status": prior_outcome.status,
            "body": prior_outcome.body[:300] if prior_outcome.body else "",
            "hypothesis": (
                prior_outcome.review_result.get("hypothesis", "")[:200]
                if prior_outcome.review_result
                else ""
            ),
        }
        prepared.append((len(prepared), gap, prior_outcome, ctx))

    def _do_review(item):
        idx, _gap, _prior, ctx = item
        try:
            if throttle is not None:
                with throttle.acquire_sync():
                    outcome = review_fn(ctx, config)
            else:
                outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:
            return (idx, None, exc)

    if effective_workers <= 1:
        raw_results = []
        for item in prepared:
            if _check_budget(config, start_time, result):
                break
            raw_results.append(_do_review(item))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        raw_results = []
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_item = {
                pool.submit(_do_review, item): item for item in prepared
            }
            for fut in as_completed(future_to_item):
                if _check_budget(config, start_time, result):
                    for f in future_to_item:
                        f.cancel()
                    break
                raw_results.append(fut.result())

    # --- Process results in main thread ---
    idx_to_prepared = {item[0]: item for item in prepared}
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, gap, prior_outcome, ctx = idx_to_prepared[idx]

        if exc is not None:
            logger.warning(
                "study re-review failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
            continue

        outcome.line = gap.get("line_start", 0)

        if outcome.status in ("finding", "suspicious"):
            if outcome.status == "finding" and config.sweep_validate_findings:
                outcome = _sweep_validate(
                    outcome,
                    config,
                    sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
            if outcome.status == "finding":
                outcome = _apply_reachability_gate(
                    outcome,
                    ctx,
                    entry_points,
                    config,
                )
            if outcome.status == "finding":
                gate_violations = _check_finding_gates(
                    outcome,
                    audit_log=audit_log,
                    mode=config.mode,
                )
                if gate_violations:
                    outcome = _demote_outcome(
                        outcome,
                        f"[gate violation: {'; '.join(gate_violations)}]",
                    )

        if outcome.status != prior_outcome.status:
            _untally_outcome(result, prior_outcome)
            oi = result.outcomes.index(prior_outcome)
            result.outcomes[oi] = outcome
            _tally_outcome(result, outcome, append=False)

            try:
                _commit_outcome(config, outcome, gap)
            except Exception:
                logger.warning(
                    "commit failed for %s:%s",
                    gap["file"],
                    gap["name"],
                    exc_info=True,
                )

            if (
                config.enable_session_context
                and session_observations is not None
                and outcome.review_result
            ):
                _accumulate_observations(
                    session_observations,
                    outcome,
                    gap,
                    sweep_pre_status=prior_outcome.status,
                )

            logger.info(
                "study re-review %s:%s: %s -> %s",
                gap["file"],
                gap["name"],
                prior_outcome.status,
                outcome.status,
            )

    return result


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
            has_flow=et == "dynamic:sanitizer",
        )

    language = gap.get("language", "")
    return resolve_disagreement(
        gap.get("file", ""),
        gap.get("name", ""),
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
            spec_ev.append(
                GradedEvidence(
                    source=EvidenceSource.LLM_SPEC,
                    confidence=Confidence.LOW,
                    description=f"spec precondition: {pc}",
                )
            )
        for ns in getattr(spec, "negative_specs", []) or []:
            spec_ev.append(
                GradedEvidence(
                    source=EvidenceSource.LLM_SPEC,
                    confidence=Confidence.LOW,
                    description=f"spec negative: {ns}",
                )
            )

    ns_ev: List[GradedEvidence] = []
    for finding in ctx.get("negative_space", []):
        desc = getattr(finding, "title", "") or getattr(finding, "expected", "")
        ns_ev.append(
            GradedEvidence(
                source=EvidenceSource.NEGATIVE_SPACE,
                confidence=Confidence.MEDIUM,
                description=desc,
                detail=getattr(finding, "evidence", None),
            )
        )

    contract_ev: List[GradedEvidence] = []
    for viol in ctx.get("postcondition_violations", []):
        desc = getattr(viol, "description", "") or str(viol)
        contract_ev.append(
            GradedEvidence(
                source=EvidenceSource.COCCINELLE,
                confidence=Confidence.MEDIUM,
                description=f"postcondition violation: {desc}",
            )
        )

    ts_ev: List[GradedEvidence] = []
    for viol in ctx.get("typestate_violations", []):
        desc = getattr(viol, "description", "") or str(viol)
        ts_ev.append(
            GradedEvidence(
                source=EvidenceSource.TYPESTATE,
                confidence=Confidence.MEDIUM,
                description=f"typestate: {desc}",
            )
        )

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
    """Run dark-verification pass on eligible outcomes.

    Eligible outcomes are those with status ``"dark"`` (no tool could
    confirm or refute) OR whose CWE class has ``dark_verify: True`` in
    the dispatch table (auth/biz-logic CWEs where witness execution is
    the primary grounding mechanism).

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

    try:
        from .cwe_dispatch import dark_verify_applicable
    except ImportError:
        dark_verify_applicable = lambda _cwe: False  # noqa: E731

    def _eligible(o: ReviewOutcome) -> bool:
        if o.status == "dark":
            return True
        cwe = (
            (o.review_result or {}).get("cwe_class")
            or (o.review_result or {}).get("cwe")
            or ""
        )
        return bool(cwe) and dark_verify_applicable(cwe)

    dark_outcomes = [o for o in result.outcomes if _eligible(o)]
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

        prior = outcome.status
        if verify_result.verdict == "confirmed":
            outcome.status = "finding"
            outcome.evidence_tool = "dark_verify:confirmed"
            if prior != "finding":
                result.findings += 1
                if prior in ("dark", "dormant"):
                    result.dormant -= 1
                elif prior == "suspicious":
                    result.suspicious -= 1
                elif prior == "clean":
                    result.clean -= 1
                elif prior == "error":
                    result.errors -= 1
        elif verify_result.verdict == "refuted":
            outcome.status = "clean"
            outcome.evidence_tool = "dark_verify:refuted"
            if prior != "clean":
                result.clean += 1
                if prior in ("dark", "dormant"):
                    result.dormant -= 1
                elif prior == "suspicious":
                    result.suspicious -= 1
                elif prior == "finding":
                    result.findings -= 1
                elif prior == "error":
                    result.errors -= 1

        records.append(
            {
                "file": outcome.file,
                "function": outcome.function,
                "status": outcome.status,
                "evidence_tool": outcome.evidence_tool,
                "verdict": verify_result.verdict,
                "match_detail": verify_result.match_detail,
            }
        )

    if records:
        results_path = config.out_dir / "dark-verify-results.json"
        results_path.write_text(
            json.dumps(records, indent=2),
            encoding="utf-8",
        )
