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

import contextlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading as _threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TYPE_CHECKING

from core.analysis.reachability_gates import (
    GUARD_UNAVAILABLE,
    build_sink_reachable_set,
    check_sink_guarded,
    compute_demotion_verdict,
)
from core.evidence import (
    EvidenceRecord,
    build_evidence_index,
    format_evidence_prose,
    format_evidence_structured,
)
from core.json import load_json, save_json
from core.smt_solver.availability import Z3_ERRORS
from packages.checker_synthesis.library import RuleLibrary

from ._util import extract_context_map_set
from .codeql_backend import (
    build_sink_results as _build_sink_results_raw,
)
from .codeql_backend import (
    build_taint_summary as _build_taint_summary_raw,
)
from .codeql_backend import (
    codeql_pre_sweep as _codeql_pre_sweep_raw,
)
from .constraints import (
    extract_constraints_from_review,
    load_constraints,
    merge_constraint,
    open_constraints,
    save_constraints,
)
from .context import assemble_context
from .cost_tracker import PhaseCostLedger
from .diagnostics import (
    format_tier_diagnostics,
    write_tier_diagnostics,
)
from .diagnostics import (
    increment_tier as _increment_tier,
)
from .diagnostics import (
    increment_tier_dict as _increment_tier_dict,
)
from .diagnostics import (
    inject_discovered_evidence as _inject_discovered_evidence,
)
from .diagnostics import (
    iris_candidate_to_spec as _iris_candidate_to_spec,
)
from .exploit_feedback import (
    FeedbackState,
    format_feedback_for_context,
    format_feedback_summary,
    load_feedback_state,
)
from .findings import write_findings
from .gaps import (
    compute_gaps,
    gap_for_site,
    hoist_pins,
    hydrate_live_gaps_for_detectors,
    load_checklist,
    load_context_map,
    truncate_gaps_to_budget,
    write_gaps,
)
from .hypothesis_mapping import (
    hypothesis_to_cocci_check as _hypothesis_to_cocci_check,
)
from .hypothesis_mapping import (
    hypothesis_to_semgrep_rule_keyed as _hypothesis_to_semgrep_rule_keyed,
)
from .hypothesis_mapping import (
    hypothesis_to_smt_verb as _hypothesis_to_smt_verb,
)
from .joern_backend import (
    adaptive_max_depth as _adaptive_max_depth,
)
from .joern_backend import (
    drain_joern_future as _drain_joern_future,
)
from .joern_backend import (
    enrich_joern_evidence as _enrich_joern_evidence,
)
from .joern_backend import (
    enrich_summaries_from_joern as _enrich_summaries_from_joern,
)
from .joern_backend import (
    import_sibling_joern_flows as _import_sibling_joern_flows_raw,
)
from .joern_backend import (
    joern_live_query as _joern_live_query,
)
from .joern_backend import (
    joern_tunables as _joern_tunables,
)
from .joern_backend import (
    merge_joern_flows as _merge_joern_flows,
)
from .joern_backend import (
    resolve_joern_evidence as _resolve_joern_evidence_raw,
)
from .joern_backend import (
    sibling_run_dirs as _sibling_run_dirs,
)
from .joern_backend import (
    run_exclude_dirs as _run_exclude_dirs,
)
from .joern_backend import (
    start_joern_server as _start_joern_server_raw,
)
from .joern_backend import (
    stop_joern_server as _stop_joern_server,
)
from .loaders import (
    fuzz_coverage_for as _fuzz_coverage_for,
)
from .loaders import (
    load_coverage_records as _load_coverage_records,
)
from .loaders import (
    load_exploit_feedback as _load_exploit_feedback_raw,
)
from .loaders import (
    load_fuzz_coverage as _load_fuzz_coverage,
)
from .loaders import (
    load_fuzz_coverage_any as _load_fuzz_coverage_any,
)
from .loaders import (
    load_or_build_taint_approx as _load_or_build_taint_approx_raw,
)
from .loaders import (
    load_variants as _load_variants,
)
from .pipeline import ReviewMode, VerificationTier
from .prefilter import (
    PrefilterResult,
    evidence_matches_hypothesis,
    family_for_rule,
    run_prefilter,
)
from .priority import (
    group_by_subsystem,
    load_flow_traces,
    load_tool_failures,
    score_functions,
)
from .priority import (
    load_fuzz_coverage as _load_fuzz_coverage_from_runs,
)
from .propagation import PropagationConfig, propagate_one_hop
from .record import (
    _resolve_annotations_dir as _resolve_ann_dir,
)
from .record import (
    append_audit_log,
    load_audit_log,
)
from .shared_state import SharedState
from .sweep import (
    SarifCache,
    run_coccinelle_sweep,
    run_semgrep_sweep,
    run_smt_verb_direct,
)
from .topo_order import topological_sort as _topological_sort
from .triage import TriageBucket, classify_all, format_triage_summary

from core.inventory.binary_builder import BINARY_PATH_PREFIX

if TYPE_CHECKING:
    from concurrent.futures import Future
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Single-entry cache for per-run call-graph extraction: three phases
# (IRIS compositional analysis, the postcondition tier, structural
# detectors) load call graphs with identical (target, checklist)
# arguments, and each uncached load re-parses up to the file cap of
# sources from scratch. One target per orchestrator process, so one
# entry suffices; keyed on the checklist's identity fields so a
# rebuilt inventory refreshes it.
_call_graphs_cache: dict[tuple[str, Any, Any], dict[str, Any]] = {}


def _load_call_graphs_cached(
    target_path: Any, checklist: dict[str, Any] | None,
) -> dict[str, Any]:
    from core.inventory.call_graph import load_call_graphs

    key = (
        str(target_path),
        (checklist or {}).get("generated_at"),
        (checklist or {}).get("total_files"),
    )
    hit = _call_graphs_cache.get(key)
    if hit is not None:
        return hit
    graphs = load_call_graphs(target_path, checklist)
    _call_graphs_cache.clear()
    _call_graphs_cache[key] = graphs
    return graphs

# Byte budgets for the orchestrator's own artifact reads: 8 MiB for
# small state sidecars, 64 MiB for findings/chains/study documents
# (findings-class budget, matching the validate bridge).
_MAX_STATE_BYTES = 8 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _pinned_or_parent_project_dir(out_dir):
    """Project-level dir for cross-run stores: the RUN PIN's project
    dir when the run carries a real pin (an --out run pinned to P uses
    P's dir; a pin-null standalone run uses NOTHING even under a
    project-shaped parent); the historical out_dir.parent shape probe
    only for pin-less legacy run dirs."""
    from pathlib import Path as _P
    if not out_dir:
        return None
    out_dir = _P(out_dir)
    try:
        from core.run.pin import pin_project_dir, resolve_run_pin
        pin = resolve_run_pin(out_dir)
        if pin.authoritative:
            return pin_project_dir(out_dir)
    except Exception:  # noqa: BLE001 — shape fallback below
        pass
    if (out_dir / ".raptor-run.json").exists():
        return out_dir.parent
    return None


# ── Narrowed exception sets for best-effort blocks ──────────────────
# suppress(Exception) narrowing sweep: miswiring-class exceptions
# (TypeError, AttributeError, KeyError, NameError, ImportError on
# in-repo modules) must propagate — a swallowed one hides a wired-in
# call gone wrong.

#: Best-effort analysis/formatting over data derived from arbitrary
#: (hostile) target source: format/encoding quirks, pathological
#: nesting.  Deliberately excludes the miswiring classes.
_ENRICH_ERRORS = (ValueError, IndexError, RecursionError)

#: SMT screens over hostile C/Go source.  The condition_smt checkers
#: self-handle child-process and import failures; what can still
#: escape is extraction quirks (``_ENRICH_ERRORS``), subprocess spawn
#: failures (OSError) and in-process Z3 errors.
_SMT_SCREEN_ERRORS = (*_ENRICH_ERRORS, OSError, *Z3_ERRORS)

_shutdown_event = _threading.Event()


_active_target_path: Path | None = None


def is_shutdown_requested() -> bool:
    return _shutdown_event.is_set()


def request_shutdown() -> None:
    _shutdown_event.set()


# ── SIGTERM grace ────────────────────────────────────────────────────
# External supervisors stop long audits with SIGTERM (or a plain kill
# after a shell cap). First TERM: stop dispatching, harvest in-flight
# completions via the executor's shutdown path, flush ledgers/journal,
# write the salvage exports, and let the CLI mark the lifecycle
# `interrupted` with a resume hint — bounded by a ~30s watchdog that
# forces exit 130 if the drain stalls. Second TERM: immediate exit 130
# (after the best-effort flush hooks).

_SIGTERM_GRACE_S = 30.0
_sigterm_event = _threading.Event()
_sigterm_state: dict[str, Any] = {"installed": False, "count": 0}
#: Best-effort callables run before any FORCED exit (watchdog expiry /
#: second TERM): collector flush, lifecycle interrupt marking. The
#: graceful path runs the real salvage sequence instead.
_sigterm_flush_hooks: list[Callable[[], None]] = []


def is_sigterm_requested() -> bool:
    return _sigterm_event.is_set()


def _run_sigterm_flush_hooks() -> None:
    # Snapshot: run_orchestrator's finally clears the registry
    # concurrently with a late watchdog.
    hooks = list(_sigterm_flush_hooks)
    for hook in hooks:
        try:
            hook()
        except Exception:
            logger.debug("sigterm flush hook failed", exc_info=True)


def _sigterm_watchdog(grace_s: float) -> None:
    time.sleep(grace_s)
    logger.warning(
        "SIGTERM grace (%.0fs) expired — forcing exit 130 after "
        "best-effort flush (salvage may be incomplete; resume with "
        "`raptor-audit resume <out-dir>`)",
        grace_s,
    )
    _run_sigterm_flush_hooks()
    os._exit(130)


def _handle_sigterm(_signum, _frame) -> None:  # signal-handler API shape
    _sigterm_state["count"] += 1
    if _sigterm_state["count"] >= 2:
        _run_sigterm_flush_hooks()
        os._exit(130)
    logger.warning(
        "SIGTERM received — stopping dispatch, harvesting in-flight "
        "completions, then flushing ledgers/journal and writing the "
        "salvage report (bounded grace ~%.0fs; a second SIGTERM exits "
        "immediately). Resume later with: raptor-audit resume <out-dir>",
        _SIGTERM_GRACE_S,
    )
    _sigterm_event.set()
    request_shutdown()
    _threading.Thread(
        target=_sigterm_watchdog,
        args=(_SIGTERM_GRACE_S,),
        daemon=True,
        name="sigterm-watchdog",
    ).start()


def install_sigterm_grace() -> bool:
    """Install the graceful TERM handler — main thread, once.

    Returns True when the handler is (already) installed. Library
    callers on worker threads (and platforms where signal
    registration fails) keep the default disposition — the run then
    dies as before, and `raptor-audit resume` remains the recovery.
    """
    if _sigterm_state["installed"]:
        return True
    if _threading.current_thread() is not _threading.main_thread():
        return False
    import signal as _signal
    try:
        _signal.signal(_signal.SIGTERM, _handle_sigterm)
    except (ValueError, OSError):
        logger.debug("SIGTERM handler installation failed", exc_info=True)
        return False
    _sigterm_state["installed"] = True
    return True


def _reset_shutdown_state() -> None:
    """Reset per-run shutdown/SIGTERM request state at run start.

    The events and the TERM count are module globals: a prior
    in-process run that was stopped (SIGTERM drain, request_shutdown)
    left them set, so a second run in the same process stopped
    immediately at its first ``is_shutdown_requested()`` check, and
    its first real SIGTERM was miscounted as the second (immediate
    exit 130 instead of the graceful drain). Reset at run start like
    the per-run caches. The handler-installed flag persists — the
    signal disposition is process-global and installing is
    idempotent-guarded.
    """
    _shutdown_event.clear()
    _sigterm_event.clear()
    _sigterm_state["count"] = 0


def _update_run_progress(out_dir: Path, result: Any) -> None:
    """Update run metadata with progress checkpoint.

    Atomic + locked like every other ``.raptor-run.json`` writer
    (``core.run.metadata._update_status``): the previous bare
    ``write_text`` could be torn by a kill mid-write, leaving the run
    metadata unparseable, and the unlocked read-modify-write raced the
    lifecycle writers — the last writer silently dropped the other's
    update (a SIGTERM drain marking the run ``interrupted`` could be
    clobbered back to ``running`` by a checkpoint that loaded the
    stale status a moment earlier).
    """
    meta_path = out_dir / ".raptor-run.json"
    try:
        from core.json import load_json, save_json
        from core.run.metadata import _metadata_lock

        with _metadata_lock(meta_path):
            meta = load_json(meta_path)
            if not isinstance(meta, dict):
                return
            meta.setdefault("extra", {})["progress"] = {
                # OrchestratorResult counts completed reviews in
                # ``reviewed`` (it has no ``completed`` field).
                "completed": getattr(result, "reviewed", 0),
            }
            save_json(meta_path, meta)
    except Exception:
        logger.debug("progress checkpoint write failed", exc_info=True)


@dataclass
class OrchestratorConfig:
    """Configuration for an orchestrator run."""

    target_path: Path
    out_dir: Path
    budget: int | None = None
    scope: str | list[str] | None = None
    # Coverage floor for scoped runs: under --budget, every in-scope
    # file keeps its best-scored gap before score order fills the
    # rest (see gaps.truncate_gaps_to_budget). Only consulted when
    # scope is set.
    scope_floor: bool = True
    # Operator pins (``--pin file:function``, repeatable): guaranteed
    # review slots, hoisted to the head of the schedule before the
    # budget cut. Guidance only — never excludes the rest of the queue.
    pins: list[str] | None = None
    strategy_filter: str | None = None
    models: list[str] = field(default_factory=lambda: ["default"])
    multi_model: bool = False
    adversarial: bool = False
    # Opt-in LLM re-rank of the gap-queue head within priority tiers
    # (core.audit.gap_ranking) before pins/budget. Ordering only.
    rank_gaps: bool = False
    critique_interval: int = 10
    max_cost_usd: float | None = None
    max_seconds: float | None = None
    resume: bool = True
    annotations_dir: Path | None = None
    include_stale: bool = True
    subsystem_depth: int = 0
    batch_sloc_threshold: int = 15
    propagate_constraints: bool = True
    binary_verdicts: dict[str, str] | None = None
    no_binary_oracle: bool = False
    inventory: dict[str, Any] | None = None
    codeql_db_path: str | None = None
    # Repeatable ``--codeql-db``: one database per language for
    # multi-language targets. Normalised at run start into
    # ``codeql_db_router`` (see core.audit.codeql_dbs); after
    # normalisation ``codeql_db_path`` holds the router's primary.
    codeql_db_paths: list[str] | None = None
    # Derived at run start (never set by callers).
    codeql_db_router: Any | None = None
    threat_model: dict[str, Any] | None = None
    validate: bool = True
    prefilter: bool = True
    # Prefilter skip_llm shortcut. False keeps the prefilter running
    # (hits still feed review context and the post-review structural
    # override) but a skip_llm verdict no longer resolves the function
    # clean without review (corpus calibration sets this off so labeled
    # deep mechanisms are actually exercised). Production default
    # unchanged (on).
    prefilter_skip: bool = True
    # Triage-classifier SKIP shortcut. False disables the skip — every
    # workqueue function gets a real review instead of a classifier
    # "clean" (corpus calibration sets this off so labeled deep
    # mechanisms are actually exercised). Buckets other than SKIP
    # (glance/investigate/deep_dive) are unaffected.
    triage: bool = True
    # Vendored/generated-code triage tier (--no-vendored-triage to
    # disable): files with corroborated generator provenance route to
    # the skip tier, uncorroborated banners / vendored paths /
    # generated-shape structure to the glance tier. Every decision
    # writes a suppressions.jsonl record; pinned gaps are exempt.
    vendored_triage: bool = True
    sweep_validate_findings: bool = True
    deepen_suspicious: bool = True
    # Slice of the LLM cost cap held back from the discovery loop so
    # the deepen phase can actually execute the re-reviews it
    # announces (a measured run announced 4 re-reviews with $0 left).
    # Held on the budget client before the main loop, released when
    # the deepen phase starts (or immediately when deepen has nothing
    # to do). 0 disables the reserve.
    deepen_reserve_fraction: float = 0.15
    # Slice of the LLM cost cap held back from the PRE-review bulk
    # passes (prep, study, synthesis, summaries) so the per-function
    # review loop is guaranteed headroom. Held on the budget client at
    # run start, released when the review executor takes over (the
    # deepen reserve then takes its own slice for re-reviews). Same
    # mechanism as deepen_reserve_fraction — the client holds one
    # reserve at a time, and the two phases hand it over. 0 (default)
    # disables it; the corpus runner sets it so label reviews are
    # never starved by a hungry prep phase.
    review_reserve_fraction: float = 0.0
    enable_session_context: bool = True
    review_passes: int = 1
    max_propagation_depth: int | None = None
    force: bool = False
    joern_overrides: dict[str, Any] | None = None
    blind_first_pass: bool = False
    max_refinements: int = 2
    clean_check: bool = True
    dynamic_validation: bool = False
    # Operator repo-trust assertion (the project 'config' trust marker
    # / --trust-repo umbrella, resolved at config build).  Consumed by
    # trust-gated witnesses (the Go internal-concurrency discharge)
    # whose soundness bounds assume non-adversarial target code.
    # Never auto-set from the scanned repo.
    repo_trusted: bool = False
    caps: Any | None = None
    max_workers: int = 0  # 0 = auto (derive from model RPM), 1 = serial
    # Additional item kinds to review beyond functions/methods
    # (e.g. {"top_level", "macro", "global"}). None = default set.
    include_kinds: set | None = None
    functions: list[str] | None = None
    joern_server: Any | None = None  # pre-started server; caller owns lifecycle
    study_root: Path | None = None  # full source root for study loop (when target_path is an excerpt)
    mode: ReviewMode = ReviewMode.SECURITY
    project_sinks: frozenset | None = None  # IRIS-derived sink names for wrapper pre-filter
    # The LLM client whose cost cap governs this run (core.llm.client.
    # LLMClient). Used ONLY for budget introspection: loop drivers poll
    # ``is_budget_exhausted()`` before expensive per-function prep, and
    # ``_check_budget`` consults its ledger — which, unlike
    # ``result.total_cost_usd``, includes spend from failed/timed-out
    # attempts that never produced an outcome.
    llm_budget_client: Any | None = None
    # The LLM client the executor's batch-glance dispatch uses to send
    # ten GLANCE-tier functions in ONE call (see
    # executor._get_batch_review_fn / batch_glance.make_batch_review_fn).
    # None disables batching (every glance falls back to an individual
    # review call). Distinct from ``llm_budget_client`` in ROLE only —
    # the pipeline wires the same client instance into both.
    llm_client: Any | None = None
    # Cross-run verdict reuse: when True (default), prior-run journal
    # entries whose source_hash still matches the current source are
    # imported as $0 ``reused`` outcomes instead of being silently
    # suppressed (findings re-enter mechanical sweeps). False
    # (--no-verdict-reuse) restores the plain hash-aware fold:
    # unchanged reviewed functions are suppressed, nothing imported.
    # ``force=True`` bypasses both (everything re-reviews).
    verdict_reuse: bool = True
    # Cross-function edge obligations (--edges, flag-gated until the
    # CopyFail/DirtyFrag validation bar passes): scope tier-1/tier-2
    # edge obligations from the checklist adjacency + context-map,
    # review tier-1 edges as dedicated contract units before the
    # function loop, and fold tier-2 edge contracts into caller
    # reviews. Default off.
    edges: bool = False
    # Set by the end-of-run corrective passes: once final statuses are
    # re-journaled/re-logged, any straggler commit (an abandoned study
    # re-review finishing after the drain gave up on it) must not
    # append — it would land after the corrective rows and win the
    # last-row-wins read with a verdict the export never saw.
    _verdicts_finalized: bool = False
    # ── Accumulated-knowledge gates ────────────────────────────────
    # Every gate below defaults ON — today's production behaviour.
    # The corpus runner's cold profile turns them off so a
    # measurement run sees exactly what a first-time user with
    # default flags and cold caches would see; nothing outside the
    # run's own target and out_dir feeds the verdicts. Each disabled
    # gate logs one INFO line at run start (see _apply_profile_gates)
    # so runs are self-describing.
    #
    # Profile label stamped into those log lines. Informational only;
    # no behaviour keys off the string.
    profile: str = "deployed"
    # IRIS: taint-spec synthesis, project-sink store reads, the
    # refinement loop (including its prior_specs store reads), and
    # the heuristic assumption/bypass passes.
    iris: bool = True
    # SAGE recall READS: prior hypothesis-verdict recall, prior-run
    # observation seeding, and SAGE-recalled proven-rule replay in
    # checker synthesis. SAGE writes are unaffected.
    sage_recall: bool = True
    # Graduated-rule library replay (RuleLibrary.find_replayable) in
    # checker synthesis. In-run on-demand synthesis, library writes,
    # and graduation stay on.
    library_replay: bool = True
    # Cross-run journal reads: the verdict-reuse import eligibility
    # AND the sibling-run / project-index sources feeding external
    # checker-synthesis seeds. The run's OWN journal stays readable.
    cross_run_import: bool = True
    # Prior domain-model import: when False, domain-model loads see
    # only THIS run's out_dir (the in-run study pass still writes and
    # re-reads its fresh model there); a project-level
    # domain-model.json from an earlier /understand --study run is
    # not imported.
    domain_model_import: bool = True
    # Operator annotation reads (review-context assembly, the
    # stale-annotation merge, fp-feedback). When False the project
    # resolve fallback is suppressed and annotations_dir is cleared
    # at run start.
    annotations_read: bool = True
    # Opt-in (--pre-scan): when NO scan SARIF exists — neither this
    # run's scan/ dir nor any fresh sibling run — run one bounded
    # semgrep baseline pass over the scoped target with RAPTOR's
    # local rule library, so the SARIF corroboration channels have
    # something to corroborate against.
    pre_scan: bool = False
    # Caller-contract call-site digest in the review context for
    # teardown-named / pointer-param-dealloc functions
    # (--no-caller-contract-context to disable).  Context-only channel:
    # it never stamps evidence_tool and never touches verdict lanes.
    caller_contract_context: bool = True
    # Post-review caller-contract confidence demotion
    # (--no-caller-contract-demotion to disable): a caller-obligation
    # hypothesis mechanically refuted at EVERY in-repo call site
    # (structural receipts, enumeration verified complete) exports at
    # confidence=low with receipts.  Never suppresses (status
    # untouched, finding still exported); never touches
    # tool-confirmed outcomes.
    caller_contract_demotion: bool = True
    # Review scheduling with >1 worker: "cost" (default) dispatches
    # predicted-longest reviews first (LPT makespan packing);
    # "priority" keeps the highest-priority-first order (better
    # time-to-first-finding). Serial runs always use priority order.
    schedule: str = "cost"
    # Outcome-level post-processing hooks — ``hook(result, config)`` —
    # invoked after resolution but BEFORE the journal correction pass
    # and the graded findings export, so any status change they make
    # is reflected consistently in journal, export, and summary
    # counters (e.g. the ensemble pipeline's file-pile-up dampener).
    pre_export_hooks: list | None = None
    # Monotonic deadline for the run (start + max_seconds), stamped by
    # ``run_orchestrator``. Verification tools with long per-query
    # timeouts (Joern) clamp to the remaining budget so one stuck
    # query can't hold a worker past the run's end.
    run_deadline_monotonic: float | None = None
    # On-demand Mode-2 checker synthesis for chain-less hypotheses:
    # when a suspicious outcome's (possibly inferred) CWE yields no
    # tool-chain entry and no cheap channel binds the hypothesis, a
    # one-off negatively-controlled rule is synthesized and run instead
    # of letting the hypothesis die untested. Opt-out
    # (--no-on-demand-synthesis); capped per run
    # (checker_synthesis.MAX_ONDEMAND_SYNTHESIS_PER_RUN).
    on_demand_synthesis: bool = True
    # Determine-value compile probes (--probe-determine-value):
    # bisection over static assertions resolves "what is the value of
    # X?" study questions. Default OFF — up to ~66 sandboxed compiles
    # per constant (question cap: compile_probe._DEFAULT_DETERMINE_CAP
    # per run).
    probe_determine_value: bool = False
    # Per-model review functions for cross-model panels. Built by the
    # pipeline (one make_review_fn per configured model) when
    # ``len(models) > 1``. The multi-model dispatch in
    # ``_multi_pass_review`` looks the panel handle's effective model
    # up here — without this map every "panel member" silently called
    # the single review_fn pinned to models[0] and model B was never
    # invoked at all.
    review_fns_by_model: dict[str, Callable] | None = None
    # Same-run resume (``raptor-audit resume <out-dir>``): fold this
    # run's OWN journal hash-aware into the reuse candidates (a $0
    # re-import per prior-segment verdict) instead of the blanket
    # already-reviewed suppression, and bypass the reuse importer's
    # own-journal idempotence guard. See core.audit.resume.
    same_run_reuse: bool = False
    # Prior segments' reconciled ledger (cost-breakdown.json contents
    # loaded by the resume CLI). Booked into the cost tracker as a
    # ``prior_segments`` phase at reconciliation so the end-of-run
    # ledger covers ALL segments while this process's budget client
    # only ever sees the remaining cap.
    prior_cost_breakdown: dict[str, Any] | None = None
    # RESOLVED whole-run prior-segment spend from the resume CLI
    # (core.audit.resume.resolve_prior_spend): reconciled ledger, else
    # journal per-entry floor, raised to the incremental spend floor.
    # Authoritative over ``prior_cost_breakdown`` for the amount
    # booked — a segment whose predecessor died UNRECONCILED has no
    # prior ledger dict, and booking only the dict used to drop every
    # segment before the immediately-prior one from the ledger chain.
    prior_booked_spend_usd: float = 0.0
    # 1 for a first run; the segment number stamped by
    # core.run.metadata.resume_run for resumed segments.
    resume_segment: int = 1
    # Extra run dirs whose review journals feed prior FINDING-GRADE
    # claims (/agentic per-finding analyses) into review context
    # (``--prior-journal``, repeatable). The project index is always
    # consulted; this covers journals not yet merged into it — the
    # /agentic post-pass launches the audit BEFORE the parent run
    # completes (the lifecycle merge happens at completion).
    prior_journal_dirs: list[Path] | None = None
    # Derived at run start (never set by callers): ``file:function`` →
    # newest-first finding-grade journal entries, consumed by
    # ``_build_context`` as prior claims. Kind-gated OUT of coverage
    # by the gap fold; kind-gated INTO the prompt here.
    prior_finding_analyses: dict[str, list] | None = None
    # Newest-first cap on prior finding-grade claims per function
    # (``--prior-claims``; 0 disables the injection entirely) and the
    # per-claim body excerpt length. Defaults are starting points, not
    # measured optima — tune per target density.
    prior_claims_per_function: int = 3
    prior_claim_excerpt_chars: int = 600


@dataclass
class ReviewOutcome:
    """Result of reviewing a single function."""

    file: str
    function: str
    status: str
    body: str
    # Receiver-qualified name (``Class.method`` / Go ``Receiver.Method``)
    # when the inventory metadata carries one — stamped at the commit
    # chokepoint from ``gap["qualified_name"]``. Presentation and
    # report-join identity only; ``function`` stays the bare inventory
    # name every call-graph/coverage key is built from.
    function_qualified: str = ""
    hypothesis: str = ""
    hypotheses: list[dict[str, Any]] | None = None
    evidence_tool: str = ""
    cost_usd: float = 0.0
    model: str = ""
    duration_s: float = 0.0
    # Token usage of the review call(s) behind this outcome, when the
    # transport surfaces it. Feeds cost-breakdown.json's per-phase
    # token columns (previously always 0 on the claudecode transport)
    # and the prompt-cache hit-rate measurement.
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    review_result: dict[str, Any] | None = None
    line: int = 0
    error_class: str = ""
    # True when this verdict was produced by the reduced-context
    # timeout retry (block analysis / sibling / type-constraint
    # context stripped). Deepen re-reviews such outcomes at full
    # context.
    context_reduced: bool = False
    # True when this verdict was imported from a prior run's journal
    # entry (matching source hash) instead of a live review.
    # ``reused_from_run`` names the ORIGINAL producing run.
    reused: bool = False
    reused_from_run: str = ""
    verification_tier: str = "speculative"
    tools_dispatched: set | None = field(default=None, repr=False)
    # Chain step types that errored or timed out while verifying THIS
    # function. A channel that errored did not meaningfully run — the
    # gate-resolution pass must not count it as class coverage (a
    # Joern query timeout is a failure, not a refutation).
    tools_errored: set | None = field(default=None, repr=False)
    semantic_confidence: str = ""
    provenance_all_trusted: bool = False
    caller_attributed: bool = False
    attributed_caller: str = ""
    _propagated: bool = field(default=False, repr=False)

    _CONFIRMED_EVIDENCE = frozenset({
        "dark_verify:confirmed", "dynamic:crash", "frida:runtime",
        "validate:observed_runtime", "validate:replayed_crash",
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
        tools = et_lower.split("+")
        if any(t.strip() in self._CONFIRMED_EVIDENCE for t in tools):
            return VerificationTier.CONFIRMED.value
        if any(t.strip().endswith(":witness") for t in tools):
            return VerificationTier.CONFIRMED.value

        from .evidence_grade import _PROVENANCE_WRAPPERS, is_tool_evidence
        if not is_tool_evidence(self.evidence_tool):
            # Detection-role receipts corroborate but may not convict:
            # a stamp the evidence-grade firewall rejects must not
            # export tool_backed just because its tool namespace was
            # dispatched.  (Instrumented corpus: 136/137 tool_backed
            # findings disproven; the dominant stamps were
            # detection-role smt:check-* variants.)
            return VerificationTier.LLM_ONLY.value

        first_tool = et_lower.split("+")[0].strip()
        for _wrapper in _PROVENANCE_WRAPPERS:
            if first_tool.startswith(_wrapper):
                # Provenance wrapper (e.g. ``clean-refuted:smt``): the
                # wrapped stamp names the tool that actually ran.
                first_tool = first_tool[len(_wrapper):]
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


def _make_tier_counters() -> dict[str, TierCounters]:
    return {
        "prefilter": TierCounters(),
        "sink_unreach": TierCounters(),
        "taint_approx": TierCounters(),
        "taint_summary": TierCounters(),
        "llm_summary": TierCounters(),
        "semgrep": TierCounters(),
        "joern": TierCounters(),
        "codeql": TierCounters(),
        "codeql_smt_prune": TierCounters(),
        "coccinelle": TierCounters(),
        "smt": TierCounters(),
        "smt_invariant": TierCounters(),
        "api_boundary": TierCounters(),
        "fail_open": TierCounters(),
        "consistency": TierCounters(),
        "resource_bounds": TierCounters(),
        "release_order": TierCounters(),
        "protocol_state": TierCounters(),
        "compiler": TierCounters(),
        "refuted_sweep": TierCounters(),
        "adversarial_refute": TierCounters(),
        "cwe_inference": TierCounters(),
        "precondition_promotion": TierCounters(),
        "synthesis_on_demand": TierCounters(),
        "adapter_aggregation": TierCounters(),
        "secondary_sweep": TierCounters(),
        "sweep_validate": TierCounters(),
        "primary_sweep": TierCounters(),
        "lifecycle": TierCounters(),
        "triage_skip": TierCounters(),
        "joern_guard": TierCounters(),
        "joern_flow": TierCounters(),
        "coccinelle_flow": TierCounters(),
        "joern_dominance": TierCounters(),
        "ptr_lifecycle": TierCounters(),
        "lock_region": TierCounters(),
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
    # Prior-run verdicts imported via cross-run verdict reuse (source
    # hash unchanged). Counted separately from ``reviewed`` — no LLM
    # call happened for them this run.
    reused_from_prior: int = 0
    # Hash-verified prior verdicts the reuse eligibility screen
    # refused, counted per reason class (context_reduced /
    # model_changed / strategy_changed / domain_model_context). The
    # run summary prints the split so a re-review storm names its
    # driver.
    reuse_blocked_reasons: dict[str, int] = field(default_factory=dict)
    # Post-loop mechanical journal entries (taint-spec / negative-space
    # / postcondition checks appended after the review loop). Counted
    # separately from ``reviewed``: no LLM call happened for them, but
    # they DO appear in the review journal — so the report's
    # journal-derived counts include them. Surfacing this figure lets
    # every summary state one counting rule ("N reviewed, +M mechanical
    # post-loop") instead of two surfaces silently disagreeing.
    post_loop_mechanical: int = 0
    # Spend attributed to completed review calls (outcome-carrying).
    total_cost_usd: float = 0.0
    # Spend consumed by attempts that raised (timeouts, retries, budget
    # kills) — no outcome carries it, but the LLM client billed it.
    failed_attempts_cost_usd: float = 0.0
    # Authoritative end-of-run LLM-client ledger (0.0 when the run had
    # no budget client). Includes BOTH of the above plus anything the
    # phase ledgers missed; the operator-facing "Cost:" line uses this.
    llm_spend_usd: float = 0.0
    total_duration_s: float = 0.0
    terminated_by: str = "complete"
    prefilter_skipped: int = 0
    prefilter_hits: int = 0
    # Vendored/generated triage decisions (run-summary counters;
    # per-function records live in suppressions.jsonl).
    vendored_skipped: int = 0
    vendored_glanced: int = 0
    sweep_validated: int = 0
    sweep_demoted: int = 0
    sweep_promoted: int = 0
    # Self-refuted hypotheses that a mechanical tool subsequently
    # confirmed (clean → suspicious promotions with a tool receipt).
    refuted_rescued: int = 0
    # Suspicious outcomes whose LLM-stated preconditions ALL verified
    # mechanically in the vulnerability-supporting direction
    # (suspicious → finding promotions with a precondition receipt).
    precondition_promoted: int = 0
    synthesis_amplified: int = 0
    # On-demand synthesis attempts for chain-less suspicious hypotheses
    # (each attempt costs an LLM call; capped per run).
    ondemand_synthesized: int = 0
    # Promotions earned by Bayesian aggregation of independent
    # detection-role channels (no single receipt was high-precision,
    # but the combined posterior crossed the promote threshold).
    aggregation_promoted: int = 0
    # Glance-suspicious outcomes escalated to a full individual review
    # instead of committing the 500-token guess (capped per run).
    glance_escalated: int = 0
    # Non-primary medium/high-confidence hypotheses that a mechanical
    # tool confirmed (secondary-hypothesis dispatch lane).
    secondary_confirmed: int = 0
    # Positive outcomes demoted by the adversarial refuter pass
    # (--adversarial): the refuter named a defeating mechanism and no
    # tool receipt overturned it.
    adversarial_refuted: int = 0
    # Positive outcomes the refuter attacked and could not defeat.
    adversarial_stands: int = 0
    refinement_rounds: int = 0
    clean_checks: int = 0
    clean_check_rescues: int = 0
    sarif_clean_resolved: int = 0
    outcomes: list[ReviewOutcome] = field(default_factory=list)
    # Structured prefilter/triage kill records (see
    # core.audit.prefilter_ledger) — written to prefilter-kills.jsonl
    # with sampled compiler-analyzer corroboration at end of run.
    prefilter_kills: list = field(default_factory=list)
    dormant: int = 0
    error_counts: dict[str, int] = field(default_factory=dict)
    error_retries: int = 0
    error_retry_recovered: int = 0
    # Phases that ABORTED on persistent auth-layer refusal (see
    # _record_phase_abort): "<phase>: <error>" strings. Also persisted
    # to <out_dir>/phase-aborts.json so audit-report.json (rebuilt
    # from the out_dir) surfaces them to downstream consumers — a
    # phase in this list produced NO trustworthy output, which is
    # different from a phase that ran and found nothing.
    phase_aborts: list[str] = field(default_factory=list)
    tier_counters: dict[str, TierCounters] = field(
        default_factory=_make_tier_counters,
    )
    cost_tracker: PhaseCostLedger = field(default_factory=PhaseCostLedger)
    _lock: _threading.Lock = field(
        default_factory=_threading.Lock,
        repr=False,
    )


class _LockedOutcomes:
    """Thread-safe dict-like for reviewed_outcomes shared across workers."""

    __slots__ = ("_data", "_lock")

    def __init__(self) -> None:
        self._data: dict[str, ReviewOutcome] = {}
        self._lock = _threading.Lock()

    def __setitem__(self, key: str, value: ReviewOutcome) -> None:
        with self._lock:
            self._data[key] = value

    def __getitem__(self, key: str) -> ReviewOutcome:
        with self._lock:
            return self._data[key]

    def get(self, key: str) -> ReviewOutcome | None:
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


def _get_dangerous_flows(approx) -> dict | None:
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


def _taint_approx_has_flow(approx) -> bool:
    """True when a taint approximation carries any dangerous or direct
    flow.  Like ``_get_dangerous_flows``, handles both ``TaintApprox``
    objects and the plain dicts the cache round-trips through JSON on
    resumed runs.
    """
    if approx is None:
        return False
    if isinstance(approx, dict):
        return bool(
            approx.get("dangerous_flows") or approx.get("direct_flows")
        )
    return bool(
        getattr(approx, "has_any_dangerous_flow", lambda: False)()
        or getattr(approx, "direct_flows", None)
    )


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
            if entry.get("edge_callee"):
                # Edge-contract records review one outgoing EDGE, not
                # the caller function — they must never suppress the
                # caller's own function review.
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


def _fn_filter_match(gap: dict[str, Any], fn_filter: tuple) -> bool:
    """True when *gap* matches a ``--functions`` spec.

    Specs are ``file:name`` (simple) or ``file:name:line`` (line-scoped,
    matched with ``_line_near``'s tolerance). Class-qualified specs
    (``file:Class.method``) match through the gap's ``class_name``
    metadata.
    """
    simple, lined = fn_filter
    key = f"{gap['file']}:{gap['name']}"
    line = gap.get("line_start", 0)
    meta = gap.get("metadata") or {}
    cls = meta.get("class_name")
    qual_key = f"{gap['file']}:{cls}.{gap['name']}" if cls else key
    if key in simple or qual_key in simple:
        return True
    return (
        _line_near(line, lined.get(key, set()))
        or _line_near(line, lined.get(qual_key, set()))
    )


def _fn_filter_keep(gap: dict[str, Any], fn_filter: tuple) -> bool:
    """True when the ``--functions`` filter keeps *gap* for review.

    Pinned gaps are always kept: an operator pin is an explicit review
    order, and pins carry no line number — a spec whose line number has
    drifted from the current source must not silently drop the pinned
    function. (Observed: a calibration run where the ±3 line tolerance
    dropped every pinned label from the workqueue, so none of them was
    ever reviewed.)
    """
    if gap.get("pinned"):
        return True
    return _fn_filter_match(gap, fn_filter)


# Accumulated-knowledge gates: (config field, log label). Order is
# the log order at run start.
_KNOWLEDGE_GATES = (
    ("iris", "iris"),
    ("sage_recall", "sage recall"),
    ("library_replay", "graduated-rule library replay"),
    ("cross_run_import", "cross-run journal import"),
    ("domain_model_import", "prior domain-model import"),
    ("annotations_read", "annotations read"),
)


def _apply_profile_gates(config: OrchestratorConfig) -> None:
    """Log one INFO line per disabled accumulated-knowledge gate and
    normalize dependent config.

    Runs once at run start so a cold-profile run is self-describing
    in its log. ``annotations_read=False`` also clears
    ``annotations_dir`` here — every downstream consumer reads that
    field directly, so clearing it at the source covers them all
    (the resolve fallback is gated separately at its two seams).
    """
    profile = getattr(config, "profile", "deployed") or "deployed"
    for field_name, label in _KNOWLEDGE_GATES:
        if not getattr(config, field_name, True):
            logger.info("profile=%s: %s disabled", profile, label)
    if not getattr(config, "annotations_read", True):
        config.annotations_dir = None


def _load_domain_model(config: OrchestratorConfig):
    """Domain-model read chokepoint honouring ``domain_model_import``.

    Gate on (default): the standard search — this run's out_dir, then
    the project-level ``concepts/domain-model.json`` locations a prior
    /understand --study run may have produced. Gate off: only the
    run's own out_dir, so the in-run study pass's fresh model is
    still picked up but nothing pre-existing is imported.
    """
    from .journal import load_domain_model
    return load_domain_model(
        config.out_dir,
        run_only=not getattr(config, "domain_model_import", True),
    )


def _annotations_dir(config: OrchestratorConfig):
    """Annotations-read chokepoint for the resolve-fallback seams."""
    if not getattr(config, "annotations_read", True):
        return None
    return config.annotations_dir or _resolve_ann_dir(config.out_dir)


def run_orchestrator(
    config: OrchestratorConfig,
    review_fn: Callable[[dict[str, Any], OrchestratorConfig], ReviewOutcome],
    *,
    on_progress: Callable[[int, int, ReviewOutcome], None] | None = None,
    prep_cache: dict | None = None,
) -> OrchestratorResult:
    """Run the orchestrator loop.

    Args:
        config: Run configuration.
        review_fn: Called for each function. Takes (context_dict, config)
            and returns a ReviewOutcome. This is where the LLM call happens.
            The orchestrator is agnostic to HOW the LLM is called — the
            consumer provides the implementation.
        on_progress: Optional callback (current_idx, total, outcome).
        prep_cache: Shared dict for ensemble (multi-model) runs: the
            first pass stores its prep result and coordination keys
            (``_lock``/``_event``/``_ready``) here for later passes to
            reuse, and ``_caches_cleared`` gates the per-run module
            cache / shutdown-state reset to once per shared dict.

    Returns:
        OrchestratorResult summarizing the run.
    """
    start_time = time.monotonic()

    # Accumulated-knowledge gate banner + config normalization (one
    # INFO line per disabled gate; clears annotations_dir when
    # annotation reads are off).
    _apply_profile_gates(config)

    # CodeQL database routing: normalise the single-path and
    # multi-path config fields into one router. Per-function dispatch
    # goes through _codeql_db_for (language match on multi-database
    # runs); single-database consumers (IRIS runner, capability flag)
    # read config.codeql_db_path, which becomes the router's primary.
    from .codeql_dbs import CodeqlDbRouter
    config.codeql_db_router = CodeqlDbRouter(
        config.codeql_db_paths
        or ([config.codeql_db_path] if config.codeql_db_path else []),
    )
    config.codeql_db_paths = config.codeql_db_router.paths or None
    config.codeql_db_path = config.codeql_db_router.primary

    # Reset per-run shutdown state BEFORE installing the handler (see
    # _reset_shutdown_state): a prior in-process run's stop request or
    # first-TERM count must not poison this run.
    if prep_cache is None or not prep_cache.get("_caches_cleared"):
        _reset_shutdown_state()

    # Graceful SIGTERM (main thread, once): drain + salvage instead of
    # dying mid-write when an external supervisor stops the run.
    install_sigterm_grace()
    if config.out_dir:
        _out_dir_for_term = Path(config.out_dir)

        def _mark_interrupted_on_forced_exit() -> None:
            # Forced-exit path only (watchdog expiry / second TERM) —
            # the graceful path lets the CLI record the lifecycle
            # transition. interrupt_run is terminal-guarded, so a
            # late double-mark is refused, not corrupting.
            from core.run.metadata import interrupt_run
            interrupt_run(
                _out_dir_for_term,
                "SIGTERM — forced exit before salvage completed",
            )

        _sigterm_flush_hooks.append(_mark_interrupted_on_forced_exit)

    if prep_cache is None or not prep_cache.get("_caches_cleared"):
        _sink_guard_cache.clear()
        _file_lines_cache.clear()
        _parse_wrapper_cache.clear()
        # line_end values come from the run's inventory — stale bounds
        # from a previous in-process run mis-window the sweeps.
        _line_end_cache.clear()
        if prep_cache is not None:
            prep_cache["_caches_cleared"] = True

    # Warm the claudecode probe cache before any workers are derived
    # or dispatched — one tiny disk-cached call resolving the
    # backend's real model identity. Best-effort and non-fatal; the
    # helper itself guards against pytest and non-claudecode primaries.
    from core.llm.concurrency import warm_claudecode_probe
    warm_claudecode_probe()

    # Stamp the run deadline so long-timeout verification tools
    # (Joern) can clamp per-query timeouts to the remaining budget.
    if config.max_seconds:
        config.run_deadline_monotonic = start_time + config.max_seconds

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
    elif config.target_path.is_file():
        # Binary target: Joern builds CPGs from source trees — a
        # compiled artifact has nothing for it to parse.
        joern_server = None
        _joern_lifecycle = False
    else:
        _joern_path = _joern_target(config)
        joern_server = _start_joern_server_raw(
            _joern_path, config.joern_overrides, _jt,
            # Keep an in-target run output dir out of the CPG content
            # key and graph — its artifacts change every segment, and
            # a flapping key re-buys a full CPG rebuild per resume.
            exclude_dirs=_run_exclude_dirs(
                config.out_dir, _joern_path,
            ),
        )
        _joern_lifecycle = (
            joern_server is not None
            and hasattr(joern_server, "_proc")
            and joern_server._proc is None
        )
    # Per-call LLM telemetry: one JSONL record per provider round-trip
    # (call class, duration, tokens, cache read/write counters,
    # timeout/retry disposition) in the run directory. Diagnostics
    # only — installation failure must never block the run.
    _telemetry_sink = None
    try:
        from core.llm.telemetry import TELEMETRY_FILENAME, TelemetrySink, set_sink
        if config.out_dir:
            _telemetry_sink = TelemetrySink(
                Path(config.out_dir) / TELEMETRY_FILENAME,
            )
            set_sink(_telemetry_sink)
    except Exception:
        logger.debug("llm telemetry sink install failed", exc_info=True)

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
        # This run's flush hooks must not outlive it (a later run in
        # the same process registers its own).
        _sigterm_flush_hooks.clear()
        if _telemetry_sink is not None:
            try:
                from core.llm.telemetry import set_sink
                set_sink(None)
                if _telemetry_sink.total_records:
                    logger.info(_telemetry_sink.summary_line())
            except Exception:
                logger.debug(
                    "llm telemetry summary failed", exc_info=True,
                )
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


# (target_path, library) → detected version or None. Manifest parsing
# is cheap but runs per callee lookup; memoised for the process. Racy
# double-computes are benign (same deterministic value).
_target_lib_version_memo: dict[tuple[str, str], str | None] = {}


def _target_library_version(target_path, library: str) -> str | None:
    """Version of *library* the target verifiably depends on, or None.

    Backed by ``summary_cache.detect_library_version`` (dependency
    manifest parsing). None means the target's manifests do not name
    the library — cached cross-library summaries must then not attach
    as evidence for this target's callees.
    """
    key = (str(target_path), library)
    if key not in _target_lib_version_memo:
        try:
            from .summary_cache import detect_library_version

            _target_lib_version_memo[key] = detect_library_version(
                Path(target_path), library,
            )
        except Exception:  # noqa: BLE001 — no detection, no attachment
            _target_lib_version_memo[key] = None
    return _target_lib_version_memo[key]


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
    start_time: float=0.0,
    layer_disagreements=None,
    on_progress=None,
    review_idx: int=0,
    total: int=0,
    collector=None,
    graph=None,
    reviewed_outcomes=None,
):
    """Review a single function gap and return the outcome.

    Extracted from the main loop in ``_run_audit_body`` so that the executor
    can drive the loop (serial or parallel) while the per-function logic
    lives in one place.

    Raises ``LLMBudgetExceededError`` (a ``RuntimeError`` whose message
    contains "budget exceeded") when the LLM client exhausts its cost
    cap — the caller is expected to catch this and break the loop.
    """
    from core.llm.client import LLMBudgetExceededError

    from .negative_space import check_negative_space

    # ── Budget gate BEFORE any per-function prep ──────────────────────
    # Block-level CFG analysis, context assembly, prefilter and sibling
    # analysis are expensive (observed ~minutes per complex function).
    # Once the LLM budget is exhausted the review call below can only
    # fail, so paying that prep cost is pure waste — bail out first.
    _budget_client = getattr(config, "llm_budget_client", None)
    if _budget_client is not None and _budget_client.is_budget_exhausted():
        msg = (
            f"LLM budget exceeded before reviewing "
            f"{gap['file']}:{gap['name']} — skipping prep and stopping"
        )
        raise LLMBudgetExceededError(msg)

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
    if (
        triage is not None
        and triage.bucket == TriageBucket.SKIP
        and not getattr(config, "triage", True)
    ):
        # Triage-classifier skips disabled for this run: fall through
        # to a real review instead of recording a classifier clean.
        triage = None
    if (
        triage
        and triage.bucket == TriageBucket.SKIP
        and gap.get("pinned")
        and not gap.get("force_review")
    ):
        # An operator pin is an explicit review order — it bypasses
        # triage skips entirely. Loud: the operator asked for this
        # function by name; silently recording a classifier skip as
        # "clean" is how a pinned real finding got dropped.
        logger.warning(
            "--pin override: %s:%s was triage-SKIP (%s) — operator pin "
            "forces LLM review",
            gap["file"], gap["name"], ", ".join(triage.reasons),
        )
        triage = None
    if triage and triage.bucket == TriageBucket.SKIP and not gap.get("force_review"):
        _increment_tier(result, "triage_skip", "confirmed")
        # Oracle-earned skips are dead code, not reviewed-clean: the
        # compiler removed the function from every analysed binary.
        _oracle_skip = any(
            "binary_oracle_absent" in r for r in triage.reasons
        )
        outcome = ReviewOutcome(
            file=gap["file"],
            function=gap["name"],
            status="dormant" if _oracle_skip else "clean",
            body=(
                f"[triage: {', '.join(triage.reasons)}] "
                + (
                    "Binary oracle: absent from every analysed binary "
                    "— skipped without spending hypothesis budget."
                    if _oracle_skip else
                    "Triage classifier determined this function "
                    "does not need LLM review."
                )
            ),
            evidence_tool=(
                "reachability:binary_oracle_absent" if _oracle_skip
                else "triage:classifier"
            ),
        )
        outcome.line = gap.get("line_start", 0)
        with result._lock:
            result.prefilter_skipped += 1
        try:
            from .prefilter_ledger import GATE_TRIAGE_SKIP, make_kill_record

            with result._lock:
                result.prefilter_kills.append(make_kill_record(
                    file=gap["file"],
                    function=gap["name"],
                    gate=GATE_TRIAGE_SKIP,
                    reason=", ".join(triage.reasons),
                    sloc=gap.get("sloc", 0),
                    line_start=gap.get("line_start", 0),
                    line_end=gap.get("line_end", 0),
                ))
        except Exception:
            logger.debug("triage kill record failed", exc_info=True)
        try:
            if collector is not None:
                collector.submit(outcome, gap)
            else:
                _commit_outcome(config, outcome, gap)
        except Exception as exc:  # noqa: BLE001
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
        if _dead_reason.startswith("binary_oracle_absent") and config.out_dir:
            # Best-effort audit trail; record_suppression self-handles
            # IO — only path-level OSErrors can legitimately escape.
            with contextlib.suppress(OSError):
                from core.analysis.reach_chokepoint import record_suppression

                record_suppression(
                    config.out_dir,
                    finding={
                        "finding_id": (
                            f"audit-deadcode:{gap_key}:"
                            f"{gap.get('line_start', 0)}"
                        ),
                        "rule_id": "audit:dead-code-gate",
                        "file_path": gap["file"],
                        "line": gap.get("line_start", 0),
                        "function": gap["name"],
                    },
                    verdict="binary_oracle_absent",
                    reason=(
                        "dead-code gate (G7): function absent from the "
                        "compiled binary — LLM review skipped"
                    ),
                    dropped=False,
                    extra={"stage": "dead-code-gate"},
                )
        try:
            if collector is not None:
                collector.submit(outcome, gap)
            else:
                _commit_outcome(config, outcome, gap)
        except Exception as exc:  # noqa: BLE001
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
    # hash_span self-handles unreadable files; only path-level OSErrors
    # can legitimately escape.
    with contextlib.suppress(OSError):
        from core.sage.hooks import compute_finding_source_hash

        line_start = gap.get("line_start", 0)
        if line_start:
            # Whole-function span: the gap carries the function bounds,
            # so hash line_start..line_end rather than a ±10 window —
            # a change anywhere in the function invalidates the prior
            # verdict (compute_finding_source_hash also folds in the
            # full file content).
            src_hash = compute_finding_source_hash(
                config.target_path / gap["file"],
                line_start,
                line_end=gap.get("line_end") or None,
            )
            if src_hash:
                gap["_sage_source_hash"] = src_hash

    # ── SAGE: recall prior hypothesis verdict → skip if clean/dormant ─
    # Gated by ``config.sage_recall`` (cold-profile corpus runs) on
    # top of the force/force_review bypasses.
    if (
        getattr(config, "sage_recall", True)
        and not config.force
        and not gap.get("force_review")
        and gap.get("_sage_source_hash")
    ):
        try:
            from core.sage.hooks import recall_audit_hypothesis_verdict

            prior = recall_audit_hypothesis_verdict(
                repo_path=str(config.target_path),
                file_path=gap["file"],
                function=gap["name"],
                source_hash=gap["_sage_source_hash"],
            )
        except Exception:  # noqa: BLE001
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
            except Exception as exc:  # noqa: BLE001
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

    # Consistency-census leads seeded onto the gap by the prep phase
    # (gap-extra-key pattern; renderer caps + envelopes them).
    if gap.get("consistency_leads"):
        ctx["consistency_leads"] = list(gap["consistency_leads"])

    # Fail-open census leads (same pattern): the renderer turns each
    # into a hypothesize-or-discharge obligation.
    if gap.get("fail_open_leads"):
        ctx["fail_open_leads"] = list(gap["fail_open_leads"])

    # --- Mechanical gates: per-function context enrichment ---
    if provenance_map and gap_key_mech in provenance_map:
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .mechanical_gates import format_provenance_for_context

            ctx["entry_point_provenance"] = format_provenance_for_context(
                provenance_map[gap_key_mech],
            )

    if gap_key_mech in security_decision_keys:
        ctx["is_security_decision"] = True
    if gap_key_mech in feeds_security_keys:
        ctx["feeds_security_decision"] = True

    if ctx.get("source") and gap.get("file", "").endswith(".py"):
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .mechanical_gates import detect_constant_dangerous_calls

            const_calls = detect_constant_dangerous_calls(
                ctx["source"],
                gap["file"],
            )
            if const_calls:
                ctx["constant_dangerous_calls"] = const_calls

    if ctx.get("callers"):
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .mechanical_gates import sort_callers_by_constraint

            ctx["callers"] = sort_callers_by_constraint(ctx["callers"])

    if ctx.get("source"):
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .mechanical_gates import extract_type_constraints

            tc = extract_type_constraints(
                ctx["source"],
                gap.get("file", ""),
                gap.get("name", ""),
            )
            if tc:
                ctx["type_constraints"] = tc

    with contextlib.suppress(*_ENRICH_ERRORS):
        from .condition_cpg import check_interprocedural_guards

        ipc_result = check_interprocedural_guards(
            gap.get("name", ""),
            gap["file"],
            joern_server=joern_server,
        )
        if ipc_result.unguarded_callers > 0:
            ctx["interprocedural_guards"] = ipc_result.to_dict()

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
                    # Dependency-context gate: a bare function-name
                    # match in SOME cached library says nothing about
                    # THIS target's callee unless the target verifiably
                    # depends on that library at that version — the
                    # first-match-wins scan attached whichever cached
                    # library happened to share the name, and its
                    # contracts then drove contract-violation evidence.
                    if _target_library_version(
                        config.target_path, lib_info["library"],
                    ) != lib_info["version"]:
                        continue
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
            from .contracts import enforce_callee_contracts, extract_callee_contracts

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
            census=getattr(shared, "consistency_census", None),
        )
        if spec and spec.intent:
            ctx["inferred_spec"] = spec
            if spec.preconditions and ctx.get("source"):
                try:
                    from .contracts import ContractContext, enforce_callee_contracts

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
                    client=getattr(config, "llm_budget_client", None),
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

    # Convention-independent structural checks (the asymmetry/race
    # shape is intra-function or intra-file), so they run even when no
    # project conventions were discovered. Findings ride the same
    # ctx["negative_space"] channel into the review prompt.
    auth_mode_findings: list = []
    try:
        from .negative_space import (
            check_auth_mode_registration,
            check_shared_writer_race,
            check_url_boundary_composition,
        )
        # ctx["source"] is the PROMPT rendering — every line carries a
        # "{n:4d}  " number prefix (context._read_source), which
        # defeats the structural checkers' line-start regexes: they
        # silently returned [] on it. Hand them the gap without the
        # rendered source so they read the raw span from disk.
        if gap.get("source"):
            _structural_gap = gap_with_source
        else:
            _structural_gap = {
                k: v for k, v in gap_with_source.items()
                if k != "source"
            }
        auth_mode_findings = check_auth_mode_registration(
            _structural_gap, domain_model=shared.domain_model,
            target_path=config.target_path,
        )
        auth_mode_findings.extend(
            check_url_boundary_composition(
                _structural_gap, target_path=config.target_path,
            ),
        )
        if gap.get("file", "").endswith(".go"):
            _swr_gap = dict(_structural_gap)
            with contextlib.suppress(OSError):
                _fp = config.target_path / gap.get("file", "")
                if _fp.is_file():
                    # Whole-file source: the receiver struct decl and
                    # method bodies live outside the function span.
                    _swr_gap["file_source"] = _fp.read_text(
                        errors="replace",
                    )
            auth_mode_findings.extend(
                check_shared_writer_race(
                    _swr_gap, target_path=config.target_path,
                ),
            )
    except Exception:
        logger.debug(
            "structural negative-space checks failed for %s:%s",
            gap.get("file"), gap.get("name"), exc_info=True,
        )
    if auth_mode_findings and not conventions:
        ctx["negative_space"] = (
            ctx.get("negative_space", []) + auth_mode_findings
        )

    if conventions:
        strategies = gap.get("strategies", set())
        if isinstance(strategies, (list, tuple)):
            strategies = set(strategies)
        ns_findings = list(auth_mode_findings)
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
            with contextlib.suppress(*_ENRICH_ERRORS):
                from .dispatch_table import format_displacement_context
                _dc = format_displacement_context(func_displacements)
                if _dc:
                    ctx["capability_displacement"] = _dc

    if shared.struct_accessor_index:
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .struct_accessor_index import (
                format_co_accessor_context,
                get_co_accessors,
            )
            co_groups = get_co_accessors(
                shared.struct_accessor_index, func_name, func_file,
            )
            _cac = format_co_accessor_context(co_groups)
            if _cac:
                ctx["co_accessor_analysis"] = _cac

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
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .fp_feedback import format_fp_warnings

            fp_warn = format_fp_warnings(fp_patterns, gap["file"])
            if fp_warn:
                ctx["fp_warnings"] = fp_warn
    if evidence_index:
        _vh_rec = evidence_index.get(gap_key)
        _vh_entry = (
            getattr(_vh_rec, "validate_history", None) if _vh_rec else None
        )
        if _vh_entry:
            with contextlib.suppress(*_ENRICH_ERRORS):
                from .validate_bridge import format_validate_history

                _vh_text = format_validate_history(_vh_entry)
                if _vh_text:
                    ctx["validate_history"] = _vh_text
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
        if pf_result.skip_llm and not getattr(config, "prefilter_skip", True):
            # Prefilter skips disabled for this run: fall through to a
            # real review instead of recording a mechanical clean. The
            # prefilter's hits (below) still feed review context.
            pf_result.skip_llm = False
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
                from .prefilter_ledger import (
                    gate_for_skip_reason,
                    make_kill_record,
                )

                with result._lock:
                    result.prefilter_kills.append(make_kill_record(
                        file=gap["file"],
                        function=gap["name"],
                        gate=gate_for_skip_reason(pf_result.skip_reason),
                        reason=pf_result.skip_reason,
                        language=pf_result.language,
                        sloc=pf_result.sloc,
                        line_start=gap.get("line_start", 0),
                        line_end=gap.get("line_end", 0),
                    ))
            except Exception:
                logger.debug("prefilter kill record failed", exc_info=True)
            try:
                if collector is not None:
                    collector.submit(outcome, gap)
                else:
                    _commit_outcome(config, outcome, gap)
            except Exception as exc:  # noqa: BLE001
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
            # Block analysis embeds repo-derived labels, variable
            # names, and source snippets and lands in the review
            # prompt as a priority-0 section — route it through the
            # same prompt-defence chokepoint as every other
            # repo-derived context block (sanitise + injection scan
            # feeding ctx['injection_warnings']).
            from .context import defend_repo_text
            ctx["block_analysis"] = defend_repo_text(
                ctx, block_ctx,
                location=f"{gap['file']}:{gap['name']} (block analysis)",
            )
    except Exception:
        logger.debug(
            "block-level analysis failed for %s:%s",
            gap["file"],
            gap["name"],
            exc_info=True,
        )

    # ── Intra-function sibling analysis ─────────────────────────────
    with contextlib.suppress(*_ENRICH_ERRORS):
        from .intra_function import (
            analyse_intra_function,
            format_intra_function_context,
        )
        _ifsa = analyse_intra_function(
            ctx.get("source", ""),
            domain_model=domain_model,
            target_path=Path(config.target_path)
            if getattr(config, "target_path", None) else None,
        )
        _ifsa_ctx = format_intra_function_context(_ifsa)
        if _ifsa_ctx:
            ctx["intra_function_analysis"] = _ifsa_ctx

    _fuse_all_evidence(ctx)

    # ── LLM review ────────────────────────────────────────────────────
    review_start = time.monotonic()
    # Failed attempts are counted (failed_calls) but carry NO per-call
    # cost figure: the old client-ledger before/after snapshot booked
    # every CONCURRENT worker's successful spend from the failure's
    # wall-clock window as this function's "failed-attempt cost" —
    # 8-way parallel runs multiply-booked the same money until the
    # summary ledger showed ~9x real spend and the cap tripped with
    # most of the budget unspent. Money genuinely consumed by failed
    # attempts stays on the LLM client's provider ledger and surfaces
    # once, at end-of-run reconciliation (_finalise_cost_ledger), as
    # the unattributed residual.

    # Cross-model panels (--model A --model B) must reach the
    # multi-model branch regardless of --review-passes: gating the
    # dispatch on review_passes > 1 alone meant the flagship
    # multi-model mode never invoked model B with the default single
    # pass.
    if config.review_passes > 1 or (
        config.multi_model and len(config.models) > 1
    ):
        outcome = _multi_pass_review(
            review_fn,
            ctx,
            config,
            max(config.review_passes, 1),
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
            from core.llm.client import is_budget_exceeded_error

            result.cost_tracker.record_failed_attempt(
                "review", cost_usd=0.0,
            )
            if is_budget_exceeded_error(exc):
                # Budget exhaustion is terminal for the run, not a
                # per-function error: re-raise so the executor stops
                # the loop. Crucially, do NOT journal an outcome — the
                # function stays unreviewed and gap-eligible for a
                # future run instead of being recorded as an "error"
                # review that never actually happened.
                raise
            logger.warning(
                "review_fn failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
            if _classify_error(exc) == "timeout" and not _check_budget(
                config, start_time, result,
            ):
                # First timeout for this function: one immediate
                # retry with reduced context and a capped timeout.
                outcome = _timeout_reduced_retry(
                    gap, ctx, exc, review_fn, config,
                )
            else:
                outcome = _error_outcome(gap, exc)

    outcome.line = gap.get("line_start", 0)
    result.cost_tracker.record_call(
        "review",
        cost_usd=outcome.cost_usd,
        tokens_in=getattr(outcome, "tokens_in", 0),
        tokens_out=getattr(outcome, "tokens_out", 0),
        cache_read_tokens=getattr(outcome, "cache_read_tokens", 0),
        cache_write_tokens=getattr(outcome, "cache_write_tokens", 0),
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
            from .refutation import diagnose_rescue, rescue_self_refuted

            # Raw disk span (not the prompt rendering): the gate's
            # race-protection acceptance needs lock-call syntax intact.
            _rescue_src = _read_raw_source(
                config.target_path,
                gap.get("file", ""),
                gap.get("line_start", 0),
                gap.get("line_end"),
            )
            rv = rescue_self_refuted(
                outcome,
                config=config,
                negative_space=ctx.get("negative_space"),
                source=_rescue_src or None,
                pre_evidence=gap.get("_smt_pre_evidence"),
                detector_findings=ctx.get("mechanical_detector_findings"),
                target_path=config.target_path,
                out_dir=config.out_dir,
                repo_trusted=config.repo_trusted,
            )
            if rv is None:
                # Durable receipt for the non-fire: when a structural
                # receipt exists on this function (or the reviewer
                # refuted a hypothesis), record which precondition
                # blocked the rescue so a miss is diagnosable from the
                # audit log instead of invisible.
                diag = diagnose_rescue(
                    outcome, negative_space=ctx.get("negative_space"),
                )
                if diag is not None and (
                    diag.get("receipts")
                    or "refuted" in (diag.get("confidences") or [])
                ):
                    append_audit_log(config.out_dir, {
                        "action": "rescue_diagnostic",
                        "gate": "anti_self_refutation",
                        "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
                        "file": outcome.file,
                        "function": outcome.function,
                        "stage": "review",
                        **diag,
                    })
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
        except Exception as exc:
            logger.warning(
                "anti-self-refutation error for %s:%s: %s",
                outcome.file, outcome.function, exc,
                exc_info=True,
            )
            with contextlib.suppress(Exception):
                append_audit_log(config.out_dir, {
                    "action": "rescue_diagnostic",
                    "gate": "anti_self_refutation",
                    "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
                    "file": outcome.file,
                    "function": outcome.function,
                    "stage": "review",
                    "blocked_on": "exception",
                    "error": f"{type(exc).__name__}: {exc}",
                })

    # ── Clean check ───────────────────────────────────────────────────
    if config.clean_check and outcome.status == "clean":
        try:
            from .refinement import (
                build_clean_check_prompt,
            )
            from .refinement import (
                merge_outcomes as _merge_clean,
            )
            from .refinement import (
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
                        # Phase-book the continuation call: the merge
                        # below folds its cost into the outcome for
                        # the journal, but the outcome-level booking
                        # already happened — without this the second
                        # call of every two-call review vanished from
                        # the phase ledger ($8.93 on one measured run).
                        result.cost_tracker.record_call(
                            "clean_check",
                            cost_usd=revised.cost_usd,
                            tokens_in=getattr(revised, "tokens_in", 0),
                            tokens_out=getattr(revised, "tokens_out", 0),
                            cache_read_tokens=getattr(
                                revised, "cache_read_tokens", 0),
                            cache_write_tokens=getattr(
                                revised, "cache_write_tokens", 0),
                            wall_time_s=revised.duration_s,
                        )
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
                RefinementContext,
                build_refinement_prompt,
                collect_tool_results,
                dispatch_suggestion,
            )
            from .refinement import (
                merge_outcomes as _merge_refined,
            )
            from .refinement import (
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
                # Phase-book the refinement round: merge_outcomes sums
                # the cost into the surviving outcome for the journal,
                # but the outcome-level phase booking already happened
                # before refinement — continuation rounds otherwise
                # never reach the phase ledger.
                result.cost_tracker.record_call(
                    "refinement",
                    cost_usd=refined.cost_usd,
                    tokens_in=getattr(refined, "tokens_in", 0),
                    tokens_out=getattr(refined, "tokens_out", 0),
                    cache_read_tokens=getattr(
                        refined, "cache_read_tokens", 0),
                    cache_write_tokens=getattr(
                        refined, "cache_write_tokens", 0),
                    wall_time_s=refined.duration_s,
                )
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
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .semantic_confidence import classify_semantic_confidence
            _sc = classify_semantic_confidence(
                outcome.hypothesis or "",
                ctx.get("source", ""),
                line_start=gap.get("line_start", 0),
            )
            if _sc == "high":
                outcome.semantic_confidence = "high"

    # ── Refutation gates ──────────────────────────────────────────────
    # Cheap mechanical checks that kill false-positive hypotheses.
    # Runs after G2 finding gates, before suspicious-demotion.
    if outcome.status in ("finding", "suspicious"):
        # Binary items: journal which gates could actually run
        # (records only — a gate blocked on missing inputs must be
        # distinguishable from a gate that ran and passed). Own try:
        # a records-only failure must never skip refutation below.
        try:
            from .binary_honesty import record_gate_engagement

            record_gate_engagement(
                config.out_dir,
                outcome,
                domain_model=domain_model,
                checklist=checklist,
                line_start=gap.get("line_start", 0),
            )
        except Exception:
            logger.debug("gate-engagement record skipped", exc_info=True)

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

    # ── Suspicious demotion gate: REMOVED ───────────────────────────
    # The old in-loop gate demoted EVERY suspicious outcome without
    # verification evidence to clean whenever Joern was up — blind to
    # the bug class (a tool-blind auth-logic hypothesis was "resolved"
    # by tools that cannot see it) and blind to tool errors (a Joern
    # query timeout became a clean verdict). Its body prefix also
    # excluded the outcome from every later rescue pass. These
    # outcomes now stay suspicious through deepen/sweep and are
    # resolved by the end-of-run ``_resolve_gate_demoted`` pass:
    # mechanical-corroboration check, then class coverage computed
    # from channels that actually RAN (error-aware) → clean when a
    # covering channel ran silent, dark when the class is tool-blind
    # or the channel errored.

    # ── Dynamic validation ────────────────────────────────────────────
    if config.dynamic_validation and outcome.status == "finding":
        try:
            from .dynamic_sweep import run_dynamic_sweep, should_run_dynamic

            if should_run_dynamic(outcome, config):
                dyn_result = run_dynamic_sweep(outcome, ctx, config)
                if dyn_result and dyn_result.evidence_strength == "sanitizer":
                    outcome.evidence_tool = "dynamic:sanitizer"
                elif dyn_result and dyn_result.evidence_strength == "crash":
                    outcome.evidence_tool = "dynamic:crash"
                elif dyn_result and dyn_result.evidence_strength == "exception":
                    # Exception-grade dynamic evidence (in-harness
                    # Python exception, bare nonzero exit, sanitizer
                    # text without a signal-grade death): a review
                    # hint, never confirmation. Idiomatic targets
                    # raise on garbage input and hostile targets mint
                    # this shape at will — it used to stamp
                    # dynamic:crash → CONFIRMED. Route to suspicious
                    # with the reason on the record; the stamp is NOT
                    # in _CONFIRMED_EVIDENCE.
                    outcome.evidence_tool = "dynamic:exception"
                    if outcome.status == "finding":
                        outcome.status = "suspicious"
                        outcome.body = (
                            "[dynamic: exception-grade evidence only — "
                            "harness observed an exception/nonzero "
                            "exit, not a signal-grade crash; routed "
                            "finding → suspicious] " + (outcome.body or "")
                        )
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
                from .frida_observe import run_frida_observation, should_run_frida

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

    # ── Prior /validate runtime evidence (bridge) ────────────────────
    # OBSERVED_RUNTIME / REPLAYED_CRASH evidence from a prior /validate
    # run on unchanged source stamps the re-confirmed finding so
    # compute_tier() reaches CONFIRMED instead of LLM_ONLY.
    if outcome.status in ("finding", "suspicious") and evidence_index:
        with contextlib.suppress(*_ENRICH_ERRORS):
            from .validate_bridge import validate_runtime_stamp

            _vrt_rec = evidence_index.get(gap_key)
            _vrt_stamp = validate_runtime_stamp(
                getattr(_vrt_rec, "validate_history", None)
                if _vrt_rec else None
            )
            if _vrt_stamp and _vrt_stamp not in (outcome.evidence_tool or ""):
                outcome.evidence_tool = (
                    f"{outcome.evidence_tool}+{_vrt_stamp}"
                    if outcome.evidence_tool else _vrt_stamp
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
                quarantined_rules=set(shared.quarantined_rules),
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
                        dual_control=bool(
                            getattr(synth, "dual_control", False)),
                        rule_tier=getattr(
                            synth, "rule_tier", "sweep_once"),
                    )
                logger.info(
                    "mid-loop synthesis: %d new targets from %s:%s",
                    len(synth.hits),
                    outcome.file,
                    outcome.function,
                )
        except Exception as exc:
            from core.llm.client import LLMAuthPersistentError
            if isinstance(exc, LLMAuthPersistentError):
                # Dead credential, not a bad seed: record the phase
                # abort (deduplicated) instead of a per-function
                # debug line that reads as "no rule synthesised".
                _record_phase_abort(config, result, exc)
            else:
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
            propagate_taint_upward,
            summary_from_review_result,
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
    except Exception as exc:  # noqa: BLE001
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

    # In-run rule precision feedback. ``is_tp`` mirrors record_match's
    # convention: a claim verdict on the matched function counts the
    # match as a true positive; clean/dormant counts it false.
    _rule_is_tp = outcome.status in ("finding", "suspicious")
    if (
        pf_result
        and pf_result.hits
        and checker_library
        and checker_library.all_entries()
    ):
        library_rule_ids = {
            e.rule_id for e in checker_library.all_entries()
        }
        for hit in pf_result.hits:
            checker_library.record_match(hit.rule_id, _rule_is_tp)
            if hit.rule_id in library_rule_ids:
                _note_rule_triage(shared, hit.rule_id, _rule_is_tp)
    if outcome.status != "error" and gap.get("synthesis_rule_id"):
        # This gap exists because a run-synthesized rule matched it —
        # the review verdict is a direct triage of that match.
        _note_rule_triage(shared, gap["synthesis_rule_id"], _rule_is_tp)

    disagree = _check_layer_disagreement(outcome, ctx, gap)
    if disagree is not None and layer_disagreements is not None:
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


_HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".hxx")


def _binary_absent_gap_keys(
    gaps: list[dict[str, Any]],
    checklist: dict[str, Any] | None,
    config: OrchestratorConfig,
    context_map: dict[str, Any] | None,
) -> set[str]:
    """file:function keys the binary oracle proves absent.

    Suppression-earning only: when an enriched inventory is available
    the chokepoint helper ``core.analysis.reachability.
    binary_oracle_absent`` decides (full-DWARF tier on EVERY
    contributing binary, multi-binary alive-in-any combined upstream);
    otherwise the pre-extracted ``config.binary_verdicts`` map is used
    (``extract_verdicts`` already withholds absent without a full-tier
    contributor). Binary trust (git-untracked provenance, source-
    coverage floor) is enforced upstream where the verdicts are
    produced. Header files and context-map entry points are exempt —
    mirrors the G7 dead-code gate.
    """
    keys: set[str] = set()
    inventory = next(
        (
            c for c in (config.inventory, checklist)
            if isinstance(c, dict) and c.get("binary_oracle")
        ),
        None,
    )
    if inventory is None and not config.binary_verdicts:
        return keys

    absent_fn = None
    if inventory is not None:
        try:
            from core.analysis.reachability import (
                binary_oracle_absent as absent_fn,
            )
        except ImportError:
            absent_fn = None

    entry_exempt = extract_context_map_set(context_map, "entry_points")
    for gap in gaps:
        file_path = gap.get("file", "")
        name = gap.get("name", "")
        if not file_path or not name:
            continue
        if file_path.endswith(_HEADER_SUFFIXES):
            continue
        key = f"{file_path}:{name}"
        if key in entry_exempt:
            continue
        is_absent = False
        if absent_fn is not None:
            try:
                is_absent = absent_fn(
                    inventory, file_path, name,
                    gap.get("line_start", 0) or 0,
                )
            except Exception:  # noqa: BLE001
                is_absent = False
        elif config.binary_verdicts:
            is_absent = config.binary_verdicts.get(name, "") == "absent"
        if is_absent:
            keys.add(key)
    return keys


def _record_triage_suppressions(
    gaps: list[dict[str, Any]],
    triage_results: dict,
    binary_absent_keys: set[str],
    out_dir: Path | None,
) -> int:
    """suppressions.jsonl audit trail for oracle-earned triage skips."""
    if not binary_absent_keys or not out_dir:
        return 0
    try:
        from core.analysis.reach_chokepoint import record_suppression
    except ImportError:
        return 0
    written = 0
    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        if key not in binary_absent_keys:
            continue
        line = gap.get("line_start", 0) or 0
        tr = triage_results.get(f"{key}:{line}") or triage_results.get(key)
        if tr is None or tr.bucket != TriageBucket.SKIP:
            continue
        if not any("binary_oracle_absent" in r for r in tr.reasons):
            continue
        record_suppression(
            out_dir,
            finding={
                "finding_id": f"audit-triage:{key}:{line}",
                "rule_id": "audit:hypothesis-triage",
                "file_path": gap["file"],
                "line": line,
                "function": gap["name"],
            },
            verdict="binary_oracle_absent",
            reason=(
                "hypothesis triage: function absent from every analysed "
                "binary (full-DWARF tier) — no hypothesis/synthesis "
                "budget spent"
            ),
            dropped=False,
            extra={"stage": "hypothesis-triage"},
        )
        written += 1
    return written


def _vendored_triage_verdicts(
    config: OrchestratorConfig,
    gaps: list[dict[str, Any]],
    *,
    checklist: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Per-file vendored/generated verdicts for the triage tier.

    Gated by ``config.vendored_triage`` (``--no-vendored-triage``
    disables the tier for a run). Best-effort — a detector failure
    must never kill prep.
    """
    if not getattr(config, "vendored_triage", True):
        logger.info(
            "vendored/generated triage disabled for this run "
            "(--no-vendored-triage)"
        )
        return {}
    vendor_verdicts: dict[str, Any] = {}
    try:
        from .vendored_detector import KIND_GENERATED, detect_vendored_files

        vendor_verdicts = detect_vendored_files(
            gaps, target_path=config.target_path, checklist=checklist,
        )
    except Exception:
        logger.debug(
            "vendored/generated detection failed", exc_info=True,
        )
        return {}
    if vendor_verdicts:
        _n_gen = sum(
            1 for v in vendor_verdicts.values() if v.kind == KIND_GENERATED
        )
        logger.info(
            "vendored/generated triage: %d files detected "
            "(%d generated, %d vendored)",
            len(vendor_verdicts), _n_gen, len(vendor_verdicts) - _n_gen,
        )
    return vendor_verdicts


def _record_vendored_suppressions(
    gaps: list[dict[str, Any]],
    triage_results: dict,
    vendor_verdicts: dict[str, Any],
    out_dir: Path | None,
) -> tuple[int, int]:
    """suppressions.jsonl audit trail for vendored/generated triage
    decisions — one record per skipped or glance-routed function, same
    house shape as the binary-oracle triage records (single writer:
    core.analysis.reach_chokepoint.record_suppression). Functions the
    tier saw but did not route (pinned, boundary-adjacent vendored)
    get no record — no decision was made for them.

    Returns ``(skipped, glanced)``.
    """
    if not vendor_verdicts or not out_dir:
        return (0, 0)
    try:
        from core.analysis.reach_chokepoint import record_suppression
    except ImportError:
        return (0, 0)
    from .triage import vendor_decision
    from .vendored_detector import KIND_GENERATED

    skipped = glanced = 0
    for gap in gaps:
        verdict = vendor_verdicts.get(gap["file"])
        if verdict is None:
            continue
        key = f"{gap['file']}:{gap['name']}"
        line = gap.get("line_start", 0) or 0
        tr = triage_results.get(f"{key}:{line}") or triage_results.get(key)
        if tr is None:
            continue
        tier = vendor_decision(tr)
        if tier is None:
            continue
        record_suppression(
            out_dir,
            finding={
                "finding_id": f"audit-triage:{key}:{line}",
                "rule_id": "audit:vendored-triage",
                "file_path": gap["file"],
                "line": line,
                "function": gap["name"],
            },
            verdict=(
                "generated_code" if verdict.kind == KIND_GENERATED
                else "vendored_code"
            ),
            reason=(
                f"hypothesis triage: {verdict.kind} code "
                f"({verdict.signal}: {verdict.detail}) — routed to "
                f"{tier} tier"
            ),
            dropped=False,
            extra={
                "stage": "hypothesis-triage",
                "tier": tier,
                "signal": verdict.signal,
            },
        )
        if tier == "skip":
            skipped += 1
        else:
            glanced += 1
    return (skipped, glanced)


def _iris_prep_specs(
    config: OrchestratorConfig,
    gaps: list[dict[str, Any]],
    taint_summary_results: dict | None,
) -> tuple[list, Any]:
    """IRIS prep seam: taint-spec synthesis + project-sink store read.

    Returns ``(iris_taint_specs, project_sinks)``. Gated by
    ``config.iris`` — a cold-profile run gets ``([], None)`` without
    touching the spec synthesiser or the persistent sink store (the
    disable is announced once at run start by _apply_profile_gates).
    """
    if not getattr(config, "iris", True):
        return [], None

    iris_taint_specs: list = []
    try:
        from .iris_specs import compile_joern_config, identify_candidates, specs_to_json

        taint_chain_callees: set[str] = set()
        if taint_summary_results:
            for _ts_summ in taint_summary_results.values():
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

    return iris_taint_specs, project_sinks


def _current_binary_build_ids(
    config, checklist: dict[str, Any] | None,
) -> dict[str, str]:
    """``{build_id: binary_path}`` for the binaries in THIS run's target set.

    Sourced from the enriched inventory's ``binary_oracle`` summary
    (the same block the peer-group and triage consumers read), which
    already passed the provenance filter + source-coverage floor.
    Empty when no binary oracle ran — cache merges then stay fail
    closed rather than adopting every build-id in the shared cache.
    """
    out: dict[str, str] = {}
    inventory = next(
        (
            c for c in (config.inventory, checklist)
            if isinstance(c, dict) and c.get("binary_oracle")
        ),
        None,
    )
    if inventory is None:
        return out
    summary = inventory.get("binary_oracle")
    if not isinstance(summary, dict):
        return out
    for b in summary.get("binaries") or []:
        if not isinstance(b, dict):
            continue
        bid = b.get("build_id") or ""
        if isinstance(bid, str) and bid:
            out[bid] = str(b.get("path", "") or "")
    return out


def _sarif_clean_files_from_cache(
    sarif_cache: SarifCache | None,
    checklist: dict[str, Any],
) -> set[str]:
    """Checklist files PROVABLY scanned with zero SARIF alerts.

    The SARIF cache is positive-only: a file absent from its alert
    index may simply never have been scanned (semgrep-only sibling
    runs, language gaps, scoped scans). Treating that absence as
    authoritative "clean" resolved small helpers without LLM review on
    no evidence at all. A file only counts as sarif-clean when the
    producing scan DECLARED it analysed the file (``runs[].artifacts``
    coverage, tracked in ``SarifCache.scanned_files``) and recorded no
    alert for it. No declared coverage → no clean verdicts (the gate
    fails closed and the functions go to normal review).
    """
    clean: set[str] = set()
    if not sarif_cache:
        return clean
    scanned = getattr(sarif_cache, "scanned_files", None) or set()
    if not scanned:
        return clean
    from .sweep import _normalize_sarif_path

    alerted = set(sarif_cache._by_file.keys())
    for fi in checklist.get("files", []):
        fp = fi.get("path", "") if isinstance(fi, dict) else ""
        if not fp:
            continue
        normalized = _normalize_sarif_path(fp)
        if normalized in scanned and normalized not in alerted:
            clean.add(fp)
    return clean


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

    # Binary targets: the checklist speaks address space and the
    # target is a compiled artifact — source-tree pre-passes (macro
    # recovery, source call-graph enrichment, Joern CPG) have nothing
    # to parse and are skipped explicitly rather than left to error
    # into their fallbacks one by one.
    binary_mode = checklist.get("target_kind") == "binary"
    if binary_mode:
        logger.info(
            "audit prep: binary target — source-only pre-passes "
            "skipped (macro recovery, source call edges, Joern)"
        )
        # Run-level honesty records (never verdict-affecting): which
        # channels are structurally disabled on this binary and why,
        # plus the binary's fact-provenance block (build-id, stripped-
        # ness, DWARF presence, fortification, name-provenance census)
        # journaled and persisted in the build-id cache. Own try:
        # records only, must never block prep.
        try:
            from .binary_honesty import (
                declare_binary_channel_skips,
                journal_binary_provenance,
            )

            declare_binary_channel_skips(config.out_dir, checklist)
            journal_binary_provenance(config.out_dir, checklist)
        except Exception:
            logger.debug(
                "binary run honesty records skipped", exc_info=True,
            )

    # Fidelity-3 macro recovery: function definitions that only exist
    # post-expansion (DEFINE_HANDLER-style generators) are invisible to
    # the AST inventory — recover them so they reach the review loop.
    # Best-effort, bounded (textual prefilter + file cap inside).
    if not binary_mode:
        try:
            from .preprocessor_view import (
                augment_checklist_with_macro_functions,
            )

            augment_checklist_with_macro_functions(
                checklist, config.target_path,
                out_dir=config.out_dir, scope=config.scope,
            )
        except ImportError:
            pass
        except Exception:
            logger.debug("macro-function recovery failed", exc_info=True)

    context_map = load_context_map(config.out_dir)
    if context_map is None:
        context_map = _try_understand_bridge(config)
    if context_map is None:
        context_map = {}
    if "call_edges" not in context_map and not binary_mode:
        from core.orchestration.context_map_callgraph import enrich_with_call_edges

        edge_count = enrich_with_call_edges(
            context_map,
            checklist=checklist,
        )
        if edge_count:
            logger.debug("bootstrapped %d call edges from checklist", edge_count)
    if not context_map.get("crypto_inventory"):
        # Bare-audit fallback (A9): without a prior /understand map the
        # crypto API packs never fed the audit — per-function contexts
        # and strategy routing saw zero crypto_inventory refs even on
        # an openssl-shaped target. Pack-driven mechanical scan; a
        # cocci-derived inventory from a real map always wins.
        try:
            from core.orchestration.context_map_crypto import (
                enrich_with_crypto_inventory,
            )
            n_crypto = enrich_with_crypto_inventory(
                context_map,
                checklist=checklist,
                target_path=config.target_path,
            )
            if n_crypto:
                logger.info(
                    "crypto inventory: %d call sites from the crypto API "
                    "packs (mechanical bootstrap — no /understand map)",
                    n_crypto,
                )
        except Exception:
            logger.debug(
                "crypto inventory bootstrap failed", exc_info=True,
            )
    flow_traces = load_flow_traces(config.out_dir)

    variant_targets = _load_variants(config.out_dir)

    sarif_cache = SarifCache.from_directory(config.out_dir)

    # Cross-run SARIF reuse: prior /scan and /agentic runs in the same
    # project left SARIF one directory over — import it (bounded,
    # freshness-gated) so corroboration channels see it.
    try:
        from .sweep import import_sibling_sarif

        _sibling_results = import_sibling_sarif(
            sarif_cache, config.out_dir, config.target_path,
        )
        if _sibling_results:
            logger.info(
                "sarif_cache: imported %d results from prior scan runs",
                _sibling_results,
            )
        else:
            # Loud-once no-op: a silent zero is indistinguishable
            # from the import never running.
            logger.info(
                "sarif_cache: no fresh sibling-run SARIF found for "
                "this target — nothing imported",
            )
    except Exception:
        logger.debug("sibling SARIF import failed", exc_info=True)

    # Opt-in bounded baseline pass when nothing exists to corroborate
    # against.
    if config.pre_scan and not sarif_cache:
        try:
            from .pre_scan import run_baseline_pre_scan

            if run_baseline_pre_scan(
                config.target_path,
                config.out_dir,
                scope=(
                    config.scope
                    if isinstance(config.scope, list)
                    else ([config.scope] if config.scope else None)
                ),
            ):
                sarif_cache = SarifCache.from_directory(config.out_dir)
        except Exception:
            logger.debug("baseline pre-scan failed", exc_info=True)

    if config.codeql_db_paths and not sarif_cache:
        # One suite per database; run_suite writes per-language SARIF
        # (codeql_<language>.sarif), so multi-database runs don't
        # clobber each other's output.
        for _db in config.codeql_db_paths:
            _codeql_pre_sweep_raw(_db, config.out_dir, sarif_cache)

    sarif_clean_files = _sarif_clean_files_from_cache(sarif_cache, checklist)
    if sarif_clean_files:
        logger.info(
            "sarif_clean: %d / %d checklist files scanned with zero "
            "SARIF alerts",
            len(sarif_clean_files),
            len(sarif_clean_files) + len(sarif_cache._by_file),
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

    joern_future: Future | None = None
    joern_flows: dict[str, list] | None = None

    imported_joern = _import_sibling_joern_flows_raw(
        config.out_dir, target_path=config.target_path
    )

    cm_sinks = context_map.get("sink_details", []) if context_map else None

    from .binary_bridge import load_binary_bridge

    if config.no_binary_oracle:
        binary_bridge_early = None
    else:
        # Build-ID cache: merges artifacts cached by prior runs (or by
        # an external consumer sharing the cache dir) so a binary is
        # not re-analysed. Best-effort — a missing/broken cache never
        # blocks the bridge.
        _build_id_cache = None
        try:
            from .build_id_cache import load_build_id_cache

            _build_id_cache = load_build_id_cache()
        except Exception:
            logger.debug("build-id cache unavailable", exc_info=True)
        binary_bridge_early = load_binary_bridge(
            config.out_dir,
            target_path=config.target_path,
            build_id_cache=_build_id_cache,
            # Scope cache merges to the binaries of THIS run's target
            # set — the shared cache holds every build-id any run (or
            # external writer) ever cached.
            current_build_ids=_current_binary_build_ids(config, checklist),
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

    validate_confirmed_keys: set[str] | None = None
    validate_ruled_out_keys: set[str] | None = None
    try:
        from .validate_bridge import (
            import_validate_evidence,
            index_verdict_history,
            validate_history_keys,
        )

        _bridge_project = _pinned_or_parent_project_dir(config.out_dir)
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
        if (
            bridge_result
            and bridge_result.verdict_history
            and evidence_index is not None
        ):
            _vh_index = index_verdict_history(bridge_result)
            for _vh_key, _vh_entry in _vh_index.items():
                _vh_rec = evidence_index.get(_vh_key)
                if _vh_rec is not None:
                    _vh_rec.validate_history = _vh_entry
            validate_confirmed_keys, validate_ruled_out_keys = (
                validate_history_keys(_vh_index)
            )
            logger.info(
                "validate bridge: verdict history — %d confirmed-function"
                " boosts, %d ruled-out deprioritisations",
                len(validate_confirmed_keys),
                len(validate_ruled_out_keys),
            )
    except Exception:
        logger.debug("validate bridge import failed", exc_info=True)

    try:
        from .binary_layer0 import (
            format_layer0_summary,
            run_source_presweep,
        )

        l0_result = run_source_presweep(
            evidence_index, config.target_path, out_dir=config.out_dir,
        )
        if l0_result.findings:
            # Name the producer and the destination: this counter is
            # the source-pattern pre-sweep attached to the evidence
            # index — NOT the mechanical-detector findings written to
            # mechanical-findings.json later, whose different count
            # read as a silent dedup next to this line.
            logger.info(
                "%s (source-pattern pre-sweep; attached to the "
                "evidence index, separate from mechanical-findings"
                ".json)",
                format_layer0_summary(l0_result),
            )
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

    provenance_map: dict[str, list[dict[str, str]]] = {}
    security_decision_keys: frozenset = frozenset()
    feeds_security_keys: frozenset = frozenset()
    try:
        from .mechanical_gates import (
            build_feeds_security_map,
            build_provenance_map,
            build_security_decision_set,
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
        # Provenance suffix: under a replay-gated profile (cold corpus
        # runs) the library entries are inert for THIS run — without
        # the suffix the banner is indistinguishable from a
        # replay-gate breach when a rule synthesized by an earlier
        # group in the same process shows up here.
        if getattr(config, "library_replay", True):
            _lib_provenance = "replay enabled"
        else:
            _lib_provenance = (
                "replay gated off — entries inert this run; any new "
                "rules are synthesized this run"
            )
        logger.info("%s [%s]", checker_library.summary(), _lib_provenance)

    summary_cache = None
    try:
        from .summary_cache import load_summary_cache

        summary_cache = load_summary_cache()
        if summary_cache.available_libraries():
            logger.info(summary_cache.summary())
    except Exception:
        logger.debug("summary_cache load failed", exc_info=True)

    discovered_tests: dict[str, Any] | None = None
    try:
        from core.analysis.test_discovery import discover_tests_cached

        discovered_tests = discover_tests_cached(
            config.target_path, config.out_dir,
        )
        if discovered_tests:
            logger.info(
                "test_discovery: %d functions with tests",
                len(discovered_tests),
            )
    except Exception:
        logger.debug("test_discovery failed", exc_info=True)

    typestate_models: dict[str, Any] | None = None
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
    # Per-function fuzz coverage: this run's own artifact, else the
    # newest sibling /fuzz run in the same project (the producer
    # writes into ITS run dir, one directory over).
    fuzz_coverage = _load_fuzz_coverage(config.out_dir)
    if fuzz_coverage is None:
        try:
            fuzz_coverage = _load_fuzz_coverage_any(
                config.out_dir,
                _sibling_run_dirs(
                    config.out_dir, target_path=config.target_path,
                ),
            )
            if fuzz_coverage is not None:
                logger.info(
                    "fuzz coverage: imported per-function map from a "
                    "sibling /fuzz run",
                )
        except Exception:
            logger.debug("sibling fuzz coverage import failed", exc_info=True)

    _project_dir = _pinned_or_parent_project_dir(config.out_dir)
    # Prior finding-grade claims (/agentic per-finding analyses) for
    # review context. The gap fold kind-gates these OUT of coverage;
    # this map kind-gates them INTO the prompt as prior claims.
    config.prior_finding_analyses = _build_prior_finding_analyses(
        config, _project_dir,
    )
    # Cross-run verdict reuse: compute_gaps fills this with
    # hash-verified, reuse-eligible prior-run journal entries; they
    # are imported as $0 outcomes just before the review loop.
    reuse_candidates: dict[str, Any] = {}
    # Per-reason counts of hash-verified entries the reuse screen
    # refused (context_reduced / model_changed / strategy_changed /
    # domain_model_context) — surfaced in the run summary so a mass
    # re-review is attributable to its driver.
    reuse_blocked_stats: dict[str, int] = {}
    _same_run_reuse = (
        getattr(config, "same_run_reuse", False) and not config.force
    )
    _reuse_enabled = (
        getattr(config, "verdict_reuse", True)
        and getattr(config, "cross_run_import", True)
        and not config.force
        and (_project_dir is not None or _same_run_reuse)
    )
    _primary_model = (
        config.models[0]
        if config.models and config.models[0] != "default"
        else None
    )
    # New/changed-code signal: materialise inventory-diff.json (vs the
    # previous run's checklist) so compute_gaps' tier boost and
    # score_functions' SCORE_NEW_CODE both see it. Best-effort — a
    # first run has no previous inventory and gets an empty set.
    new_fn_keys: set | None = None
    try:
        from .priority import ensure_inventory_diff
        new_fn_keys = ensure_inventory_diff(
            config.out_dir, checklist, target_path=config.target_path,
        )
    except Exception:
        logger.debug("inventory-diff materialisation failed", exc_info=True)
    gaps = compute_gaps(
        checklist,
        [] if config.force else coverage_records,
        context_map=context_map,
        strategy_filter=config.strategy_filter,
        scope=config.scope,
        fuzz_coverage=fuzz_coverage,
        out_dir=None if config.force else config.out_dir,
        project_dir=None if config.force else _project_dir,
        include_kinds=getattr(config, "include_kinds", None),
        reuse_sink=reuse_candidates if _reuse_enabled else None,
        current_model=_primary_model,
        own_run_reuse=_same_run_reuse,
        reuse_stats=reuse_blocked_stats,
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

    iris_taint_specs, project_sinks = _iris_prep_specs(
        config, gaps, taint_summary_results,
    )

    if config.include_stale:
        ann_dir = _annotations_dir(config)
        if ann_dir is not None:
            gaps = _merge_stale(gaps, ann_dir, config.target_path)

    _edge_pass_summary: dict[str, Any] = {}
    if config.edges:
        # Cross-function edge obligations (--edges): scope the tiered
        # obligation set, review unreviewed tier-1 (boundary) edges as
        # dedicated contract units BEFORE the function loop — boundary
        # contracts outrank function gaps — and stamp each caller's
        # tier-2 edges onto its gap so the function review folds them
        # in as an "edge contracts" section. Best-effort: a failed
        # pass degrades to a normal function-only audit.
        try:
            from .edge_review import run_edge_pass
            edge_summary, _tier2_by_caller = run_edge_pass(
                config, checklist, context_map,
                commit_fn=_commit_outcome,
                on_progress=on_progress,
            )
            _edge_pass_summary = edge_summary
            logger.info(
                "edge pass: %d/%d tier-1 reviewed (%d finding(s), "
                "%d budget-skipped); %d tier-2 folded; %d blind spot(s)",
                edge_summary.get("reviewed", 0),
                edge_summary.get("tier1_total", 0),
                edge_summary.get("findings", 0),
                edge_summary.get("skipped_budget", 0),
                edge_summary.get("tier2_total", 0),
                edge_summary.get("blind_spots", 0),
            )
            if _tier2_by_caller:
                for _gap in gaps:
                    _lst = _tier2_by_caller.get(
                        f"{_gap['file']}:{_gap['name']}")
                    if _lst:
                        _gap["edge_contracts"] = _lst
        except Exception:
            logger.warning(
                "edge-obligation pass failed — continuing as a "
                "function-only audit", exc_info=True,
            )

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

    # Prior sibling-scan hits: a scanner already flagged these
    # functions in an earlier run — boost them for review.
    prior_scan_keys: set[str] = set()
    if sarif_cache:
        try:
            for _gap in gaps:
                hits = sarif_cache.lookup(
                    _gap["file"],
                    _gap.get("line_start", 0),
                    _gap.get("line_end") or 0,
                )
                if hits and any(h.get("_sarif_sibling") for h in hits):
                    prior_scan_keys.add(f"{_gap['file']}:{_gap['name']}")
        except Exception:
            logger.debug("prior-scan-hit key scan failed", exc_info=True)
            prior_scan_keys = set()

    binary_absent_keys: set[str] = set()
    try:
        binary_absent_keys = _binary_absent_gap_keys(
            gaps, checklist, config, context_map,
        )
        if binary_absent_keys:
            logger.info(
                "binary oracle: %d gap functions absent from all analysed"
                " binaries — hard-deprioritised and skipped at triage",
                len(binary_absent_keys),
            )
    except Exception:
        logger.debug("binary-absent gap key scan failed", exc_info=True)

    gaps = score_functions(
        gaps,
        context_map=context_map,
        flow_traces=flow_traces,
        threat_model=config.threat_model,
        open_constraint_keys=open_keys,
        tool_failures=tool_failures,
        fuzz_coverage=fuzz_cov_files,
        fuzz_function_coverage=fuzz_coverage,
        prior_scan_hit_keys=prior_scan_keys or None,
        strategy_weights=strat_weights,
        binary_bridge=binary_bridge_early,
        new_functions=new_fn_keys or None,
        validate_confirmed_keys=validate_confirmed_keys,
        validate_ruled_out_keys=validate_ruled_out_keys,
        binary_absent_keys=binary_absent_keys or None,
    )

    # Fix-history mining: the target's past security fixes become
    # variant hunts + regression hypotheses (bounded; sandboxed
    # read-only git; never raises). Merged before the budget cap so
    # boosted/injected gaps compete for review slots.
    try:
        from .fix_history import apply_fix_history

        _n_gaps_before = len(gaps)
        gaps = apply_fix_history(
            gaps, checklist, config.target_path, out_dir=config.out_dir,
        )
        if len(gaps) != _n_gaps_before or any(
            g.get("from_fix_history") for g in gaps
        ):
            gaps.sort(
                key=lambda g: (
                    g["priority"],
                    -(g.get("priority_score") or 0),
                    -g.get("sloc", 0),
                    g["file"],
                    g["name"],
                )
            )
    except Exception:
        logger.debug("fix-history enrichment failed", exc_info=True)

    # SCA advisory priors: gaps in files that import a component with
    # advisory history get a boost, per-CWE-family strategy hints and
    # a defanged context note (see core.audit.sca_bridge). Applied
    # before the budget cap so boosted gaps compete for review slots.
    try:
        from .sca_bridge import apply_sca_advisories

        if apply_sca_advisories(gaps, config.out_dir):
            gaps.sort(
                key=lambda g: (
                    g["priority"],
                    -(g.get("priority_score") or 0),
                    -g.get("sloc", 0),
                    g["file"],
                    g["name"],
                )
            )
    except Exception:
        logger.debug("SCA advisory enrichment failed", exc_info=True)

    # Opt-in LLM re-rank of the queue head, strictly within priority
    # tiers (core.audit.gap_ranking). Placed after every mechanical
    # re-sort above, and before hoist_pins + the budget cut so
    # operator pins still outrank it and the cut drops the least
    # promising within-tier tail. Two wiring details matter here:
    # stamp_scores makes the LLM order visible to everything
    # downstream that keys on priority_score instead of list order
    # (the workqueue topological tiebreak, subsystem grouping) —
    # without it the re-rank would only decide budget-cut membership;
    # and the seed is derived from the run directory so resume
    # segments recompute the SAME order instead of churning the cut
    # between segments. Dispatches through the run's budget-governed
    # client (the _run_llm_client doctrine) so spend lands on the
    # --max-cost ledger.

    # Graph store: boost gap-queue items connected to prior findings/hypotheses.
    # Bumps priority_score so graph-connected items rank higher in the budget cut.
    import sqlite3 as _graph_sqlite3
    try:
        from core.understand_graph import graph_path_for_run, hypothesis_seeds
        _gp = graph_path_for_run(config.out_dir, str(config.target_path or ""))
        if _gp.exists():
            seeds = hypothesis_seeds(_gp)
            if seeds:
                _seed_keys = {(s["file"], s["function"]) for s in seeds}
                _boosted = 0
                for gap in gaps:
                    if (gap.get("file", ""), gap.get("name", "")) in _seed_keys:
                        gap["priority_score"] = gap.get("priority_score", 0) + 10
                        _boosted += 1
                if _boosted:
                    logger.info("graph store: boosted %d/%d gaps from %d hypothesis seeds",
                                _boosted, len(gaps), len(seeds))
    except (ImportError, _graph_sqlite3.Error, KeyError, TypeError, ValueError):
        logger.debug("graph hypothesis_seeds skipped", exc_info=True)

    if getattr(config, "rank_gaps", False):
        try:
            import zlib

            from core.audit.gap_ranking import rank_gap_queue

            gaps, _rank_note = rank_gap_queue(
                gaps,
                client=_run_llm_client(config),
                seed=zlib.crc32(str(config.out_dir).encode()) & 0x7FFFFFFF,
                stamp_scores=True,
            )
            logger.info("gap ranking: %s", _rank_note)
        except Exception:
            logger.debug("gap ranking failed", exc_info=True)

    # Operator pins (``--pin file:function``): guaranteed review slots,
    # hoisted ahead of the budget cut. See gaps.hoist_pins. The
    # checklist classifies any unmatched pin's cause in the warning.
    gaps = hoist_pins(
        gaps, getattr(config, "pins", None), checklist=checklist,
    )

    if config.budget and config.budget > 0:
        # Records the dropped tail in not-attempted.json so the run
        # summary reports it as "not attempted (budget)" instead of
        # silently conflating it with reviewed code. Scoped runs get
        # the per-file coverage floor + loud zero-slot report.
        gaps = truncate_gaps_to_budget(
            gaps, config.budget, config.out_dir,
            scope=config.scope,
            scope_floor=getattr(config, "scope_floor", True),
        )

    entry_points = extract_context_map_set(context_map, "entry_points")

    _ops_eps: set = set()
    try:
        from .ops_struct import collect_ops_entry_points

        _ops_srcs: dict[str, str] = {}
        for gap in gaps:
            fp = gap.get("file", "")
            if fp and fp not in _ops_srcs:
                with contextlib.suppress(OSError):
                    sp = config.target_path / fp
                    if sp.is_file():
                        _ops_srcs[fp] = sp.read_text(errors="replace")
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
        if _taint_approx_has_flow(approx)
    )
    vendor_verdicts = _vendored_triage_verdicts(
        config, gaps, checklist=checklist,
    )
    # Hydrated detector gaps + dispatch tables are built BEFORE triage
    # so the classifier can consume the dispatch-table census: a
    # function registered as a handler is invoked through a function
    # pointer — never "callerless" for skip purposes. (They were built
    # after classify_all when their only consumer was the peer-group
    # resolver.)
    detector_gaps = hydrate_live_gaps_for_detectors(
        [g for g in gaps if not g.get("dead")],
        Path(config.target_path),
    )
    prep_dispatch_tables = None
    callback_target_names: frozenset[str] = frozenset()
    try:
        from .dispatch_table import build_dispatch_tables

        prep_dispatch_tables = build_dispatch_tables(detector_gaps)
        if prep_dispatch_tables:
            logger.info(
                "dispatch tables: %d extracted for peer-group L2",
                len(prep_dispatch_tables),
            )
            callback_target_names = frozenset(
                name
                for table in prep_dispatch_tables
                for name in table.handlers.values()
            )
    except Exception:
        logger.debug("dispatch-table extraction failed", exc_info=True)
    triage_results = classify_all(
        gaps,
        entry_points=frozenset(entry_points),
        sinks=frozenset(sinks_set),
        trust_boundaries=frozenset(trust_boundary_set),
        taint_path_keys=taint_path_keys,
        joern_flow_keys=joern_flow_keys,
        binary_absent_keys=frozenset(binary_absent_keys),
        sink_unreachable_keys=sink_unreachable_keys,
        validate_confirmed_keys=frozenset(validate_confirmed_keys or ()),
        dangerous_callee_keys=dangerous_callee_keys,
        callback_target_names=callback_target_names,
        priority_scores=priority_scores,
        target_path=Path(config.target_path),
        vendor_verdicts=vendor_verdicts or None,
    )
    logger.info(format_triage_summary(triage_results))
    try:
        n_suppressed = _record_triage_suppressions(
            gaps, triage_results, binary_absent_keys, config.out_dir,
        )
        if n_suppressed:
            logger.info(
                "binary oracle: %d triage suppressions recorded in"
                " suppressions.jsonl",
                n_suppressed,
            )
    except Exception:
        logger.debug("triage suppression records failed", exc_info=True)
    # MANDATORY audit trail: every vendored/generated skip/glance
    # decision leaves one suppressions.jsonl record — nothing is
    # silently dropped. Counts surface in the run summary.
    vendored_triage_counts = {
        "files": len(vendor_verdicts), "skipped": 0, "glanced": 0,
    }
    try:
        _n_vskip, _n_vglance = _record_vendored_suppressions(
            gaps, triage_results, vendor_verdicts, config.out_dir,
        )
        vendored_triage_counts["skipped"] = _n_vskip
        vendored_triage_counts["glanced"] = _n_vglance
        if _n_vskip or _n_vglance:
            logger.info(
                "vendored/generated triage: %d functions skipped, %d "
                "routed to glance — records in suppressions.jsonl",
                _n_vskip, _n_vglance,
            )
    except Exception:
        logger.debug("vendored suppression records failed", exc_info=True)

    from .negative_space import (
        check_sibling_negative_space,
        discover_conventions,
    )

    conv_vocab = None
    # load_domain_model self-handles read/parse errors; only path-level
    # OSErrors can legitimately escape.
    with contextlib.suppress(OSError):
        from .condition_smt import DomainVocabulary
        conv_vocab = DomainVocabulary.from_domain_model(
            _load_domain_model(config),
            target_path=config.target_path,
        )
    conventions = discover_conventions(
        detector_gaps, domain_vocab=conv_vocab,
    )
    if conventions:
        logger.info(
            "negative-space: discovered %d security conventions",
            len(conventions),
        )

    from core.analysis.peer_groups import resolve_peer_groups

    # Study domain model, when a prior study loop produced one — the
    # resolver's L3 (domain-concept) layer previously had no producer
    # at this call site, so it never ran.
    prep_domain_model = None
    try:

        prep_domain_model = _load_domain_model(config)
    except Exception:
        logger.debug(
            "domain model load for peer groups failed", exc_info=True,
        )

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
    # Dispatch tables (peer-group L2) were extracted above, before
    # triage — ``prep_dispatch_tables`` is reused here unchanged.

    # L1: cached r2 binary call edges for the declared binaries.
    # Cache-only (populated by /agentic / /codeql --binary-edges or a
    # binary graph store); binaries come from the enriched inventory's
    # binary_oracle block, which already passed the provenance filter
    # + source-coverage floor. Tier gating and the --no-binary-oracle
    # opt-out are enforced inside the producer. Cold cache / no
    # binaries → None → the layer stays empty (equivalence pin).
    prep_binary_edge_index = None
    try:
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        _pg_inventory = next(
            (
                c for c in (config.inventory, checklist)
                if isinstance(c, dict) and c.get("binary_oracle")
            ),
            None,
        )
        prep_binary_edge_index = binary_edge_index_from_inventory(
            _pg_inventory,
            no_binary_oracle=config.no_binary_oracle,
        )
    except Exception:
        logger.debug(
            "binary edge index load for peer groups failed",
            exc_info=True,
        )

    # L4: type-cohort index from the inventory's recorded param /
    # return types (typed extractors) with a C/C++ signature fallback.
    # No usable type metadata → None → the layer stays empty.
    prep_type_ref_index = None
    try:
        from core.analysis.peer_groups import type_ref_index_from_inventory

        prep_type_ref_index = type_ref_index_from_inventory(checklist)
    except Exception:
        logger.debug(
            "type-cohort index build for peer groups failed",
            exc_info=True,
        )

    peer_groups = resolve_peer_groups(
        gap_func_dicts,
        joern_server=joern_server,
        binary_edge_index=prep_binary_edge_index,
        dispatch_tables=prep_dispatch_tables or None,
        domain_model=prep_domain_model,
        type_ref_index=prep_type_ref_index,
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

    semantic_findings: list[dict[str, Any]] = []
    try:
        from .sibling_analysis import check_semantic_consistency

        # detector_gaps, not gaps: raw checklist gaps carry line spans
        # but no text, so a source map built from them is always empty
        # — only the hydrated detector copies have gap["source"].
        source_map = {
            f"{g['file']}:{g['name']}": {"source": g.get("source", "")}
            for g in detector_gaps
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

    mechanical_findings: dict[str, list[dict[str, Any]]] = {}
    guard_clean_keys: set[str] = set()
    try:
        mechanical_findings, guard_clean_keys = _run_mechanical_detectors(
            gaps,
            config,
            context_map=context_map,
            evidence_index=evidence_index,
            joern_server=joern_server,
            checklist=checklist,
        )
    except Exception:
        logger.debug("mechanical detectors phase failed", exc_info=True)

    # Route semantic-consistency outliers through the mechanical-
    # findings channel so they reach mechanical-findings.json and the
    # per-gap review prompt — previously they were computed and dropped
    # (stored on shared state with no consumer).
    if semantic_findings:
        try:
            from .sibling_analysis import semantic_findings_to_mechanical

            for mf in semantic_findings_to_mechanical(semantic_findings):
                key = f"{mf['file']}:{mf['function']}"
                mechanical_findings.setdefault(key, []).append(mf)
        except Exception:
            logger.debug(
                "semantic-consistency routing failed", exc_info=True,
            )

    # Ops-struct reachability receipts: a function reached through an
    # ops-struct member (file_operations, net_device_ops, ...) is an
    # indirect entry point — the collector only widened entry_points,
    # so the channel fired without ever leaving a receipt and could
    # not be attributed. Route a detector record through the standard
    # mechanical-findings channel for every reviewed gap it covers.
    if _ops_eps:
        _route_ops_struct_receipts(gaps, _ops_eps, mechanical_findings)

    # Route perlasm generated-asm leads through the same channel:
    # the zero-length-loop-entry check runs over inventory records
    # with ``language == "asm-generated"`` (emitted by the perlasm
    # enrichment) and its detection-grade findings reach
    # mechanical-findings.json + the per-gap review prompt exactly
    # like the semantic-consistency outliers above.
    try:
        from .asm_zero_len_loop import scan_inventory_asm

        for mf in scan_inventory_asm(checklist):
            key = f"{mf['file']}:{mf['function']}"
            mechanical_findings.setdefault(key, []).append(mf)
    except Exception:
        logger.debug("perlasm asm-check routing failed", exc_info=True)

    # Standing consistency pre-pass (§2.3/§2.4): usage-enum census +
    # return-census.json, LLM-free verdicts on census deviants,
    # flag/mode + cleanup comparators, capped checklist leads, and the
    # acknowledged-discard → fail_open handoff hypotheses.
    consistency_prepass: dict[str, Any] = {}
    try:
        from .consistency_prepass import (
            run_consistency_prepass,
            seed_consistency_leads,
            seed_fail_open_handoffs,
        )

        prepass_texts: dict[str, str] = {}
        for gap in gaps:
            fp = gap.get("file", "")
            if fp and fp not in prepass_texts:
                with contextlib.suppress(OSError):
                    src_path = config.target_path / fp
                    if src_path.is_file():
                        prepass_texts[fp] = src_path.read_text(
                            errors="replace",
                        )
        if prepass_texts:
            consistency_prepass = run_consistency_prepass(
                prepass_texts,
                target_path=config.target_path,
                out_dir=config.out_dir,
                annotations_dir=getattr(config, "annotations_dir", None),
                inventory=getattr(config, "inventory", None),
                context_map=context_map,
                domain_model=prep_domain_model,
                joern_server=joern_server,
                # Interface-implementor parity consumes the
                # resolver's mechanical layers (L2 dispatch-site, L4
                # type-cohort) — groups already built above.
                peer_groups=peer_groups,
            )
            for mf in consistency_prepass.get("mechanical", []):
                key = f"{mf['file']}:{mf['function']}"
                mechanical_findings.setdefault(key, []).append(mf)
            n_leads = seed_consistency_leads(
                gaps, consistency_prepass.get("leads", []),
            )
            n_handoffs = seed_fail_open_handoffs(
                gaps, consistency_prepass.get("handoffs", []),
            )
            if n_leads or n_handoffs:
                logger.info(
                    "consistency prepass: %d leads seeded, %d "
                    "fail-open handoff hypotheses injected",
                    n_leads, n_handoffs,
                )
            if config.out_dir:
                with contextlib.suppress(OSError, ValueError):
                    append_audit_log(config.out_dir, {
                        "action": "consistency_prepass",
                        **(consistency_prepass.get("telemetry") or {}),
                    })
    except Exception:
        logger.debug("consistency prepass failed", exc_info=True)

    # Fail-open census pre-pass: detection-grade leg-1 x
    # leg-2 sweep over the handler-outcome family; leads land on gap
    # dicts so the review prompt renders a hypothesize-or-discharge
    # obligation. The phase-1 field runs had a quiet fail_open tier —
    # seeding generates the candidates instead of waiting for the LLM
    # to phrase one.
    fail_open_census: dict[str, Any] = {}
    try:
        from .fail_open_census import (
            run_fail_open_census,
            seed_fail_open_leads,
        )

        fo_texts: dict[str, str] = {}
        for gap in gaps:
            fp = gap.get("file", "")
            if fp and fp not in fo_texts:
                with contextlib.suppress(Exception):
                    src_path = config.target_path / fp
                    if src_path.is_file():
                        fo_texts[fp] = src_path.read_text(
                            errors="replace",
                        )
        if fo_texts:
            fail_open_census = run_fail_open_census(
                fo_texts,
                out_dir=config.out_dir,
                annotations_dir=getattr(config, "annotations_dir", None),
                inventory=getattr(config, "inventory", None),
                context_map=context_map,
            )
            n_fo_leads = seed_fail_open_leads(
                gaps, fail_open_census.get("leads", []),
            )
            if n_fo_leads:
                logger.info(
                    "fail-open census: %d handler leads seeded onto "
                    "gaps", n_fo_leads,
                )
            if config.out_dir:
                with contextlib.suppress(Exception):
                    append_audit_log(config.out_dir, {
                        "action": "fail_open_census",
                        **(fail_open_census.get("telemetry") or {}),
                    })
    except Exception:
        logger.debug("fail-open census failed", exc_info=True)

    # Field-access census + phase-A lifecycle channel pre-passes
    # (five-channel programme §0/§3/§5): the shared field-census.json
    # artifact, ptr_lifecycle leg-A parity leads (consistency
    # namespace, detection grade) + leg-B stale-alias candidates, and
    # lock_region callback-under-lock candidates. Mechanical entries
    # and injected hypotheses only — verdicts stay with the dispatch
    # channels (G1 holds: the hypothesis exists before any finding).
    try:
        from .condition_smt import DomainVocabulary
        from .fail_open_roles import RoleContext as _CensusRoleCtx
        from .field_census import (
            build_field_census_cached,
            priority_fields_from_study_list,
            seed_injected_hypotheses,
            write_census_artifact,
        )
        from .lock_region import run_lock_region_prepass
        from .ptr_lifecycle import run_ptr_lifecycle_prepass

        census_texts: dict[str, str] = {}
        for gap in gaps:
            fp = gap.get("file", "")
            if fp and fp not in census_texts:
                with contextlib.suppress(Exception):
                    src_path = config.target_path / fp
                    if src_path.is_file():
                        census_texts[fp] = src_path.read_text(
                            errors="replace",
                        )
        if census_texts:
            channel_vocab = DomainVocabulary.from_domain_model(
                prep_domain_model, target_path=config.target_path,
            )
            field_census = build_field_census_cached(
                census_texts,
                out_dir=config.out_dir,
                priority_fields=priority_fields_from_study_list(
                    config.out_dir,
                ),
            )
            if config.out_dir:
                write_census_artifact(field_census, config.out_dir)
            census_ctx = _CensusRoleCtx(
                out_dir=config.out_dir,
                annotations_dir=getattr(
                    config, "annotations_dir", None,
                ),
                inventory=getattr(config, "inventory", None),
                context_map=context_map,
            )
            # Per-channel isolation: one channel's crash must not take
            # its sibling down. In production a ptr_lifecycle
            # IndexError aborted this whole block BEFORE lock_region
            # ran — the callback-under-lock sweep never happened and
            # the only trace was a debug-level line. Degradation is
            # loud (WARNING): a standing channel that silently stops
            # covering its claim class is the failure mode the
            # channels exist to prevent.
            def _census_prepass(label, fn, /, **kw):
                try:
                    return fn(census_texts, **kw)
                except Exception:
                    logger.warning(
                        "%s prepass failed — channel degraded for "
                        "this run (no %s coverage)",
                        label, label, exc_info=True,
                    )
                    return {}

            pl_prepass = _census_prepass(
                "ptr_lifecycle", run_ptr_lifecycle_prepass,
                census=field_census,
                domain_vocab=channel_vocab,
                inventory=getattr(config, "inventory", None),
                context=census_ctx,
            )
            lr_prepass = _census_prepass(
                "lock_region", run_lock_region_prepass,
                domain_vocab=channel_vocab,
                inventory=getattr(config, "inventory", None),
                context=census_ctx,
            )
            n_channel_seeded = 0
            for chan_prepass, action, source_tag in (
                (pl_prepass, "ptr_lifecycle_prepass",
                 "ptr_lifecycle_census"),
                (lr_prepass, "lock_region_prepass",
                 "lock_region_census"),
            ):
                for mf in chan_prepass.get("mechanical", []):
                    key = f"{mf['file']}:{mf['function']}"
                    mechanical_findings.setdefault(key, []).append(mf)
                n_channel_seeded += seed_injected_hypotheses(
                    gaps, chan_prepass.get("handoffs", []),
                    source=source_tag,
                )
                if config.out_dir:
                    with contextlib.suppress(Exception):
                        append_audit_log(config.out_dir, {
                            "action": action,
                            **(chan_prepass.get("telemetry") or {}),
                        })
            if n_channel_seeded:
                logger.info(
                    "lifecycle channel prepass: %d handoff "
                    "hypotheses injected",
                    n_channel_seeded,
                )
    except Exception:
        logger.warning(
            "lifecycle channel prepass block failed — ptr_lifecycle "
            "and lock_region coverage degraded for this run",
            exc_info=True,
        )

    # Five-channel standing prepasses (adjacent to — and independent
    # of — the consistency prepass block above): each channel sweeps
    # the same source set, emits mechanical-findings entries plus
    # injected hypotheses on the matching gaps (the fix_history
    # mechanically-injected-hypothesis precedent), and appends its
    # telemetry to the audit log. Channel list grows per landed
    # channel; every entry degrades independently.
    _channel_prepasses: list[tuple[str, str]] = [
        ("resource_bounds", "run_resource_bounds_prepass"),
        ("release_order", "run_release_order_prepass"),
        ("protocol_state", "run_protocol_state_prepass"),
    ]
    for _ch_name, _ch_fn in _channel_prepasses:
        try:
            import importlib
            _ch_mod = importlib.import_module(
                f"core.audit.{_ch_name}",
            )
            _ch_run = getattr(_ch_mod, _ch_fn)

            _ch_texts: dict[str, str] = {}
            for gap in gaps:
                fp = gap.get("file", "")
                if fp and fp not in _ch_texts:
                    with contextlib.suppress(Exception):
                        src_path = config.target_path / fp
                        if src_path.is_file():
                            _ch_texts[fp] = src_path.read_text(
                                errors="replace",
                            )
            if not _ch_texts:
                continue
            from .fail_open_roles import RoleContext as _ChRoleCtx
            _ch_out = _ch_run(
                _ch_texts,
                target_path=config.target_path,
                out_dir=config.out_dir,
                inventory=getattr(config, "inventory", None),
                context=_ChRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                    context_map=context_map,
                ),
                domain_model=prep_domain_model,
            )
            for mf in _ch_out.get("mechanical", []):
                key = f"{mf['file']}:{mf['function']}"
                mechanical_findings.setdefault(key, []).append(mf)
            _ch_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for lead in _ch_out.get("leads", []):
                _ch_by_key.setdefault(
                    (lead.get("file", ""), lead.get("function", "")),
                    [],
                ).append(lead)
            _ch_seeded = 0
            for gap in gaps:
                key = (gap.get("file", ""), gap.get("name", ""))
                for lead in _ch_by_key.get(key, []):
                    if not lead.get("mechanism"):
                        continue
                    gap.setdefault("injected_hypotheses", []).append({
                        "mechanism": lead["mechanism"],
                        "confidence": "medium",
                        "source": f"{_ch_name}_prepass",
                    })
                    _ch_seeded += 1
            if _ch_seeded:
                logger.info(
                    "%s prepass: %d hypothesis lead(s) injected",
                    _ch_name, _ch_seeded,
                )
            if config.out_dir:
                with contextlib.suppress(Exception):
                    append_audit_log(config.out_dir, {
                        "action": f"{_ch_name}_prepass",
                        **(_ch_out.get("telemetry") or {}),
                    })
        except Exception:
            logger.warning(
                "%s prepass failed — channel degraded for this run",
                _ch_name, exc_info=True,
            )

    if mechanical_findings and config.out_dir:
        try:
            mech_path = config.out_dir / "mechanical-findings.json"
            save_json(mech_path, mechanical_findings)
            logger.info(
                "wrote %d mechanical-detector findings to %s "
                "(separate from the Layer 0 source-pattern pre-sweep)",
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
        "edge_pass_summary": _edge_pass_summary,
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
        "vendored_triage_counts": vendored_triage_counts,
        "vendor_verdicts": vendor_verdicts,
        "conventions": conventions,
        "sibling_ns_findings": sibling_ns_findings,
        "peer_groups": peer_groups,
        "sibling_postcond_violations": sibling_postcond_violations,
        "capability_displacements": capability_displacements,
        "struct_accessor_index": struct_accessor_index,
        "semantic_findings": semantic_findings,
        "mechanical_findings": mechanical_findings,
        "consistency_prepass": consistency_prepass,
        "fail_open_census": fail_open_census,
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
        "reuse_candidates": reuse_candidates,
        "reuse_blocked_stats": reuse_blocked_stats,
    }


def _review_duration_hints(
    workqueue: list[dict[str, Any]],
    triage_results: dict[str, Any] | None,
) -> dict[str, float]:
    """Predicted relative review duration per task key (LPT input).

    Review duration correlates with context size, which is known at
    dispatch: the triage token budget is the coarse per-class signal
    (glance 500 / investigate 6k / deep-dive 50k — an order of
    magnitude apart, matching the observed 62-317s per-call spread),
    and SLOC orders functions within a class. The value is a relative
    rank, not seconds — only the ordering matters to the scheduler.
    """
    hints: dict[str, float] = {}
    for gap in workqueue:
        key = f"{gap['file']}:{gap['name']}:{gap.get('line_start', 0)}"
        budget = 0
        if triage_results:
            tr = triage_results.get(key) or triage_results.get(
                f"{gap['file']}:{gap['name']}",
            )
            budget = getattr(tr, "token_budget", 0) or 0
        sloc = gap.get("sloc") or 0
        if not sloc:
            ls, le = gap.get("line_start") or 0, gap.get("line_end") or 0
            if le and ls and le >= ls:
                sloc = le - ls + 1
        hints[key] = float(budget + sloc)
    return hints


_IRIS_JOERN_PAIR_BUDGET = 64


def _make_iris_joern_tool_runner(joern_server) -> Callable:
    """Build the IRIS refinement ToolRunner backed by the live Joern server.

    Mirrors ``core.iris.codeql_runner.make_codeql_tool_runner``: the
    returned callable takes the current spec list, exercises the tool,
    and reports which specs the tool confirmed (``RefinementFeedback``
    keyed by the persistent-store spec key).  Source specs are checked
    pairwise against sink specs via targeted live taint queries; a
    flow confirms both endpoints.  The pair walk is budgeted so a
    spec-heavy round cannot monopolise the single-threaded REPL.
    """

    def joern_tool_runner(specs):
        from core.iris.refine import RefinementFeedback
        from core.iris.store import _spec_key

        sources = [s for s in specs if s.role == "source"]
        sinks = [s for s in specs if s.role == "sink"]
        if not sources or not sinks:
            return RefinementFeedback()
        confirmed: list[str] = []
        errors: list[str] = []
        seen: set[str] = set()
        budget = _IRIS_JOERN_PAIR_BUDGET
        attempts = 0
        successes = 0
        for src in sources:
            if budget <= 0:
                break
            for snk in sinks:
                if budget <= 0:
                    break
                budget -= 1
                attempts += 1
                # Per-pair error accounting: an empty flow list with a
                # populated errors_out is "unanswered", not "no flow".
                # The refine loop needs the distinction — a round in
                # which every query degraded carries zero signal and
                # must not converge or persist (RefinementFeedback.
                # zero_signal).
                pair_errors: list = []
                flows = _joern_live_query(
                    joern_server,
                    src.function,
                    [snk.function],
                    label="iris-refine",
                    errors_out=pair_errors,
                )
                if flows or not pair_errors:
                    successes += 1
                if pair_errors:
                    errors.extend(str(e) for e in pair_errors)
                if not flows:
                    continue
                for spec in (src, snk):
                    key = _spec_key(spec)
                    if key not in seen:
                        seen.add(key)
                        confirmed.append(key)
        return RefinementFeedback(
            confirmed_keys=confirmed,
            tool_errors=errors,
            n_attempts=attempts,
            n_successes=successes,
        )

    return joern_tool_runner


def _heuristic_bypass_findings(
    gaps: list[dict[str, Any]],
    bypass_runner: Callable | None,
) -> list[dict[str, Any]]:
    """Stored-taint / config-provenance assumption bypass detection.

    *bypass_runner* is ``None`` when IRIS refinement did not build a
    compositional analyzer (no candidates, missing call graphs, or the
    refine imports failed) — nothing to check then.
    """
    findings: list[dict[str, Any]] = []
    if bypass_runner is None:
        return findings
    try:
        from core.iris.synthesise import (
            config_provenance_assumptions,
            stored_taint_assumptions,
        )

        heuristic_assumptions = stored_taint_assumptions(
            gaps
        ) + config_provenance_assumptions(gaps)
        heuristic_with_enforcers = [
            a for a in heuristic_assumptions if a.enforced_by
        ]
        if heuristic_with_enforcers:
            findings.extend({
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
                        "missing_enforcer": bf.missing_enforcer,
                    } for bf in bypass_runner(heuristic_with_enforcers))
    except Exception:
        logger.debug("IRIS heuristic assumption bypass failed", exc_info=True)
    return findings


def _write_iris_bypass_findings(
    out_dir: Path,
    bypass_findings: list[Any],
) -> None:
    """Serialize refine-loop bypass findings round-trippably.

    Uses ``BypassFinding.to_dict()`` so ``core.iris.api.
    get_bypass_findings`` can reconstruct the objects — the previous
    hand-rolled dict stringified the assumption and dropped
    ``evidence_tier`` / ``line_info`` / transitivity, making the file
    unreadable by its own reader.
    """
    try:
        path = out_dir / "iris-bypass-findings.json"
        save_json(
            path,
            [
                bf.to_dict()
                for bf in bypass_findings
                if hasattr(bf, "to_dict") and hasattr(bf, "caller_file")
            ],
        )
    except Exception:
        logger.debug("iris bypass findings write failed", exc_info=True)


def _refine_bypass_post_loop_findings(
    bypass_findings: list[Any],
    existing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert IRIS refine-loop bypass findings to post-loop entries.

    The compositional (tool-confirmed-spec) bypass findings used to be
    serialized to ``iris-bypass-findings.json`` and dropped every run —
    this routes them through the same post-loop path the heuristic
    bypasses already take (journal as ``suspicious`` + graded export),
    deduplicated against the heuristic pass on
    ``(file, function, missing_enforcer)``.
    """
    seen = {
        (
            f.get("file", ""),
            f.get("function", ""),
            f.get("missing_enforcer", ""),
        )
        for f in existing
        if str(f.get("check", "")).startswith("iris_")
    }
    out: list[dict[str, Any]] = []
    for bf in bypass_findings or []:
        if not hasattr(bf, "caller_file"):
            continue
        key = (bf.caller_file, bf.caller_function, bf.missing_enforcer)
        if key in seen:
            continue
        seen.add(key)
        assumption = getattr(bf, "assumption", None)
        bug_class = getattr(assumption, "bug_class", "") or ""
        target = getattr(assumption, "target", "") or ""
        if getattr(bf, "ordering_violation", False):
            kind = "ordering violation"
        elif getattr(bf, "is_transitive", False):
            kind = "transitive bypass"
        else:
            kind = "bypass"
        entry: dict[str, Any] = {
            "check": f"iris_{bug_class or 'bypass'}",
            "title": (
                f"IRIS {kind}: {bf.caller_function}"
                f" skips {bf.missing_enforcer}"
            ),
            "description": (
                f"Caller {bf.caller_file}:{bf.caller_function} reaches "
                f"{target} without {bf.missing_enforcer}"
            ),
            "file": bf.caller_file,
            "function": bf.caller_function,
            "cwe": bug_class,
            "confidence": "medium",
            "missing_enforcer": bf.missing_enforcer,
            "source": "iris_refine_loop",
        }
        try:
            entry["evidence"] = bf.to_dict()
        except Exception:
            logger.debug("bypass finding to_dict failed", exc_info=True)
        line_info = getattr(bf, "line_info", None) or {}
        lines = [
            v for v in line_info.values() if isinstance(v, int) and v > 0
        ]
        if lines:
            entry["line_start"] = min(lines)
            entry["line_end"] = max(lines)
        out.append(entry)
    return out


# Refine-loop bypass findings routed into the same-run review pass are
# bounded: each one costs a full LLM review.
_MAX_BYPASS_REVIEWS = 5


def _bypass_findings_to_gaps(
    bypass_plfs: list[dict[str, Any]],
    checklist: dict[str, Any],
    *,
    max_reviews: int = _MAX_BYPASS_REVIEWS,
) -> list[dict[str, Any]]:
    """Resolve refine-loop bypass findings to reviewable gaps.

    Mirrors ``_synthesis_hits_to_gaps``: checklist resolution via
    ``gap_for_site``, dedup per function, provenance marked
    (``from_bypass``), and the bypass mechanism carried as an injected
    hypothesis so the review prompt investigates it concretely.
    """
    from .gaps import gap_for_site

    gaps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for plf in bypass_plfs:
        if len(gaps) >= max_reviews:
            break
        file_path = plf.get("file", "")
        func = plf.get("function", "")
        if not file_path or not func:
            continue
        gap = None
        try:
            line = int(plf.get("line_start") or 0)
        except (TypeError, ValueError):
            line = 0
        if line > 0:
            gap = gap_for_site(checklist, file_path, line)
        if gap is None:
            decl_line = _checklist_function_line(checklist, file_path, func)
            if decl_line:
                gap = gap_for_site(checklist, file_path, decl_line)
        if gap is None:
            continue
        key = f"{gap['file']}:{gap['name']}"
        if key in seen:
            continue
        seen.add(key)
        gap["priority_score"] = max(
            float(gap.get("priority_score") or 0.0), 0.9,
        )
        gap["from_bypass"] = True
        mechanism = (
            f"{plf.get('title', '')}: {plf.get('description', '')}"
        ).strip(": ")[:300]
        gap["injected_hypotheses"] = [
            {
                "mechanism": mechanism,
                "confidence": plf.get("confidence", "medium"),
                "source": "iris_bypass",
            }
        ]
        gaps.append(gap)
    return gaps


def _fail_open_adjudicated_sites(out_dir: Path | None) -> set:
    """(file, line) pairs the fail_open channel already adjudicated —
    the CWE-252 premise-split dedup: the census defers, the
    fail_open verdict wins (deeper role+fallibility receipts)."""
    sites: set = set()
    if not out_dir:
        return sites
    try:
        for record in load_audit_log(out_dir):
            if record.get("action") != "fail_open_check":
                continue
            if record.get("outcome") not in ("confirmed", "refuted"):
                continue
            fp = record.get("file", "")
            handler = record.get("handler") or {}
            if fp and handler.get("line"):
                sites.add((fp, int(handler["line"])))
            for s in record.get("sites") or []:
                if isinstance(s, dict) and fp and s.get("line"):
                    sites.add((fp, int(s["line"])))
    except Exception:
        logger.debug("fail_open site collection failed", exc_info=True)
    return sites


def _consistency_synthetic_outcomes(
    consistency_prepass: dict[str, Any],
    outcomes: list[Any],
    out_dir: Path | None,
) -> list[Any]:
    """Synthesized-hypothesis outcomes for the census pre-pass's
    LLM-free confirmations (§2.3, the ``fix_history``
    mechanically-injected-hypothesis precedent — G1 holds because the
    hypothesis exists before the finding). Registry-grade
    confirmations carry their promote-capable ``consistency:*``
    receipt; detection-grade (majority-only) stay ``suspicious``.
    Deduplicates against functions that already export an outcome and
    against fail_open-adjudicated (file, line) sites."""
    findings = (consistency_prepass or {}).get("findings") or []
    if not findings:
        return []
    existing = {
        (getattr(o, "file", ""), getattr(o, "function", ""))
        for o in outcomes
        if getattr(o, "status", "") in ("finding", "suspicious", "dark")
    }
    fail_open_sites = _fail_open_adjudicated_sites(out_dir)
    extra: list[Any] = []
    for f in findings:
        file_path = f.get("file", "")
        func = f.get("function", "")
        line = int(f.get("line") or 0)
        if not file_path or not func:
            continue
        if (file_path, func) in existing:
            continue
        if (file_path, line) in fail_open_sites:
            logger.info(
                "consistency finding at %s:%d deferred — fail_open "
                "adjudicated this site (premise-split dedup)",
                file_path, line,
            )
            continue
        existing.add((file_path, func))
        extra.append(SimpleNamespace(
            file=file_path,
            function=func,
            line=line,
            status=f.get("status", "suspicious"),
            body=f"[consistency:{f.get('dimension', '')}] "
                 f"{f.get('description', '')}",
            hypothesis=f.get("hypothesis", ""),
            hypotheses=None,
            review_result={
                "hypothesis": f.get("hypothesis", ""),
                "cwe_class": f.get("cwe", ""),
                "consistency_receipts": f.get("receipts") or {},
            },
            evidence_tool=f.get("evidence_tool", ""),
            tools_dispatched={"consistency"},
            discovered_by="consistency_census",
            model="",
            cost_usd=0.0,
            duration_s=0.0,
        ))
    return extra


def _journal_undischarged_leads(
    consistency_prepass: dict[str, Any],
    outcomes: list[Any],
    out_dir: Path | None,
) -> None:
    """``consistency_lead:undischarged`` telemetry: leads
    seeded onto gaps whose function never reached a review."""
    if not out_dir:
        return
    leads = (consistency_prepass or {}).get("leads") or []
    if not leads:
        return
    reviewed = {
        (getattr(o, "file", ""), getattr(o, "function", ""))
        for o in outcomes
    }
    undischarged = [
        ld for ld in leads
        if (ld.get("file", ""), ld.get("function", "")) not in reviewed
    ]
    if not undischarged:
        return
    try:
        append_audit_log(out_dir, {
            "action": "consistency_lead:undischarged",
            "count": len(undischarged),
            "leads": [
                {
                    "dimension": ld.get("dimension", ""),
                    "callee": ld.get("callee", ""),
                    "file": ld.get("file", ""),
                    "function": ld.get("function", ""),
                    "line": ld.get("line", 0),
                }
                for ld in undischarged[:20]
            ],
        })
    except Exception:
        logger.debug("undischarged-lead telemetry failed", exc_info=True)


def _journal_undischarged_fail_open_leads(
    fail_open_census: dict[str, Any],
    outcomes: list[Any],
    out_dir: Path | None,
) -> None:
    """``fail_open_lead:undischarged`` telemetry: census
    leads seeded onto gaps whose function never reached a review —
    the negative-space-style absence-is-signal bookkeeping."""
    if not out_dir:
        return
    leads = (fail_open_census or {}).get("leads") or []
    if not leads:
        return
    reviewed = {
        (getattr(o, "file", ""),
         (getattr(o, "function", "") or "").rsplit(".", 1)[-1])
        for o in outcomes
    }
    undischarged = [
        ld for ld in leads
        if (ld.get("file", ""),
            (ld.get("function", "") or "").rsplit(".", 1)[-1])
        not in reviewed
    ]
    if not undischarged:
        return
    try:
        append_audit_log(out_dir, {
            "action": "fail_open_lead:undischarged",
            "count": len(undischarged),
            "leads": [
                {
                    "idiom": ld.get("idiom", ""),
                    "role_kind": ld.get("role_kind", ""),
                    "role_source": ld.get("role_source", ""),
                    "file": ld.get("file", ""),
                    "function": ld.get("function", ""),
                    "line": ld.get("line", 0),
                }
                for ld in undischarged[:20]
            ],
        })
    except Exception:
        logger.debug("undischarged fail-open lead telemetry failed",
                     exc_info=True)


def _checklist_function_line(
    checklist: dict[str, Any],
    file_path: str,
    function_name: str,
) -> int:
    """Declaration line of *function_name* in *file_path*, or 0."""
    for f in checklist.get("files", []):
        if f.get("path") != file_path:
            continue
        items = f.get("items", f.get("functions", [])) or []
        for item in items:
            if item.get("name") == function_name:
                try:
                    return int(item.get("line_start") or 0)
                except (TypeError, ValueError):
                    return 0
    return 0


def _bypass_export_outcomes(
    post_loop_findings: list[dict[str, Any]],
    outcomes: list[Any],
) -> list[Any]:
    """Synthetic suspicious outcomes for IRIS bypass post-loop findings.

    Bypass findings (heuristic and refine-loop) reached only the
    journal; ``export_findings`` iterates outcomes, so the whole
    CWE-862/306-shaped class was invisible in findings-graded.json.
    Deduplicates against functions that already export an outcome.
    """
    existing = {
        (getattr(o, "file", ""), getattr(o, "function", ""))
        for o in outcomes
        if getattr(o, "status", "") in ("finding", "suspicious", "dark")
    }
    extra: list[Any] = []
    for plf in post_loop_findings:
        if not str(plf.get("check", "")).startswith("iris_"):
            continue
        file_path = plf.get("file", "")
        func = plf.get("function", "")
        if not file_path or not func or (file_path, func) in existing:
            continue
        existing.add((file_path, func))
        o = SimpleNamespace(
            file=file_path,
            function=func,
            line=int(plf.get("line_start") or 0),
            status="suspicious",
            hypothesis=plf.get("title", ""),
            review_result={
                "hypothesis": plf.get("description", ""),
                "cwe_class": plf.get("cwe", ""),
            },
            evidence_tool="",
            discovered_by="iris_bypass",
            model="",
            cost_usd=0.0,
        )
        extra.append(o)
    return extra


def _attach_bypass_evidence(
    graded: dict[str, Any],
    post_loop_findings: list[dict[str, Any]],
) -> None:
    """Attach the compositional bypass evidence to exported findings."""
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for plf in post_loop_findings:
        if not str(plf.get("check", "")).startswith("iris_"):
            continue
        by_key.setdefault(
            (plf.get("file", ""), plf.get("function", "")), plf,
        )
    for finding in graded.get("findings", []):
        disc = finding.get("discovery", {})
        if disc.get("discovered_by") != "iris_bypass":
            continue
        plf = by_key.get((finding.get("file", ""), finding.get("function", "")))
        if not plf:
            continue
        chain = finding.setdefault("evidence_chain", [])
        chain.append(
            {
                "source": "iris:bypass_detector",
                "confidence": plf.get("confidence", "medium"),
                "description": (
                    "compositional bypass detection: caller reaches the "
                    "assumption target without the enforcer"
                ),
            }
        )
        if plf.get("evidence"):
            finding["iris_bypass_evidence"] = plf["evidence"]


def _demotion_log_entry(d) -> dict:
    """Audit-log record for one confidence-propagation demotion.

    ``source_functions`` carries the full evidentiary basis for the
    verdict flip — ``d.reason`` truncates the caller list at 5.
    """
    return {
        "action": "sweep_promotion",
        "key": f"{d.file}:{d.function}:0",
        "status": "clean",
        "prior_status": "suspicious",
        "evidence_tool": "confidence_propagation",
        "model": "",
        "cost_usd": 0.0,
        "duration_s": 0.0,
        "hypothesis": d.reason,
        "source_functions": d.source_functions,
    }


def _cleanup_after_executor_failure(
    throttle: Any,
    study_queue: Any,
    study_consumer_thread: Any,
    collector: Any,
) -> None:
    """Best-effort teardown when the main review executor raises.

    Runs the same drain/close/flush steps the success path performs
    after the executor returns, so an executor crash cannot leak the
    study consumer (blocked on its queue forever), the throttle's
    cooldown thread, or the collector's buffered outcomes/audit log.
    Every step is individually guarded — the caller re-raises the
    original exception.
    """
    if study_queue is not None:
        try:
            study_queue.signal_producer_done()
        except Exception:
            logger.debug(
                "study queue shutdown failed during executor-failure "
                "cleanup", exc_info=True,
            )
    if study_consumer_thread is not None:
        try:
            _drain_study_consumer(
                study_consumer_thread, study_queue, budget_exhausted=True,
            )
        except Exception:
            logger.debug(
                "study consumer drain failed during executor-failure "
                "cleanup", exc_info=True,
            )
    try:
        throttle.close()
    except Exception:
        logger.debug(
            "throttle close failed during executor-failure cleanup",
            exc_info=True,
        )
    if collector is not None:
        try:
            collector.flush()
        except Exception:
            logger.warning(
                "collector flush failed during executor-failure cleanup "
                "— buffered outcomes may be lost", exc_info=True,
            )




_PHASE_ABORTS_FILENAME = "phase-aborts.json"


def _record_phase_abort(config: Any, result: Any, exc: Exception) -> None:
    """Record a phase-level ABORT on persistent LLM auth refusal.

    Fail-closed counterpart to the phases' degrade paths: when a
    phase raises ``LLMAuthPersistentError`` (dead dispatcher token,
    revoked key — every call refused), its output is auth-refusal
    zero-fill, not a real empty result. Three sinks, deduplicated per
    phase: an ERROR log line, ``result.phase_aborts`` (run summary),
    and ``<out_dir>/phase-aborts.json`` — the sidecar survives the
    process and is folded into ``audit-report.json`` by
    ``generate_report``, so downstream consumers of the run state see
    "phase aborted", never "phase found nothing".
    """
    phase = str(getattr(exc, "phase", "") or "unknown")
    entry_text = f"{phase}: {exc}"
    if result is not None:
        with result._lock:
            already = any(
                a.split(":", 1)[0] == phase for a in result.phase_aborts
            )
            if not already:
                result.phase_aborts.append(entry_text)
        if already:
            logger.debug("phase abort repeat suppressed: %s", phase)
            return
    logger.error(
        "PHASE ABORT — %s. The phase produced NO trustworthy output "
        "(recorded in %s); its empty results must not be read as "
        "\"nothing found\".",
        entry_text, _PHASE_ABORTS_FILENAME,
    )
    out_dir = getattr(config, "out_dir", None)
    if not out_dir:
        return
    try:
        path = Path(out_dir) / _PHASE_ABORTS_FILENAME
        records: list = []
        if path.is_file():
            loaded = load_json(path, max_bytes=_MAX_STATE_BYTES)
            if isinstance(loaded, list):
                records = loaded
        if any(
            isinstance(r, dict) and r.get("phase") == phase
            for r in records
        ):
            return
        records.append({
            "phase": phase,
            "error": str(exc),
            "ts": time.time(),
        })
        save_json(path, records)
    except Exception:  # noqa: BLE001 — recording must not mask the abort
        logger.warning(
            "phase-abort sidecar write failed for %s", phase,
            exc_info=True,
        )


def _clear_phase_abort(
    config: Any, *phases: str, result: Any = None,
) -> None:
    """Supersede stale sidecar abort records for *phases*.

    A run that aborted a phase, then was reopened/resumed with a fixed
    credential and COMPLETED the phase, must not keep reporting "Phase
    aborts" for output that now exists — the sidecar survives in the
    shared out_dir across segments. Called by each protected phase
    driver on successful completion; a phase that aborted THIS call
    never reaches its clear (the abort path returns first). Best-effort
    like the recorder.

    ``result``: the current run's in-memory state. A phase name several
    drivers share ("checker-synthesis": mid-loop, external seeds,
    post-loop auto-rules) can abort in one leg and complete in a LATER
    leg of the SAME run — that completion supersedes nothing, the
    aborted leg's work is still lost. Phases recorded in
    ``result.phase_aborts`` are therefore never cleared; only records a
    PRIOR segment left behind (absent from this run's memory) are
    stale. Fail-noisy by construction: a kept record makes the operator
    look, a dropped one hides real loss.
    """
    if result is not None:
        # Duck-typed guard: drivers are exercised with stub results in
        # tests, and the supersede is best-effort — a result without
        # abort state reads as "no in-run aborts", the pre-guard
        # behaviour.
        try:
            with result._lock:
                aborted_this_run = {
                    a.split(":", 1)[0] for a in result.phase_aborts
                }
        except AttributeError:
            aborted_this_run = set()
        phases = tuple(p for p in phases if p not in aborted_this_run)
        if not phases:
            return
    out_dir = getattr(config, "out_dir", None)
    if not out_dir:
        return
    path = Path(out_dir) / _PHASE_ABORTS_FILENAME
    if not path.is_file():
        return
    try:
        loaded = load_json(path, max_bytes=_MAX_STATE_BYTES)
        if not isinstance(loaded, list):
            return
        keep = [
            r for r in loaded
            if not (isinstance(r, dict) and r.get("phase") in phases)
        ]
        if len(keep) == len(loaded):
            return
        if keep:
            save_json(path, keep)
        else:
            path.unlink()
        logger.info(
            "phase abort record(s) superseded — %s completed on this "
            "run", ", ".join(sorted(set(phases))),
        )
    except Exception:  # noqa: BLE001 — supersede is best-effort
        logger.debug("phase-abort supersede failed", exc_info=True)


def _iris_refine_and_bypass(
    config: OrchestratorConfig,
    gaps: list[dict[str, Any]],
    taint_summary_results: dict | None,
    joern_server: Any,
    checklist: dict[str, Any],
    iris_taint_specs: list,
    result: Any = None,
) -> tuple[Any, list[Any]]:
    """IRIS post-loop seam: refinement loop + bypass detection.

    Returns ``(bypass_runner, iris_bypass_findings)`` — always bound,
    ``(None, [])`` when nothing refines. Gated by ``config.iris``: a
    cold-profile run skips the refine loop, its prior_specs store
    reads, and the bypass analyzer entirely (announced once at run
    start by _apply_profile_gates).

    ``result`` (the run's OrchestratorResult, when the caller has it)
    receives the phase-abort record on persistent LLM auth refusal.
    """
    if not getattr(config, "iris", True):
        return None, []

    bypass_runner = None
    iris_bypass_findings: list[Any] = []
    try:
        from core.iris.refine import refine_loop as iris_refine_loop

        from .iris_specs import identify_candidates

        taint_chain_callees_post: set[str] = set()
        if taint_summary_results:
            for _ts_summ in taint_summary_results.values():
                for _ts_callee in getattr(_ts_summ, "callees", []):
                    taint_chain_callees_post.add(_ts_callee)
        iris_candidates = identify_candidates(
            gaps,
            taint_chain_callees=taint_chain_callees_post,
        )
        if iris_candidates:
            joern_tool_runner = None
            if joern_server is not None:
                joern_tool_runner = _make_iris_joern_tool_runner(joern_server)

            bypass_runner = None
            try:
                from core.iris import CompositionalAnalyzer

                call_graphs = _load_call_graphs_cached(
                    config.target_path, checklist,
                )
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
                # Budget-governed client: iris refinement spend must hit
                # the run ledger and the reservation gate (a private
                # client once dispatched an iris call 11 minutes after
                # budget exhaustion).
                iris_llm = _run_llm_client(config)
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

            # Prior specs: persistent project store + the run-local
            # refined artifact (resume / re-entry continuity), then
            # this run's heuristic candidates. merge_specs keeps the
            # higher evidence tier on collision, so a tool-confirmed
            # spec from a previous round is never demoted by a fresh
            # heuristic candidate.
            prior_specs = iris_taint_specs or []
            try:
                from core.iris.store import (
                    load_refined_specs as _iris_load_refined,
                )
                from core.iris.store import (
                    load_specs as _iris_load_store,
                )
                from core.iris.store import (
                    merge_specs as _iris_merge,
                )

                _iris_prior_store: list = []
                _iris_prior_refined: list = []
                if config.out_dir:
                    _iris_prior_store = _iris_load_store(
                        config.out_dir,
                        target_path=Path(config.target_path),
                    )
                    _iris_prior_refined = _iris_load_refined(
                        config.out_dir,
                    )
                if _iris_prior_store or _iris_prior_refined:
                    prior_specs = _iris_merge(
                        _iris_merge(
                            _iris_prior_store, _iris_prior_refined,
                        ),
                        prior_specs,
                    )
                    logger.info(
                        "IRIS: seeded refine loop with %d prior specs "
                        "(%d store, %d refined artifact)",
                        len(prior_specs), len(_iris_prior_store),
                        len(_iris_prior_refined),
                    )
            except Exception:
                logger.debug(
                    "IRIS prior-spec load failed", exc_info=True,
                )
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
                    # Caller-persist step: merge the refined specs
                    # into the persistent project store (evidence
                    # tiers carried through; envelope metadata —
                    # history, assumptions, target — preserved).
                    # Suppression-direction readers are tier-gated in
                    # core.iris.api, so heuristic-tier refined specs
                    # land as prompt-only hints, never suppression.
                    try:
                        from dataclasses import asdict as _dc_asdict

                        from core.iris.store import (
                            checklist_sha as _iris_cl_sha,
                        )
                        from core.iris.store import (
                            persist_refined_specs as _iris_persist,
                        )

                        _iris_persist(
                            config.out_dir,
                            refined_specs,
                            cl_sha=(
                                _iris_cl_sha(checklist)
                                if checklist else ""
                            ),
                            history=[_dc_asdict(r) for r in history],
                            assumptions=assumptions or None,
                            target_path=Path(config.target_path),
                        )
                    except Exception:
                        logger.debug(
                            "IRIS refined-spec store persist failed",
                            exc_info=True,
                        )

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
                iris_bypass_findings = [
                    bf for bf in bypass_findings
                    if hasattr(bf, "caller_file")
                ]
                if config.out_dir:
                    _write_iris_bypass_findings(
                        config.out_dir, iris_bypass_findings,
                    )
    except Exception as exc:
        from core.llm.client import LLMAuthPersistentError
        if isinstance(exc, LLMAuthPersistentError):
            # Persistent auth refusal: the refine loop's output would
            # be zero-filled refusals (observed: iris-assumptions 0/6,
            # iris.synthesise 0 assumptions after 690 straight 401s).
            # Abort the phase loudly and record it in run state — do
            # NOT let the debug-level degrade path read as success.
            _record_phase_abort(config, result, exc)
        else:
            logger.debug("IRIS refinement/bypass failed", exc_info=True)
    else:
        # Completed without an abort: supersede any stale sidecar
        # record a prior (reopened/resumed) segment left behind.
        _clear_phase_abort(config, "iris-synth", "iris-assumptions",
                            result=result)
    return bypass_runner, iris_bypass_findings


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

    # --- Review budget reserve ---
    # Held before ANY bulk pass spends (prep, study, synthesis,
    # summaries): they gate against cap - reserve, guaranteeing the
    # per-function review loop its slice. Released right before the
    # executor starts; the deepen reserve then takes over for the
    # announced re-reviews.
    review_reserve_held = _hold_review_reserve(config)

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
    reuse_candidates = _prep.get("reuse_candidates") or {}
    _edge_summary = _prep.get("edge_pass_summary") or {}
    if _edge_summary.get("cost_usd"):
        # Book the prep-phase edge reviews into the ledger — the pass
        # runs before AuditResult exists. One aggregate booking (the
        # per-call telemetry keeps the true call count); popped so a
        # prep-cache reuse pass can never book the same spend twice.
        result.cost_tracker.record_call(
            "edge_review",
            cost_usd=_edge_summary.pop("cost_usd"),
            wall_time_s=_edge_summary.pop("wall_time_s", 0.0),
        )
    # Collapse the fold's per-function refusal map (key → reason
    # class, unique per function) into per-class counts for the
    # summary line.
    _blocked_counts: dict[str, int] = {}
    for _cls in (_prep.get("reuse_blocked_stats") or {}).values():
        _blocked_counts[_cls] = _blocked_counts.get(_cls, 0) + 1
    result.reuse_blocked_reasons = _blocked_counts
    iris_taint_specs = _prep["iris_taint_specs"]
    prior_constraints = _prep["prior_constraints"]
    gaps = _prep["gaps"]
    entry_points = _prep["entry_points"]
    sinks_set = _prep["sinks_set"]
    trust_boundary_set = _prep.get("trust_boundary_set", set())
    priority_scores = _prep["priority_scores"]
    triage_results = _prep["triage_results"]
    _vt_counts = _prep.get("vendored_triage_counts") or {}
    result.vendored_skipped = int(_vt_counts.get("skipped", 0) or 0)
    result.vendored_glanced = int(_vt_counts.get("glanced", 0) or 0)
    conventions = _prep["conventions"]
    sibling_ns_findings = _prep["sibling_ns_findings"]
    peer_groups = _prep["peer_groups"]
    sibling_postcond_violations = _prep["sibling_postcond_violations"]
    capability_displacements = _prep.get("capability_displacements", [])
    struct_accessor_index = _prep.get("struct_accessor_index", {})
    semantic_findings = _prep["semantic_findings"]
    mechanical_findings = _prep["mechanical_findings"]
    consistency_prepass = _prep.get("consistency_prepass") or {}
    fail_open_census = _prep.get("fail_open_census") or {}
    guard_clean_keys = _prep.get("guard_clean_keys", set())

    # Census budget overrun surfaces as a skipped tier count (design
    # §9: abandoned, not an error).
    try:
        if (fail_open_census.get("telemetry") or {}).get(
                "budget_exceeded"):
            result.tier_counters["fail_open"].skipped += 1
    except Exception:
        logger.debug("fail_open census tier seeding failed",
                     exc_info=True)

    # Pre-pass verdict counts surface in tier-diagnostics alongside the
    # in-loop channel adjudications.
    try:
        for counts in (
            (consistency_prepass.get("telemetry") or {})
            .get("dimensions") or {}
        ).values():
            tc = result.tier_counters["consistency"]
            tc.confirmed += counts.get("confirmed", 0)
            tc.refuted += counts.get("refuted", 0)
            tc.inconclusive += counts.get("inconclusive", 0)
    except Exception:
        logger.debug("consistency tier seeding failed", exc_info=True)
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
            save_json(mech_path, mechanical_findings)
        except Exception:
            logger.debug("failed to persist mechanical findings", exc_info=True)

    write_gaps(gaps, config.out_dir)

    # Same-run resume relies on the hash-aware journal fold alone: the
    # audit-log-derived reviewed_set would ALSO suppress the drifted
    # functions the fold deliberately resurfaced for re-review.
    reviewed_set = (
        set()
        if config.force or getattr(config, "same_run_reuse", False)
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
        # --functions filter first, so a kept gap carries force_review
        # BEFORE the mechanical clean-resolvers below — an explicitly
        # selected (or pinned) function must reach a real review, not
        # be resolved by the guard-clean / sarif-clean shortcuts.
        if fn_filter is not None:
            if not _fn_filter_keep(gap, fn_filter):
                result.skipped += 1
                continue
            gap["force_review"] = True
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
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "commit failed for guard-clean %s: %s", key, exc,
                )
            _tally_outcome(result, outcome)
            result.prefilter_skipped += 1
            guard_clean_resolved += 1
            continue
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

    # --- Pre-loop LLM summary pass: callee context for reviews -------
    # The topo sort orders callees before callers, but that alone does
    # NOT guarantee a callee's summary exists when its caller is
    # reviewed: parallel workers review caller and callee concurrently,
    # subsystem grouping re-orders the queue after the sort, and
    # languages with no mechanical summariser (C/C++) never produce
    # one at all. Connected-but-unsummarized functions get a focused
    # LLM summary here, merged into taint_summary_results so the
    # callee-summary lookup in review_one_function finds it.
    # Budget-gated: spend routes through config.llm_budget_client
    # (call class "summary" — reservation-gated per call, booked into
    # the phase ledger by _reconcile_cost_ledgers); without a budget
    # client the pass is skipped rather than spending outside the cap.
    if config.llm_budget_client is None:
        logger.info(
            "llm_summary_pass: skipped — no budget client on this run",
        )
        _increment_tier_dict(result.tier_counters, "llm_summary", "skipped")
    else:
        try:
            from .llm_summaries import (
                identify_summary_candidates,
                run_llm_summary_pass,
            )

            _summ_t0 = time.monotonic()
            summary_candidates = identify_summary_candidates(
                workqueue,
                taint_summary_results,
                checklist,
                call_edges=call_edges,
            )
            if not summary_candidates:
                # Loud-once no-op: a silent zero here is
                # indistinguishable from the pass never running.
                logger.info(
                    "llm_summary_pass: 0 candidates — every connected "
                    "workqueue function already has a mechanical summary",
                )
                _increment_tier_dict(
                    result.tier_counters, "llm_summary", "skipped",
                )
            else:
                llm_summaries = run_llm_summary_pass(
                    summary_candidates,
                    config.target_path,
                    config,
                )
                if taint_summary_results is None:
                    taint_summary_results = {}
                merged = 0
                for sk, sv in llm_summaries.items():
                    if sk not in taint_summary_results:
                        taint_summary_results[sk] = sv
                        merged += 1
                failed = len(summary_candidates) - len(llm_summaries)
                logger.info(
                    "llm_summary_pass: %d candidates → %d summaries "
                    "merged (%d failed/empty)",
                    len(summary_candidates), merged, failed,
                )
                if merged:
                    _increment_tier_dict(
                        result.tier_counters, "llm_summary",
                        "confirmed", merged,
                    )
                if failed > 0:
                    _increment_tier_dict(
                        result.tier_counters, "llm_summary",
                        "errors", failed,
                    )
                _increment_tier_dict(
                    result.tier_counters, "llm_summary", "wall_time_s",
                    time.monotonic() - _summ_t0,
                )
        except Exception:
            logger.warning("pre-loop LLM summary pass failed", exc_info=True)

    constraints = prior_constraints

    prop_config = PropagationConfig(
        max_depth=_adaptive_max_depth(
            config.inventory,
            entry_points,
            operator_override=config.max_propagation_depth,
        ),
        codeql_db_path=config.codeql_db_path,
        codeql_db_for=(lambda f: _codeql_db_for(config, f)),
        target_path=config.target_path,
        binary_verdicts=config.binary_verdicts,
        inventory=config.inventory,
        evidence_index=evidence_index,
        # P23: dominance resolver tier consults the already-running
        # Joern server (caller-owned lifecycle) when the CPG is warm.
        joern_server=joern_server,
    )

    session_observations: list[dict[str, str]] = []
    if config.enable_session_context:
        try:
            session_observations.extend(
                _seed_observations_from_sage(config)
            )
        except Exception:
            logger.debug("SAGE observation seeding failed", exc_info=True)
    discovered_evidence: dict[str, Any] = {}
    reviewed_before_joern: list[dict[str, Any]] = []
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
        )
        from .live_classifications import (
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
        # Buffered audit-log rows must survive a FORCED SIGTERM exit
        # (watchdog expiry / second TERM) — journal rows are appended
        # per-outcome and already safe.
        _sigterm_flush_hooks.append(collector.flush)
    except Exception:
        logger.debug("collector init failed", exc_info=True)

    # --- Domain model: loaded once, reloaded after study loop ---
    domain_model = None
    try:

        domain_model = _load_domain_model(config)
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
                with contextlib.suppress(OSError, ValueError):
                    mech_path = config.out_dir / "mechanical-findings.json"
                    save_json(mech_path, mechanical_findings)
    except Exception:
        logger.debug("invariant prescreening failed", exc_info=True)

    feedback_state = _load_exploit_feedback_raw(
        config.out_dir, load_feedback_state, FeedbackState
    )
    if feedback_state.outcomes:
        logger.info(format_feedback_summary(feedback_state))

    from .demand_explore import ExpansionBudget

    expansion_budget = ExpansionBudget(max_expansions=min(50, len(workqueue)))

    fp_patterns: list[Any] = []
    try:
        from .fp_feedback import load_fp_patterns, scan_fp_patterns

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
    shared.consistency_census = consistency_prepass.get("census")
    shared.discovered_evidence = discovered_evidence
    shared.session_observations = session_observations
    shared.reviewed_before_joern = reviewed_before_joern
    shared.live_classifications = live_classifications

    # --- Executor config ---
    from core.llm.concurrency import derive_max_workers

    from .executor import ExecutorConfig, run_executor_sync
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

    layer_disagreements: list[Any] = []


    # --- Joern tick: drain future between dispatches ---
    joern_state = {"future": joern_future, "submit_time": joern_submit_time}

    def _joern_tick(gap: dict) -> None:
        # Health probe at loop entry: relaunch-on-death is bounded and
        # loud inside ensure_alive (at most one attempt per cooldown
        # window). Without this, a died server process kept the whole
        # taint tier down for the rest of the run — restart() is
        # otherwise only reachable from query-timeout branches, which
        # a dead process fails fast before ever hitting.
        if joern_server is not None:
            try:
                joern_server.ensure_alive()
            except Exception:
                logger.debug("joern liveness probe failed", exc_info=True)
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
    # Schedule: with >1 worker, most-expensive-first (LPT) packing
    # shrinks the makespan; serial runs keep priority order, where
    # time-to-first-finding is what matters. config.schedule
    # ("priority") opts parallel runs back into finding-first order.
    _schedule = getattr(config, "schedule", "cost")
    if resolved_workers <= 1:
        _schedule = "priority"
    # Soft dependencies: glance-tier and vendored-verdict callees
    # neither gate their callers nor inherit caller rank (see
    # TaskGraph.from_workqueue). Keys use the graph's lined form.
    _soft_keys = frozenset(
        k for k, tr in (triage_results or {}).items()
        if tr.bucket == TriageBucket.GLANCE
        or any(r.startswith(("generated code (", "vendored code ("))
               for r in tr.reasons)
    )
    graph = TaskGraph.from_workqueue(
        workqueue,
        call_edges,
        max_workers=resolved_workers,
        duration_hints=_review_duration_hints(workqueue, triage_results),
        schedule=_schedule,
        soft_dep_keys=_soft_keys,
    )
    if _soft_keys:
        logger.info(
            "task graph: %d glance/vendored callees demoted to soft "
            "dependencies (no caller gating, no rank inheritance)",
            len(_soft_keys),
        )
    reviewed_outcomes = _LockedOutcomes()

    # --- Cross-run verdict reuse: import prior verdicts at $0 ---
    # Before the executor so reused outcomes are visible to chain
    # findings / dependent-context lookups the same way live reviews
    # are. Best-effort: a reuse failure must never cost the run.
    if reuse_candidates:
        try:
            from .verdict_reuse import import_reused_verdicts

            import_reused_verdicts(
                reuse_candidates,
                config,
                result,
                collector=collector,
                sarif_cache=sarif_cache,
                evidence_index=evidence_index,
                joern_server=joern_server,
                reviewed_outcomes=reviewed_outcomes,
                same_run=getattr(config, "same_run_reuse", False),
            )
        except Exception:
            logger.warning(
                "verdict reuse import failed — continuing without "
                "imported prior verdicts", exc_info=True,
            )

    # --- Shared concurrency throttle ---
    # A single AdaptiveThrottle gates all LLM calls across Thread A
    # (review executor) and Thread B (study consumer).  429 broadcasts
    # from any provider reach both consumers via the throttle registry.
    from core.llm.concurrency import read_throttle_cooldown_s
    from core.llm.throttle import AdaptiveThrottle

    throttle = AdaptiveThrottle(
        resolved_workers,
        cooldown_s=read_throttle_cooldown_s(),
    )

    # --- Start incremental study consumer (Thread B) ---
    # The study loop resolves assumptions in C/C++ (via the study-prep
    # corpus) and in Python/Go/Java/JS-TS/Rust (via in-process
    # lang_resolve dispatch); reviews of any of those languages may
    # emit reading_list items.
    from core.concepts.lang_resolve import is_study_supported_path
    _has_study_files = any(
        is_study_supported_path(g["file"]) for g in workqueue
    )
    study_queue: StudyQueue | None = None
    study_consumer_thread: _threading.Thread | None = None
    concept_index_ref: list = [ConceptIndex.empty()]
    if _has_study_files and config.out_dir:
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
            kwargs={
                "checklist": checklist,
                "context_map": context_map,
                "evidence_index": evidence_index,
                "sarif_cache": sarif_cache,
                "entry_points": entry_points,
                "start_time": start_time,
                "on_progress": on_progress,
                "audit_log": audit_log,
                "session_observations": session_observations,
                "discovered_evidence": discovered_evidence,
                "joern_server": joern_server,
                "collector": collector,
                "throttle": throttle,
                "concept_index_ref": concept_index_ref,
            },
            daemon=True,
            name="study-consumer",
        )
        study_consumer_thread.start()
        logger.info("study-consumer: started")

    # --- Deepen budget reserve ---
    # Hold back a slice of the cost cap so the deepen phase can
    # execute the re-reviews it announces; the discovery loop (and the
    # study/synthesis passes that run before deepen) gate against
    # cap - reserve. Released right before the deepen phase.
    if review_reserve_held:
        _release_review_reserve(config)
    deepen_reserve_held = _hold_deepen_reserve(config)

    try:
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
    except BaseException:
        # Exception-path cleanup mirroring the success path below:
        # without it an executor crash left the study consumer blocked
        # on its queue forever, leaked the throttle's cooldown thread,
        # and discarded every outcome buffered in the collector. Each
        # step is best-effort so the ORIGINAL exception always
        # propagates.
        _cleanup_after_executor_failure(
            throttle, study_queue, study_consumer_thread, collector,
        )
        raise
    joern_future = joern_state["future"]
    _record_executor_stop(result, executor_stats)
    if executor_stats.budget_stopped:
        _announce_budget_stop(
            result, executor_stats, graph, on_progress,
        )

    # --- Trivial-function batch pass (moved after the main executor) ---
    # Batched trivial functions are the lowest-value reviews per
    # dollar: under a cost cap they must not consume budget before the
    # priority-ordered graph pass has had it (observed live: a capped
    # run spent its budget on the trivial tier and stopped before any
    # top-priority function was reviewed). Worker-side rail pre-checks
    # (see _review_batch) stop this pass cleanly when the executor
    # already exhausted the budget.
    if batched:
        from concurrent.futures import (
            FIRST_COMPLETED,
            ThreadPoolExecutor,
            wait,
        )

        def _review_batch(batch):
            # Pre-execution rail check: every batch is submitted to the
            # pool up front, so a QUEUED batch must re-check the budget
            # when a worker picks it up. Pre-fix, nothing gated queued
            # batches: after the rails tripped, the pool kept executing
            # the entire pre-submitted backlog (observed live: many
            # hours of post-exhaustion reviews on one run).
            if _check_budget(config, start_time, result):
                return None, batch
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
        batch_stop = False
        with ThreadPoolExecutor(max_workers=resolved_workers) as pool:
            pending = {pool.submit(_review_batch, b) for b in batched}
            while pending:
                if batch_stop:
                    # shutdown(cancel_futures=True) cancels queued
                    # batches by DRAINING the pool's work queue: no
                    # worker ever picks them up, so nothing ever
                    # notifies a completion waiter for them. Both
                    # as_completed and wait() treat such a future as
                    # pending forever — waiting on one deadlocks the
                    # pass (a capped run hung here when the cost rail
                    # fired with batches still queued). Drop them by
                    # state instead; whatever remains was RUNNING at
                    # the drain and always completes.
                    pending = {f for f in pending if not f.cancelled()}
                    if not pending:
                        break
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done:
                    if fut.cancelled():
                        continue
                    batch_outcomes, batch = fut.result()
                    if batch_outcomes is None:
                        # Worker-side rail refusal — nothing was
                        # dispatched.
                        continue
                    # Tally BEFORE the stop decision: these outcomes
                    # are paid work. Pre-fix the consumption loop broke
                    # on the rail check and every outcome the workers
                    # completed after that vanished from the result
                    # (journal had them; result.total_cost_usd froze,
                    # blinding the cost-cap rail itself).
                    for outcome, gap in zip(batch_outcomes, batch):
                        outcome.line = gap.get("line_start", 0)
                        # Phase-book batched reviews like the
                        # single-review path does — pre-fix only that
                        # path booked, so every batched review's spend
                        # surfaced as "unattributed" in the run cost
                        # summary (measured as the large majority of
                        # one run's spend; same class of miss as the
                        # two-call continuation booking above).
                        result.cost_tracker.record_call(
                            "review",
                            cost_usd=outcome.cost_usd,
                            tokens_in=getattr(outcome, "tokens_in", 0),
                            tokens_out=getattr(outcome, "tokens_out", 0),
                            cache_read_tokens=getattr(
                                outcome, "cache_read_tokens", 0),
                            cache_write_tokens=getattr(
                                outcome, "cache_write_tokens", 0),
                            wall_time_s=getattr(outcome, "duration_s", 0.0),
                        )
                        _tally_outcome(result, outcome)
                        if on_progress:
                            on_progress(review_idx, total, outcome)
                        review_idx += 1
                    if not batch_stop and _check_budget(
                        config, start_time, result,
                    ):
                        # Cancel every not-yet-started batch; keep
                        # harvesting in-flight completions in this loop
                        # so their outcomes are tallied. The cancelled
                        # futures can never complete — the loop head
                        # drops them by state — and the
                        # context-manager join then has nothing
                        # unstarted left to block on.
                        batch_stop = True
                        pool.shutdown(wait=False, cancel_futures=True)
        if batch_stop:
            logger.info(
                "batched review pass stopped on budget/deadline "
                "exhaustion — pending batches cancelled",
            )

    # --- Drain study consumer ---
    if study_queue is not None:
        study_queue.signal_producer_done()
    if study_consumer_thread is not None:
        _drain_study_consumer(
            study_consumer_thread,
            study_queue,
            budget_exhausted=bool(
                executor_stats.budget_stopped
                or _check_budget(config, start_time, result)
            ),
        )

    # --- SIGTERM salvage: skip every optional post pass ---
    # In-flight completions are already harvested (the executor's
    # shutdown path) and the study consumer drained above. Everything
    # past this point is enrichment the ~30s grace cannot afford —
    # flush what exists, write the partial exports, and return so the
    # CLI can write the salvage report and mark the lifecycle
    # interrupted.
    if is_sigterm_requested():
        return _sigterm_salvage(result, config, collector, start_time)

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
    # External ground-truth seeds (prior-run journal findings, crash
    # RCAs, cvefix fixture pairs): synthesize checkers from them now so
    # the hits ride the SAME second-pass review below. Bounded per
    # source and by the shared amplification-lane cap; budget-gated.
    try:
        if not executor_stats.budget_stopped and not _check_budget(
            config, start_time, result,
        ):
            _synthesize_external_seeds(config, result, shared, checklist)
    except Exception:
        logger.warning(
            "external seed synthesis failed — continuing without it",
            exc_info=True,
        )

    try:
        if shared.synthesis_queue and not executor_stats.budget_stopped:
            synth_hits = list(shared.synthesis_queue)
            shared.synthesis_queue.clear()
            if shared.quarantined_rules:
                kept = [
                    h for h in synth_hits
                    if h.get("rule_id") not in shared.quarantined_rules
                ]
                dropped = len(synth_hits) - len(kept)
                if dropped:
                    logger.info(
                        "synthesis pass: %d hit(s) dropped from "
                        "quarantined rule(s) (%s)",
                        dropped,
                        ", ".join(sorted(shared.quarantined_rules)),
                    )
                synth_hits = kept
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
    # Budget-gated like the synthesis pass above: a budget/deadline-
    # stopped run must not dispatch a fresh post-loop LLM pass — it
    # overruns the SIGTERM drain margin and gets hard-killed with no
    # report, leaving the lifecycle stuck running.
    try:
        if executor_stats.budget_stopped or _check_budget(
            config, start_time, result,
        ):
            logger.info(
                "callee-contract propagation skipped — budget/deadline "
                "exhausted",
            )
        else:
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

    # Release the deepen reserve: from here on the deepen phase itself
    # is the consumer (or, when deepen is disabled/has nothing to do,
    # the remaining post-loop phases inherit the headroom).
    if deepen_reserve_held:
        _release_deepen_reserve(config)

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
                    mechanical_findings=mechanical_findings,
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
            # One index build instead of two linear outcome scans per
            # gap (the pass was O(gaps x outcomes) — quadratic on
            # large audits).  First occurrence wins, matching the old
            # next() semantics.
            ls_outcome_by_key: dict[tuple[str, str], ReviewOutcome] = {}
            for o in result.outcomes:
                ls_outcome_by_key.setdefault((o.file, o.function), o)
            live_sink_targets = []
            for gap in gaps:
                gap_key = f"{gap['file']}:{gap['name']}"
                prior = ls_outcome_by_key.get((gap["file"], gap["name"]))
                if prior is None:
                    continue
                callees = [
                    e.get("callee", "")
                    for e in (call_edges or [])
                    if f"{e.get('caller_file', '')}:{e.get('caller', '')}" == gap_key
                ]
                upgrade = live_classifications.should_upgrade_triage(gap_key, callees)
                if upgrade and prior.status == "clean":
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
                    prior = ls_outcome_by_key.get(
                        (target_gap["file"], target_gap["name"]),
                    )
                    ls_prepared.append((len(ls_prepared), target_gap, prior, ctx))

                def _do_ls_review(item):
                    idx, _gap, _prior, ctx = item
                    try:
                        outcome = review_fn(ctx, config)
                        return (idx, outcome, None)
                    except Exception as exc:  # noqa: BLE001
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
            result, config, sarif_cache, checklist,
            joern_server=joern_server,
            mechanical_findings=mechanical_findings,
        )
        logger.debug("exited _promote_suspicious")

        logger.debug("entering _promote_suspicious_preconditions")
        _promote_suspicious_preconditions(result, config, context_map)
        logger.debug("exited _promote_suspicious_preconditions")

        logger.debug("entering _promote_clean_refuted")
        _promote_clean_refuted(
            result, config, checklist, joern_server=joern_server,
        )
        logger.debug("exited _promote_clean_refuted")

        logger.debug("entering _dispatch_secondary_hypotheses")
        _dispatch_secondary_hypotheses(
            result, config, checklist, joern_server=joern_server,
        )
        logger.debug("exited _dispatch_secondary_hypotheses")

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
                # Own try: records only, must never skip refutation.
                try:
                    from .binary_honesty import record_gate_engagement

                    record_gate_engagement(
                        config.out_dir,
                        outcome,
                        domain_model=domain_model,
                        checklist=checklist,
                        phase="post_promote",
                    )
                except Exception:
                    logger.debug(
                        "gate-engagement record skipped (post-promote)",
                        exc_info=True,
                    )
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
                    # Counters must follow demote_to. The old
                    # unconditional suspicious-=1/clean+=1 drifted the
                    # tallies whenever the gate demoted TO suspicious
                    # (the outcome stayed suspicious while the counters
                    # recorded a clean).
                    result.suspicious -= 1
                    if rv.demote_to == "suspicious":
                        result.suspicious += 1
                    else:
                        result.clean += 1
        except Exception:
            logger.debug(
                "refutation gate (post-promote) error",
                exc_info=True,
            )

        logger.debug("entering _promote_smt_clean")
        _promote_smt_clean(result, config, checklist)
        logger.debug("exited _promote_smt_clean")

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
                if getattr(outcome, "function_qualified", ""):
                    entry["function_qualified"] = outcome.function_qualified
                append_audit_log(config.out_dir, entry)

    if config.adversarial:
        logger.debug("entering _adversarial_refute_pass")
        try:
            _adversarial_refute_pass(
                result, config, checklist,
                joern_server=joern_server,
                start_time=start_time,
            )
        except Exception:
            logger.warning(
                "adversarial refutation pass failed — positive outcomes "
                "keep their verdicts",
                exc_info=True,
            )
        logger.debug("exited _adversarial_refute_pass")

    try:
        from .propagation import propagate_confidence
        edge_index = shared.call_edge_index if shared else {}
        check_index = shared.checklist_index if shared else {}
        conf_demotions = propagate_confidence(
            result.outcomes, edge_index, check_index,
        )
        for d in conf_demotions:
            append_audit_log(config.out_dir, _demotion_log_entry(d))
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
        mechanical_findings=mechanical_findings,
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
            # Graduation writes TRUSTED engine config — the run pin
            # (or the target-keyed standalone dir) decides where,
            # never bare out_dir.parent topology: a standalone run
            # graduating into the shared out/ root made its rules load
            # as trusted config for every future standalone run of ANY
            # target.
            from core.audit.rules_dirs import graduation_dir
            engine_rules_dir = graduation_dir(
                config.out_dir, config.target_path)
            graduated = (checker_library.graduate(engine_rules_dir)
                         if engine_rules_dir is not None else [])
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
                LayerVerdict,
                format_disagreement_summary,
                write_disagreements,
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
    bypass_runner, iris_bypass_findings = _iris_refine_and_bypass(
        config,
        gaps,
        taint_summary_results,
        joern_server,
        checklist,
        iris_taint_specs,
        result=result,
    )

    if result.findings >= 2 and config.out_dir:
        try:
            from .attacker_synthesis import (
                format_chains_summary,
                synthesize_chains,
                write_attack_chains,
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
        from .taint_specs import check_config_dependent, check_stored_taint

        post_loop_findings.extend(tf.to_dict() for tf in check_stored_taint(gaps, target_path=config.target_path))
        post_loop_findings.extend(tf.to_dict() for tf in check_config_dependent(gaps, target_path=config.target_path))
    except Exception:
        logger.debug("taint-spec post-loop checks failed", exc_info=True)

    if getattr(config, "iris", True):
        # Heuristic assumption/bypass pass rides the same IRIS gate
        # as spec synthesis and refinement.
        post_loop_findings.extend(
            _heuristic_bypass_findings(gaps, bypass_runner),
        )
    post_loop_findings.extend(
        _refine_bypass_post_loop_findings(
            iris_bypass_findings, post_loop_findings,
        )
    )

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
        # load_domain_model / vocab-pack merge self-handle parse
        # errors; only path-level OSErrors can legitimately escape.
        with contextlib.suppress(OSError):
            from .condition_smt import DomainVocabulary
            ns_vocab = DomainVocabulary.from_domain_model(
                domain_model, target_path=config.target_path,
            )
        post_loop_findings.extend(nf.to_dict() for nf in check_resource_exhaustion(
            gaps, target_path=tp, domain_vocab=ns_vocab,
        ))
        post_loop_findings.extend(nf.to_dict() for nf in check_protocol_ambiguity(gaps, target_path=tp))
        from .negative_space import (
            check_auth_mode_registration,
            check_shared_writer_race,
            check_url_boundary_composition,
        )
        for g in gaps:
            post_loop_findings.extend(nf.to_dict() for nf in check_auth_mode_registration(
                g, domain_model=domain_model, target_path=tp,
            ))
            post_loop_findings.extend(nf.to_dict() for nf in check_url_boundary_composition(g, target_path=tp))
            if (g.get("file") or "").endswith(".go"):
                _swr_g = dict(g)
                with contextlib.suppress(OSError):
                    _gfp = tp / (g.get("file") or "")
                    if _gfp.is_file():
                        _swr_g["file_source"] = _gfp.read_text(
                            errors="replace",
                        )
                post_loop_findings.extend(nf.to_dict() for nf in check_shared_writer_race(_swr_g))
        post_loop_findings.extend(nf.to_dict() for nf in check_missing_app_features(gaps, target_path=tp))
        post_loop_findings.extend(nf.to_dict() for nf in check_signal_safety(
            gaps, target_path=tp, domain_vocab=ns_vocab,
        ))
        post_loop_findings.extend(nf.to_dict() for nf in check_ub_patterns(gaps, target_path=tp))
        post_loop_findings.extend(nf.to_dict() for nf in check_side_channels(gaps, target_path=tp))
        post_loop_findings.extend(nf.to_dict() for nf in check_multi_process(gaps, target_path=tp))
        post_loop_findings.extend(nf.to_dict() for nf in check_deployment_assumptions(gaps, target_path=tp))
        post_loop_findings.extend(nf.to_dict() for nf in check_lock_ordering(
            gaps, target_path=tp, domain_vocab=ns_vocab,
        ))
    except Exception:
        logger.debug("negative-space post-loop checks failed", exc_info=True)

    try:
        from .postcondition_verify import verify_postconditions

        # Call graphs unlock the ordering/composition/completeness
        # tier — every production call used to pass None here, so
        # that whole tier had never executed. Same loader the
        # compositional analyzer and sentinel collapse use; a load
        # failure degrades to extraction-only, as before. The
        # checklist bounds extraction to in-scope files — a bare tree
        # walk enumerates test/vendored candidates in arbitrary order
        # and large targets then lose in-scope files to the file cap.
        _pc_call_graphs = None
        try:
            _pc_call_graphs = _load_call_graphs_cached(
                config.target_path, checklist,
            )
        except Exception:
            logger.debug("postcondition: call-graph load failed",
                         exc_info=True)
        pc_result = verify_postconditions(
            gaps,
            taint_summary_results or {},
            call_graphs=_pc_call_graphs,
        )
        if pc_result.violations:
            post_loop_findings.extend(v.to_dict() for v in pc_result.violations)
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
            save_json(
                pl_path,
                {
                    "findings": post_loop_findings,
                    "generated_files": generated,
                    "finding_count": len(post_loop_findings),
                },
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
                # Journalled but NOT tallied as reviewed — count it so
                # the console summary can state the mechanical share
                # instead of contradicting the journal-derived report.
                with result._lock:
                    result.post_loop_mechanical += 1
            except Exception:
                logger.debug(
                    "post-loop journal append failed for %s:%s",
                    plf_file,
                    plf_func,
                    exc_info=True,
                )

    # --- Structural-receipt rescue composition (post-loop) ---
    #
    # The review-time anti-self-refutation gate depends on the receipt
    # surviving in ctx["negative_space"] at gate time. The post-loop
    # pass re-derives the same structural receipts for every gap, so a
    # clean outcome whose own hypotheses contradict an active receipt
    # gets one deterministic re-evaluation here — before the corrective
    # journal/log passes, which propagate the flipped status.
    try:
        n_rescued = _post_loop_receipt_rescue(
            result, post_loop_findings, config,
            mechanical_findings=mechanical_findings,
            gaps=gaps,
        )
        if n_rescued:
            logger.info(
                "post-loop receipt rescue: %d clean outcomes floored "
                "to suspicious",
                n_rescued,
            )
    except Exception:
        logger.debug("post-loop receipt rescue failed", exc_info=True)

    # --- Consistency pre-pass outcomes (LLM-free promote path) ---
    #
    # Census confirmations become synthesized-hypothesis outcomes:
    # journaled here, merged into the graded export below. Registry-
    # grade receipts promote (status decided by the reachability
    # escalator at prep time); majority-only stay suspicious.
    consistency_outcomes: list[Any] = []
    try:
        consistency_outcomes = _consistency_synthetic_outcomes(
            consistency_prepass, result.outcomes, config.out_dir,
        )
        for co in consistency_outcomes:
            try:
                from .collector import append_journal_for_outcome

                append_journal_for_outcome(
                    out_dir=config.out_dir,
                    target_path=config.target_path,
                    run_id=(config.out_dir.name if config.out_dir else ""),
                    outcome=co,
                    gap={
                        "line_start": co.line,
                        "line_end": None,
                        "strategies": ["consistency-census"],
                    },
                    checked_by=["consistency:census"],
                )
                with result._lock:
                    result.post_loop_mechanical += 1
            except Exception:
                logger.debug(
                    "consistency journal append failed for %s:%s",
                    co.file, co.function, exc_info=True,
                )
        if consistency_outcomes:
            logger.info(
                "consistency census: %d LLM-free outcomes journaled "
                "(%d promote-capable findings)",
                len(consistency_outcomes),
                sum(1 for o in consistency_outcomes
                    if o.status == "finding"),
            )
        _journal_undischarged_leads(
            consistency_prepass, result.outcomes, config.out_dir,
        )
    except Exception:
        logger.debug("consistency outcome export failed", exc_info=True)

    try:
        _journal_undischarged_fail_open_leads(
            fail_open_census, result.outcomes, config.out_dir,
        )
    except Exception:
        logger.debug("fail-open lead telemetry failed", exc_info=True)

    # --- Bypass-finding review pass (bounded) ---
    #
    # Refine-loop bypass findings resolve to reviewable functions and
    # get one bounded LLM review each, with the bypass mechanism
    # injected as a hypothesis. Same degradation contract as the
    # synthesis second pass: a failure here must never cost the run
    # its main-pass results.
    try:
        bypass_review_gaps = _bypass_findings_to_gaps(
            [
                plf for plf in post_loop_findings
                if plf.get("source") == "iris_refine_loop"
            ],
            checklist,
        )
        if bypass_review_gaps and not executor_stats.budget_stopped:
            logger.info(
                "bypass review pass: %d bypass findings resolved to "
                "reviewable functions",
                len(bypass_review_gaps),
            )
            bypass_graph = TaskGraph.from_workqueue(
                bypass_review_gaps, call_edges,
            )
            run_executor_sync(
                bypass_graph,
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
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "bypass review pass failed (%s: %s) — keeping main-pass results",
            type(exc).__name__,
            exc,
        )

    # Dark outcomes gate the post-pass too: they are the tool-blind
    # "needs concrete verification" bucket /validate exists to judge —
    # a dark-only run used to skip the dispatch entirely and every
    # dark row dead-ended unadjudicated.
    _dark_pending = sum(
        1 for o in result.outcomes if getattr(o, "status", "") == "dark"
    )
    if config.validate and (result.findings > 0 or _dark_pending > 0):
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
        _dark_client = _run_llm_client(config)
        _run_dark_verification(
            result,
            config,
            llm_client=lambda p, s: (
                _dark_client.generate(
                    p,
                    system_prompt=s or None,
                ).content
            ),
            start_time=start_time,
        )
    except Exception:
        logger.debug("dark verification pass failed", exc_info=True)

    # --- Binary-oracle demotion of promotions in absent functions ---
    # After dark verification so witness-confirmed outcomes carry the
    # runtime evidence that vetoes the absent verdict.
    try:
        n_demoted = _demote_absent_promotions(result, config)
        if n_demoted:
            logger.info(
                "binary oracle: %d sweep promotions demoted (absent"
                " functions)",
                n_demoted,
            )
    except Exception:
        logger.debug("absent-promotion demotion failed", exc_info=True)

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

    # Gate-engagement run summary (binary lane): which refutation
    # gates were live vs could-not-run, aggregated from the per-item
    # journal records. One line; absent on runs with no such records.
    try:
        from .binary_honesty import summarize_gate_engagement

        _gate_line = summarize_gate_engagement(config.out_dir)
        if _gate_line:
            logger.info(_gate_line)
    except Exception:
        logger.debug("gate-engagement summary failed", exc_info=True)

    # Prefilter-kill ledger: structured record of every prefilter /
    # triage kill, spot-audited against the compiler analyzer so the
    # cheapest gates in the funnel carry an error bar.
    if result.prefilter_kills and config.out_dir:
        try:
            from .prefilter_ledger import (
                corroborate_sample,
                format_summary,
                write_ledger,
            )

            corroborate_sample(
                result.prefilter_kills,
                config.target_path,
                out_dir=config.out_dir,
            )
            write_ledger(result.prefilter_kills, config.out_dir)
            logger.info(format_summary(result.prefilter_kills))
        except Exception:
            logger.debug("prefilter kill ledger failed", exc_info=True)

    # Fuzz handoff: dictionary tokens + seed hints mined from audit
    # knowledge (unique constants, parse-shape string literals,
    # dispatch keys, IRIS specs), written where /fuzz auto-discovers
    # them (fuzz.dict / fuzz-dict.json, sibling-run lookup).
    if config.out_dir:
        try:
            from .fuzz_handoff import emit_fuzz_dict

            emit_fuzz_dict(config.target_path, config.out_dir)
        except Exception:
            logger.debug("fuzz dict handoff failed", exc_info=True)

    # Caller-contract confidence demotion: caller-obligation
    # hypotheses mechanically refuted at every in-repo call site
    # export at confidence=low with receipts (status untouched —
    # never suppression). Runs before the journal correction pass and
    # the export so all three surfaces agree.
    try:
        _caller_contract_demotion_pass(result, config)
    except Exception:
        logger.debug(
            "caller-contract demotion pass failed", exc_info=True,
        )

    # Pre-export hooks: outcome-level post-processing (e.g. the ensemble
    # pipeline's file-pile-up dampener) runs BEFORE the journal
    # correction pass and the graded export so stats, journal and
    # findings-graded.json all agree on the final statuses.
    for _hook in (config.pre_export_hooks or ()):
        try:
            _hook(result, config)
        except Exception:
            logger.debug("pre-export hook failed", exc_info=True)

    # Journal entries were committed mid-loop, pre-resolution — append
    # corrective entries so the journal reflects final statuses (dark
    # included) before the export and report read it.
    try:
        _rejournal_final_statuses(result, config)
    except Exception:
        logger.debug("re-journal pass failed", exc_info=True)
    try:
        _relog_final_statuses(result, config)
        config._verdicts_finalized = True
    except Exception:
        logger.debug("re-log pass failed", exc_info=True)

    try:
        from .findings_export import export_findings, write_graded_findings

        chains = None
        chains_path = config.out_dir / "attack-chains.json"
        if chains_path.exists():
            chains = load_json(chains_path, max_bytes=_MAX_ARTIFACT_BYTES)
        export_outcomes = list(result.outcomes)
        try:
            export_outcomes.extend(
                _bypass_export_outcomes(post_loop_findings, result.outcomes)
            )
        except Exception:
            logger.debug("bypass export outcomes failed", exc_info=True)
        try:
            export_outcomes.extend(consistency_outcomes)
        except Exception:
            logger.debug(
                "consistency export outcomes failed", exc_info=True,
            )
        graded = export_findings(
            export_outcomes,
            evidence_index=evidence_index,
            attack_chains=chains,
            out_dir=config.out_dir,
            # Prep-time vendored/generated per-file verdicts → each
            # finding's file_class (threaded, not re-detected).
            vendor_verdicts=_prep.get("vendor_verdicts") or None,
        )
        try:
            _attach_bypass_evidence(graded, post_loop_findings)
        except Exception:
            logger.debug("bypass evidence attach failed", exc_info=True)
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
                evaluate_run,
                format_evaluation,
                load_ground_truth,
                write_evaluation,
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
                build_matrix,
                format_matrix_report,
                load_planted_bugs,
                match_findings_to_bugs,
                write_matrix,
            )

            planted = load_planted_bugs(config.target_path / "planted-bugs.json")
            if planted:
                matrix = build_matrix(planted)
                graded_path = config.out_dir / "findings-graded.json"
                if graded_path.is_file():
                    graded_data = load_json(
                        graded_path, max_bytes=_MAX_ARTIFACT_BYTES,
                    )
                    graded_data = (
                        graded_data if isinstance(graded_data, dict) else {}
                    )
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
            summaries_out = {}
            for key, summary in taint_summary_results.items():
                if hasattr(summary, "to_dict"):
                    summaries_out[key] = summary.to_dict()
                else:
                    summaries_out[key] = summary
            sp = config.out_dir / "summaries.json"
            save_json(sp, summaries_out)
            logger.info(
                "summaries: wrote %d entries to summaries.json", len(summaries_out)
            )
        except Exception:
            logger.debug("summaries.json write failed", exc_info=True)

    try:
        _reconcile_cost_ledgers(config, result)
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

    # Graph store enrichment — ingest audit hypotheses + scan findings.
    if config.out_dir:
        import sqlite3 as _graph_sqlite3_end
        try:
            from core.understand_graph import ingest_audit_hypotheses, ingest_scan_findings
            _tgt = str(config.target_path or "")
            ingest_audit_hypotheses(config.out_dir, _tgt)
            ingest_scan_findings(config.out_dir, _tgt)
        except (ImportError, _graph_sqlite3_end.Error, KeyError, TypeError, ValueError):
            logger.debug("graph store enrichment skipped", exc_info=True)

    return result


def _sigterm_salvage(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    collector: Any,
    start_time: float,
) -> OrchestratorResult:
    """Bounded SIGTERM conclusion: flush and export what exists.

    Runs the durable tail only — collector flush (journal fsync +
    buffered audit-log rows), corrective re-journal of final statuses,
    the graded findings export (mechanical, no LLM), tier diagnostics,
    and ledger reconciliation — then returns so the CLI writes the
    salvage report and marks the lifecycle ``interrupted``. Every step
    is best-effort: one failed export must not cost the rest.
    """
    logger.warning(
        "SIGTERM salvage: flushing journal/ledgers and writing "
        "partial exports (%d outcomes harvested)",
        len(result.outcomes),
    )
    result.terminated_by = "sigterm"
    result.total_duration_s = time.monotonic() - start_time

    if collector is not None:
        try:
            collector.flush()
        except Exception:
            logger.debug("salvage: collector flush failed", exc_info=True)

    try:
        _rejournal_final_statuses(result, config)
    except Exception:
        logger.debug("salvage: re-journal pass failed", exc_info=True)
    try:
        _relog_final_statuses(result, config)
        config._verdicts_finalized = True
    except Exception:
        logger.debug("salvage: re-log pass failed", exc_info=True)

    try:
        from .findings_export import export_findings, write_graded_findings

        graded = export_findings(
            list(result.outcomes),
            evidence_index=None,
            attack_chains=None,
            out_dir=config.out_dir,
        )
        write_graded_findings(graded, config.out_dir)
    except Exception:
        logger.debug("salvage: graded export failed", exc_info=True)

    try:
        write_tier_diagnostics(result.tier_counters, config.out_dir)
    except Exception:
        logger.debug("salvage: tier diagnostics failed", exc_info=True)

    try:
        _reconcile_cost_ledgers(config, result)
    except Exception:
        logger.debug("salvage: ledger reconciliation failed", exc_info=True)

    return result


def _reconcile_cost_ledgers(config, result) -> None:
    """End-of-run cost ledger reconciliation.

    The LLM client's ledger is the authoritative total spend: it
    includes failed/timed-out attempts and anything the phase ledgers
    missed. Inject it so cost-breakdown.json carries
    totals.total_spend_usd / failed_attempts_cost_usd /
    unattributed_cost_usd, and stash it on the result for the
    operator-facing "Cost:" summary line. Without this, one run
    produced three unexplained numbers: $8.08 (client), $4.52 (review
    phase), $2.82 (summary).

    Before injecting, book call classes no phase captured (audit,
    iris, summary, glance_batch, …) from the telemetry sink's
    per-class ledger. Pre-fix their spend either printed under
    "failed/timed-out" (budget-client spend the phases missed) or
    vanished from the summary entirely (standalone-client spend
    outside the budget ledger — one run reported $36.85 while
    telemetry showed $38.84). Afterwards, assert the telemetry ledger
    and the summary ledger describe the same money: warn when they
    diverge by more than 1% (unbooked or double-booked spend).
    """
    from core.llm.telemetry import current_sink as _current_sink

    sink = _current_sink()
    if sink is not None:
        booked = result.cost_tracker.book_unbooked_classes(
            sink.class_costs(),
        )
        if booked:
            logger.info(
                "cost: booked %d call class(es) outside the phase "
                "ledger: %s",
                len(booked),
                ", ".join(
                    f"{c}=${v:.2f}" for c, v in sorted(booked.items())
                ),
            )
    # Same-run resume: book the prior segments' spend BEFORE injecting
    # this segment's client ledger, so the rewritten
    # cost-breakdown.json covers the whole run (the budget client only
    # ever saw the remaining cap for this segment). The RESOLVED
    # figure from the resume CLI (prior_booked_spend_usd) is
    # authoritative: it survives a predecessor that died before
    # reconciling (no prior ledger dict), where booking only the dict
    # dropped every segment before the immediately-prior one — the
    # final ledger then under-reported the run by the whole early
    # spend (observed live: $47.29 booked of ~$4,534).
    prior_breakdown = getattr(config, "prior_cost_breakdown", None)
    prior_booked = max(
        0.0,
        float(getattr(config, "prior_booked_spend_usd", 0.0) or 0.0),
    )
    if prior_breakdown or prior_booked > 0:
        try:
            from .resume import booked_spend_usd
            result.cost_tracker.book_prior_segments(
                max(booked_spend_usd(prior_breakdown), prior_booked),
                segment=getattr(config, "resume_segment", 1),
            )
        except Exception:
            logger.debug(
                "prior-segment ledger booking failed", exc_info=True,
            )
    client = getattr(config, "llm_budget_client", None)
    if client is not None:
        # The provider ledger is the honest floor for money actually
        # gone: it includes failed-attempt spend the client ledger
        # deliberately does not book per-call (unattributable under
        # parallel workers). max() never double-counts.
        spent = max(
            float(getattr(client, "total_cost", 0.0) or 0.0),
            float(getattr(client, "provider_spend_usd", 0.0) or 0.0),
        )
        result.cost_tracker.set_total_spend(spent)
    result.llm_spend_usd = result.cost_tracker.total_spend_usd
    if config.out_dir:
        result.cost_tracker.write(config.out_dir)
    logger.info(result.cost_tracker.summary())
    if sink is not None:
        tel_total = sink.total_cost_usd()
        # The telemetry sink counts THIS process's calls only —
        # compare against the segment-local ledger, not the booked
        # prior-segment spend a resumed run carries.
        ledger_total = (
            result.cost_tracker.total_spend_usd
            - result.cost_tracker.prior_segments_spend_usd
        )
        scale = max(tel_total, ledger_total)
        if scale > 0 and abs(tel_total - ledger_total) > 0.01 * scale:
            gap = abs(tel_total - ledger_total)
            # Known-legitimate component before alarming: the summary
            # ledger's floor includes failed-attempt spend (timeouts,
            # aborted long calls) that per-call telemetry deliberately
            # never books — money gone with no outcome to carry it.
            failed = float(
                getattr(
                    result.cost_tracker,
                    "total_failed_attempts_cost_usd",
                    0.0,
                ) or 0.0
            )
            if ledger_total > tel_total and failed >= gap - 0.01 * scale:
                logger.info(
                    "cost reconciliation: telemetry ledger $%.2f vs "
                    "summary ledger $%.2f — the $%.2f gap is covered "
                    "by recorded failed-attempt spend ($%.2f), which "
                    "telemetry never books per-call",
                    tel_total, ledger_total, gap, failed,
                )
            else:
                logger.warning(
                    "cost reconciliation: telemetry ledger $%.2f vs "
                    "summary ledger $%.2f (%.1f%% divergence; "
                    "recorded failed-attempt spend $%.2f) — residual "
                    "spend is unbooked or double-booked",
                    tel_total,
                    ledger_total,
                    100.0 * gap / scale,
                    failed,
                )


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
            n_attempts=j_fb.n_attempts + c_fb.n_attempts,
            n_successes=j_fb.n_successes + c_fb.n_successes,
        )

    return _composite


def _run_invariant_prescreening(
    domain_model: dict[str, Any] | None,
    config: OrchestratorConfig,
    gaps: list[dict[str, Any]],
    mechanical_findings: dict[str, list[dict[str, Any]]],
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
        _proj = _pinned_or_parent_project_dir(config.out_dir)
        if _proj is not None:
            checkers_dirs.append(_proj / "concepts" / "checkers")
            checkers_dirs.append(_proj / "checkers")

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
    reviewed_outcomes: _LockedOutcomes,
    config: OrchestratorConfig,
    shared: SharedState,
    gaps: list[dict[str, Any]],
    mechanical_findings: dict[str, list[dict[str, Any]]],
    _reviewed_set: set,
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
            dm_path = config.out_dir / "domain-model.json"
            save_json(dm_path, dm)
        except Exception:
            logger.debug("concept discovery: domain model write failed", exc_info=True)

    from core.llm.task_types import TaskType

    client = _run_llm_client(config)

    def _llm(prompt, schema, system_prompt):
        from core.security.prompt_framing import with_audit_framing
        try:
            data, _ = client.generate_structured(
                prompt=prompt,
                schema=schema,
                # Audit-purpose framing — same auxiliary-class gap as
                # the refused summary/spec prompts (see
                # core.security.prompt_framing).
                system_prompt=with_audit_framing(system_prompt),
                task_type=TaskType.AUDIT,
                call_class="concept_discovery",
            )
            return data
        except Exception as exc:  # noqa: BLE001
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
        config: OrchestratorConfig,
        joern_server: Any = None,
    ) -> None:
        self._config = config
        self._joern_server = joern_server
        self._cache: dict[str, list[dict[str, Any]]] = {}

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
            with contextlib.suppress(OSError):
                dm = _load_domain_model(config)
            self._vocab = DomainVocabulary.from_domain_model(
                dm, target_path=config.target_path,
            )
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
        self, file: str, function: str, line_start: int, line_end: int | None,
    ) -> list[dict[str, Any]]:
        """Return inject-mode findings for a single function (cached)."""
        key = f"{file}:{function}"
        if key in self._cache:
            return self._cache[key]

        findings: list[dict[str, Any]] = []
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
                findings.extend({
                        "file": file,
                        "function": function,
                        "detector": f"uninit_leak:{uleak.tier}",
                        "line": uleak.line,
                        "description": uleak.description,
                    } for uleak in self._check_uninit_leak(
                    src, function,
                    joern_server=self._joern_server,
                ))
            except Exception:
                logger.debug(
                    "uninit_leak inject failed for %s:%s",
                    file, function, exc_info=True,
                )

        if self._check_callback_cross is not None and is_c:
            try:
                clr = self._check_callback_cross(
                    self._joern_server, file, function, self._vocab,
                )
                if clr.violation_found:
                    findings.extend({
                            "file": file,
                            "function": function,
                            "detector": "callback_lifetime_cross",
                            "line": v.register_line or line_start,
                            "description": v.reasoning,
                        } for v in clr.violations)
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


def _route_ops_struct_receipts(
    gaps: list[dict[str, Any]],
    ops_eps: set,
    mechanical_findings: dict[str, list[dict[str, Any]]],
) -> int:
    """Detector receipts for ops-struct-reached functions.

    The collector only widened ``entry_points``, so the channel fired
    without ever leaving a receipt: nothing downstream (review prompt,
    mechanical-findings.json, attribution) could see that a function
    is reachable through a function-pointer table. Returns the number
    of receipts routed.
    """
    routed = 0
    for gap in gaps:
        gk = f"{gap.get('file', '')}:{gap.get('name', '')}"
        if gk not in ops_eps:
            continue
        mechanical_findings.setdefault(gk, []).append({
            "file": gap.get("file", ""),
            "function": gap.get("name", ""),
            "detector": "ops_struct",
            "line": gap.get("line_start", 0),
            "description": (
                "reached indirectly via an ops-struct member "
                "registration (function pointer table) — an entry "
                "point regardless of direct callers"
            ),
        })
        routed += 1
    return routed


def _run_mechanical_detectors(
    gaps: list[dict[str, Any]],
    config: OrchestratorConfig,
    context_map: dict[str, Any] | None = None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    joern_server: Any = None,
    checklist: dict[str, Any] | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    """Run pre-loop mechanical detectors over all source files.

    Returns a tuple of:
      1. Findings keyed by "file:function".  Each value is a list of
         finding dicts with keys: file, function, detector, line, description.
      2. A set of "file:function" keys that are mechanically clean — all
         sinks had sufficient guards with no detector findings.

    Design ref: ~/design/audit.md lines 782-813.
    """
    mechanical_findings: dict[str, list[dict[str, Any]]] = {}
    guard_clean_keys: set[str] = set()
    _guarded_funcs: set[str] = set()
    _sufficient_funcs: dict[str, bool] = {}
    _decorative_funcs: set[str] = set()
    _smt_insufficient_funcs: set[str] = set()
    total = 0

    source_texts: dict[str, str] = {}
    for gap in gaps:
        fp = gap.get("file", "")
        if fp and fp not in source_texts:
            with contextlib.suppress(OSError):
                src_path = config.target_path / fp
                if src_path.is_file():
                    source_texts[fp] = src_path.read_text(errors="replace")

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
    guard_cache: dict[str, list] = {}
    _extract_sg = None
    _assess_guards = None
    _check_bindings = None
    _check_sufficiency = None
    _check_pf = None
    _check_sm = None
    _cpg_verify = None

    try:
        from .condition_adequacy import assess_file_guards as _assess_guards
        from .condition_binding import check_all_bindings as _check_bindings
        from .condition_extraction import extract_sink_guards as _extract_sg
    except Exception:
        logger.debug("mechanical: condition chain import failed", exc_info=True)

    try:
        from .condition_smt import (
            check_all_sufficiency as _check_sufficiency,
        )
        from .condition_smt import (
            check_path_feasibility as _check_pf,
        )
        from .condition_smt import (
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
                except Exception:  # noqa: BLE001
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
                findings.extend((
                        fp, asym.sink_function, "sink_guard_asymmetry",
                        asym.unguarded_line,
                        (
                            f"asymmetric guarding of {asym.sink_api}: "
                            f"guarded at L{asym.guarded_line}, "
                            f"unguarded at L{asym.unguarded_line}"
                        ),
                    ) for asym in asymmetries)
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
                            (
                                f"all {ba.decorative_guard_count} guard(s) "
                                f"decorative for {ba.sink_api}"
                            ),
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
                                (
                                    f"SMT: guard '{sr.guard_text}' insufficient "
                                    f"for {sg.sink_api}: {detail}"
                                ),
                            ))
                    # Clearing a sink guard (skipping the CPG
                    # decorative-guard round) requires a GENUINE
                    # sufficiency proof (feasible is False).  Empty
                    # result lists and inconclusive checks (feasible is
                    # None: no sufficiency model, unmodeled boolean
                    # structure, insufficient variables) are the
                    # absence of an analysis, not a proof.
                    has_proof = any(
                        sr.feasible is False for sr in results
                    )
                    if not has_insufficient and has_proof:
                        _smt_cleared.add(idx)
            except Exception:
                logger.debug("condition_smt failed for %s", fp, exc_info=True)

        if _cpg_verify is not None:
            try:
                for idx, sg in enumerate(guards):
                    if idx in _smt_cleared:
                        continue
                    cpg_results = _cpg_verify(sg, joern_server=joern_server)
                    findings.extend((
                                fp, sg.sink_function, "decorative_guard_cpg",
                                sg.sink_line,
                                (
                                    f"CPG: guard '{cr.guard_text}' neither "
                                    f"on data-dep path nor dominates sink "
                                    f"{cr.sink_api}"
                                ),
                            ) for cr in cpg_results if cr.data_dep_bound is False and cr.dominates_sink is False)
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
                            # Pass the file source so the check can
                            # consult the variable's declared type —
                            # unknown signedness produces no finding
                            # (the old default assumed every variable
                            # unsigned and stamped a witness-carrying
                            # mismatch per resolvable guard).
                            smr = _check_sm(guard, source=src)
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
            for fut, fut_fp in futures.items():
                try:
                    for finding_tuple in fut.result():
                        _add(*finding_tuple)
                except Exception:
                    fp = fut_fp
                    logger.debug("condition chain failed for %s", fp, exc_info=True)

    # --- Structural detectors ---
    call_graphs = None
    # Pure-AST extraction over hostile source: IO errors, parse quirks
    # and pathological nesting are the legitimate set. The checklist
    # bounds extraction to in-scope files (a bare tree walk loses
    # in-scope files to the file cap on large targets).
    with contextlib.suppress(OSError, ValueError, RecursionError):
        call_graphs = _load_call_graphs_cached(config.target_path, checklist)

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
        from .return_domain import detect_return_domain_mismatches

        _rd_roots = [config.target_path]
        if getattr(config, "study_root", None):
            _rd_roots.append(Path(config.study_root))
        for rdm in detect_return_domain_mismatches(
            source_texts, roots=_rd_roots,
        ):
            _add(
                rdm.file,
                rdm.function,
                "return_domain",
                rdm.line,
                rdm.description,
            )
    except Exception:
        logger.debug("mechanical: return_domain failed", exc_info=True)

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
        from .block_sibling_analysis import detect_block_sibling_asymmetries

        for bs in detect_block_sibling_asymmetries(source_texts):
            _add(
                bs.file,
                bs.function,
                "block_sibling",
                bs.line,
                f"branch '{bs.branch_label}' deviates from its "
                f"siblings: {bs.explanation}",
            )
    except Exception:
        logger.debug("mechanical: block_sibling failed", exc_info=True)

    try:
        from .dispatch_completeness import find_dispatch_gaps

        for dg in find_dispatch_gaps(call_graphs or {}, source_texts):
            _add(
                dg.table.file,
                dg.table.function,
                "dispatch_gap",
                dg.table.line,
                f"dispatch table misses key '{dg.missing_key}' "
                f"produced at {dg.produced_by} "
                f"(confidence {dg.confidence})",
            )
    except Exception:
        logger.debug("mechanical: dispatch_completeness failed", exc_info=True)

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
            _add(
                tcf.file,
                tcf.function,
                "type_confusion",
                tcf.line,
                tcf.describe(),
            )
    except Exception:
        logger.debug("mechanical: type_confusion failed", exc_info=True)

    try:
        from .callback_lifetime import check_callback_lifetime_local

        cb_vocab = None
        with contextlib.suppress(OSError):
            from .condition_smt import DomainVocabulary
            cb_vocab = DomainVocabulary.from_domain_model(
                _load_domain_model(config),
                target_path=config.target_path,
            )

        for fp in source_texts:
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
                clr = check_callback_lifetime_local(func_src, cb_vocab)
                if clr.violation_found:
                    desc = clr.reasoning
                    detector = "callback_lifetime_local"
                    if clr.rcu_kfree_mismatch:
                        detector = "rcu_kfree_mismatch"
                    _add(fp, func_name, detector, line_start, desc)
    except Exception:
        logger.debug("mechanical: callback_lifetime failed", exc_info=True)

    # --- Auth-dismissal witnesses (Java) ---
    try:
        from .auth_witnesses import scan_gaps as _authw_scan

        for aw in _authw_scan(gaps, source_texts):
            _add(aw.file, aw.function, aw.detector, aw.line, aw.description)
    except Exception:
        logger.debug("mechanical: auth_witnesses failed", exc_info=True)

    # --- Check-then-create compound (keyed registration race) ---
    try:
        from .check_then_create import scan_gaps as _ctc_scan

        for cf in _ctc_scan(gaps, source_texts):
            _add(
                cf.file, cf.function, "check_then_create",
                cf.write_line, cf.description(),
            )
    except Exception:
        logger.debug(
            "mechanical: check_then_create failed", exc_info=True,
        )

    # --- ASN.1 template declared-vs-accessed type witness ---
    try:
        from .asn1_template_mismatch import scan_sources as _asn1_scan

        for am in _asn1_scan(source_texts):
            func_name = ""
            for gap in gaps:
                if gap.get("file") != am.file:
                    continue
                gs = gap.get("line_start", 0)
                ge = gap.get("line_end", gs)
                if gs <= am.line <= (ge or gs):
                    func_name = gap.get("name", "")
                    break
            if func_name:
                _add(
                    am.file, func_name, "asn1_template_mismatch",
                    am.line, am.description(),
                )
    except Exception:
        logger.debug(
            "mechanical: asn1_template_mismatch failed", exc_info=True,
        )

    # --- Standing Coccinelle templates ---
    try:
        from packages.coccinelle.runner import (
            is_available as _cocci_avail,
        )
        from packages.coccinelle.runner import (
            run_rule as _run_cocci_rule,
        )

        raptor_dir = Path(os.environ["RAPTOR_DIR"])
        rules_dir = raptor_dir / "engine" / "coccinelle" / "rules"
        if _cocci_avail() and rules_dir.is_dir() and config.target_path:
            from .cwe_dispatch import CWE_TO_TOOL_DISPATCH

            standing_rules: set[str] = set()
            for entry in CWE_TO_TOOL_DISPATCH.values():
                cocci_name = entry.get("cocci")
                # A dispatch entry carries one rule filename or a list
                # of them (a CWE family with more than one standing
                # witness shape).
                cocci_names = (
                    cocci_name if isinstance(cocci_name, (list, tuple))
                    else [cocci_name] if cocci_name else []
                )
                for one_name in cocci_names:
                    rule_path = rules_dir / one_name
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
                            # In-repo standing engine/coccinelle rules
                            # (code trust) — @script:python trusted.
                            allow_scripting=True,
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
    gaps: list[dict[str, Any]],
    annotations_dir: Path,
    target_path: Path,
) -> list[dict[str, Any]]:
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


def _codeql_db_for(config, file_path):
    """CodeQL database for ``file_path`` via the run's router.

    Falls back to the single configured path when the router is absent
    (unit tests driving internals without run_orchestrator's
    normalisation)."""
    router = getattr(config, "codeql_db_router", None)
    if router is not None:
        return router.for_file(file_path)
    return config.codeql_db_path


def _build_prior_finding_analyses(
    config: OrchestratorConfig,
    project_dir: Path | None,
) -> dict[str, list] | None:
    """``file:function`` → newest-first finding-grade journal entries.

    Sources: the project journal index (prior runs, any producer) and
    ``config.prior_journal_dirs`` (journals not yet merged into the
    index — the /agentic post-pass case). Only FINDING-GRADE entries
    qualify: function-grade priors already reach the prompt through
    the verdict-reuse / prior_verdict machinery.

    The per-function cap (newest first) keeps a finding-dense function
    from flooding the review prompt with near-duplicate per-finding
    narratives; bodies are excerpted here so every consumer sees the
    same bound. ``config.prior_claims_per_function == 0`` disables the
    injection entirely.

    Best-effort — a missing or corrupt journal costs the claims, never
    the run. Returns None when nothing qualifies so callers can gate
    on truthiness.
    """
    cap = getattr(config, "prior_claims_per_function", 3)
    if cap <= 0:
        return None
    excerpt = max(int(getattr(config, "prior_claim_excerpt_chars", 600)), 0)
    from core.coverage.journal import (
        is_function_grade,
        load_entries,
        load_index_full,
    )

    entries: list = []
    if project_dir is not None:
        try:
            entries.extend(load_index_full(project_dir).values())
        except Exception:
            logger.debug("prior-claim index read failed", exc_info=True)
    for run_dir in config.prior_journal_dirs or []:
        try:
            entries.extend(load_entries(Path(run_dir)))
        except Exception:
            logger.debug(
                "prior-claim journal read failed for %s",
                run_dir, exc_info=True,
            )

    claims: dict[str, list] = {}
    for entry in entries:
        if is_function_grade(entry) or entry.verdict == "error":
            continue
        claims.setdefault(f"{entry.file}:{entry.function}", []).append(entry)
    if not claims:
        return None
    out: dict[str, list] = {}
    for key, group in claims.items():
        group.sort(key=lambda e: e.ts, reverse=True)
        out[key] = [
            {
                "verdict": e.verdict,
                "cwe": e.cwe,
                "model": e.model,
                "run_id": e.run_id,
                "ts": e.ts,
                "body": (e.body or "")[:excerpt],
            }
            for e in group[:cap]
        ]
    return out


def _build_context(
    config: OrchestratorConfig,
    gap: dict[str, Any],
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
    *,
    blind: bool = False,
) -> dict[str, Any]:
    """Assemble context for one function.

    When *blind* is True, mechanical evidence is withheld from the prompt
    so the LLM reasons from code alone.  sink_unreachable is still set
    (it's a prefilter, not a leading hint).
    """
    ann_dir = _annotations_dir(config)
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
        caller_contract=getattr(config, "caller_contract_context", True),
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

    if gap.get("edge_contracts"):
        # Tier-2 edge obligations for THIS caller (stamped by the
        # --edges pass): rendered as an "edge contracts" prompt
        # section; per-edge verdicts come back as edge_verdicts and
        # land on the caller's journal entry. Callee contracts from
        # the domain model ride along when one names the callee.
        contracts_by_fn: dict[str, str] = {}
        try:
            from core.concepts.audit_bridge import _find_domain_model
            dm = _find_domain_model(config.out_dir)
            for c in (dm or {}).get("contracts", []) or []:
                fn = c.get("function")
                text = c.get("input_semantics") or c.get("implication") or ""
                if fn and text:
                    contracts_by_fn.setdefault(str(fn), str(text))
        except Exception:
            logger.debug("edge-contract domain lookup failed", exc_info=True)
        ctx["edge_contracts"] = [
            {
                "callee": e.get("callee"),
                "callee_file": e.get("callee_file"),
                "call_line": e.get("call_line"),
                "contract": contracts_by_fn.get(str(e.get("callee"))),
            }
            for e in gap["edge_contracts"]
            if isinstance(e, dict)
        ]

    if gap.get("injected_hypotheses"):
        # Mechanically derived hypotheses (IRIS bypass detection,
        # fix-history mining) ride the gap into the review prompt.
        ctx["injected_hypotheses"] = list(gap["injected_hypotheses"])

    if not blind and config.prior_finding_analyses:
        # Prior finding-grade claims (/agentic per-finding analyses of
        # scanner findings located in this function). Advisory prior
        # claims only — withheld in blind mode like the mechanical
        # evidence, and never a verdict.
        claims = config.prior_finding_analyses.get(
            f"{gap['file']}:{gap['name']}"
        )
        if claims:
            ctx["prior_finding_analyses"] = claims

    if config.models:
        ctx["model"] = config.models[0]

    ctx["review_mode"] = config.mode

    return ctx


def _commit_outcome(
    config: OrchestratorConfig,
    outcome: ReviewOutcome,
    gap: dict[str, Any],
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
    if config._verdicts_finalized:
        logger.warning(
            "late commit after verdict finalization suppressed for "
            "%s:%s (status %s) — the run's exports are already cut",
            outcome.file, outcome.function, outcome.status,
        )
        return

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
    entry: dict[str, Any] = {
        "action": "orchestrator_review",
        "key": f"{outcome.file}:{outcome.function}:{line_start}",
        "status": outcome.status,
        "verification_tier": outcome.verification_tier,
        "model": outcome.model,
        "cost_usd": outcome.cost_usd,
        "duration_s": outcome.duration_s,
    }
    if gap.get("edge_callee"):
        # Tier-1 edge-contract reviews journal under an edge-suffixed
        # key, but this audit-log record's key is the caller's plain
        # function key — without the stamp, get_reviewed_set() treats
        # the caller as already reviewed and the workqueue silently
        # drops its function review (observed live: both --pin targets
        # skipped because the edge pass had reviewed one of their
        # outgoing edges first).
        entry["edge_callee"] = gap["edge_callee"]
    _qualified = (
        gap.get("qualified_name")
        or getattr(outcome, "function_qualified", "")
    )
    if _qualified:
        entry["function_qualified"] = _qualified
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

    # Git-history corroboration for findings: prior security-fix
    # commits touching this file, attached as CONTEXT.  Never a
    # verdict — the oracle has no outcome and its stamp is not tool
    # evidence (see core.audit.git_oracle).  Best-effort and cached
    # per file inside the module.
    if outcome.status in ("finding", "suspicious"):
        try:
            from .git_oracle import corroboration_for_journal

            corroboration = corroboration_for_journal(
                target_path=config.target_path,
                file_path=outcome.file,
                line_start=gap.get("line_start", 0) or 0,
                line_end=gap.get("line_end", 0) or 0,
                out_dir=config.out_dir,
            )
            if corroboration:
                entry["git_corroboration"] = corroboration
        except ImportError:
            pass
        except Exception:
            logger.debug("git corroboration failed", exc_info=True)

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
    domain_model: dict[str, Any] | None,
) -> list[str]:
    """Match a hypothesis against RECEIPT-CHECKED domain-model invariants.

    Returns list of matching invariant IDs. Delegates to the shared
    :mod:`core.audit.invariant_gate` matcher: only invariants with an
    actionable provenance tier (verbatim/mechanical) AND a verified
    receipt qualify, the invariant's scope must cover *file_path*, and
    the hypothesis must share a source-anchored identifier with the
    receipt quote on top of the word-overlap floor. ``llm_summarized``
    invariants (quote-less study output) never match — word overlap
    between two pieces of LLM prose is not mechanical provenance
   .
    """
    from .invariant_gate import match_receipted_invariants

    return [
        m["id"]
        for m in match_receipted_invariants(
            hypothesis, file_path, domain_model,
        )
    ]


def _resolve_hypothesis(outcome: ReviewOutcome) -> str:
    """Extract the best hypothesis string from the review result.

    Prefers the singular ``hypothesis`` field.  When it is empty, falls
    back to the highest-confidence entry in the ``hypotheses`` array.
    Delegates to the shared resolver so the G2 gate (grant side) and
    the promotion alarm (re-verification side) read the same claim.
    """
    from .invariant_gate import resolve_hypothesis

    return resolve_hypothesis(outcome)


def _check_finding_gates(
    outcome: ReviewOutcome,
    *,
    audit_log: list[dict[str, Any]] | None = None,
    domain_model: dict[str, Any] | None = None,
    mode: ReviewMode = ReviewMode.SECURITY,
) -> list[str]:
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
        from .invariant_gate import match_receipted_invariants

        matched_invariants = match_receipted_invariants(
            hypothesis,
            outcome.file,
            domain_model,
        )
        if matched_invariants:
            inv_ids = ", ".join(
                f"{m['id']}({m['tier']})" for m in matched_invariants
            )
            # Machine-readable marker for the designed exception so the
            # promotion-without-tool-evidence alarm can distinguish it
            # from a genuine gate bypass. ADVISORY: the alarm re-derives
            # the match from the on-disk domain model instead of
            # trusting this stamp (the review result is parsed LLM JSON,
            # so a raw model response can plant the key).
            if outcome.review_result is not None:
                outcome.review_result["g2_invariant_bypass"] = [
                    m["id"] for m in matched_invariants
                ]
                outcome.review_result["g2_invariant_bypass_tiers"] = {
                    m["id"]: m["tier"] for m in matched_invariants
                }
            logger.info(
                "G2 bypassed for %s:%s — hypothesis matches "
                "receipt-checked domain-model invariant(s): %s",
                outcome.file,
                outcome.function,
                inv_ids,
            )
        else:
            violations.append("G2: finding emitted without tool-grounded evidence")

    # G3: NO-SELF-CRITIQUE — re-recording same function requires a sweep
    if audit_log is not None:
        key = f"{outcome.file}:{outcome.function}"

        def _bare_key(k: str) -> str:
            # Journal keys are lined ("file:function:line") — strip a
            # numeric tail so they compare against the bare form, like
            # get_reviewed_set does.
            head, _, tail = k.rpartition(":")
            return head if tail.isdigit() else k

        prior_records = [
            e
            for e in audit_log
            if _bare_key(e.get("key", "")) == key
            and e.get("action") in ("record", "orchestrator_review")
            and e.get("status") in ("finding", "suspicious")
            # Edge-contract records review one outgoing EDGE — a prior
            # edge suspicion must not make the caller's own function
            # review count as re-recording (same screen as
            # get_reviewed_set).
            and not e.get("edge_callee")
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


class _ClientBudgetGate:
    """CostGate over the run's budget-capped LLM client.

    Panel dispatch multiplies per-function review cost by the panel
    size; the multi-model substrate's reviewer/aggregator cost gating
    needs to see the client's live spend against its per-scan cap.
    ``budget_ratio() == 0.0`` (gate open) when the client has no
    finite cap.

    Reservation note: cost reservations are taken per call inside the
    LLM client (generate/generate_structured pre-debit an estimate
    atomically), so a panel's N model calls each hold their own
    reservation — no panel-level multiplication is needed here. This
    gate only exposes the live spend ratio.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def budget_ratio(self) -> float:
        cfg = getattr(self._client, "config", None)
        max_cost = getattr(cfg, "max_cost_per_scan", None)
        if not max_cost or max_cost <= 0 or max_cost == float("inf"):
            return 0.0
        spent = getattr(self._client, "total_cost", 0.0) or 0.0
        return spent / max_cost


def _outcome_to_panel_result(
    outcome: ReviewOutcome, model_name: str,
) -> dict[str, Any]:
    """Convert a ReviewOutcome to the multi_review panel result shape."""
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


def _is_budget_exceeded(exc: Exception) -> bool:
    """True for the budget-exceeded RuntimeError the executor stops on.

    Review fallbacks must re-raise it — journaling it as a
    per-function 'error' outcome (or dispatching another fallback
    pass) hides the stop signal and keeps spending past the cap.
    """
    from core.llm.client import is_budget_exceeded_error
    return isinstance(exc, RuntimeError) and is_budget_exceeded_error(exc)


def _multi_pass_review(
    review_fn: Callable,
    ctx: dict[str, Any],
    config: OrchestratorConfig,
    passes: int,
) -> ReviewOutcome:
    """Run review_fn across a panel and merge verdicts.

    Cross-model consensus (multi_model + 2+ models) and single-model
    self-consistency (review_passes > 1) both go through the
    core.audit.multi_review substrate (run_audit_multi_review /
    run_self_consistency). The former inline best-of-N loop — a third
    "self-consistency" implementation — was removed in favour of the
    substrate's majority-vote merge; hypothesis dedup across passes is
    preserved caller-side from the panel's raw results. A single plain
    pass remains as the last-resort fallback when the substrate fails
    at runtime.
    """
    file_path = ctx.get("file", "")
    function_name = ctx.get("function", "")
    model = config.models[0] if config.models else "default"

    # Use multi_review substrate for cross-model consensus when
    # multiple distinct models are configured
    if config.multi_model and len(config.models) > 1:
        try:
            from .multi_review import consensus_status, run_audit_multi_review

            def context_fn(_file: str, _func: str) -> dict[str, Any]:
                return ctx

            review_fns = config.review_fns_by_model or {}

            def adapted_review_fn(
                context: dict[str, Any],
                model_name: str,
            ) -> dict[str, Any]:
                # Dispatch by the panel handle's effective model: each
                # configured model gets ITS review_fn (pinned via
                # make_review_fn(model_name=...)). Falling back to the
                # single review_fn keeps consumers that never built the
                # map (tests, ensemble mode) on the old behaviour.
                model_review_fn = review_fns.get(model_name, review_fn)
                outcome = model_review_fn(context, config)
                return _outcome_to_panel_result(outcome, model_name)

            refute_fn = None
            if config.adversarial:

                def refute_fn(finding: dict[str, Any]) -> dict[str, Any]:
                    # Real refutation: a purpose-built prompt attacks
                    # the specific hypothesis (the old path re-reviewed
                    # identical context — ``adversarial_target`` was
                    # consumed by no prompt builder, so "refuted" was
                    # a coin-flip second sample saying clean).
                    from .adversarial_refute import (
                        VERDICT_NEEDS_EVIDENCE,
                        VERDICT_REFUTED,
                        pick_refuter_model,
                        run_refutation,
                    )

                    ref = run_refutation(
                        config.llm_client,
                        file=finding.get("file", file_path),
                        function=finding.get("function", function_name),
                        hypothesis=finding.get("hypothesis", "") or "",
                        body=finding.get("body", "") or "",
                        source=ctx.get("source", "") or "",
                        model_name=pick_refuter_model(
                            config.models,
                            finding.get("model")
                            or finding.get("_model") or "",
                        ),
                    )
                    if ref is None:
                        # Failed refutation is a no-op, never a demote.
                        return {
                            "refuted": False,
                            "reason": "refutation call failed",
                        }
                    return {
                        "refuted": ref.verdict == VERDICT_REFUTED,
                        "verdict": ref.verdict,
                        "reason": ref.counter_argument,
                        "defeating_mechanism": ref.defeating_mechanism,
                        "settling_evidence": ref.settling_evidence,
                        "needs_evidence": (
                            ref.verdict == VERDICT_NEEDS_EVIDENCE
                        ),
                    }

            cost_gate = (
                _ClientBudgetGate(config.llm_budget_client)
                if config.llm_budget_client is not None
                else None
            )

            # Calibrated merge inputs: the run client's scorecard store
            # (per-model per-decision-class reliability) and /validate-
            # derived priors from the journal. Both optional — without
            # them the adapter keeps the prefer-positive rule.
            scorecard = None
            priors_by_class = None
            try:
                _sc_client = config.llm_client or config.llm_budget_client
                if _sc_client is not None and hasattr(_sc_client, "scorecard"):
                    scorecard = _sc_client.scorecard()
                if scorecard is not None:
                    from .calibrated_merge import priors_from_journal
                    priors_by_class = priors_from_journal(config.out_dir)
            except Exception:
                logger.debug(
                    "calibrated-merge input wiring failed", exc_info=True,
                )

            mr_result = run_audit_multi_review(
                file_path=file_path,
                function_name=function_name,
                models=config.models,
                context_fn=context_fn,
                review_fn=adapted_review_fn,
                refute_fn=refute_fn,
                cost_gate=cost_gate,
                scorecard=scorecard,
                priors_by_class=priors_by_class,
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

        except ImportError:
            logger.debug(
                "multi_review unavailable, falling back to inline loop",
                exc_info=True,
            )
        except Exception as exc:
            # Budget exhaustion is the executor's stop signal, not a
            # per-function failure: swallowing it here journaled an
            # 'error' verdict (or bought MORE spend via the fallback
            # passes below) after the cap was already blown.
            if _is_budget_exceeded(exc):
                raise
            # The operator asked for cross-model consensus (--model A
            # --model B); a runtime failure here silently downgrades
            # to single-model self-consistency — say so visibly.
            logger.warning(
                "multi-model consensus failed for %s:%s — falling back "
                "to single-model self-consistency",
                file_path,
                function_name,
                exc_info=True,
            )

    # Single-model self-consistency: same model N times through the
    # multi_review substrate (Wang-style majority-vote merge). This
    # replaces the former inline best-of-N loop — the codebase's third
    # "self-consistency" implementation. Hypothesis dedup across
    # passes is preserved from the panel's raw results.
    if passes >= 2:
        try:
            from .multi_review import consensus_status, run_self_consistency

            def sc_context_fn(_file: str, _func: str) -> dict[str, Any]:
                return ctx

            def sc_review_fn(
                context: dict[str, Any], _model_name: str,
            ) -> dict[str, Any]:
                # Per-pass failures become error results so one bad
                # sample doesn't sink the whole panel (parity with the
                # former inline loop's per-pass handling).
                try:
                    outcome = review_fn(context, config)
                except _ContentFilterError:
                    return {"file": file_path, "function": function_name,
                            "status": "error",
                            "body": "blocked by content filter"}
                except Exception as exc:
                    if _is_budget_exceeded(exc):
                        raise
                    logger.warning(
                        "review_fn pass failed for %s:%s: %s",
                        file_path, function_name, exc,
                    )
                    return {"file": file_path, "function": function_name,
                            "status": "error",
                            "body": f"pass failed: {exc}"}
                return _outcome_to_panel_result(outcome, model)

            mr_result = run_self_consistency(
                file_path=file_path,
                function_name=function_name,
                model=model,
                n_samples=passes,
                context_fn=sc_context_fn,
                review_fn=sc_review_fn,
            )
            if mr_result.items:
                primary = mr_result.items[0]
                all_raw = [
                    r
                    for raw_list in mr_result.per_model_raw.values()
                    for r in raw_list
                ]
                seen_mechanisms: set = set()
                merged_hypotheses: list[dict[str, Any]] = []
                for r in all_raw:
                    for h in r.get("hypotheses") or []:
                        mech = h.get("mechanism", "")
                        if mech and mech not in seen_mechanisms:
                            seen_mechanisms.add(mech)
                            merged_hypotheses.append(h)
                total_cost = sum(r.get("cost_usd", 0) or 0 for r in all_raw)
                total_duration = max(
                    (r.get("duration_s", 0) or 0 for r in all_raw),
                    default=0,
                )
                return ReviewOutcome(
                    file=primary.get("file", file_path),
                    function=primary.get("function", function_name),
                    status=(consensus_status(mr_result)
                            or primary.get("status", "error")),
                    body=primary.get("body", ""),
                    hypothesis=primary.get("hypothesis", ""),
                    hypotheses=merged_hypotheses or None,
                    evidence_tool=_sanitize_llm_et(
                        primary.get("evidence_tool", "")),
                    cost_usd=total_cost,
                    model=primary.get("model", model),
                    duration_s=total_duration,
                    review_result=primary,
                )
            logger.warning(
                "self-consistency produced no items for %s:%s — "
                "falling back to a single pass",
                file_path, function_name,
            )
        except Exception as exc:
            if _is_budget_exceeded(exc):
                raise
            logger.warning(
                "self-consistency substrate failed for %s:%s — "
                "falling back to a single pass",
                file_path, function_name,
                exc_info=True,
            )

    # Last resort (passes == 1 fallback from the cross-model branch, or
    # substrate failure above): one plain pass with the standard
    # per-pass error handling.
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
        if _is_budget_exceeded(exc):
            raise
        logger.warning(
            "review_fn pass failed for %s:%s: %s",
            file_path, function_name, exc,
        )
        outcome = ReviewOutcome(
            file=file_path,
            function=function_name,
            status="error",
            body=f"pass failed: {exc}",
        )
    return ReviewOutcome(
        file=outcome.file,
        function=outcome.function,
        status=outcome.status,
        body=outcome.body,
        hypothesis=outcome.hypothesis,
        hypotheses=outcome.hypotheses,
        evidence_tool=_sanitize_llm_et(outcome.evidence_tool),
        cost_usd=outcome.cost_usd,
        model=outcome.model,
        duration_s=outcome.duration_s,
        review_result=outcome.review_result,
    )


# ``timeout`` is recoverable, with a twist: a timed-out review already
# got its single reduced-context retry inline (see
# ``_timeout_reduced_retry``), so by the time a timeout-class outcome
# reaches the end-of-run pass both the full-context call and the
# immediate reduced retry have failed. The end-of-run pass still
# re-queues it — at reduced context AND a capped per-call timeout
# (honoured by the claudecode transport; SDK providers keep their own
# class ceiling) — because by end of run a transport brownout has
# usually cleared, and without the re-queue a single timeout
# permanently errors the function's review.
_RECOVERABLE_ERROR_CLASSES = frozenset(
    {"json_parse", "truncation", "api_error", "timeout"},
)


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
    try:
        from core.llm.client import is_timeout_error
        if is_timeout_error(exc):
            return "timeout"
    except ImportError:
        pass
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


def _error_outcome(gap: dict[str, Any], exc: Exception) -> ReviewOutcome:
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

# Ceiling for the single reduced-context retry after a review call
# times out. The stripped prompt is substantially smaller, so a call
# that can succeed at all completes well inside this; a call that
# can't must not re-buy the transport's full 600s timeout.
_TIMEOUT_RETRY_TIMEOUT_S = 300


def _timeout_reduced_retry(
    gap: dict,
    ctx: dict,
    exc: Exception,
    review_fn: Callable,
    config: OrchestratorConfig,
) -> ReviewOutcome:
    """Single reduced-context retry after a review call timed out.

    Reuses the truncation-recovery strip set (block analysis, sibling
    negative-space, type constraints — the bulkiest optional context
    blocks) and caps the retry's per-call timeout at
    ``_TIMEOUT_RETRY_TIMEOUT_S``. A successful retry is tagged
    ``context_reduced=True`` so deepen re-reviews the function at
    full context later in the run; a failed retry degrades to the
    original timeout error outcome, which the end-of-run error retry
    pass re-queues once more (reduced context, capped timeout).
    """
    logger.warning(
        "review timed out for %s:%s — retrying once with reduced "
        "context (timeout capped at %ds)",
        gap["file"],
        gap["name"],
        _TIMEOUT_RETRY_TIMEOUT_S,
    )
    for key in _TRUNCATION_STRIP_KEYS:
        ctx.pop(key, None)
    ctx["error_retry"] = True
    ctx["timeout_s"] = _TIMEOUT_RETRY_TIMEOUT_S
    try:
        outcome = review_fn(ctx, config)
    except Exception as retry_exc:
        from core.llm.client import is_budget_exceeded_error

        if is_budget_exceeded_error(retry_exc):
            raise
        logger.warning(
            "reduced-context retry failed for %s:%s: %s",
            gap["file"],
            gap["name"],
            retry_exc,
        )
        # Report the ORIGINAL timeout: its classification routes the
        # outcome into the end-of-run retry pass's timeout handling
        # (reduced context + capped per-call timeout).
        return _error_outcome(gap, exc)
    outcome.context_reduced = True
    if outcome.review_result is not None:
        outcome.review_result["context_reduced"] = True
    return outcome


def _retry_error_outcomes(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: dict[str, Any],
    _shared: Any,
    _llm_client: Any,
    start_time: float,
    _sarif_cache: Any,
) -> OrchestratorResult:
    """Retry recoverable error outcomes (json_parse, truncation,
    api_error, timeout). Truncation and timeout retries strip the
    bulkiest optional context blocks; timeout retries additionally cap
    the per-call timeout (honoured by the claudecode transport; SDK
    providers keep their own class ceiling) and tag any recovered
    verdict ``context_reduced`` so it is re-reviewed rather than
    reused cross-run."""
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
        # Silent skip is intentional: a context-build failure just drops
        # this outcome from the error-retry pass.
        except Exception:  # noqa: BLE001, S112
            continue

        if outcome.error_class in ("truncation", "timeout"):
            for key in _TRUNCATION_STRIP_KEYS:
                ctx.pop(key, None)
        if outcome.error_class == "timeout":
            # The full-context call and the inline reduced retry both
            # timed out — cap the re-queue's per-call timeout so it
            # doesn't re-buy the transport's full timeout on top
            # (per-call caps are honoured by the claudecode
            # transport; SDK providers keep their own class ceiling).
            ctx["timeout_s"] = _TIMEOUT_RETRY_TIMEOUT_S
        ctx["error_retry"] = True

        try:
            new_outcome = review_fn(ctx, config)
        except Exception as exc:  # noqa: BLE001
            from core.llm.client import is_budget_exceeded_error

            if is_budget_exceeded_error(exc):
                # Terminal: every remaining retry would fail the same
                # way — stop the retry pass instead of burning prep
                # time on each leftover error outcome.
                result.terminated_by = "llm_budget_exceeded"
                break
            continue

        if outcome.error_class == "timeout" and new_outcome.status != "error":
            # Mirror the inline reduced retry's provenance tag: this
            # verdict came from stripped context, so it must not
            # become durable full-confidence coverage evidence —
            # cross-run reuse (gaps._reuse_ineligibility) refuses to
            # import context_reduced verdicts and the next run
            # re-reviews the function at full context. (Deepen has
            # already run by this point in the pipeline, so the tag's
            # effect is purely cross-run.)
            new_outcome.context_reduced = True
            if new_outcome.review_result is not None:
                new_outcome.review_result["context_reduced"] = True

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


def _record_executor_stop(result: OrchestratorResult, executor_stats: Any) -> None:
    """Name the stop reason when the executor stopped without one.

    ``terminated_by`` defaults to the truthy string "complete" (the old
    ``not result.terminated_by`` guard here never fired).  Budget stops
    are named by ``_check_budget`` or the budget-RuntimeError handlers;
    the remaining unnamed cause of ``budget_stopped`` is an operator
    shutdown request.
    """
    if executor_stats.budget_stopped and result.terminated_by == "complete":
        result.terminated_by = "shutdown"


def _hold_review_reserve(config: OrchestratorConfig) -> float:
    """Hold the review loop's budget slice on the run's budget client.

    Mirrors :func:`_hold_deepen_reserve` for the phase boundary one
    step earlier: the pre-review bulk passes gate against
    ``cap - reserve`` so the per-function reviews (and the deepen
    re-reviews after them) can always execute. Returns the amount
    held (0.0 when no reserve was taken)."""
    fraction = getattr(config, "review_reserve_fraction", 0.0) or 0.0
    if fraction <= 0:
        return 0.0
    client = getattr(config, "llm_budget_client", None)
    if client is None or not hasattr(client, "hold_budget_reserve"):
        return 0.0
    try:
        cap = getattr(
            getattr(client, "config", None), "max_cost_per_scan", 0,
        ) or 0
        if not cap or cap == float("inf"):
            return 0.0
        held = client.hold_budget_reserve(cap * min(fraction, 0.9))
        if held:
            logger.info(
                "review: holding $%.2f (%.0f%% of the $%.2f cap) in "
                "reserve so the review loop cannot be starved by the "
                "prep passes",
                held, 100.0 * min(fraction, 0.9), cap,
            )
        return held
    except Exception:  # reserve is an optimisation, never fatal
        logger.debug("review reserve hold failed", exc_info=True)
        return 0.0


def _release_review_reserve(config: OrchestratorConfig) -> None:
    """Release the review reserve back to dispatch (idempotent)."""
    client = getattr(config, "llm_budget_client", None)
    if client is None or not hasattr(client, "release_budget_reserve"):
        return
    try:
        released = client.release_budget_reserve()
        if released:
            logger.info(
                "review: released the $%.2f reserve to the review "
                "loop", released,
            )
    except Exception:
        logger.debug("review reserve release failed", exc_info=True)


def _hold_deepen_reserve(config: OrchestratorConfig) -> float:
    """Hold the deepen phase's budget slice on the run's budget client.

    Only when deepen is enabled AND reachable (a budget client with a
    finite cap exists and the fraction is positive). Returns the amount
    held (0.0 when no reserve was taken)."""
    if not config.deepen_suspicious:
        return 0.0
    fraction = getattr(config, "deepen_reserve_fraction", 0.0) or 0.0
    if fraction <= 0:
        return 0.0
    client = getattr(config, "llm_budget_client", None)
    if client is None or not hasattr(client, "hold_budget_reserve"):
        return 0.0
    try:
        cap = getattr(
            getattr(client, "config", None), "max_cost_per_scan", 0,
        ) or 0
        if not cap or cap == float("inf"):
            return 0.0
        held = client.hold_budget_reserve(cap * min(fraction, 0.9))
        if held:
            logger.info(
                "deepen: holding $%.2f (%.0f%% of the $%.2f cap) in "
                "reserve so announced re-reviews can execute",
                held, 100.0 * min(fraction, 0.9), cap,
            )
        return held
    except Exception:  # reserve is an optimisation, never fatal
        logger.debug("deepen reserve hold failed", exc_info=True)
        return 0.0


def _release_deepen_reserve(config: OrchestratorConfig) -> None:
    """Release the deepen reserve back to dispatch (idempotent)."""
    client = getattr(config, "llm_budget_client", None)
    if client is None or not hasattr(client, "release_budget_reserve"):
        return
    try:
        released = client.release_budget_reserve()
        if released:
            logger.info(
                "deepen: released the $%.2f reserve to the deepen "
                "phase", released,
            )
    except Exception:
        logger.debug("deepen reserve release failed", exc_info=True)


def _client_class_cost(client: Any, call_class: str) -> float:
    """Completed-call spend the client has recorded for one call class.

    Reads the client's per-class cost history — the only per-purpose
    ledger that stays accurate when several audit phases share the
    budget-governed client concurrently."""
    hist = getattr(client, "_call_cost_history", None) or {}
    entry = hist.get(call_class)
    return float(entry[1]) if entry else 0.0


def _run_llm_client(config: OrchestratorConfig) -> Any:
    """The run's budget-governed LLM client.

    EVERY audit call class must dispatch through the client whose
    ledger enforces --max-cost: a fresh ``LLMClient()`` carries its own
    (default) cap, so its calls bypass the per-call reservation gate
    AND never reach the run's authoritative spend ledger — one measured
    run booked $24.10 while telemetry showed $29.18 because iris /
    spec_inference / post-loop classes each built private clients.

    Falls back to a fresh client (pinned to the run's primary model)
    only when no budget client was wired — library callers and tests.
    """
    client = getattr(config, "llm_budget_client", None)
    if client is not None:
        return client
    from core.llm.client import LLMClient

    model = (
        config.models[0]
        if config.models and config.models[0] != "default"
        else None
    )
    return LLMClient(pinned_model=model) if model else LLMClient()


#: Seconds between incremental spend-floor writes from the budget
#: poll. Cheap (one small atomic file) but there is no reason to
#: write it on every poll.
_SPEND_FLOOR_INTERVAL_S = 5.0


def _persist_spend_floor(
    config: OrchestratorConfig,
    result: OrchestratorResult,
    *,
    force: bool = False,
) -> None:
    """Throttled incremental persist of the whole-run spend floor.

    cost-breakdown.json is only written at reconciliation/salvage, so
    a hard-killed segment (SIGKILL, OOM) booked $0 and the next
    resume segment overspent the cap by the dead segment's spend.
    Riding the budget poll keeps the floor at most a few seconds
    stale. Never raises.
    """
    out_dir = getattr(config, "out_dir", None)
    if not out_dir:
        return
    try:
        now = time.monotonic()
        with result._lock:
            last = getattr(result, "_spend_floor_written_at", 0.0)
            if not force and now - last < _SPEND_FLOOR_INTERVAL_S:
                return
            result._spend_floor_written_at = now
            spend = float(result.total_cost_usd or 0.0)
        client = getattr(config, "llm_budget_client", None)
        if client is not None:
            spend = max(
                spend,
                float(getattr(client, "total_cost", 0.0) or 0.0),
                float(getattr(client, "provider_spend_usd", 0.0) or 0.0),
            )
        # Whole-run figure: a resume segment's ledgers are segment-
        # local; add the prior segments' spend. Same resolution rule
        # as the reconciliation booking: the resolved figure from the
        # resume CLI survives an unreconciled predecessor (no prior
        # ledger dict).
        prior = getattr(config, "prior_cost_breakdown", None)
        prior_booked = max(
            0.0,
            float(getattr(config, "prior_booked_spend_usd", 0.0) or 0.0),
        )
        if prior or prior_booked > 0:
            from .resume import booked_spend_usd
            spend += max(booked_spend_usd(prior), prior_booked)
        from .resume import persist_spend_floor
        persist_spend_floor(
            out_dir, spend,
            segment=getattr(config, "resume_segment", None),
        )
    except Exception:
        logger.debug("spend floor persist failed", exc_info=True)


def _check_budget(
    config: OrchestratorConfig,
    start_time: float,
    result: OrchestratorResult,
    *,
    skip_max_seconds: bool = False,
) -> bool:
    """Return True when budget is exhausted.

    ``skip_max_seconds`` lets a CONSUMER loop defer wall-clock
    enforcement to its producer: the study consumer stopping on
    ``max_seconds`` while the review loop is still dispatching paid
    reviews saves no wall clock (the producer governs it) and starves
    those very reviews of study results. Cost caps and SIGTERM are
    never skipped — money is fungible across threads.
    """
    # Keep the on-disk spend floor fresh while any loop polls the
    # rails — this is what books a hard-killed segment's spend for
    # the next resume segment.
    _persist_spend_floor(config, result)
    # SIGTERM rides the budget-exhaustion rails: every loop and
    # post-loop pass that polls this stops dispatching, and the study
    # consumer's state-aware drain sees "exhausted" and stops too.
    if is_sigterm_requested():
        result.terminated_by = "sigterm"
        _persist_spend_floor(config, result, force=True)
        return True
    if (
        not skip_max_seconds
        and config.max_seconds
        and time.monotonic() - start_time >= config.max_seconds
    ):
        result.terminated_by = "max_seconds"
        return True
    if config.max_cost_usd:
        with result._lock:
            if result.total_cost_usd >= config.max_cost_usd:
                result.terminated_by = "max_cost_usd"
                return True
    # The LLM client's own ledger includes spend from failed/timed-out
    # attempts that never produced an outcome, so it can be exhausted
    # while ``result.total_cost_usd`` (successful outcomes only) is
    # far below the cap. Without this check every post-exhaustion loop
    # (deepen, error retry, study) kept dispatching doomed LLM calls.
    _client = getattr(config, "llm_budget_client", None)
    if _client is not None and _client.is_budget_exhausted():
        result.terminated_by = "llm_budget_exceeded"
        return True
    return False


_BUDGET_STOP_REASONS = {
    "llm_budget_exceeded": "budget exhausted",
    "max_cost_usd": "budget exhausted",
    "max_seconds": "time budget exhausted",
}


def _announce_budget_stop(
    result: OrchestratorResult,
    executor_stats: Any,
    graph: Any,
    on_progress: Callable | None,
) -> None:
    """Emit ONE clear operator-facing line when the review loop stops
    on budget exhaustion, instead of a silent break (or, pre-fix, a
    wall of per-function error lines). Unreviewed functions are not
    journaled, so they stay gap-eligible for a future run."""
    reason = _BUDGET_STOP_REASONS.get(result.terminated_by)
    if reason is None:
        return  # operator shutdown or other stop — not a budget event
    completed = executor_stats.completed + executor_stats.repass_completed
    total = len(graph)
    remaining = graph.pending
    msg = (
        f"{reason} after {completed}/{total} reviews — stopping; "
        f"{remaining} functions left unreviewed "
        f"(they remain gaps for a future run)"
    )
    # ONE channel: the progress callback renders on the operator
    # console (stdout); also warning through the logger printed the
    # same line twice. The logger is the fallback when no callback
    # exists (library callers, tests).
    emitted_via_progress = False
    if on_progress:
        try:
            # idx < 0 is the progress protocol's "print body verbatim"
            # channel (see libexec/raptor-audit on_progress).
            on_progress(-1, total, ReviewOutcome(
                file="", function="", status="error", body=msg,
            ))
            emitted_via_progress = True
        except Exception:
            logger.debug("budget-stop progress emit failed", exc_info=True)
    if not emitted_via_progress:
        logger.warning(msg)


@dataclass
class StudyRequest:
    """A single reading-list item produced by a review."""
    question: str
    source_file: str
    source_function: str
    priority: str = "normal"
    resolution: str = "identifier"
    context: str = ""


# C/C++ suffixes route to the study-prep corpus; the other supported
# languages (core.concepts.lang_resolve.STUDY_LANGUAGES) resolve
# in-process per batch.
_C_STUDY_SUFFIXES = frozenset(
    (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"),
)


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
        # Drain/shutdown seam: the orchestrator's drain path requests a
        # cooperative stop; the consumer checks it at every lifecycle
        # checkpoint (loop top, dequeue wait, before each study step)
        # and the interruptible prep runner kills its subprocess.
        self._stop_requested = False
        # Liveness telemetry for the drain path: progress ticks at each
        # completed consumer step, and a "working" flag distinguishes
        # "mid-batch (prep/study/re-review)" from "idle on the queue".
        self._progress = 0
        self._working = False
        self._inflight_proc: Any = None

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
            if self._stop_requested:
                return []
            if not self._queue and not self._producer_done:
                self._not_empty.wait(timeout=timeout)
            if self._stop_requested:
                return []
            batch = self._queue[:max_items]
            del self._queue[:max_items]
            return batch

    def signal_producer_done(self) -> None:
        with self._not_empty:
            self._producer_done = True
            self._not_empty.notify_all()

    def producer_done(self) -> bool:
        with self._not_empty:
            return self._producer_done

    def is_done(self) -> bool:
        with self._not_empty:
            if self._stop_requested:
                return True
            return self._producer_done and not self._queue

    def request_stop(self) -> None:
        """Cooperative shutdown: wake the consumer out of its dequeue
        wait, make every subsequent lifecycle checkpoint observe the
        stop, and kill the in-flight study-prep subprocess (if any).
        Idempotent and thread-safe."""
        with self._not_empty:
            self._stop_requested = True
            proc = self._inflight_proc
            self._not_empty.notify_all()
        if proc is not None:
            with contextlib.suppress(OSError):
                proc.kill()

    @property
    def stop_requested(self) -> bool:
        with self._not_empty:
            return self._stop_requested

    def register_inflight(self, proc: Any) -> None:
        """Expose a killable subprocess handle to :meth:`request_stop`."""
        kill_now = False
        with self._not_empty:
            self._inflight_proc = proc
            kill_now = self._stop_requested
        if kill_now and proc is not None:
            # A stop raced ahead of registration — honour it.
            with contextlib.suppress(OSError):
                proc.kill()

    def clear_inflight(self) -> None:
        with self._not_empty:
            self._inflight_proc = None

    def note_progress(self) -> None:
        """Bump the liveness counter (one completed consumer step)."""
        with self._not_empty:
            self._progress += 1

    def set_working(self, working: bool) -> None:
        """Mark whether the consumer is mid-batch (prep / study /
        re-review) as opposed to idle on the queue."""
        with self._not_empty:
            self._working = working

    def drain_state(self) -> tuple[int, bool, bool]:
        """Snapshot for the drain loop: (progress, queue_empty, working)."""
        with self._not_empty:
            return self._progress, not self._queue, self._working

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


def _diff_new_concepts(
    seen_concepts: set,
    pre_dm: dict | None,
    post_dm: dict | None,
) -> set:
    """Return concept names added by this study batch, updating
    *seen_concepts* in place.

    Pre-study names (*pre_dm*) are folded into *seen_concepts* first so
    only genuinely new concepts from *post_dm* are returned; the
    post-study names are then folded in for the next iteration.
    """
    seen_concepts.update(
        c.get("name", "").lower() for c in (pre_dm or {}).get("concepts", [])
    )
    new: set = set()
    if post_dm:
        all_concepts = {
            c.get("name", "").lower() for c in post_dm.get("concepts", [])
        }
        new = all_concepts - seen_concepts
        seen_concepts.update(all_concepts)
    return new


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
    "Does process_heartbeat validate payload_len against out_cap?",
    and dotted/qualified non-C shapes like "Does json.loads reject
    NaN?" or "Does Vec::with_capacity zero memory?".
    """
    import re as _re
    m = _re.search(
        r"(?:what is|how does|does)\s+[`'\"]?([\w.:]+)[`'\"]?",
        question,
        _re.IGNORECASE,
    )
    if not m:
        return None
    concept = m.group(1).strip(".:")
    return concept or None


def _partition_study_batch(
    batch: list[StudyRequest],
) -> tuple[list[StudyRequest], list[StudyRequest], list[StudyRequest]]:
    """Split a study batch by resolver.

    Returns ``(c_reqs, ml_reqs, unsupported)``: C/C++ questions resolve
    against the study-prep corpus, ``ml_reqs`` (Python/Go/Java/JS-TS/
    Rust) resolve in-process, and ``unsupported`` languages have no
    resolver — those items are marked unresolvable, never guessed.
    Requests without a source file stay on the C path (legacy shape).
    """
    from core.concepts.lang_resolve import language_for_path

    c_reqs: list[StudyRequest] = []
    ml_reqs: list[StudyRequest] = []
    unsupported: list[StudyRequest] = []
    for req in batch:
        sf = req.source_file or ""
        suffix = Path(sf).suffix.lower()
        if not sf or suffix in _C_STUDY_SUFFIXES:
            c_reqs.append(req)
        elif language_for_path(sf):
            ml_reqs.append(req)
        else:
            unsupported.append(req)
    return c_reqs, ml_reqs, unsupported


def _mark_concepts_studied(
    study_queue: StudyQueue, reqs: list[StudyRequest],
) -> None:
    """Release the suppression gate for this batch's concepts."""
    batch_concepts = set()
    for req in reqs:
        c = _extract_concept_from_question(req.question)
        if c:
            batch_concepts.add(c.lower())
    if batch_concepts:
        study_queue.mark_studied(batch_concepts)


def _warn_critical_unresolvable(req: StudyRequest, reason: str) -> None:
    """A critical assumption the verdict depended on could not be
    verified — one operator-visible line, mirroring the loud-
    degradation convention of the rest of the consumer."""
    if (req.priority or "") == "critical":
        logger.warning(
            "study-consumer: CRITICAL assumption unresolvable "
            "(%s): %s [%s:%s]",
            reason, req.question, req.source_file, req.source_function,
        )


def _mark_unsupported_unresolvable(
    out_dir: Path, reqs: list[StudyRequest],
) -> None:
    """Mark reading-list items from languages with no resolver as
    unresolvable — they must not be studied, retried, or reported as
    resolved-clean."""
    try:
        from core.concepts.reading_list import ReadingList

        rl_path = out_dir / "reading-list.json"
        rl = ReadingList.load(rl_path)
        changed = False
        for req in reqs:
            suffix = Path(req.source_file or "").suffix or "?"
            reason = (
                f"study loop has no resolver for '{suffix}' sources"
            )
            for item in rl.items:
                if (
                    item.question == req.question
                    and not item.resolved
                    and not item.unresolvable
                ):
                    item.mark_unresolvable(reason)
                    changed = True
                    _warn_critical_unresolvable(req, reason)
                    break
        if changed:
            rl.save(rl_path)
    except Exception:
        logger.debug(
            "study-consumer: unsupported-language marking failed",
            exc_info=True,
        )


def _resolve_scoped(
    root: Path,
    all_idents: list[str],
    ident_reqs: list[StudyRequest],
    resolve_identifiers,
    *,
    include_c: bool = False,
):
    """Directory-scoped identifier resolution, any study language.

    A stdlib- or kernel-sized tree defeats the resolver's flat file
    cap (a root scan stops after the cap and reports resolvable
    identifiers as not-found — observed marking a critical premise
    question unresolvable for a function that exists in the tree), so
    each request's subsystem directory is searched first — premise
    questions overwhelmingly name identifiers defined near the
    reviewed code. Identifiers the subsystem passes leave unresolved
    get an include-chase pass over each request source file's
    ``#include`` graph — definitions in shared header roots
    (``include/linux/...``) are reachable from the reviewed code but
    sit in neither its directory nor the capped root scan (observed
    live: a static-inline helper under ``include/`` reported as
    not-found for a driver-subsystem request). Leftovers after that
    get one root-scoped pass (which fully covers small trees).
    """
    merged_items: list = []
    remaining = list(all_idents)
    scopes: list[Path] = []
    seen_scopes: set[str] = set()
    for req in ident_reqs:
        sf = (req.source_file or "").strip()
        if not sf:
            continue
        d = root / Path(sf).parent
        key = str(d)
        if key not in seen_scopes and d.is_dir() and d != root:
            seen_scopes.add(key)
            scopes.append(d)
    for scope in scopes:
        if not remaining:
            break
        res = resolve_identifiers(
            root, remaining, scope=scope, include_c=include_c,
        )
        merged_items.extend(res.items)
        unres = {u["name"] for u in res.unresolved}
        remaining = [n for n in remaining if n in unres]
    if remaining:
        chase_files: list = []
        chase_seen: set = set()
        chased: set[str] = set()
        try:
            from core.concepts.lang_resolve import include_scope_files
            for req in ident_reqs:
                sf = (req.source_file or "").strip()
                if not sf or sf in chased:
                    continue
                chased.add(sf)
                for p in include_scope_files(root, sf):
                    if p not in chase_seen:
                        chase_seen.add(p)
                        chase_files.append(p)
        except Exception:
            logger.debug(
                "study-consumer: include chase failed", exc_info=True,
            )
        if chase_files:
            res = resolve_identifiers(
                root, remaining, files=chase_files, include_c=include_c,
            )
            merged_items.extend(res.items)
            unres = {u["name"] for u in res.unresolved}
            remaining = [n for n in remaining if n in unres]
    final = resolve_identifiers(root, remaining, include_c=include_c)
    final.items = merged_items + final.items
    return final


def _resolve_multilang_requests(
    config: OrchestratorConfig,
    ml_reqs: list[StudyRequest],
    study_list_path: Path | None,
    *,
    include_c: bool = False,
) -> dict[str, str]:
    """Per-batch in-process resolution for non-C study requests.

    Resolved definitions are merged into study-list.json so the
    subsequent run_study call (which re-reads the file) studies them.
    Returns ``{question: reason}`` for questions whose identifiers
    could not be statically resolved — the caller marks those
    reading-list items unresolvable instead of resolved-clean.

    With ``include_c`` True this is the C per-batch definition splice:
    study-prep runs once, so C questions raised in later batches never
    gain corpus definitions through it. Resolution is scoped to each
    request's subsystem directory first (bounded on huge trees), then
    the tree root for leftovers. The caller must not treat C misses as
    authoritative failures — the one-shot prep corpus may already
    carry the concept.
    """
    failures: dict[str, str] = {}
    try:
        from core.concepts.lang_resolve import (
            extract_question_identifiers,
            merge_into_study_list,
            resolve_concept_docs,
            resolve_identifiers,
        )
    except Exception:
        logger.warning(
            "study-consumer: lang_resolve unavailable — multilang "
            "batch skipped", exc_info=True,
        )
        return failures

    root = Path(config.study_root or config.target_path)
    ident_reqs = [r for r in ml_reqs if r.resolution != "concept"]
    concept_reqs = [r for r in ml_reqs if r.resolution == "concept"]

    q_idents: dict[str, list[str]] = {}
    all_idents: list[str] = []
    seen: set[str] = set()
    for req in ident_reqs:
        names = extract_question_identifiers(req.question, req.context)
        sf_fn = (req.source_function or "").strip()
        if sf_fn and sf_fn not in names:
            names.append(sf_fn)
        q_idents[req.question] = names
        for n in names:
            if n not in seen:
                seen.add(n)
                all_idents.append(n)

    unresolved_by_name: dict[str, str] = {}
    if all_idents:
        res = _resolve_scoped(
            root, all_idents, ident_reqs, resolve_identifiers,
            include_c=include_c,
        )
        unresolved_by_name = {
            u["name"]: u["reason"] for u in res.unresolved
        }
        if study_list_path is not None:
            try:
                merge_into_study_list(
                    study_list_path, res.items, unresolved=res.unresolved,
                )
            except OSError:
                logger.warning(
                    "study-consumer: study-list merge failed",
                    exc_info=True,
                )
        logger.info(
            "study-consumer: %s batch: %d identifiers → "
            "%d items, %d unresolvable",
            "C splice" if include_c else "multilang",
            len(all_idents), len(res.items), len(res.unresolved),
        )

    for req in ident_reqs:
        names = q_idents.get(req.question) or []
        if not names:
            failures[req.question] = (
                "question names no resolvable identifier"
            )
            continue
        if all(n in unresolved_by_name for n in names):
            failures[req.question] = unresolved_by_name[names[0]]

    if concept_reqs:
        docs = resolve_concept_docs(
            root, [r.question for r in concept_reqs],
        )
        if docs and study_list_path is not None:
            try:
                merge_into_study_list(
                    study_list_path, [], related_docs=docs,
                )
            except OSError:
                logger.warning(
                    "study-consumer: study-list doc merge failed",
                    exc_info=True,
                )
        if not docs:
            for req in concept_reqs:
                failures[req.question] = (
                    "no project documentation found for this concept"
                )

    return failures


def _match_domain_entry(
    domain_model: dict | None,
    concept_l: str,
    tail: str,
) -> tuple[str, str, dict | None, str] | None:
    """Best domain-model entry matching a question's identifier.

    Returns ``(entry_id, provenance, receipt, description)`` preferring
    actionable tiers (verbatim/mechanical) over unverified summaries,
    or None when nothing matches.
    """
    if not domain_model or not concept_l:
        return None
    from core.concepts.receipts import tier_rank

    candidates: list[tuple[str, str, dict | None, str]] = []
    for c in domain_model.get("concepts", []):
        cid = (c.get("id") or "").lower()
        if cid and (concept_l in cid or (tail and tail in cid)):
            candidates.append((
                c.get("id") or "",
                c.get("provenance") or "",
                c.get("receipt"),
                c.get("description") or "",
            ))
    for inv in domain_model.get("invariants", []):
        iid = (inv.get("id") or "").lower()
        ic = (inv.get("concept") or "").lower()
        if (iid and (concept_l in iid or (tail and tail in iid))) or (
            ic and (concept_l in ic or (tail and tail in ic))
        ):
            candidates.append((
                inv.get("id") or "",
                inv.get("provenance") or "",
                inv.get("receipt"),
                inv.get("statement") or "",
            ))
    for ct in domain_model.get("contracts", []):
        fn = (ct.get("function") or "").lower()
        if fn and (concept_l in fn or (tail and tail == fn)):
            candidates.append((
                f"contract:{ct.get('function')}",
                ct.get("provenance") or "",
                ct.get("receipt"),
                ct.get("output_semantics") or ct.get("implication") or "",
            ))
    if not candidates:
        return None
    candidates.sort(key=lambda c: tier_rank(c[1]))
    return candidates[0]


def _record_study_scorecard(
    model: str, agreed: bool, reason: str,
) -> None:
    """Log a flip-path study answer to the per-model scorecard
    (study_question decision class).  Best-effort — never blocks the
    consumer."""
    try:
        from core.llm.scorecard.scorecard import EventType, ModelScorecard

        raptor_dir = os.environ.get("RAPTOR_DIR")
        path = (
            Path(raptor_dir) / "out" / "llm_scorecard.json"
            if raptor_dir else Path("out/llm_scorecard.json")
        )
        sc = ModelScorecard(path)
        sc.record_event(
            "study_question",
            model or "default",
            EventType.STUDY_QUESTION,
            "correct" if agreed else "incorrect",
            sample=None if agreed else {"reason": reason[:200]},
        )
    except Exception:
        logger.debug("study scorecard record failed", exc_info=True)


def _record_study_flip(config: OrchestratorConfig, outcome: Any) -> None:
    """Register a study-answer-driven verdict flip on the scorecard
    (volume signal under the study_question decision class)."""
    try:
        from core.llm.scorecard.scorecard import ModelScorecard

        raptor_dir = os.environ.get("RAPTOR_DIR")
        path = (
            Path(raptor_dir) / "out" / "llm_scorecard.json"
            if raptor_dir else Path("out/llm_scorecard.json")
        )
        model = (
            getattr(outcome, "model", "")
            or (config.models[0] if config.models else "default")
        )
        ModelScorecard(path).register_uses([{
            "model": model,
            "decision_class": "study_question",
            "calls": 1,
        }])
    except Exception:
        logger.debug("study flip record failed", exc_info=True)


def _corpus_has_snippet(concept_l: str, tail: str, study_items: list[dict]) -> bool:
    """Extract-then-answer check: did mechanical extraction produce
    ANY snippet for this identifier?"""
    for it in study_items:
        if not isinstance(it, dict):
            continue
        name = (it.get("name") or "").lower()
        if name and (
            name in (tail, concept_l)
            or concept_l.endswith(("." + name, "::" + name))
        ):
            return True
        defn = (it.get("definition") or "").lower()
        if tail and tail in defn:
            return True
    return False


_NO_SNIPPET_REASON = (
    "no extracted source snippet — the study loop does not answer "
    "from prior knowledge"
)


def _mark_batch_reading_list(
    out_dir: Path,
    reqs: list[StudyRequest],
    domain_model: dict | None,
    failures: dict[str, str],
    *,
    study_list_path: Path | None = None,
    source_root: Path | None = None,
    study_client: Any = None,
    scorecard_model: str = "",
    probe_budget: Any = None,
    determine_budget: Any = None,
) -> set[str]:
    """Post-study reading-list bookkeeping for one batch.

    Semantics (pinned by tests):
    - resolved: an ACTIONABLE-tier answer (receipt-verified verbatim
      quote, or mechanical extraction) matches the question — and, on
      the verbatim flip path, survived the independent agreement
      gate.  Only resolved questions re-enter the review queue.
    - unresolvable(+reason): the resolver reported the question cannot
      be answered from the source, the answer's receipt failed
      verification, or extraction produced no snippet (the study loop
      never answers from prior knowledge).  Never counted as resolved.
    - inconclusive: the agreement gate disagreed — the answer is
      quarantined in the ledger, the item stays pending, no re-review.
    - pending: studied but no verified answer landed — attempted yet
      unverified is NOT resolved-clean; the item stays visible.

    Every processed question is recorded in study-answers.json with
    its tier, receipt, and original assumption.  Returns the set of
    ``file:function`` keys whose questions RESOLVED (re-review
    eligible).
    """
    from core.concepts.reading_list import ReadingList
    from core.concepts.receipts import (
        TIER_LLM_SUMMARIZED,
        TIER_VERBATIM,
        is_actionable_tier,
    )
    from core.concepts.study_answers import StudyAnswer, append_answers

    rl_path = out_dir / "reading-list.json"
    rl = ReadingList.load(rl_path)

    # Study corpus (for spot-checks + extract-then-answer enforcement)
    study_items: list[dict] = []
    corpus_loaded = False
    if study_list_path is not None and Path(study_list_path).is_file():
        raw = load_json(
            Path(study_list_path), max_bytes=_MAX_ARTIFACT_BYTES,
        )
        if raw is not None:
            study_items = raw.get("items", []) if isinstance(raw, dict) else []
            corpus_loaded = True

    # Receipt-verification discards from run_study
    discard_names: set[str] = set()
    discards_path = out_dir / "study-discards.json"
    if discards_path.is_file():
        discards = load_json(discards_path, max_bytes=_MAX_STATE_BYTES)
        discards = discards if isinstance(discards, dict) else {}
        for d in discards.get("discarded", []):
            if not isinstance(d, dict):
                continue
            for n in [d.get("id"), *(d.get("names") or [])]:
                if n:
                    discard_names.add(str(n).lower())

    import re as _re
    eligible: set[str] = set()
    ledger: list = []
    changed = False

    def _mark_unresolvable(item, req, reason: str, tier: str = "") -> None:
        nonlocal changed
        item.mark_unresolvable(reason)
        _warn_critical_unresolvable(req, reason)
        changed = True
        ledger.append(StudyAnswer(
            question=req.question,
            source_file=req.source_file,
            source_function=req.source_function,
            assumption=req.context or "",
            tier=tier,
            status="unresolvable",
            reason=reason,
        ))

    for req in reqs:
        item = next(
            (
                i for i in rl.items
                if i.question == req.question
                and not i.resolved and not i.unresolvable
            ),
            None,
        )
        if item is None:
            continue
        fn_key = f"{req.source_file}:{req.source_function}"

        reason = failures.get(req.question)
        if reason:
            _mark_unresolvable(item, req, reason)
            continue

        concept = _extract_concept_from_question(req.question)
        cl = (concept or "").lower()
        tail = _re.split(r"\.|::", cl)[-1] if cl else ""

        # Receipt-check failure: the study answered but the quote did
        # not verify — the answer was discarded, never delivered.
        if cl and (cl in discard_names or (tail and tail in discard_names)):
            _mark_unresolvable(
                item, req, "receipt verification failed",
            )
            continue

        # Mechanical spot-check: decidable without an LLM — preferred
        # over any LLM summary.
        spot = None
        if study_items:
            try:
                from core.concepts.spot_check import spot_check_question
                spot = spot_check_question(req.question, study_items)
            except Exception:
                logger.debug("spot-check failed", exc_info=True)

        # Compiler channel: textually undecidable constant claims on
        # C/C++ targets (computed #defines, enum auto-values, sizeof/
        # alignof/offsetof) resolve by sandboxed compile-probe.
        # Verified/contradicted are mechanical verdicts with a
        # compiler receipt; unavailable keeps the question's prior
        # state with an explicit note — never a fabricated verdict.
        probe_note = ""
        probe = None
        if spot is None and study_items and source_root is not None:
            try:
                from core.audit.compile_probe import (
                    compile_probe_question,
                )
                probe = compile_probe_question(
                    req.question, study_items, Path(source_root),
                    budget=probe_budget,
                )
            except Exception:
                logger.debug("compile probe failed", exc_info=True)
            if probe is not None and probe.status == "unavailable":
                probe_note = (
                    f"compile-probe unavailable/failed: {probe.reason}"
                )
                logger.info(
                    "study-consumer: %s (%s)", probe_note, req.question,
                )
                probe = None
        # Determine-value channel (config-gated; determine_budget is
        # None when the mode is off): claim-less "what is the value
        # of X?" questions resolve by bisection whose only verdict is
        # the final equality probe — same mechanical tier + receipt.
        if (
            probe is None and determine_budget is not None
            and spot is None and study_items and source_root is not None
        ):
            try:
                from core.audit.compile_probe import (
                    determine_probe_question,
                )
                probe = determine_probe_question(
                    req.question, study_items, Path(source_root),
                    budget=determine_budget,
                )
            except Exception:
                logger.debug("determine probe failed", exc_info=True)
            if probe is not None and probe.status == "unavailable":
                probe_note = (
                    f"determine-probe unavailable/failed: {probe.reason}"
                )
                logger.info(
                    "study-consumer: %s (%s)", probe_note, req.question,
                )
                probe = None
        if probe is not None:
            from core.audit.compile_probe import probe_receipt
            probe_l = probe.expression.lower()
            overrode = _match_domain_entry(
                domain_model, cl or probe_l, tail or probe_l,
            ) is not None
            concept_id = f"compileprobe:{probe.expression}"
            item.resolve(concept_id)
            changed = True
            eligible.add(fn_key)
            if probe.status == "contradicted":
                logger.info(
                    "study-consumer: compile-probe CONTRADICTED the "
                    "claimed value for %r%s",
                    probe.expression,
                    " — overriding LLM summary" if overrode else "",
                )
            elif overrode:
                logger.info(
                    "study-consumer: compile-probe overrode LLM "
                    "summary for %r", probe.expression,
                )
            _record_study_scorecard(
                scorecard_model, True, "compile-probe",
            )
            ledger.append(StudyAnswer(
                question=req.question,
                source_file=req.source_file,
                source_function=req.source_function,
                assumption=req.context or "",
                answer=probe.answer,
                tier="mechanical",
                receipt=probe_receipt(probe).to_dict(),
                status="resolved",
                resolved_concept_id=concept_id,
                spot_check_override=overrode,
                agreement={
                    "agreed": True,
                    "reason": "mechanical answer — deterministic, "
                              "gate skipped",
                },
            ))
            continue

        if spot is not None:
            spot_l = spot.identifier.lower()
            overrode = _match_domain_entry(
                domain_model, cl or spot_l, tail or spot_l,
            ) is not None
            concept_id = f"spotcheck:{spot.identifier}"
            # A spot-check answer that CONTRADICTS the question's
            # asserted value (matches is False — the assertion the
            # reviewing LLM staked its hypothesis on) does not get
            # unconditional trust: the regex extractor is
            # deterministic but can read the wrong statement.  Same
            # agreement gate as any other flip-causing answer.
            # Displacing a domain-model summary with an AGREEING or
            # open-question value is precedence, not contradiction —
            # it keeps the deterministic exemption.
            contradicts = spot.matches is False
            agreement = {
                "agreed": True,
                "reason": "mechanical answer — deterministic, "
                          "gate skipped",
            }
            if contradicts:
                if study_client is None or source_root is None:
                    agreement = {
                        "agreed": False,
                        "reason": "no verification client available",
                    }
                else:
                    try:
                        from core.concepts.answer_gate import (
                            verify_flip_answer,
                        )
                        snippets = [
                            it for it in study_items
                            if isinstance(it, dict)
                            and (it.get("name") or "").lower()
                            in (spot_l, tail, cl)
                        ] or study_items[:4]
                        agreement = verify_flip_answer(
                            req.question, snippets,
                            spot.receipt.to_dict(),
                            study_client, Path(source_root),
                            tier="mechanical",
                            contradicts_llm=True,
                        )
                    except Exception:
                        logger.debug(
                            "spot-check agreement gate failed",
                            exc_info=True,
                        )
                        agreement = {
                            "agreed": False,
                            "reason": "verification call failed",
                        }
            if not agreement.get("agreed"):
                logger.info(
                    "study-consumer: contradicting spot-check answer "
                    "quarantined (%s): %s",
                    agreement.get("reason"), req.question,
                )
                _record_study_scorecard(
                    scorecard_model, False,
                    agreement.get("reason") or "",
                )
                ledger.append(StudyAnswer(
                    question=req.question,
                    source_file=req.source_file,
                    source_function=req.source_function,
                    assumption=req.context or "",
                    answer=spot.answer,
                    tier="mechanical",
                    receipt=spot.receipt.to_dict(),
                    status="inconclusive",
                    reason=agreement.get("reason") or "",
                    spot_check_override=overrode,
                    agreement=agreement,
                ))
                continue
            item.resolve(concept_id)
            changed = True
            eligible.add(fn_key)
            if overrode:
                logger.info(
                    "study-consumer: mechanical spot-check overrode "
                    "LLM summary for %r", spot.identifier,
                )
            _record_study_scorecard(
                scorecard_model, True, "mechanical spot-check",
            )
            ledger.append(StudyAnswer(
                question=req.question,
                source_file=req.source_file,
                source_function=req.source_function,
                assumption=req.context or "",
                answer=spot.answer,
                tier="mechanical",
                receipt=spot.receipt.to_dict(),
                status="resolved",
                resolved_concept_id=concept_id,
                spot_check_override=overrode,
                agreement=agreement,
            ))
            continue

        # Extract-then-answer: no mechanically extracted snippet for
        # this identifier means the question is unresolvable — the
        # LLM must never answer it from prior knowledge.
        if cl and corpus_loaded and not _corpus_has_snippet(
            cl, tail, study_items,
        ):
            _mark_unresolvable(item, req, _NO_SNIPPET_REASON)
            continue

        entry = _match_domain_entry(domain_model, cl, tail)
        if entry is None:
            ledger.append(StudyAnswer(
                question=req.question,
                source_file=req.source_file,
                source_function=req.source_function,
                assumption=req.context or "",
                status="pending",
                reason="studied but produced no matching domain-model "
                       "concept",
                probe_note=probe_note,
            ))
            continue
        matched_id, provenance, receipt, description = entry

        if not is_actionable_tier(provenance):
            # Unverified hint only — never resolves, never re-reviews.
            ledger.append(StudyAnswer(
                question=req.question,
                source_file=req.source_file,
                source_function=req.source_function,
                assumption=req.context or "",
                answer=description,
                tier=provenance or TIER_LLM_SUMMARIZED,
                status="pending",
                reason="answer lacks a verified receipt — unverified "
                       "hint only",
                resolved_concept_id="",
                probe_note=probe_note,
            ))
            continue

        # Agreement gate on the flip-causing (re-review) path.
        agreement = {
            "agreed": True,
            "reason": "mechanical answer — deterministic, gate skipped",
        }
        if provenance == TIER_VERBATIM:
            if study_client is None or source_root is None:
                agreement = {
                    "agreed": False,
                    "reason": "no verification client available",
                }
            else:
                try:
                    from core.concepts.answer_gate import verify_flip_answer
                    snippets = [
                        it for it in study_items
                        if isinstance(it, dict)
                        and (it.get("name") or "").lower() in (tail, cl)
                    ] or study_items[:4]
                    agreement = verify_flip_answer(
                        req.question, snippets, receipt,
                        study_client, Path(source_root),
                        tier=provenance,
                    )
                except Exception:
                    logger.debug("agreement gate failed", exc_info=True)
                    agreement = {
                        "agreed": False,
                        "reason": "verification call failed",
                    }
            _record_study_scorecard(
                scorecard_model,
                bool(agreement.get("agreed")),
                agreement.get("reason") or "",
            )
        if not agreement.get("agreed"):
            logger.info(
                "study-consumer: flip-causing answer quarantined "
                "(%s): %s", agreement.get("reason"), req.question,
            )
            ledger.append(StudyAnswer(
                question=req.question,
                source_file=req.source_file,
                source_function=req.source_function,
                assumption=req.context or "",
                answer=description,
                tier=provenance,
                receipt=receipt,
                status="inconclusive",
                reason=agreement.get("reason") or "",
                agreement=agreement,
                probe_note=probe_note,
            ))
            continue

        item.resolve(matched_id)
        changed = True
        eligible.add(fn_key)
        ledger.append(StudyAnswer(
            question=req.question,
            source_file=req.source_file,
            source_function=req.source_function,
            assumption=req.context or "",
            answer=description,
            tier=provenance,
            receipt=receipt,
            status="resolved",
            resolved_concept_id=matched_id,
            agreement=agreement,
            probe_note=probe_note,
        ))

    if changed:
        rl.save(rl_path)
    if ledger:
        try:
            append_answers(out_dir, ledger)
        except OSError:
            logger.warning(
                "study-consumer: answer ledger write failed",
                exc_info=True,
            )
    return eligible


# Drain policy for the study consumer (all seconds):
# hard ceiling on the wait — unchanged from the historical join(600);
_STUDY_DRAIN_TIMEOUT_S = 600.0
# how often the drain loop re-samples the consumer's state;
_STUDY_DRAIN_POLL_S = 2.0
# how long an IDLE consumer (empty queue, not mid-batch, no progress)
# is tolerated before the drain requests a stop — an idle consumer has
# nothing left that could ever complete, so waiting longer only burns
# wall time;
_STUDY_DRAIN_NO_PROGRESS_S = 60.0
# grace after a stop request before the thread is abandoned (a stop
# unwinds in milliseconds unless the consumer is inside a non-
# interruptible LLM call).
_STUDY_DRAIN_STOP_GRACE_S = 30.0


def _drain_study_consumer(
    thread: _threading.Thread,
    study_queue: StudyQueue | None,
    *,
    budget_exhausted: bool,
    timeout_s: float = _STUDY_DRAIN_TIMEOUT_S,
    no_progress_grace_s: float = _STUDY_DRAIN_NO_PROGRESS_S,
    stop_grace_s: float = _STUDY_DRAIN_STOP_GRACE_S,
    poll_s: float = _STUDY_DRAIN_POLL_S,
) -> None:
    """Wait for the study consumer to drain — but never wait on nothing.

    The historical drain was a blind ``join(timeout=600)``: when the
    consumer was stuck inside a doomed step (observed: a study-prep
    subprocess whose LLM seeding call timed out at 600s and retried),
    the run idled for the full 10 minutes even though no result could
    ever arrive. This drain is state-aware:

    * run budget already exhausted → any in-flight study work is
      unusable (the consumer's own budget gate would discard it), so a
      cooperative stop is requested immediately and only a short grace
      is waited;
    * consumer idle (empty queue, not mid-batch) with no progress for
      ``no_progress_grace_s`` → nothing can ever complete; request a
      stop rather than sleeping to the cap;
    * consumer actively mid-batch with budget remaining → allow it up
      to the full ``timeout_s`` cap (post-loop study results feed
      re-reviews, they are worth finishing).

    Loud-degradation semantics are kept: abandoning a still-alive
    thread emits an operator-visible warning, and a forced stop is
    announced once.
    """
    stop_sent = False
    drain_start = time.monotonic()
    deadline = drain_start + timeout_s

    def _request_stop(reason: str) -> float:
        nonlocal stop_sent
        stop_sent = True
        logger.warning(
            "study-consumer: %s — requesting stop (study results for "
            "this run may be incomplete)",
            reason,
        )
        if study_queue is not None:
            study_queue.request_stop()
        return min(deadline, time.monotonic() + stop_grace_s)

    if budget_exhausted:
        deadline = _request_stop("run budget exhausted before drain")

    last_progress, _, _ = (
        study_queue.drain_state() if study_queue is not None
        else (0, True, False)
    )
    last_change = time.monotonic()

    while thread.is_alive():
        now = time.monotonic()
        if now >= deadline:
            break
        thread.join(timeout=min(poll_s, deadline - now))
        if not thread.is_alive() or study_queue is None or stop_sent:
            continue
        progress, queue_empty, working = study_queue.drain_state()
        if progress != last_progress or not queue_empty or working:
            last_progress = progress
            last_change = time.monotonic()
            continue
        if time.monotonic() - last_change >= no_progress_grace_s:
            deadline = _request_stop(
                f"no progress for {no_progress_grace_s:.0f}s with an "
                f"empty queue",
            )

    if thread.is_alive():
        # Abandonment must carry a stop: the run is over, so anything
        # the consumer produces from here is unusable by design — but
        # without a stop the still-alive daemon thread keeps
        # dispatching re-reviews into non-daemon executor workers,
        # which the interpreter joins at exit. Observed as trailing
        # LLM retry loops after results were written (dispatcher
        # request.error ReadErrors after server.stop), up to a manual
        # kill. The timeout-with-activity path used to be the one
        # abandonment branch that never requested a stop.
        if study_queue is not None and not stop_sent:
            study_queue.request_stop()
        logger.warning(
            "study-consumer: did not drain within %.0fs — abandoning "
            "with stop requested (daemon thread unwinds at its next "
            "checkpoint; study results for this run are incomplete)",
            time.monotonic() - drain_start,
        )


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


class _StudyStopRequested(Exception):
    """Raised inside the study consumer when the drain path requested a
    cooperative stop mid-step (e.g. during the prep subprocess)."""


# How often the interruptible prep runner re-checks the stop flag while
# the subprocess runs.
_STUDY_PREP_POLL_S = 5.0


def _run_study_prep(
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: float,
    study_queue: StudyQueue | None = None,
) -> subprocess.CompletedProcess:
    """Run the study-prep subprocess, interruptible by the drain path.

    ``subprocess.run`` held the consumer thread for the full prep
    timeout (up to ~30 min on a large target) with no way for the
    orchestrator's drain to unblock it — the observed failure mode was
    ~10 idle minutes of ``join(600)`` while a doomed prep LLM call
    retried inside the subprocess. This runner registers the child with
    the study queue so :meth:`StudyQueue.request_stop` can kill it, and
    polls the stop flag between short waits.

    Raises :class:`subprocess.TimeoutExpired` on timeout (same contract
    as ``subprocess.run``) and :class:`_StudyStopRequested` when the
    drain path asked the consumer to exit.
    """
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if study_queue is not None:
        study_queue.register_inflight(proc)
    try:
        deadline = time.monotonic() + timeout
        while True:
            if study_queue is not None and study_queue.stop_requested:
                with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                    proc.kill()
                    proc.wait(timeout=10)
                raise _StudyStopRequested
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                    proc.kill()
                    proc.wait(timeout=10)
                raise subprocess.TimeoutExpired(cmd, timeout)
            try:
                stdout, stderr = proc.communicate(
                    timeout=min(_STUDY_PREP_POLL_S, remaining),
                )
            except subprocess.TimeoutExpired:
                continue
            if study_queue is not None and study_queue.stop_requested:
                # request_stop() killed the registered child, so
                # communicate() returned "normally" — this exit is a
                # shutdown, not a prep result.
                raise _StudyStopRequested
            return subprocess.CompletedProcess(
                cmd, proc.returncode, stdout=stdout, stderr=stderr,
            )
    finally:
        if study_queue is not None:
            study_queue.clear_inflight()


# Mechanical share of the study-prep budget (struct/pair extraction,
# include resolution) on top of the LLM seeding call's timeout.
_STUDY_PREP_MECHANICAL_MARGIN_S = 300

# Size scaling for the mechanical share: prep's extraction walks the
# whole target, so a fixed margin that fits a 10 KLoC repo guarantees
# a timeout on a 500 KLoC one — and a timed-out prep disables domain
# models for the entire run. Per-KLoC increment, bounded so a huge
# monorepo can't stretch the cap indefinitely.
_STUDY_PREP_PER_KLOC_S = 3.0
_STUDY_PREP_EXTRA_CAP_S = 900


def _checklist_kloc(checklist: dict | None) -> float:
    """Approximate target size (KLoC) from the checklist's function
    line spans. Returns 0.0 when the checklist is absent or carries no
    usable line numbers — callers fall back to the unscaled cap."""
    total_lines = 0
    for fi in (checklist or {}).get("files", []):
        for item in fi.get("items", []) or []:
            try:
                ls = int(item.get("line_start") or 0)
                le = int(item.get("line_end") or 0)
            except (TypeError, ValueError):
                continue
            if 0 < ls <= le:
                total_lines += le - ls + 1
    return total_lines / 1000.0


def _study_prep_timeout_s(checklist: dict | None = None) -> int:
    """Subprocess timeout for study-prep, sized to its call class and
    the target's size.

    Prep is mechanical extraction PLUS one LLM concept-seeding call,
    so its ceiling must cover the configured primary model's per-call
    timeout (600s on the claude CLI transport) plus a mechanical
    margin. The old hardcoded 120s guaranteed a timeout on any
    cc-transport run whose seeding call ran long — and each timed-out
    prep silently disabled the domain-model subsystem.

    The mechanical margin scales with target size (per-KLoC increment
    derived from the checklist, bounded by
    ``_STUDY_PREP_EXTRA_CAP_S``): the extraction cost grows with the
    tree, and a size-blind cap disabled domain models on every large
    target.
    """
    llm_timeout = 600
    try:
        from core.llm.config import _get_default_primary_model
        mc = _get_default_primary_model()
        if mc is not None and mc.timeout:
            llm_timeout = max(int(mc.timeout), 120)
    except Exception:  # config probing is best-effort
        logger.debug("study-prep timeout probe failed", exc_info=True)
    extra = min(
        _STUDY_PREP_EXTRA_CAP_S,
        int(_checklist_kloc(checklist) * _STUDY_PREP_PER_KLOC_S),
    )
    return llm_timeout + _STUDY_PREP_MECHANICAL_MARGIN_S + extra


def _announce_study_disabled(reason: str) -> None:
    """ONE operator-visible line when the domain-model subsystem is
    disabled for the rest of the run. Reviews continue without domain
    concepts — but the operator must be able to see that the run
    degraded, not discover it from a silent absence of concepts."""
    logger.warning(
        "study-consumer: %s — domain-model subsystem DISABLED for "
        "this run (reviews continue without domain concepts)",
        reason,
    )


_STUDY_REQUEUE_CAP = 200


def _requeue_pending_study(
    config: OrchestratorConfig,
    study_queue: StudyQueue,
) -> int:
    """Re-enqueue persisted pending reading-list items (resume path).

    A resumed segment's reviews are mostly $0 re-imports that never
    re-produce study questions, so the queue starts empty and prior
    segments' unanswered questions stay starved forever. Bounded and
    best-effort; the consumer's flush-back is idempotent by
    deterministic item id and ``_dedup_batch`` drops already-studied
    concepts, so re-enqueueing cannot duplicate. Returns the count.
    """
    try:
        if not config.out_dir:
            return 0
        from core.concepts.reading_list import ReadingList
        rl = ReadingList.load(Path(config.out_dir) / "reading-list.json")
        pending = rl.pending()[:_STUDY_REQUEUE_CAP]
        for it in pending:
            study_queue.enqueue(StudyRequest(
                question=it.question,
                source_file=it.source_file,
                source_function=it.source_function,
                priority=it.priority,
                resolution=it.resolution,
                context=it.context,
            ))
        if pending:
            logger.info(
                "study-consumer: re-queued %d pending reading-list "
                "item(s) persisted by prior segments", len(pending),
            )
        return len(pending)
    except Exception:
        logger.debug(
            "study-consumer: reading-list re-queue failed", exc_info=True,
        )
        return 0


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
    # Compile-probe cap is per RUN, shared across batches.
    probe_budget = st.get("probe_budget")
    if probe_budget is None:
        try:
            from core.audit.compile_probe import ProbeBudget
            probe_budget = ProbeBudget()
        except Exception:  # noqa: BLE001 - probes degrade to capped-out
            probe_budget = None
    # Determine-value probes are config-gated (default off) and carry
    # their own per-run question cap; None disables the mode.
    determine_budget = st.get("determine_budget")
    if determine_budget is None and getattr(
        config, "probe_determine_value", False,
    ):
        try:
            from core.audit.compile_probe import (
                _DEFAULT_DETERMINE_CAP,
                ProbeBudget,
            )
            determine_budget = ProbeBudget(
                remaining=_DEFAULT_DETERMINE_CAP,
            )
            st["determine_budget"] = determine_budget
        except Exception:  # noqa: BLE001 - probes degrade to capped-out
            determine_budget = None

    _requeue_pending_study(config, study_queue)

    while not study_queue.is_done():
        # Idle at the top of every iteration: the drain path uses the
        # working flag to tell "mid-batch, let it finish" apart from
        # "idle on the queue, nothing will ever happen".
        study_queue.set_working(False)
        # The consumer runs its own LLM calls (study-prep, Phase 2/3
        # batches, re-reviews) — without this gate it kept working
        # long past max_seconds/max_cost (observed 27min against a
        # 900s cap) because only the main review loop checked budget.
        # Wall-clock enforcement defers to the PRODUCER while it is
        # still feeding the queue: the review loop enforces
        # max_seconds itself, and the consumer tripping on it first
        # starves the very reviews still being paid for of study
        # results (a four-segment run got zero study output this way
        # — every segment's supervisor bound was spent before the
        # consumer's first batch). Cost caps stay absolute.
        if _check_budget(
            config, start_time, result,
            skip_max_seconds=not study_queue.producer_done(),
        ):
            logger.info(
                "study-consumer: run budget exhausted (%s) — stopping",
                result.terminated_by,
            )
            break
        batch = study_queue.dequeue_batch(max_items=15, timeout=30.0)
        if not batch:
            continue
        study_queue.set_working(True)

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

        # Language dispatch: C/C++ questions resolve against the
        # study-prep corpus; Python/Go/Java/JS-TS/Rust resolve
        # in-process per batch; languages with no resolver are marked
        # unresolvable up front — never studied, never resolved-clean.
        c_reqs, ml_reqs, unsupported = _partition_study_batch(fresh)
        if unsupported:
            _mark_unsupported_unresolvable(config.out_dir, unsupported)
        if not c_reqs and not ml_reqs:
            # Nothing studyable in this batch: release the suppression
            # gate and skip the LLM study call entirely.
            _mark_concepts_studied(study_queue, fresh)
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

            # get_llm_env, not get_safe_env: study-prep's concept
            # seeding is an LLM call — the child needs the operator's
            # API keys AND the transport-routing family
            # (CLAUDE_CODE_USE_*, AWS profile/region names,
            # RAPTOR_BEDROCK_*/RAPTOR_CC_*) or Bedrock/CC-backed
            # installs lose the domain model to a starved child.
            study_env = RaptorConfig.get_llm_env()
            study_env["_RAPTOR_TRUSTED"] = "1"
            # Prep runs AT MOST ONCE per run. Any failure disables
            # the subsystem loudly and stops the consumer — the old
            # ``continue`` retried the whole prep from scratch on
            # every subsequent batch, re-paying the full timeout each
            # time while the domain model stayed silently empty.
            prep_timeout = _study_prep_timeout_s(checklist)
            try:
                prep_result = _run_study_prep(
                    prep_cmd,
                    env=study_env,
                    timeout=prep_timeout,
                    study_queue=study_queue,
                )
                if prep_result.returncode != 0:
                    _stderr_tail = (prep_result.stderr or "").strip()[:200]
                    _announce_study_disabled(
                        f"study-prep failed "
                        f"(exit {prep_result.returncode}): {_stderr_tail}",
                    )
                    break
            except subprocess.TimeoutExpired:
                # Surface what the cap was sized for and how it
                # relates to the remaining run budget, so the
                # operator can tell "cap too small for this target"
                # apart from "run nearly out of time anyway".
                _kloc = _checklist_kloc(checklist)
                _detail = f"cap sized for ~{_kloc:.0f} KLoC"
                if config.max_seconds:
                    _remaining = max(
                        0.0,
                        config.max_seconds
                        - (time.monotonic() - start_time),
                    )
                    _detail += (
                        f"; needed >{prep_timeout}s, "
                        f"{_remaining:.0f}s left of the run's "
                        f"{config.max_seconds:.0f}s budget"
                    )
                _announce_study_disabled(
                    f"study-prep timed out after {prep_timeout}s "
                    f"({_detail})",
                )
                break
            except _StudyStopRequested:
                # Shutdown, not degradation: the drain path asked the
                # consumer to exit and killed the prep subprocess.
                logger.info(
                    "study-consumer: stop requested during study-prep "
                    "— exiting",
                )
                break
            except Exception:
                logger.debug(
                    "study-consumer: prep error", exc_info=True,
                )
                _announce_study_disabled("study-prep raised an error")
                break

            study_list_path = config.out_dir / "study-list.json"
            if not study_list_path.is_file():
                _announce_study_disabled(
                    "study-prep produced no study-list.json",
                )
                break
            study_list_built = True
            study_queue.note_progress()

            # Build ConceptIndex from study-prep type data
            if concept_index_ref is not None:
                _build_concept_index_from_prep(
                    concept_index_ref, checklist, config.out_dir,
                )

        # Multi-language requests: resolve in-process and merge the
        # definitions into study-list.json (run_study re-reads it), so
        # batches after the one-shot prep still gain non-C corpus.
        ml_failures: dict[str, str] = {}
        if ml_reqs:
            ml_failures = _resolve_multilang_requests(
                config, ml_reqs, study_list_path,
            )

        # C per-batch definition splice: prep runs once, so C questions
        # raised after it (premise questions, re-review assumptions)
        # otherwise never gain corpus definitions and stall pending.
        # Failures are NOT propagated — the prep corpus may already
        # carry the concept; a splice miss must not mark a question
        # unresolvable that run_study can still answer.
        _c_ident_reqs = [r for r in c_reqs if r.resolution != "concept"]
        if _c_ident_reqs:
            _resolve_multilang_requests(
                config, _c_ident_reqs, study_list_path, include_c=True,
            )

        # Study-run: in-process, scoped to this batch's reading-list.
        if study_queue.stop_requested:
            logger.info(
                "study-consumer: stop requested — exiting before "
                "study-run",
            )
            break
        n_before = len(dm.get("concepts", [])) if dm else 0
        try:
            from core.concepts.study import run_study

            # Budget-governed client: study spend must hit the run
            # ledger and the reservation gate. Per-class history gives
            # a contamination-free spend delta even though the client
            # is shared with concurrent review calls.
            study_client = _run_llm_client(config)
            _study_before = _client_class_cost(study_client, "study")
            try:
                if throttle is not None:
                    # Low priority: study batches yield the contended
                    # throttle slot to review calls — background
                    # enrichment must not starve the main loop.
                    with throttle.acquire_sync(low_priority=True):
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
                # Delta over the client's per-class ledger: the shared
                # budget client also carries review/iris spend, so
                # reading total_cost here would book the whole run
                # into the study phase. Failed-attempt spend stays on
                # the client ledger and reconciles at run end.
                spent = max(
                    0.0,
                    _client_class_cost(study_client, "study")
                    - _study_before,
                )
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
        study_queue.note_progress()

        # Reload domain model
        try:

            new_dm = _load_domain_model(config)
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
        _mark_concepts_studied(study_queue, fresh)

        # Reading-list bookkeeping + answer ledger: resolution is
        # tier-gated (verbatim requires a verified receipt AND
        # agreement-gate survival; mechanical spot-checks pass
        # directly); receipt failures / missing snippets become
        # unresolvable; everything else stays pending as an
        # unverified hint.  Runs after every study batch, before the
        # re-review eligibility checks below (which can
        # continue/break past it).  Only RESOLVED questions may
        # trigger re-reviews.
        eligible_keys: set[str] = set()
        try:
            eligible_keys = _mark_batch_reading_list(
                config.out_dir,
                c_reqs + ml_reqs,
                shared.domain_model,
                ml_failures,
                study_list_path=study_list_path,
                source_root=Path(config.study_root or config.target_path),
                study_client=study_client,
                scorecard_model=(
                    config.models[0]
                    if config.models else "default"
                ),
                probe_budget=probe_budget,
                determine_budget=determine_budget,
            )
        except Exception:
            logger.debug(
                "study-consumer: reading-list resolve failed",
                exc_info=True,
            )

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

        # Compute new concepts for broader re-review.  The post-study
        # model is diffed against seen_concepts + the PRE-study model
        # (dm); folding the post-study names into seen_concepts before
        # the diff (as previously done) made the difference
        # unconditionally empty, so the ConceptIndex-scoped broader
        # re-review never triggered.
        new_concept_names = _diff_new_concepts(
            seen_concepts,
            dm,
            shared.domain_model if n_after > n_before else None,
        )
        # Tier gate: only receipt-verified / mechanical concepts may
        # widen the re-review set beyond the originating functions.
        if new_concept_names and shared.domain_model:
            from core.concepts.receipts import is_actionable_tier
            actionable_names = {
                (c.get("id") or c.get("name") or "").lower()
                for c in shared.domain_model.get("concepts", [])
                if is_actionable_tier(c.get("provenance") or "")
            }
            new_concept_names &= actionable_names

        if re_review_count >= _STUDY_MAX_RE_REVIEWS:
            logger.info(
                "study-consumer: re-review cap (%d) reached",
                _STUDY_MAX_RE_REVIEWS,
            )
            continue

        # Collect re-review candidates: originating functions of
        # RESOLVED questions + broader concept-scoped functions from
        # ConceptIndex.  Unresolvable / inconclusive / unverified
        # questions gained no verified knowledge — their originating
        # functions are not re-reviewed.
        source_keys = set(eligible_keys)

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

        if study_queue.stop_requested:
            logger.info(
                "study-consumer: stop requested — exiting before "
                "re-review",
            )
            break

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
        study_queue.note_progress()

    logger.info(
        "study-consumer: done (re-reviews=%d, stale_batches=%d)",
        re_review_count,
        stale_batches,
    )
    # Persist the consumer's outcome so the report's completeness
    # block can NAME study starvation (a four-segment run produced
    # zero study output across every segment and the report said
    # nothing). Best-effort — never blocks the drain.
    try:
        if config.out_dir:
            from core.json import save_json
            save_json(Path(config.out_dir) / "study-stats.json", {
                "re_reviews": re_review_count,
                "stale_batches": stale_batches,
                "stopped_reason": result.terminated_by or "",
            })
    except Exception:
        logger.debug("study-stats persist failed", exc_info=True)


def _is_suspicious_outcome(key: str, outcomes: _LockedOutcomes) -> bool:
    """Check if a reviewed function has a suspicious verdict."""
    outcome = outcomes.get(key)
    if outcome and hasattr(outcome, "status"):
        return outcome.status == "suspicious"
    return False


def _build_concept_index_from_prep(
    concept_index_ref: list,
    checklist: dict,
    out_dir: Path,
) -> None:
    """Build ConceptIndex after study-prep, using its type data."""
    try:
        study_list_path = out_dir / "study-list.json"
        if not study_list_path.is_file():
            return
        study_list = load_json(
            study_list_path, max_bytes=_MAX_ARTIFACT_BYTES,
        )
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
    reused: bool = False,
) -> None:
    with result._lock:
        if append:
            result.outcomes.append(outcome)
        if reused:
            # Imported prior verdict — counted distinctly, not as a
            # review this run performed.
            result.reused_from_prior += 1
        else:
            result.reviewed += 1
        result.total_cost_usd += outcome.cost_usd
        if outcome.status == "finding":
            result.findings += 1
        elif outcome.status == "suspicious":
            result.suspicious += 1
        elif outcome.status == "clean":
            result.clean += 1
        elif outcome.status in {"dormant", "dark"}:
            result.dormant += 1
        elif outcome.status == "error":
            result.errors += 1
            if outcome.error_class:
                result.error_counts[outcome.error_class] = (
                    result.error_counts.get(outcome.error_class, 0) + 1
                )


def _sage_store_observation(text: str, kind: str, source: str) -> None:
    """Best-effort store of a tool-confirmed observation to SAGE."""
    # store_audit_observation self-handles transport failures; only a
    # partial/optional SAGE install (import failure) remains.
    with contextlib.suppress(ImportError):
        from core.sage.hooks import store_audit_observation

        store_audit_observation(
            repo_path=str(_active_target_path or ""),
            observation=text,
            kind=kind,
            source_function=source,
        )


_MAX_OBSERVATION_LEN = 500

# How many prior-run observations SAGE may seed into session context.
_MAX_SAGE_SEED_OBSERVATIONS = 5


def _seed_observations_from_sage(config: OrchestratorConfig) -> list[dict[str, str]]:
    """Seed session context with prior-run audit observations from SAGE.

    Closes the read half of the observation loop
    (``_sage_store_observation`` writes; nothing recalled until now).
    Hint-only by design: observations are prose, not MAC-stamped rows,
    so they inform prompts but never drive mechanical decisions.
    Recalled text passes through ``_sanitise_observation`` — the same
    injection scan live observations get — before it can re-enter a
    prompt. Never raises; returns ``[]`` when SAGE is unavailable or
    SAGE recall is gated off (cold-profile corpus runs).
    """
    if not getattr(config, "sage_recall", True):
        return []
    try:
        from core.sage.hooks import recall_audit_observations
    except ImportError:
        return []
    try:
        subject = Path(config.target_path).name
    except Exception:  # noqa: BLE001 — defensive: config may be a stub
        return []
    if not subject:
        return []
    try:
        rows = recall_audit_observations(
            subject, top_k=_MAX_SAGE_SEED_OBSERVATIONS,
        )
    except Exception:
        logger.debug("SAGE observation recall failed", exc_info=True)
        return []

    seeded: list[dict[str, str]] = []
    for row in rows[:_MAX_SAGE_SEED_OBSERVATIONS]:
        text = _sanitise_observation(str(row.get("content") or ""))
        if not text:
            continue
        seeded.append({
            "source": "sage:prior-run",
            "text": text,
            "kind": "sage_recall",
        })
    if seeded:
        logger.info(
            "session context: seeded %d prior-run observation(s) from SAGE",
            len(seeded),
        )
    return seeded


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
    session_observations: list[dict[str, str]],
    outcome: ReviewOutcome,
    gap: dict[str, Any],
    *,
    sweep_pre_status: str | None = None,
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
    workqueue: list[dict[str, Any]],
    sloc_threshold: int,
) -> tuple:
    """Split workqueue into trivial batches and normal items.

    Functions with SLOC <= threshold are grouped by file into batches
    for combined review.  Returns (batches, remaining).
    """
    if sloc_threshold <= 0:
        return [], workqueue

    batches_by_file: dict[str, list[dict[str, Any]]] = {}
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


def _synthesize_external_seeds(
    config: OrchestratorConfig,
    result: Any,
    shared: Any,
    checklist: dict[str, Any],
) -> int:
    """Synthesize checkers from external ground-truth seeds.

    Seeds come from ``core.audit.synthesis_seeds`` (prior+current-run
    journal findings, crash RCAs, cvefix fixture pairs), each bounded
    per source and carrying provenance. Sweep hits join
    ``shared.synthesis_queue`` so the existing second-pass review
    analyses them in THIS run. Returns the number of hits queued.
    """
    from .checker_synthesis import synthesize_from_external_seed
    from .synthesis_seeds import collect_external_seeds

    with result._lock:
        exclude = {
            (getattr(o, "file", ""), getattr(o, "function", ""))
            for o in result.outcomes
            if getattr(o, "status", "") == "finding"
        }
    seeds = collect_external_seeds(
        config, checklist=checklist, exclude_keys=exclude,
    )
    if not seeds:
        return 0
    logger.info(
        "external seed synthesis: %d seed(s) — %s",
        len(seeds),
        ", ".join(
            getattr(s.seed, "provenance", "") or "?" for s in seeds
        ),
    )

    queued = 0
    for ext in seeds:
        try:
            synth = synthesize_from_external_seed(
                ext, config, synthesis_count=result.synthesis_amplified,
            )
        except Exception as exc:
            from core.llm.client import LLMAuthPersistentError
            if isinstance(exc, LLMAuthPersistentError):
                # Every remaining seed would hit the same dead
                # credential — abort the phase loudly instead of
                # reporting "0 seeds synthesised" as success.
                _record_phase_abort(config, result, exc)
                return queued
            raise
        if synth is None:
            continue
        with result._lock:
            result.total_cost_usd += synth.cost_usd
            result.cost_tracker.record_call(
                "checker_synthesis", cost_usd=synth.cost_usd,
            )
        if not synth.hits:
            continue
        for hit in synth.hits:
            hit.setdefault("priority_score", 0.8)
            shared.synthesis_queue.append(hit)
            queued += 1
        result.synthesis_amplified += len(synth.hits)
        checker_library = getattr(shared, "checker_library", None)
        if checker_library and synth.rule_id:
            try:
                checker_library.add_rule(
                    rule_id=synth.rule_id,
                    engine=synth.tool,
                    body=synth.content,
                    cwe=synth.cwe or "",
                    seed_file=synth.origin_file,
                    seed_function=synth.origin_function,
                    source="audit-external",
                    dual_control=bool(
                        getattr(synth, "dual_control", False)),
                    rule_tier=getattr(synth, "rule_tier", "sweep_once"),
                )
            except Exception:
                logger.debug(
                    "external seed rule persist failed", exc_info=True,
                )
    # Completed without an abort: supersede any stale sidecar record
    # from a prior (reopened/resumed) segment.
    _clear_phase_abort(config, "checker-synthesis", result=result)
    return queued


def _synthesis_hits_to_gaps(
    hits: list[dict[str, Any]],
    checklist: dict[str, Any],
    out_dir: Path | None = None,
) -> list[dict[str, Any]]:
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
    gaps: list[dict[str, Any]] = []
    seen: set[str] = set()
    unresolved: list[dict[str, Any]] = []

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
        if hit.get("provenance"):
            gap["synthesis_provenance"] = hit["provenance"]
        if hit.get("rule_id"):
            # Joins the review verdict on this gap back to the rule
            # that produced it — the in-run quarantine's evidence.
            gap["synthesis_rule_id"] = hit["rule_id"]
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


# A run-synthesized rule whose triaged matches are ALL false positives
# is deactivated for the rest of the run once this many verdicts are
# in.  Rule-of-thumb floor: below 3 triages a single unlucky match
# would quarantine every young rule; at 3+ with zero true positives
# the rule is demonstrably minting review work (and, worse, promotion
# receipts) from a pattern the reviewers keep rejecting.
_RULE_QUARANTINE_MIN_TRIAGES = 3


def _note_rule_triage(shared: SharedState, rule_id: str, is_tp: bool) -> None:
    """Record one triaged match for a synthesized/library rule and
    quarantine the rule for the remainder of the run at 0% precision.

    Quarantine is run-scoped: the library entry survives (cross-run
    retirement stays ``retire_low_precision``'s job), but this run
    stops sweeping the rule's remaining hits into review gaps.  One
    corpus run watched an on-demand rule confirm a no-defect
    hypothesis and then sit at "avg precision 0%" in every subsequent
    group with nothing acting on it.
    """
    if not rule_id:
        return
    with shared._rule_triage_lock:
        counts = shared.rule_triage.setdefault(rule_id, [0, 0])
        counts[0 if is_tp else 1] += 1
        tp, fp = counts
        if (
            tp == 0
            and fp >= _RULE_QUARANTINE_MIN_TRIAGES
            and rule_id not in shared.quarantined_rules
        ):
            shared.quarantined_rules.add(rule_id)
            logger.warning(
                "rule quarantine: %s deactivated for the remainder of "
                "this run — %d/%d triaged match(es) false-positive "
                "(0%% precision)",
                rule_id, fp, tp + fp,
            )


def _write_unresolved_synthesis_hits(
    hits: list[dict[str, Any]],
    out_dir: Path,
) -> None:
    """Persist synthesis sites that have no enclosing reviewable function."""
    path = out_dir / "unresolved-synthesis-hits.json"
    # One non-fatal boundary around read, normalise, serialise and write.
    # This is a diagnostic artifact: a malformed, mis-encoded or
    # unserialisable one must never take the run down with it.
    try:
        existing: list[dict[str, Any]] = []
        if path.is_file():
            prior = load_json(path, max_bytes=_MAX_STATE_BYTES)
            # Tolerate any prior shape — a truncated write, a hand-edit,
            # a bare list — and replace what can't be understood.
            if isinstance(prior, dict) and isinstance(prior.get("hits"), list):
                existing = prior["hits"]
            elif isinstance(prior, list):
                existing = prior
            elif prior is not None:
                logger.debug("replacing malformed %s", path.name)

        existing = list(existing) + list(hits)
        save_json(path, {"hits": existing, "count": len(existing)})
    except (OSError, UnicodeError, TypeError, ValueError):
        logger.debug("could not persist unresolved synthesis hits", exc_info=True)


def _review_items(
    batch: list[dict[str, Any]],
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    fuzz_coverage: dict[str, Any] | None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
    domain_model: dict[str, Any] | None = None,
) -> list[ReviewOutcome]:
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
            except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            from core.llm.client import is_budget_exceeded_error

            if is_budget_exceeded_error(exc):
                # Terminal: stop the batch and return what completed.
                # The budget-killed function is NOT journaled, so it
                # stays gap-eligible for a future run.
                logger.warning(
                    "batch review stopped at %s:%s — LLM budget exhausted "
                    "(%d/%d reviewed; rest stay gaps)",
                    gap["file"], gap["name"], len(outcomes), len(batch),
                )
                break
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
            # Own try: records only, must never skip refutation.
            try:
                from .binary_honesty import record_gate_engagement

                record_gate_engagement(
                    config.out_dir,
                    outcome,
                    domain_model=domain_model,
                    checklist=checklist,
                    line_start=gap.get("line_start", 0),
                    phase="review_batch",
                )
            except Exception:
                logger.debug(
                    "gate-engagement record skipped (batch)",
                    exc_info=True,
                )

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

                rv = rescue_self_refuted(
                    outcome,
                    config=config,
                    source=_read_raw_source(
                        config.target_path,
                        gap.get("file", ""),
                        gap.get("line_start", 0),
                        gap.get("line_end"),
                    ) or None,
                    pre_evidence=gap.get("_smt_pre_evidence"),
                    target_path=config.target_path,
                    out_dir=config.out_dir,
                    repo_trusted=config.repo_trusted,
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
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "commit failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
        outcomes.append(outcome)
    return outcomes


def _dead_code_reason(gap: dict[str, Any]) -> str | None:
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
    ctx: dict[str, Any],
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
    re.IGNORECASE,
)

_NEGATION_BEFORE_RE = re.compile(
    r"\b(?:not|no|without|lacks?|missing|absent|never)\b",
    re.IGNORECASE,
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
) -> str | None:
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
    gap: dict[str, Any],
    ctx: dict[str, Any],
    domain_model: dict[str, Any] | None = None,
) -> PrefilterResult:
    """Run the mechanical pre-filter on a single gap function."""
    from .condition_smt import DomainVocabulary

    source = _read_raw_source(
        config.target_path,
        gap["file"],
        gap.get("line_start", 0),
        gap.get("line_end"),
    )
    vocab = DomainVocabulary.from_domain_model(
        domain_model, target_path=config.target_path,
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
        project_sinks=config.project_sinks,
        domain_vocab=vocab,
    )


# Keyed by (path, mtime, size) so a file rewritten mid-run (build
# steps, generated sources, a second in-process run on a drifted
# target) is re-read instead of served stale; LRU-bounded BY BYTES as
# well as entry count so a large target cannot pin every source file's
# lines in memory for the whole run (a pure entry-count bound let 256
# near-8MiB sources pin gigabytes). Entries are weighted by the file's
# on-disk size (already carried in the key); files larger than
# _FILE_LINES_CACHE_MAX_ENTRY_BYTES are served without being cached at
# all. Guarded by a lock — async-path reviews call this from worker
# threads.
_FILE_LINES_CACHE_MAX = 256
_FILE_LINES_CACHE_MAX_BYTES = 64 * 1024 * 1024
_FILE_LINES_CACHE_MAX_ENTRY_BYTES = _FILE_LINES_CACHE_MAX_BYTES // 4
_file_lines_cache: OrderedDict[tuple[str, float, int], list | None] = (
    OrderedDict()
)
_file_lines_cache_bytes = 0
_file_lines_cache_lock = _threading.Lock()

# Same-file parse-wrapper names for the parsed-int contract screen,
# keyed like _file_lines_cache (absolute path) so concurrent targets
# in one process never share entries.
_parse_wrapper_cache: dict[str, frozenset] = {}


def _read_raw_source(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: int | None,
) -> str:
    """Read raw source lines without line-number prefixes."""
    full_path = target_path / file_path
    try:
        st = full_path.stat()
    except OSError:
        return ""
    cache_key = (str(full_path), st.st_mtime, st.st_size)
    global _file_lines_cache_bytes
    with _file_lines_cache_lock:
        if cache_key in _file_lines_cache:
            _file_lines_cache.move_to_end(cache_key)
            lines = _file_lines_cache[cache_key]
        else:
            lines = None
            try:
                lines = full_path.read_text(errors="replace").splitlines()
            except OSError:
                lines = None
            # Byte-weighted admission + eviction: the key's st_size is
            # the entry's weight (splitlines memory is proportional to
            # it). Oversized files are returned uncached.
            if st.st_size <= _FILE_LINES_CACHE_MAX_ENTRY_BYTES:
                _file_lines_cache[cache_key] = lines
                _file_lines_cache_bytes += st.st_size
                while _file_lines_cache and (
                    len(_file_lines_cache) > _FILE_LINES_CACHE_MAX
                    or _file_lines_cache_bytes
                    > _FILE_LINES_CACHE_MAX_BYTES
                ):
                    evicted_key, _ = _file_lines_cache.popitem(last=False)
                    _file_lines_cache_bytes -= evicted_key[2]
    if lines is None:
        return ""
    start = max(0, line_start - 1)
    end = line_end if line_end is not None else min(start + 50, len(lines))
    return "\n".join(lines[start:end])


_R2_ABI_TABLES: dict[str, list[str]] = {
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

_R2_ARG_REGS_BY_ABI: dict[str, frozenset] = {}
for _abi, _regs in _R2_ABI_TABLES.items():
    _all = set(_regs)
    if _abi == "amd64":
        _all.update(["r8d", "r9d", "edi", "esi", "edx", "ecx"])
    elif _abi == "aarch64":
        _all.update([f"w{i}" for i in range(8)])
    _R2_ARG_REGS_BY_ABI[_abi] = frozenset(_all)


def _detect_r2_abi(source: str) -> str | None:
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
            args = [arg_vals[reg] for reg in arg_order if reg in arg_vals]
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
) -> Path | None:
    """Write decompilation to a temp directory so Semgrep can read it."""
    if not decompilation or decompilation.startswith("("):
        return None
    # Function names come from binary symbol tables (untrusted input)
    # and become the tmpfile name — reject path separators and ``..``
    # so the write cannot escape the temp directory (same pattern as
    # rules.save_rule's rule_id check).
    if (
        "/" in function_name
        or "\\" in function_name
        or ".." in function_name
    ):
        logger.debug(
            "refusing decompilation tmpfile for unsafe function name %r",
            function_name,
        )
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


def _effective_cwe(
    outcome: ReviewOutcome,
    tier_counters: dict[str, TierCounters] | None = None,
) -> str:
    """Review-supplied CWE, falling back to keyword inference.

    Reviews frequently emit ``cwe: ""`` even for non-clean verdicts,
    which starves the CWE-seeded tool chains (``_cwe_fallback_chain``)
    — the hypothesis then dispatches only through the narrower
    string-matched channels. When the field is empty but hypotheses
    exist, infer a CWE from the hypothesis texts via the existing
    keyword dispatch, stamp ``review_result["cwe_inferred"]`` so the
    journal/export show the value was inferred, and count the
    inference in tier telemetry (``cwe_inference``).
    """
    review = outcome.review_result or {}
    cwe = review.get("cwe_class") or review.get("cwe") or ""
    if cwe:
        # Placeholder classes (CWE-NOINFO / CWE-000 / CWE-Other) are
        # not classes — they starve dispatch exactly like an empty
        # field, and worse: they used to ride into checker synthesis
        # as literal seed CWEs. Treat them as absent so the keyword
        # inference below gets its re-classification shot; the
        # original value is stamped for the journal.
        try:
            from .cwe_dispatch import is_placeholder_cwe
        except ImportError:
            return cwe
        if not is_placeholder_cwe(cwe):
            return cwe
        if outcome.review_result is not None and not review.get(
            "cwe_placeholder",
        ):
            outcome.review_result["cwe_placeholder"] = cwe

    inferred_prior = review.get("cwe_inferred") or ""
    if inferred_prior:
        return inferred_prior

    texts: list[str] = []
    if outcome.hypothesis:
        texts.append(outcome.hypothesis)
    texts.extend(h["mechanism"] for h in outcome.hypotheses or review.get("hypotheses") or [] if isinstance(h, dict) and h.get("mechanism"))
    if not texts:
        return ""

    try:
        from .cwe_dispatch import infer_cwe_from_hypothesis
    except ImportError:
        return ""

    for text in texts:
        inferred = infer_cwe_from_hypothesis(text)
        if inferred:
            if outcome.review_result is not None:
                outcome.review_result["cwe_inferred"] = inferred
            if tier_counters is not None:
                _increment_tier_dict(tier_counters, "cwe_inference", "confirmed")
            logger.debug(
                "cwe inference: %s:%s — review emitted empty cwe, "
                "inferred %s from hypothesis text",
                outcome.file, outcome.function, inferred,
            )
            return inferred
    if tier_counters is not None:
        _increment_tier_dict(tier_counters, "cwe_inference", "inconclusive")
    return ""


def _hypothesis_to_tool_chain(
    hypothesis: str,
    file_path: str,
    cwe: str = "",
) -> list[dict[str, Any]]:
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
    chain: list[dict[str, Any]] = []
    seen_types: set = set()

    if cwe:
        cwe_chain = _cwe_fallback_chain(cwe, hypothesis)
        for entry in cwe_chain:
            chain.append(entry)
            seen_types.add(entry["type"])

    keyed_rule = _hypothesis_to_semgrep_rule_keyed(hypothesis, file_path)
    semgrep_rule, semgrep_keyword = keyed_rule or (None, "")
    if semgrep_rule and "semgrep" not in seen_types:
        # keyword travels with the rule so the sweep can run the
        # matching negative-control fixture before confirming.
        chain.append({
            "type": "semgrep",
            "config": {"rule": semgrep_rule, "keyword": semgrep_keyword},
        })
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

    # Caller-contract hypotheses ("only reachable if an external API
    # consumer passes NULL host…") and single-call contracts ("double
    # free if a caller invokes it twice"): flow tools answer "no
    # in-tree triggering path" and the claim dies speculative — the
    # boundary channel instead checks the asserted obligation at every
    # in-repo call site (external-only callers stay
    # inconclusive-with-reason).
    if "api_boundary" not in seen_types:
        try:
            from .api_boundary import (
                is_caller_contract_hypothesis,
                is_single_call_hypothesis,
            )
        except ImportError:
            pass
        else:
            if (
                is_caller_contract_hypothesis(hypothesis)
                or is_single_call_hypothesis(hypothesis)
            ):
                chain.append({"type": "api_boundary", "config": {}})
                seen_types.add("api_boundary")

    # Fail-open hypotheses ("the broad except swallows verification
    # errors and the request proceeds", "setuid return ignored"): the
    # channel adjudicates role x permissive-handler-outcome x
    # fallibility mechanically — the class that previously had no
    # verifying tool and died suspicious-without-receipts.
    if "fail_open" not in seen_types:
        try:
            from .fail_open_verify import is_fail_open_hypothesis
        except ImportError:
            pass
        else:
            if is_fail_open_hypothesis(hypothesis):
                chain.append({"type": "fail_open", "config": {}})
                seen_types.add("fail_open")

    # Peer-majority hypotheses ("9/10 callers check do_auth()'s
    # return; this one discards it"): the consistency channel
    # recomputes the census arithmetic and the exhibits mechanically
    # instead of trusting the claimed majority.
    if "consistency" not in seen_types:
        try:
            from .consistency_verify import is_consistency_hypothesis
        except ImportError:
            pass
        else:
            if is_consistency_hypothesis(hypothesis):
                chain.append({"type": "consistency", "config": {}})
                seen_types.add("consistency")

    # Stale-alias hypotheses ("cached pointer outlives the freed
    # owner", "sibling fields re-targeted but this one not"): the
    # ptr_lifecycle channel adjudicates the alias-hop class the flow
    # tools miss (the alias hop breaks the dataflow). Plain
    # use-after-free phrasing stays with the CWE-416 chain.
    if "ptr_lifecycle" not in seen_types:
        try:
            from .ptr_lifecycle import is_ptr_lifecycle_hypothesis
        except ImportError:
            pass
        else:
            if is_ptr_lifecycle_hypothesis(hypothesis):
                chain.append({"type": "ptr_lifecycle", "config": {}})
                seen_types.add("ptr_lifecycle")

    # Callback-under-lock hypotheses ("remove_cb fired while ctx->lock
    # is held"): the lock_region channel composes learned lock pairs
    # with the indirect-call shape — invoke-callback-while-held only
    # (imbalance stays CWE-667's smt/cocci chain).
    if "lock_region" not in seen_types:
        try:
            from .lock_region import is_lock_region_hypothesis
        except ImportError:
            pass
        else:
            if is_lock_region_hypothesis(hypothesis):
                chain.append({"type": "lock_region", "config": {}})
                seen_types.add("lock_region")

    # Unbounded-accumulation hypotheses ("the incoming list grows
    # without limit — memory exhaustion"): the resource_bounds channel
    # runs the bound-witness comparator (local dominating guard,
    # depth-3 caller walk, removal-pair parity) mechanically.
    if "resource_bounds" not in seen_types:
        try:
            from .resource_bounds import is_resource_bounds_hypothesis
        except ImportError:
            pass
        else:
            if is_resource_bounds_hypothesis(hypothesis):
                chain.append({"type": "resource_bounds", "config": {}})
                seen_types.add("resource_bounds")

    # Release-before-verify hypotheses ("decrypted chunks are written
    # to out before the cipher status is verified" — the EFAIL shape):
    # the release_order channel tests finalizer-status dominance over
    # every release site mechanically.
    if "release_order" not in seen_types:
        try:
            from .release_order import is_release_order_hypothesis
        except ImportError:
            pass
        else:
            if is_release_order_hypothesis(hypothesis):
                chain.append({"type": "release_order", "config": {}})
                seen_types.add("release_order")

    # Protocol-state hypotheses ("the peer can acknowledge packets
    # never sent"; state-field invariants): the protocol_state channel
    # runs legs 1+2 receipts and the census-driven multi-site
    # invariant harness. Ordered BEFORE smt_invariant deliberately —
    # a state-field invariant routes to the multi-site harness, not
    # the single-function one (the §4.5 precedence rule, encoded by
    # claiming the smt_invariant slot); plain local invariants
    # (obuf_len <= obuf_size) do not classify here and keep routing
    # to smt_invariant below.
    if "protocol_state" not in seen_types:
        try:
            from .protocol_state import (
                classify_protocol_state_hypothesis,
            )
        except ImportError:
            pass
        else:
            _ps_fires, _ps_inv = classify_protocol_state_hypothesis(
                hypothesis,
            )
            if _ps_fires:
                _ps_cfg: dict[str, Any] = {}
                if _ps_inv:
                    _ps_cfg["invariant"] = _ps_inv
                chain.append({
                    "type": "protocol_state", "config": _ps_cfg,
                })
                seen_types.add("protocol_state")
                if _ps_inv:
                    seen_types.add("smt_invariant")

    # Invariant-shaped hypotheses ("obuf_len <= obuf_size holds…"):
    # the preservation harness checks the stated invariant against the
    # function's mutation sites — the channel gap that left every
    # invariant-refuted verdict permanently inconclusive.
    if "smt_invariant" not in seen_types:
        try:
            from .invariant_smt import extract_invariants
        except ImportError:
            pass
        else:
            _invs = extract_invariants(hypothesis)
            if _invs:
                chain.append({
                    "type": "smt_invariant",
                    "config": {"invariant": _invs[0]},
                })
                seen_types.add("smt_invariant")

    cocci_rule = _hypothesis_to_cocci_check(hypothesis)
    if cocci_rule and "coccinelle" not in seen_types:
        chain.append({"type": "coccinelle", "config": {"rule": cocci_rule}})
        seen_types.add("coccinelle")

    if "coccinelle_flow" not in seen_types:
        try:
            from .cocci_flow import flow_template_for_hypothesis
        except ImportError:
            pass
        else:
            flow_template = flow_template_for_hypothesis(hypothesis)
            if flow_template:
                chain.append({
                    "type": "coccinelle_flow",
                    "config": {"template": flow_template},
                })
                seen_types.add("coccinelle_flow")

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

    if "integer_truncation" not in seen_types:
        try:
            from .integer_truncation_checker import (
                is_integer_truncation_hypothesis,
            )
        except ImportError:
            pass
        else:
            if is_integer_truncation_hypothesis(hypothesis):
                chain.append({"type": "integer_truncation", "config": {}})
                seen_types.add("integer_truncation")

    if "proto_length" not in seen_types:
        try:
            from .proto_length_checker import is_proto_length_hypothesis
        except ImportError:
            pass
        else:
            if is_proto_length_hypothesis(hypothesis):
                chain.append({"type": "proto_length", "config": {}})
                seen_types.add("proto_length")

    if "struct_field" not in seen_types:
        try:
            from .struct_field_checker import is_struct_field_hypothesis
        except ImportError:
            pass
        else:
            if is_struct_field_hypothesis(hypothesis):
                chain.append({"type": "struct_field", "config": {}})
                seen_types.add("struct_field")

    return chain


def _record_api_boundary_receipt(
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    ab_res: Any,
) -> None:
    """Persist the api-boundary receipt (per-call-site verdicts and
    guard evidence) to the audit log."""
    try:
        if not config.out_dir:
            return
        record = {
            "action": "api_boundary_check",
            "file": file_path,
            "function": function_name,
        }
        record.update(ab_res.to_dict())
        append_audit_log(config.out_dir, record)
    except Exception:
        logger.debug("api-boundary receipt write failed", exc_info=True)


_CALLER_CONTRACT_MARKER = "[caller-contract:"


def _apply_caller_contract_gate(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
) -> bool:
    """Adjudicate one outcome's caller-obligation hypothesis and, on a
    complete mechanical refutation, demote its exported confidence.

    Demotion requires ALL of: status finding/suspicious; no
    confirming-role tool evidence; caller-conditional hypothesis
    phrasing; api_boundary ``refuted`` (every in-repo call site
    upholds the contract on structural receipts — lexical or
    undecided sites already gate the channel to inconclusive); and
    ``enumeration_complete`` (uncapped tree scan, no address-taken
    escape — ANY enumeration uncertainty declines).  The gate runs
    the channel with ``inventory=None`` so completeness can only be
    earned the textual way; the call-graph fast path is for the
    in-loop chain, not for demotion.

    On demotion: body gains the ``[caller-contract: all N call
    site(s) uphold the precondition]`` prefix, ``review_result``
    gains a structured ``caller_evidence`` record (exported next to
    ``file_dampening`` and enforced as a confidence clamp by
    ``findings_export.build_graded_finding``), and a
    ``dropped: false`` row lands in suppressions.jsonl.  Status is
    NEVER changed: "all N current callers uphold the precondition"
    refutes a current, reachable defect of this tree — not the
    fragile-API observation, which still ships at confidence=low.
    """
    if outcome.status not in ("finding", "suspicious"):
        return False
    if outcome.file.startswith(BINARY_PATH_PREFIX):
        return False
    if _is_tool_confirmed(outcome.evidence_tool):
        return False
    review = outcome.review_result
    if review is not None and not isinstance(review, dict):
        # Exotic review_result shapes cannot carry the caller_evidence
        # record, and replacing them wholesale would destroy the
        # review payload — decline rather than half-demote.
        return False
    if isinstance(review, dict) and review.get("caller_evidence"):
        return False  # already gated (resume / replay idempotence)
    hypothesis = _resolve_hypothesis(outcome)
    if not hypothesis or _CALLER_CONTRACT_MARKER in (outcome.body or ""):
        return False
    from .api_boundary import (
        is_caller_conditional_hypothesis,
        run_api_boundary_check,
    )
    if not is_caller_conditional_hypothesis(hypothesis):
        return False
    # Multi-hypothesis outcomes: refuting the primary caller-contract
    # claim says nothing about a live sibling mechanism ("also, the
    # length is truncated before the copy") — the exported confidence
    # covers the whole finding, so demote only when every live
    # hypothesis is caller-conditional.
    for h in outcome.hypotheses or []:
        if not isinstance(h, dict):
            continue
        mech = h.get("mechanism") or ""
        if (h.get("confidence") or "").lower() == "refuted":
            continue
        if mech and not is_caller_conditional_hypothesis(mech):
            return False
    line_end = _checklist_line_end(config, outcome.file, outcome.function)
    ab_res = run_api_boundary_check(
        config.target_path,
        outcome.file,
        outcome.function,
        hypothesis,
        inventory=None,
        def_span=(
            (outcome.line, line_end)
            if outcome.line and line_end else None
        ),
    )
    _record_api_boundary_receipt(
        config, outcome.file, outcome.function, ab_res,
    )
    if ab_res.outcome != "refuted" or not ab_res.enumeration_complete:
        return False

    n = len(ab_res.sites)
    prefix = (
        f"[caller-contract: all {n} call site(s) uphold the "
        "precondition]"
    )
    outcome.body = f"{prefix}\n\n{outcome.body or ''}"
    record = {
        "rule_id": ab_res.rule_id,
        "outcome": ab_res.outcome,
        "contract": ab_res.contract,
        "reason": ab_res.reason,
        "sites": [s.to_dict() for s in ab_res.sites],
        "enumeration": {
            "method": ab_res.enumeration,
            "complete": ab_res.enumeration_complete,
            "notes": list(ab_res.enumeration_notes),
        },
        "demotion": {
            "confidence_clamp": "low",
            "status": outcome.status,  # unchanged — never suppresses
        },
    }
    if isinstance(outcome.review_result, dict):
        outcome.review_result["caller_evidence"] = record
    else:
        # review_result is None here (non-dict shapes declined above).
        # Slotted or frozen outcome objects reject the attribute — the
        # export clamp then simply never sees the record (fail-open to
        # the un-demoted state).
        with contextlib.suppress(AttributeError):
            outcome.review_result = {"caller_evidence": record}
    if config.out_dir:
        try:
            from core.analysis.reach_chokepoint import record_suppression

            record_suppression(
                Path(config.out_dir),
                finding={
                    "id": (
                        f"{outcome.file}:{outcome.function}:"
                        f"{outcome.line}"
                    ),
                    "rule_id": ab_res.rule_id,
                    "file_path": outcome.file,
                    "line": outcome.line,
                    "function": outcome.function,
                },
                verdict="caller_contract_refuted",
                reason=(
                    f"caller-contract gate: {ab_res.reason} — "
                    "confidence clamped to low; finding still exported"
                ),
                dropped=False,
                extra={
                    "contract": ab_res.contract,
                    "sites": n,
                    "confidence_clamp": "low",
                },
            )
        except Exception:
            logger.debug(
                "caller-contract suppression row failed", exc_info=True,
            )
    logger.info(
        "caller-contract gate: %s:%s confidence→low — %s",
        outcome.file, outcome.function, ab_res.reason,
    )
    return True


def _caller_contract_demotion_pass(
    result: Any,
    config: OrchestratorConfig,
) -> None:
    """Post-review caller-contract confidence demotion over the final
    outcome list (see ``_apply_caller_contract_gate`` for the per-
    outcome contract).  Runs before the journal correction pass and
    the graded export so journal, export, and summary agree."""
    if not getattr(config, "caller_contract_demotion", True):
        return
    demoted = 0
    for outcome in result.outcomes:
        try:
            if _apply_caller_contract_gate(outcome, config):
                demoted += 1
        except Exception:
            logger.debug(
                "caller-contract gate failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
    if demoted:
        logger.info(
            "caller-contract gate: %d outcome(s) demoted to "
            "confidence=low (all enumerated call sites uphold the "
            "asserted precondition; receipts in suppressions.jsonl)",
            demoted,
        )


def _record_fail_open_receipt(
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    fo_res: Any,
) -> None:
    """Persist the fail-open receipt (role provenance/grade, handler
    idiom, fallibility evidence, per-site verdicts, reachability
    escalator) to the audit log."""
    try:
        if not config.out_dir:
            return
        record = {
            "action": "fail_open_check",
            "file": file_path,
            "function": function_name,
        }
        record.update(fo_res.to_dict())
        append_audit_log(config.out_dir, record)
    except Exception:
        logger.debug("fail-open receipt write failed", exc_info=True)


def _record_consistency_receipt(
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    cs_res: Any,
) -> None:
    """Persist the consistency receipt (PeerEvidence majority
    arithmetic + exhibits, contract source/provenance, reachability
    escalator) to the audit log."""
    try:
        if not config.out_dir:
            return
        record = {
            "action": "consistency_check",
            "file": file_path,
            "function": function_name,
        }
        record.update(cs_res.to_dict())
        append_audit_log(config.out_dir, record)
    except Exception:
        logger.debug("consistency receipt write failed", exc_info=True)


def _record_channel_receipt(
    config: OrchestratorConfig,
    action: str,
    file_path: str,
    function_name: str,
    res: Any,
) -> None:
    """Persist a channel receipt (ptr_lifecycle four-receipt
    conjunction / lock_region region+invocation+setter evidence /
    resource_bounds / release_order / protocol_state — the
    fail_open receipt pattern) to the audit log — the shared
    shape of the per-channel recorders above."""
    try:
        if not config.out_dir:
            return
        record = {
            "action": action,
            "file": file_path,
            "function": function_name,
        }
        record.update(res.to_dict())
        append_audit_log(config.out_dir, record)
    except Exception:
        logger.debug("%s receipt write failed", action, exc_info=True)


def _record_invariant_receipt(
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    inv_res: Any,
) -> None:
    """Persist the invariant-preservation receipt (per-site verdicts,
    violating model when sat) to the audit log — the receipt is the
    channel's whole value; a bare confirmed/refuted counter would be
    unauditable."""
    try:
        if not config.out_dir:
            return
        record = {
            "action": "invariant_preservation",
            "file": file_path,
            "function": function_name,
        }
        record.update(inv_res.to_dict())
        append_audit_log(config.out_dir, record)
    except Exception:
        logger.debug("invariant receipt write failed", exc_info=True)


# Whether the codeql-tier degradation skip was already announced (log
# once per process, then debug — every CWE-seeded chain would
# otherwise repeat the same line).
_CODEQL_DEGRADED_LOGGED: list[bool] = [False]


def _note_codeql_degraded_skip(file_path: str, function_name: str) -> None:
    """One loud line the first time a codeql chain step is skipped
    because the tier degraded at startup (no database), debug after."""
    if not _CODEQL_DEGRADED_LOGGED[0]:
        _CODEQL_DEGRADED_LOGGED[0] = True
        logger.info(
            "codeql tier degraded at startup (no CodeQL database) — "
            "codeql chain steps are skipped for this run; fallback "
            "channels (semgrep/joern/smt) cover their claims",
        )
    logger.debug(
        "tool_chain codeql skipped %s:%s — tier degraded (no database)",
        file_path, function_name,
    )


# CWEs already reported as having no dispatch entry (log once per run,
# not once per finding — a hot class would otherwise spam the log).
_UNMAPPED_CWES_LOGGED: set[str] = set()


def _warn_unmapped_cwe(cwe: str) -> None:
    """One-line visibility when a review-emitted CWE dispatches nothing.

    Without this, a CWE outside every dispatch table silently produces
    an empty chain and the claim is never mechanically tested.
    Policy-parked classes get their own line: they are unmapped by
    decision, and their suspicious verdicts do NOT become synthesis
    candidates.
    """
    norm = cwe.upper().strip()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    if norm in _UNMAPPED_CWES_LOGGED:
        return
    _UNMAPPED_CWES_LOGGED.add(norm)
    try:
        from .cwe_dispatch import not_tool_verifiable_reason
    except ImportError:
        policy_reason = ""
    else:
        policy_reason = not_tool_verifiable_reason(norm)
    if policy_reason:
        logger.info(
            "review emitted %s — class is not tool-verifiable by "
            "policy (%s); verdicts in this family stay at "
            "hypothesis/suspicious grade and are excluded from "
            "on-demand checker synthesis",
            norm, policy_reason,
        )
        return
    logger.warning(
        "review emitted %s but no tool-chain dispatch entry exists — "
        "CWE-seeded verification will not run for this class "
        "(hypothesis-keyword channels may still fire; suspicious "
        "verdicts in this family become on-demand checker-synthesis "
        "candidates in the post-loop sweep)",
        norm,
    )


def _cwe_fallback_chain(
    cwe: str,
    hypothesis: str = "",
) -> list[dict[str, Any]]:
    """Generate tool chain from CWE dispatch when string matching fails.

    ``hypothesis`` gates the caller-conditional part of the
    api_boundary dispatch (CWE-415/416/476 route to the channel only
    when the phrasing conditions on caller behaviour).
    """
    chain: list[dict[str, Any]] = []
    try:
        from .cwe_dispatch import (
            cocci_rules_for_cwe,
            codeql_query_for_cwe,
            joern_applicable,
            sinks_for_cwe,
            smt_verb_for_cwe,
        )
    except ImportError:
        return chain

    try:
        from .compiler_sweep import compiler_applicable
    except ImportError:
        pass
    else:
        # Compiler static analyzer before SMT: cheap, deterministic,
        # verification-role for its mapped families.
        if compiler_applicable(cwe):
            chain.append({"type": "compiler", "config": {"cwe": cwe}})

    try:
        from .fail_open_verify import fail_open_applicable
    except ImportError:
        pass
    else:
        # Improper-handling-of-exceptional-conditions family
        # (CWE-703/636/391/390/252/248): the fail_open channel is the
        # verifier — pure static analysis, cheap, before the heavier
        # engines.
        if fail_open_applicable(cwe):
            chain.append({"type": "fail_open", "config": {}})

    try:
        from .api_boundary import api_boundary_applicable
    except ImportError:
        pass
    else:
        # Authenticity / boundary-obligation family (API_BOUNDARY_CWES
        # — CWE-345, unconditional) plus the caller-conditional
        # families (CALLER_CONDITIONAL_CWES — CWE-415/416/476, only
        # when the hypothesis phrasing conditions on caller behaviour):
        # the channel checks the asserted caller obligation at every
        # in-repo call site. Pure static analysis, cheap.
        if api_boundary_applicable(cwe, hypothesis):
            chain.append({"type": "api_boundary", "config": {}})

    try:
        from .consistency_verify import consistency_applicable
    except ImportError:
        pass
    else:
        # Consistency-outlier family (CONSISTENCY_CWES — CWE-252 keeps
        # its cocci entry, the consistency channel joins its chain):
        # pure static analysis, cheap, before the heavier engines.
        if consistency_applicable(cwe):
            chain.append({"type": "consistency", "config": {}})

    try:
        from .resource_bounds import resource_bounds_applicable
    except ImportError:
        pass
    else:
        # Unbounded allocation / accumulation family
        # (RESOURCE_BOUNDS_CWES — CWE-770/400/772): the bound-witness
        # comparator is the verifier. Pure static analysis, cheap.
        if resource_bounds_applicable(cwe):
            chain.append({"type": "resource_bounds", "config": {}})

    try:
        from .release_order import release_order_applicable
    except ImportError:
        pass
    else:
        # Release-before-verify family (RELEASE_ORDER_CWES —
        # CWE-354/347, plus the CWE-345 authenticity chain joined
        # additively): the dominance comparator is the verifier.
        if release_order_applicable(cwe):
            chain.append({"type": "release_order", "config": {}})

    try:
        from .protocol_state import protocol_state_applicable
    except ImportError:
        pass
    else:
        # Incomplete-internal-state family (PROTOCOL_STATE_CWES —
        # CWE-372): the census-driven invariant harness plus the
        # legs-1+2 receipts are the verifier.
        if protocol_state_applicable(cwe):
            chain.append({"type": "protocol_state", "config": {}})

    smt_verb = smt_verb_for_cwe(cwe)
    if smt_verb:
        chain.append({"type": "smt", "config": {"verb": smt_verb}})

    chain.extend({"type": "coccinelle", "config": {"rule": cocci_rule}} for cocci_rule in cocci_rules_for_cwe(cwe))

    codeql_query = codeql_query_for_cwe(cwe)
    if codeql_query:
        chain.append({"type": "codeql", "config": {"query": codeql_query}})

    if joern_applicable(cwe):
        sinks = sinks_for_cwe(cwe)
        if sinks:
            chain.append({"type": "joern", "config": {"sinks": sinks}})

    try:
        from .joern_verify import flow_chain_entry, guard_chain_entry
    except ImportError:
        pass
    else:
        guard_entry = guard_chain_entry(cwe)
        if guard_entry:
            chain.append(guard_entry)
        flow_entry = flow_chain_entry(cwe)
        if flow_entry:
            chain.append(flow_entry)

    try:
        from .cocci_flow import chain_entry_for_cwe
    except ImportError:
        pass
    else:
        cocci_flow_entry = chain_entry_for_cwe(cwe)
        if cocci_flow_entry:
            chain.append(cocci_flow_entry)

    try:
        from .ptr_lifecycle import ptr_lifecycle_applicable
    except ImportError:
        pass
    else:
        # Alias-hop lifecycle family (PTR_LIFECYCLE_CWES — CWE-825 /
        # CWE-672 are channel-owned; the CWE-416 membership is
        # additive, the channel joins after the existing
        # smt/cocci/codeql entries).
        if ptr_lifecycle_applicable(cwe):
            chain.append({"type": "ptr_lifecycle", "config": {}})

    try:
        from .lock_region import lock_region_applicable
    except ImportError:
        pass
    else:
        # Callback-under-lock family (LOCK_REGION_CWES — CWE-833 is
        # channel-owned; the CWE-667 membership is additive to its
        # existing smt/cocci lock-imbalance entry).
        if lock_region_applicable(cwe):
            chain.append({"type": "lock_region", "config": {}})

    try:
        from .integer_truncation_checker import integer_truncation_applicable
    except ImportError:
        pass
    else:
        if integer_truncation_applicable(cwe):
            chain.append({"type": "integer_truncation", "config": {}})

    try:
        from .proto_length_checker import proto_length_applicable
    except ImportError:
        pass
    else:
        if proto_length_applicable(cwe):
            chain.append({"type": "proto_length", "config": {}})

    try:
        from .struct_field_checker import struct_field_applicable
    except ImportError:
        pass
    else:
        if struct_field_applicable(cwe):
            chain.append({"type": "struct_field", "config": {}})

    if cwe and not chain:
        _warn_unmapped_cwe(cwe)

    return chain


_line_end_cache: dict[tuple[str, str, str], int] = {}


def _checklist_line_end(
    config: OrchestratorConfig, file_path: str, function_name: str,
) -> int:
    """Resolve a function's ``line_end`` from the inventory checklist.

    The sweep windows previously used ``line_start + 50``: matches from
    the NEXT function confirmed short functions, and matches past line
    50 of a long function were dropped. The checklist carries real
    bounds — use them. Returns 0 when unresolvable (callers keep their
    +50 fallback).
    """
    # Keyed by target as well: the corpus runner calls the pipeline
    # repeatedly in-process, and two targets sharing a relative path +
    # function name must not read each other's bounds.
    key = (str(config.target_path), file_path, function_name)
    cached = _line_end_cache.get(key)
    if cached is not None:
        return cached
    result = 0
    inv = getattr(config, "inventory", None) or {}
    for frec in inv.get("files", []):
        if frec.get("path") != file_path:
            continue
        for item in frec.get("items", []):
            if item.get("name") == function_name:
                result = item.get("line_end") or 0
                break
        break
    _line_end_cache[key] = result
    return result


# Below this remaining-budget floor a Joern verification query is not
# worth dispatching at all: the REPL round-trip plus parse would eat
# most of it, and a stuck query would hold the worker past the run's
# deadline anyway.
_JOERN_MIN_QUERY_BUDGET_S = 10


def _joern_budget_timeout_s(config: OrchestratorConfig) -> int | None:
    """Per-query Joern timeout clamped to the remaining run budget.

    Returns ``None`` when the run has no deadline (callers use the
    tunables default), ``0`` when the remaining budget is below
    ``_JOERN_MIN_QUERY_BUDGET_S`` (callers skip the query), otherwise
    ``min(default_query_timeout(), remaining)``. Without the clamp a
    single stuck query near the end of the run holds its worker for
    the full default timeout (300s), and the single-threaded REPL
    serialises every other worker's query behind it.
    """
    deadline = getattr(config, "run_deadline_monotonic", None)
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining < _JOERN_MIN_QUERY_BUDGET_S:
        return 0
    try:
        # Resolves the tunables default; degrades internally.
        from .joern_verify import default_query_timeout
        default = default_query_timeout()
    except ImportError:
        default = 300
    return max(1, min(default, int(remaining)))


_MAX_XREF_BYTES = 16384
_MAX_XREF_NEIGHBORS = 16


def _ghidra_re_context(
    config: Any,
    function_name: str,
) -> tuple[list[dict] | None, str | None]:
    """Extract REDatabase types and xref decompilation for a function.

    Returns (re_types, xref_source) from the Ghidra cache.  Best-effort:
    returns (None, None) when Ghidra is unavailable or no match is found.
    """
    try:
        from packages.ghidra.context_inject import lookup_function_context
        func, db = lookup_function_context(
            config.target_path, function_name)
    except Exception:  # noqa: BLE001
        return None, None
    if func is None or db is None:
        return None, None

    re_types = None
    related = [t for t in db.types
               if t.kind == "struct" and t.fields]
    if related:
        re_types = [t.to_dict() for t in related[:20]]

    parts: list[str] = []
    total = 0
    seen_addrs: set[int] = set()
    for x in db.xrefs:
        if x.kind != "call":
            continue
        neighbor = None
        label = ""
        if x.to_addr == func.address:
            neighbor = db.function_containing_address(x.from_addr)
            label = "caller"
        else:
            owner = db.function_containing_address(x.from_addr)
            if owner is not None and owner.address == func.address:
                neighbor = db.function_by_address(x.to_addr)
                label = "callee"
        if (neighbor is None or not neighbor.decompilation
                or neighbor.address in seen_addrs):
            continue
        seen_addrs.add(neighbor.address)
        chunk = (
            f"\n// --- {label}: {neighbor.name} ---\n"
            f"{neighbor.decompilation}"
        )
        if total + len(chunk) > _MAX_XREF_BYTES:
            break
        parts.append(chunk)
        total += len(chunk)
        if len(parts) >= _MAX_XREF_NEIGHBORS:
            break

    xref_source = "".join(parts) if parts else None
    return re_types, xref_source


def _run_tool_chain(
    chain: list[dict[str, Any]],
    *,
    config: OrchestratorConfig,
    file_path: str,
    function_name: str,
    source: str | None,
    hypothesis: str,
    line_start: int = 0,
    sarif_cache: SarifCache | None = None,
    tier_counters: dict[str, TierCounters] | None = None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    joern_server=None,
    target_path_override: Path | None = None,
    domain_vocab: Any = None,
    cwe: str = "",
    errored_types: set | None = None,
) -> list[str]:
    """Run tools from *chain* in order, collecting all confirmations.

    Returns a list of confirming tool IDs (e.g. ``["smt:check-oob",
    "coccinelle:missing_bounds_check"]``).  A tool that errors or
    whose dependency is missing is skipped (logged at debug) and the
    next tool in the chain is tried — this is the fallback behaviour.
    When *errored_types* is provided, the step types that errored are
    collected into it so callers can record per-function tool failures
    (a channel that errored did not meaningfully run).

    When *sarif_cache* is provided, semgrep sweeps check for prior
    SARIF results before spawning a subprocess.  Cached SARIF hits
    only count as confirmation when their rule family correlates with
    the hypothesis (or *cwe*) — an unrelated scan hit near the same
    lines proves nothing about this claim.
    """
    effective_target = target_path_override or config.target_path
    confirmed: list[str] = []

    if domain_vocab is None and config.out_dir:
        with contextlib.suppress(OSError):
            from .condition_smt import DomainVocabulary
            dm = _load_domain_model(config)
            domain_vocab = DomainVocabulary.from_domain_model(
                dm, target_path=effective_target,
            )
            if not domain_vocab.has_content:
                domain_vocab = None

    for entry in chain:
        tool_type = entry["type"]
        tool_cfg = entry["config"]

        # Wall-clock bracket for tier diagnostics: tier-diagnostics
        # wall_time_s was declared on TierCounters but never
        # accumulated anywhere, so every report showed 0.0.
        _tier_t0 = time.monotonic()
        try:
            if tool_type == "semgrep":
                if sarif_cache is not None:
                    cached = sarif_cache.lookup(
                        file_path,
                        line_start,
                        _checklist_line_end(config, file_path, function_name)
                        or (line_start + 50 if line_start else 0),
                    )
                    correlated = [
                        r for r in (cached or [])
                        if evidence_matches_hypothesis(
                            family_for_rule(r.get("ruleId", "")),
                            hypothesis,
                            cwe,
                        )
                    ]
                    if correlated:
                        # Confirm path — the ONLY case a cache hit may
                        # substitute for the per-hypothesis sweep. The
                        # semgrep channel outcome is recorded here; the
                        # dynamic rule file baked into the config would
                        # never reach the unlink finally below, so
                        # remove it or it leaks on every cache confirm.
                        confirmed.append("sarif_cache:semgrep")
                        if tier_counters:
                            _increment_tier_dict(
                                tier_counters, "semgrep", "confirmed",
                            )
                        logger.debug(
                            "sarif_cache hit: %s:%s — %d correlated "
                            "prior results",
                            file_path,
                            function_name,
                            len(correlated),
                        )
                        _cached_rule = tool_cfg.get("rule") or ""
                        if os.path.basename(_cached_rule).startswith(
                                "audit_sweep_"):
                            try:
                                os.unlink(_cached_rule)
                            except OSError:
                                pass
                        continue
                    if cached is not None:
                        # Empty-in-range or uncorrelated cache content:
                        # a prior scan's STOCK rules finding nothing
                        # (or something unrelated) near these lines
                        # says nothing about THIS hypothesis — fall
                        # through and run the per-hypothesis rule so
                        # the semgrep channel gets a real
                        # confirmed/refuted/error record.
                        logger.debug(
                            "sarif_cache: %s:%s — %d prior in-range "
                            "results, none correlated with hypothesis; "
                            "running the per-hypothesis sweep",
                            file_path,
                            function_name,
                            len(cached),
                        )

                rule_path = tool_cfg["rule"]
                # keyword marks a dynamic per-hypothesis rule: only
                # those get the identifier-consistency and
                # negative-control gates (stock rules are curated).
                rule_keyword = tool_cfg.get("keyword") or ""
                try:
                    sweep = run_semgrep_sweep(
                        target_path=effective_target,
                        file_path=file_path,
                        function_name=function_name,
                        rule_config=rule_path,
                        line_start=line_start,
                        line_end=_checklist_line_end(
                            config, file_path, function_name)
                        or (line_start + 50 if line_start else 0),
                        hypothesis=hypothesis if rule_keyword else "",
                        rule_keyword=rule_keyword,
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
                    if errored_types is not None:
                        errored_types.add(tool_type)
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "semgrep", "errors")
                elif sweep.outcome == "inconclusive":
                    logger.info(
                        "tool_chain semgrep inconclusive %s:%s: %s",
                        file_path,
                        function_name,
                        (sweep.details or {}).get("reason", ""),
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "semgrep", "inconclusive",
                        )
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "semgrep", "refuted")

            elif tool_type == "smt":
                smt_result = run_smt_verb_direct(
                    file_path=file_path,
                    function_name=function_name,
                    verb=tool_cfg["verb"],
                    source=source or "",
                    hypothesis=hypothesis,
                    target_path=str(effective_target),
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
                    if errored_types is not None:
                        errored_types.add(tool_type)
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "smt", "errors")
                elif smt_result.outcome == "inconclusive":
                    # Inconclusive (e.g. vacuous SAT on an
                    # unconstrained-arithmetic verb, missing operands,
                    # Z3 unavailable) is NOT a refutation — it must
                    # neither confirm nor clear prior SMT
                    # confirmations from other verbs.
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "smt", "inconclusive",
                        )
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

            elif tool_type == "api_boundary":
                from .api_boundary import run_api_boundary_check

                _ab_line_end = _checklist_line_end(
                    config, file_path, function_name,
                )
                ab_res = run_api_boundary_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    def_span=(
                        (line_start, _ab_line_end)
                        if line_start and _ab_line_end else None
                    ),
                )
                _record_api_boundary_receipt(
                    config, file_path, function_name, ab_res,
                )
                if ab_res.outcome == "confirmed":
                    confirmed.append("api_boundary:caller-contract")
                    logger.info(
                        "api-boundary confirmed %s:%s — %s",
                        file_path, function_name, ab_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "api_boundary", "confirmed",
                        )
                elif ab_res.outcome == "refuted":
                    logger.info(
                        "api-boundary refuted %s:%s — %s",
                        file_path, function_name, ab_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "api_boundary", "refuted",
                        )
                else:
                    logger.info(
                        "api-boundary inconclusive %s:%s — %s",
                        file_path, function_name, ab_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "api_boundary",
                            "inconclusive",
                        )

            elif tool_type == "fail_open":
                from .fail_open_roles import RoleContext
                from .fail_open_verify import run_fail_open_check

                _fo_roots: tuple = (Path(effective_target),)
                if getattr(config, "study_root", None):
                    _fo_roots += (Path(config.study_root),)
                fo_ctx = RoleContext(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                    target_roots=_fo_roots,
                )
                # Leg-3 flow escalator: live server + the same
                # remaining-run-budget clamp as the joern_guard /
                # joern_flow steps (0 -> the channel skips the leg).
                fo_budget = _joern_budget_timeout_s(config)
                fo_res = run_fail_open_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    role_context=fo_ctx,
                    joern_server=joern_server,
                    budget_s=fo_budget,
                )
                # Corroborating receipts already earned by earlier
                # chain steps (e.g. the CWE-252 compiler family's
                # -Wunused-result diagnostic) ride on the receipt; the
                # consistency programme's PeerEvidence dicts join the
                # same list once that channel lands.
                fo_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("fail_open")
                )
                _record_fail_open_receipt(
                    config, file_path, function_name, fo_res,
                )
                if fo_res.outcome == "confirmed":
                    confirmed.append(fo_res.rule_id)
                    logger.info(
                        "fail-open confirmed %s:%s — %s",
                        file_path, function_name, fo_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "fail_open", "confirmed",
                        )
                elif fo_res.outcome == "refuted":
                    logger.info(
                        "fail-open refuted %s:%s — %s",
                        file_path, function_name, fo_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "fail_open", "refuted",
                        )
                else:
                    logger.info(
                        "fail-open inconclusive %s:%s — %s",
                        file_path, function_name, fo_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "fail_open",
                            "inconclusive",
                        )

            elif tool_type == "consistency":
                from .consistency_verify import run_consistency_check
                from .fail_open_roles import RoleContext as _CsRoleCtx

                cs_ctx = _CsRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                )
                cs_res = run_consistency_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    context=cs_ctx,
                    # Joern-flow escalator (outcome-gated inside the
                    # verdict): one bounded caller-closure query when
                    # the cheap reachability leg answers unknown.
                    joern_server=joern_server,
                )
                # Receipts already earned by earlier chain steps
                # corroborate (compiler -Wunused-result, cocci,
                # fail_open confirmations on the same claim).
                cs_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("consistency")
                )
                _record_consistency_receipt(
                    config, file_path, function_name, cs_res,
                )
                if cs_res.outcome == "confirmed":
                    confirmed.append(cs_res.rule_id)
                    logger.info(
                        "consistency confirmed %s:%s — %s",
                        file_path, function_name, cs_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "consistency", "confirmed",
                        )
                elif cs_res.outcome == "refuted":
                    logger.info(
                        "consistency refuted %s:%s — %s",
                        file_path, function_name, cs_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "consistency", "refuted",
                        )
                else:
                    logger.info(
                        "consistency inconclusive %s:%s — %s",
                        file_path, function_name, cs_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "consistency",
                            "inconclusive",
                        )

            elif tool_type == "ptr_lifecycle":
                from .fail_open_roles import RoleContext as _PlRoleCtx
                from .ptr_lifecycle import run_ptr_lifecycle_check

                pl_ctx = _PlRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                )
                pl_res = run_ptr_lifecycle_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    context=pl_ctx,
                    domain_vocab=domain_vocab,
                )
                # Receipts already earned by earlier chain steps
                # (smt check-early-release, cocci use_after_free,
                # typestate) corroborate the alias claim.
                pl_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("ptr_lifecycle")
                )
                _record_channel_receipt(
                    config, "ptr_lifecycle_check", file_path,
                    function_name, pl_res,
                )
                if pl_res.outcome == "confirmed":
                    confirmed.append(pl_res.rule_id)
                    logger.info(
                        "ptr-lifecycle confirmed %s:%s — %s",
                        file_path, function_name, pl_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "ptr_lifecycle", "confirmed",
                        )
                elif pl_res.outcome == "refuted":
                    logger.info(
                        "ptr-lifecycle refuted %s:%s — %s",
                        file_path, function_name, pl_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "ptr_lifecycle", "refuted",
                        )
                else:
                    logger.info(
                        "ptr-lifecycle inconclusive %s:%s — %s",
                        file_path, function_name, pl_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "ptr_lifecycle",
                            "inconclusive",
                        )

            elif tool_type == "lock_region":
                from .fail_open_roles import RoleContext as _LrRoleCtx
                from .lock_region import (
                    cocci_corroboration,
                    run_lock_region_check,
                )

                lr_ctx = _LrRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                )
                lr_res = run_lock_region_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    context=lr_ctx,
                    domain_vocab=domain_vocab,
                )
                lr_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("lock_region")
                )
                _record_channel_receipt(
                    config, "lock_region_check", file_path,
                    function_name, lr_res,
                )
                if lr_res.outcome == "confirmed":
                    confirmed.append(lr_res.rule_id)
                    logger.info(
                        "lock-region confirmed %s:%s — %s",
                        file_path, function_name, lr_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "lock_region", "confirmed",
                        )
                    # Parametric cocci corroboration leg: an
                    # INDEPENDENT coccinelle-namespace stamp (the
                    # aggregation rule needs two namespaces; a receipt
                    # riding inside corroboration[] does not count).
                    cocci_stamp = cocci_corroboration(
                        effective_target, lr_res,
                    )
                    if cocci_stamp and cocci_stamp not in confirmed:
                        confirmed.append(cocci_stamp)
                elif lr_res.outcome == "refuted":
                    logger.info(
                        "lock-region refuted %s:%s — %s",
                        file_path, function_name, lr_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "lock_region", "refuted",
                        )
                else:
                    logger.info(
                        "lock-region inconclusive %s:%s — %s",
                        file_path, function_name, lr_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "lock_region",
                            "inconclusive",
                        )

            elif tool_type == "resource_bounds":
                from .fail_open_roles import RoleContext as _RbRoleCtx
                from .resource_bounds import run_resource_bounds_check

                rb_dm = None
                with contextlib.suppress(Exception):
                    rb_dm = _load_domain_model(config) \
                        if config.out_dir else None
                rb_ctx = _RbRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                    context_map=getattr(config, "context_map", None),
                )
                rb_res = run_resource_bounds_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    context=rb_ctx,
                    domain_model=rb_dm,
                )
                # Receipts already earned by earlier chain steps
                # corroborate (the fail_open convention).
                rb_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("resource_bounds")
                )
                _record_channel_receipt(
                    config, "resource_bounds_check", file_path,
                    function_name, rb_res,
                )
                if rb_res.outcome == "confirmed":
                    confirmed.append(rb_res.rule_id)
                    logger.info(
                        "resource-bounds confirmed %s:%s — %s",
                        file_path, function_name, rb_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "resource_bounds",
                            "confirmed",
                        )
                elif rb_res.outcome == "refuted":
                    logger.info(
                        "resource-bounds refuted %s:%s — %s",
                        file_path, function_name, rb_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "resource_bounds",
                            "refuted",
                        )
                else:
                    logger.info(
                        "resource-bounds inconclusive %s:%s — %s",
                        file_path, function_name, rb_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "resource_bounds",
                            "inconclusive",
                        )

            elif tool_type == "release_order":
                from .fail_open_roles import RoleContext as _RoRoleCtx
                from .release_order import run_release_order_check

                ro_dm = None
                with contextlib.suppress(Exception):
                    ro_dm = _load_domain_model(config) \
                        if config.out_dir else None
                ro_ctx = _RoRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                    context_map=getattr(config, "context_map", None),
                )
                ro_res = run_release_order_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    context=ro_ctx,
                    domain_model=ro_dm,
                    joern_server=joern_server,
                )
                # Prior receipts corroborate; the in-flight
                # consistency ordering dimension's PeerEvidence dicts
                # join the same list once that comparator lands.
                ro_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("release_order")
                )
                _record_channel_receipt(
                    config, "release_order_check", file_path,
                    function_name, ro_res,
                )
                if ro_res.outcome == "confirmed":
                    confirmed.append(ro_res.rule_id)
                    logger.info(
                        "release-order confirmed %s:%s — %s",
                        file_path, function_name, ro_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "release_order",
                            "confirmed",
                        )
                elif ro_res.outcome == "refuted":
                    logger.info(
                        "release-order refuted %s:%s — %s",
                        file_path, function_name, ro_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "release_order", "refuted",
                        )
                else:
                    logger.info(
                        "release-order inconclusive %s:%s — %s",
                        file_path, function_name, ro_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "release_order",
                            "inconclusive",
                        )

            elif tool_type == "protocol_state":
                from .fail_open_roles import RoleContext as _PsRoleCtx
                from .protocol_state import run_protocol_state_check

                ps_dm = None
                with contextlib.suppress(Exception):
                    ps_dm = _load_domain_model(config) \
                        if config.out_dir else None
                ps_ctx = _PsRoleCtx(
                    out_dir=config.out_dir,
                    annotations_dir=getattr(
                        config, "annotations_dir", None,
                    ),
                    inventory=getattr(config, "inventory", None),
                    context_map=getattr(config, "context_map", None),
                )
                ps_res = run_protocol_state_check(
                    effective_target,
                    file_path,
                    function_name,
                    hypothesis,
                    inventory=getattr(config, "inventory", None),
                    context=ps_ctx,
                    domain_model=ps_dm,
                    invariant=tool_cfg.get("invariant") or None,
                )
                ps_res.corroboration.extend(
                    c for c in confirmed
                    if not c.startswith("protocol_state")
                )
                _record_channel_receipt(
                    config, "protocol_state_check", file_path,
                    function_name, ps_res,
                )
                if ps_res.outcome == "confirmed":
                    confirmed.append(ps_res.rule_id)
                    logger.info(
                        "protocol-state confirmed %s:%s — %s",
                        file_path, function_name, ps_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "protocol_state",
                            "confirmed",
                        )
                elif ps_res.outcome == "refuted":
                    logger.info(
                        "protocol-state refuted %s:%s — %s",
                        file_path, function_name, ps_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "protocol_state",
                            "refuted",
                        )
                else:
                    logger.info(
                        "protocol-state inconclusive %s:%s — %s",
                        file_path, function_name, ps_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "protocol_state",
                            "inconclusive",
                        )

            elif tool_type == "smt_invariant":
                from .invariant_smt import check_invariant_preservation

                inv_res = check_invariant_preservation(
                    tool_cfg.get("invariant", ""),
                    source or "",
                )
                _record_invariant_receipt(
                    config, file_path, function_name, inv_res,
                )
                if inv_res.outcome == "violable":
                    # A model breaks the stated invariant at a concrete
                    # mutation site — detection-role confirmation (see
                    # sweep._SMT_VERB_ROLES: promotion still needs LLM
                    # agreement / non-detection corroboration).
                    confirmed.append("smt:invariant-preservation")
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "smt_invariant", "confirmed",
                        )
                elif inv_res.outcome == "preserved":
                    logger.info(
                        "invariant preserved %s:%s — %s (%s)",
                        file_path, function_name,
                        inv_res.invariant, inv_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "smt_invariant", "refuted",
                        )
                else:
                    logger.info(
                        "invariant check inconclusive %s:%s — %s (%s)",
                        file_path, function_name,
                        inv_res.invariant, inv_res.reason,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "smt_invariant",
                            "inconclusive",
                        )

            elif tool_type == "coccinelle":
                if tool_cfg.get("cross_file"):
                    # Cross-file Coccinelle consistency sweep. Import
                    # under an alias: the consistency-channel branch
                    # above binds `run_consistency_check` to the
                    # census adjudicator (.consistency_verify), which
                    # shadows the sweep helper in this function scope.
                    from .sweep import (
                        run_consistency_check as _run_cross_file_cocci,
                    )
                    cocci_result = _run_cross_file_cocci(
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
                        line_start=line_start or None,
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
                    if errored_types is not None:
                        errored_types.add(tool_type)
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
                    _live_errors: list = []
                    live_hits = _joern_live_query(
                        joern_server,
                        function_name,
                        sinks,
                        errors_out=_live_errors,
                    )
                    if live_hits:
                        confirmed.append("joern:live")
                        joern_hit = True
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "joern", "confirmed")
                    elif _live_errors:
                        # Degraded query (server restarting / timeout)
                        # — an unanswered question, NOT a refutation.
                        logger.debug(
                            "tool_chain joern error %s:%s: %s",
                            file_path, function_name, _live_errors,
                        )
                        if errored_types is not None:
                            errored_types.add(tool_type)
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "joern", "errors")
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
                _tool_db = _codeql_db_for(config, file_path)
                if not _tool_db:
                    # Startup already recorded this degradation
                    # (codeql → semgrep taint mode); honour it at
                    # dispatch instead of erroring at run time — the
                    # rest of the chain (semgrep/joern/smt) covers the
                    # claim. Loud once per run, then debug.
                    _note_codeql_degraded_skip(
                        file_path, function_name,
                    )
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "codeql", "skipped",
                        )
                    continue
                from .sweep import run_codeql_sweep

                codeql_result = run_codeql_sweep(
                    target_path=effective_target,
                    file_path=file_path,
                    function_name=function_name,
                    query_path=tool_cfg["query"],
                    database_path=_tool_db,
                    line_start=line_start,
                    line_end=_checklist_line_end(
                        config, file_path, function_name)
                    or (line_start + 50 if line_start else 0),
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
                    if errored_types is not None:
                        errored_types.add(tool_type)
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "codeql", "refuted")

            elif tool_type == "compiler":
                from .compiler_sweep import run_compiler_analyzer_sweep

                comp_result = run_compiler_analyzer_sweep(
                    target_path=effective_target,
                    file_path=file_path,
                    function_name=function_name,
                    hypothesis=hypothesis,
                    cwe=tool_cfg.get("cwe", ""),
                    line_start=line_start,
                    line_end=line_start + 50 if line_start else 0,
                    out_dir=config.out_dir,
                )
                if comp_result.outcome == "confirmed":
                    confirmed.append(comp_result.rule_id or "compiler:analyzer")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "compiler", "confirmed")
                elif comp_result.outcome == "error":
                    logger.debug(
                        "tool_chain compiler error %s:%s: %s",
                        file_path,
                        function_name,
                        comp_result.errors,
                    )
                    if errored_types is not None:
                        errored_types.add(tool_type)
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "compiler", "errors")
                elif comp_result.outcome == "refuted":
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "compiler", "refuted")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "compiler", "inconclusive")


            elif tool_type in ("joern_guard", "joern_flow"):
                from .joern_verify import (
                    extract_flow_endpoints,
                    extract_guard_target,
                    run_flow_reachability_check,
                    run_guard_dominance_check,
                )

                sinks = tool_cfg.get("sinks", [])
                if tool_type == "joern_guard":
                    ident, sink = extract_guard_target(hypothesis, sinks)
                else:
                    ident, sink = extract_flow_endpoints(hypothesis, sinks)

                jv_timeout = _joern_budget_timeout_s(config)
                if not ident or not sink or joern_server is None:
                    # No binding (identifier-consistency control) or no
                    # live server — decline, don't guess.
                    if tier_counters:
                        _increment_tier_dict(tier_counters, tool_type, "skipped")
                elif jv_timeout == 0:
                    # Remaining run budget too small for a Joern
                    # round-trip — skip rather than hold the worker
                    # past the run's deadline.
                    logger.debug(
                        "tool_chain %s skipped %s:%s — run budget "
                        "nearly exhausted",
                        tool_type, file_path, function_name,
                    )
                    if tier_counters:
                        _increment_tier_dict(tier_counters, tool_type, "skipped")
                else:
                    if tool_type == "joern_guard":
                        jv_result = run_guard_dominance_check(
                            target_path=effective_target,
                            file_path=file_path,
                            function_name=function_name,
                            identifier=ident,
                            sink_call=sink,
                            server=joern_server,
                            timeout=jv_timeout,
                        )
                    else:
                        jv_result = run_flow_reachability_check(
                            target_path=effective_target,
                            file_path=file_path,
                            function_name=function_name,
                            source_id=ident,
                            sink_call=sink,
                            server=joern_server,
                            timeout=jv_timeout,
                        )
                    if jv_result.outcome == "confirmed":
                        confirmed.append(jv_result.rule_id or f"joern:{tool_type}")
                        if tier_counters:
                            _increment_tier_dict(tier_counters, tool_type, "confirmed")
                    elif jv_result.outcome == "error":
                        logger.debug(
                            "tool_chain %s error %s:%s: %s",
                            tool_type, file_path, function_name,
                            jv_result.errors,
                        )
                        if errored_types is not None:
                            errored_types.add(tool_type)
                        if tier_counters:
                            _increment_tier_dict(tier_counters, tool_type, "errors")
                    elif jv_result.outcome == "refuted":
                        # Mechanical refutation (dominating check found /
                        # no flow with endpoints present).  The chain
                        # contract returns confirmations only; the
                        # refutation evidence stays in the sweep log.
                        if tier_counters:
                            _increment_tier_dict(tier_counters, tool_type, "refuted")
                    elif tier_counters:
                        _increment_tier_dict(tier_counters, tool_type, "inconclusive")

            elif tool_type == "coccinelle_flow":
                from .cocci_flow import run_flow_cocci_sweep

                cf_result = run_flow_cocci_sweep(
                    target_path=effective_target,
                    file_path=file_path,
                    function_name=function_name,
                    hypothesis=hypothesis,
                    template=tool_cfg.get("template"),
                    line_start=line_start or None,
                    line_end=None,
                )
                if cf_result.outcome == "confirmed":
                    template_id = (cf_result.rule_id or "cocci-flow").split(":")[-1]
                    confirmed.append(f"coccinelle:flow-{template_id}")
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "coccinelle_flow", "confirmed",
                        )
                elif cf_result.outcome == "error":
                    logger.debug(
                        "tool_chain coccinelle_flow error %s:%s: %s",
                        file_path,
                        function_name,
                        cf_result.errors,
                    )
                    if errored_types is not None:
                        errored_types.add(tool_type)
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "coccinelle_flow", "errors",
                        )
                elif cf_result.outcome == "refuted":
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, "coccinelle_flow", "refuted",
                        )
                elif tier_counters:
                    _increment_tier_dict(
                        tier_counters, "coccinelle_flow", "inconclusive",
                    )

            elif tool_type in (
                "integer_truncation", "proto_length", "struct_field",
            ):
                _re_types, _xref_src = _ghidra_re_context(
                    config, function_name)

                if tool_type == "integer_truncation":
                    from .sweep import run_integer_truncation_sweep

                    _bc_res = run_integer_truncation_sweep(
                        file_path=file_path,
                        function_name=function_name,
                        source=source or "",
                        cwe=cwe,
                        xref_source=_xref_src,
                    )
                elif tool_type == "proto_length":
                    from .sweep import run_proto_length_sweep

                    _bc_res = run_proto_length_sweep(
                        file_path=file_path,
                        function_name=function_name,
                        source=source or "",
                        cwe=cwe,
                        xref_source=_xref_src,
                    )
                else:
                    from .sweep import run_struct_field_sweep

                    _bc_res = run_struct_field_sweep(
                        file_path=file_path,
                        function_name=function_name,
                        source=source or "",
                        cwe=cwe,
                        re_types=_re_types,
                        xref_source=_xref_src,
                    )

                if _bc_res.outcome == "confirmed":
                    confirmed.append(
                        f"{tool_type}:{_bc_res.rule_id}")
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, tool_type,
                            "confirmed",
                        )
                elif _bc_res.outcome == "error":
                    logger.debug(
                        "tool_chain %s error %s:%s: %s",
                        tool_type,
                        file_path, function_name, _bc_res.errors,
                    )
                    if errored_types is not None:
                        errored_types.add(tool_type)
                    if tier_counters:
                        _increment_tier_dict(
                            tier_counters, tool_type, "errors",
                        )
                elif tier_counters:
                    _increment_tier_dict(
                        tier_counters, tool_type, "refuted",
                    )


        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "tool_chain %s exception %s:%s: %s",
                tool_type,
                file_path,
                function_name,
                exc,
            )
            if errored_types is not None:
                errored_types.add(tool_type)
        finally:
            if tier_counters:
                _increment_tier_dict(
                    tier_counters,
                    tool_type,
                    "wall_time_s",
                    time.monotonic() - _tier_t0,
                )

    return confirmed


_CWE_IMPLICIT_PRECONDITIONS: dict[str, list[dict[str, Any]]] = {
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
    context_map: dict[str, Any] | None,
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
    sarif_cache: SarifCache | None = None,
    tier_counters: dict[str, TierCounters] | None = None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    joern_server=None,
    source_override: str | None = None,
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
    outcome:
        The LLM's ReviewOutcome to validate. Returned unchanged when
        already tool-confirmed, stamped with confirming evidence, or
        demoted (no hypothesis / SMT overflow disproof).
    config:
        OrchestratorConfig — supplies target_path, project_sinks, and
        CodeQL database routing for the mechanical tool runs.
    sarif_cache:
        Prior-SARIF index passed to the tool chain so semgrep steps can
        reuse cached scan results instead of spawning a subprocess.
    tier_counters:
        Per-tier TierCounters dict; confirmed/refuted/error counts for
        the smt/codeql/joern/aggregation channels are incremented here.
    evidence_index:
        Pre-computed per-function EvidenceRecord map (``file:function``
        keys), passed through to the tool chain for evidence lookups.
    joern_server:
        Live JoernServer passed through to the tool chain for CPG-backed
        checks; None disables that channel.
    source_override:
        Pre-loaded source/decompilation text. Skips file read when set.
    is_binary:
        True when reviewing a binary target (routes to binary tool chain).
    """
    review = outcome.review_result or {}
    hypothesis = _resolve_hypothesis(outcome)
    # Two evidence channels with different trust: outcome.evidence_tool
    # is pipeline-controlled (llm_review sanitizes LLM-supplied values
    # to llm-claimed:* before they land there; sweep/critique/dynamic
    # stamps are genuine) — a confirmed stamp there legitimately skips
    # re-validation. review["evidence_tool"] is the RAW LLM response:
    # a hallucinated "semgrep" must trigger validation, never bypass
    # it, so it is sanitized before any use. (Sanitizing the OUTCOME
    # value too was a regression: sanitize_llm_evidence_tool
    # namespaces unconditionally, so genuine stamps lost their
    # refutation-gate protection whenever the live sweep didn't
    # re-confirm.)
    outcome_et = outcome.evidence_tool or ""
    if _is_tool_confirmed(outcome_et):
        return outcome
    evidence_tool = _sanitize_llm_et(
        review.get("evidence_tool") or outcome_et,
    )

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

    # Premise binding, same rule as the secondary-sweep and smt-clean
    # escalation lanes: this pass grades the LLM's OWN finding, so a
    # function-local confirm re-proves the lexical shape the reviewer
    # already saw — it encodes nothing about the hypothesis's
    # cross-function counter ("the caller validates the level"). Such
    # a confirm may not ground the finding: the verdict falls through
    # ungrounded, the G2 gate holds it at suspicious, and the parked
    # premise awaits a study receipt. Cross-function-capable channels
    # (Joern, CodeQL dataflow) still ground it.
    premise_h = _primary_hypothesis_entry(outcome, hypothesis)

    is_binary = is_binary or outcome.file.startswith(BINARY_PATH_PREFIX)
    if source_override is not None:
        source = source_override
    else:
        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            None,
        )

    _decomp_tmp_dir: Path | None = None
    effective_file = outcome.file
    if is_binary and source:
        _decomp_tmp_dir = _write_decompilation_tmpfile(
            source, outcome.function,
        )
        if _decomp_tmp_dir is not None:
            effective_file = f"{outcome.function}.c"

    cwe = _effective_cwe(outcome, tier_counters)

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
                # Only a hit in the hypothesis's vulnerability family
                # is evidence; anything else is review context.
                correlated = [
                    h for h in pf.hits
                    if evidence_matches_hypothesis(
                        family_for_rule(h.rule_id), hypothesis, cwe,
                    )
                ]
                if correlated:
                    _pf_tool = f"prefilter:{correlated[0].rule_id}"
                    if not _premise_blocks_confirm(premise_h, [_pf_tool]):
                        return _stamp_evidence(outcome, _pf_tool)
                    _note_premise_blocked_validation(
                        outcome, premise_h, [_pf_tool],
                        config, tier_counters,
                    )
                else:
                    _record_uncorrelated_hits(outcome, pf.hits)
                    logger.info(
                        "sweep_validate: %s:%s prefilter hits (%s) "
                        "uncorrelated with hypothesis — kept as context, "
                        "not evidence",
                        outcome.file,
                        outcome.function,
                        ",".join(h.rule_id for h in pf.hits[:3]),
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
        errored: set = set()

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
            cwe=cwe,
            errored_types=errored,
        )

        # No Frida auto-launch here — an earlier last-resort path gated
        # on a never-set ``config._binary_path`` attribute was dead code
        # and has been removed. Dynamic engagement is handled by
        # core/audit/dynamic_sweep.py (should_run_dynamic /
        # run_dynamic_sweep in the review loop, gated on
        # config.dynamic_validation) and core/audit/frida_observe.py.

        outcome.tools_dispatched = (outcome.tools_dispatched or set()) | dispatched
        if errored:
            outcome.tools_errored = (outcome.tools_errored or set()) | errored
        if confirmed and _premise_blocks_confirm(premise_h, confirmed):
            _note_premise_blocked_validation(
                outcome, premise_h, confirmed, config, tier_counters,
            )
        elif confirmed:
            high_prec = [t for t in confirmed if not _is_detection_only(t)]
            if high_prec:
                tool_label = "+".join(high_prec)
                return _stamp_evidence(outcome, tool_label)
            # Bayesian multi-channel aggregation: independent
            # detection-role channels agreeing on the hypothesis can
            # jointly cross the confirm threshold even though no single
            # receipt is perfect.
            agg_channels, post_mean = _aggregate_channel_confirmations(
                confirmed,
            )
            if agg_channels:
                if tier_counters:
                    _increment_tier_dict(
                        tier_counters, "adapter_aggregation", "confirmed",
                    )
                _record_aggregated_promotion(
                    outcome, agg_channels, post_mean, confirmed,
                )
                logger.info(
                    "sweep validated %s:%s via aggregated channels %s "
                    "(posterior %.2f > %.2f)",
                    outcome.file, outcome.function,
                    "+".join(agg_channels), post_mean,
                    _AGGREGATION_CONFIRM_THRESHOLD,
                )
                return _stamp_evidence(outcome, "+".join(confirmed))
            if tier_counters:
                _increment_tier_dict(
                    tier_counters, "adapter_aggregation", "inconclusive",
                )
    finally:
        if _decomp_tmp_dir is not None:
            import shutil
            shutil.rmtree(_decomp_tmp_dir, ignore_errors=True)

    # CodeQL bespoke dataflow validation (when LLM claims a source→sink
    # flow and no standard tool confirmed it)
    _outcome_db = _codeql_db_for(config, outcome.file)
    if not is_binary and _outcome_db and "codeql" not in dispatched:
        try:
            from .codeql_validation import (
                extract_claims_from_review,
                validate_dataflow_claim,
            )

            claims = extract_claims_from_review(outcome.review_result or {})
            for claim in claims:
                vr = validate_dataflow_claim(
                    claim,
                    db_path=Path(_outcome_db),
                    target_path=config.target_path,
                )
                if vr.smt_pruned and tier_counters:
                    # Vacuous-checker matches killed mechanically —
                    # counted whether or not other matches survived.
                    for _ in range(vr.smt_pruned):
                        _increment_tier_dict(
                            tier_counters, "codeql_smt_prune", "refuted",
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
            if smt_result.disproved is False:
                if _premise_blocks_confirm(premise_h, ["smt:disproof:sat"]):
                    _note_premise_blocked_validation(
                        outcome, premise_h, ["smt:disproof:sat"],
                        config, tier_counters,
                    )
                else:
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
    evidence_index: dict[str, EvidenceRecord] | None = None,
    _joern_server=None,
) -> str | None:
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
    evidence_index: dict[str, EvidenceRecord] | None = None,
    dispatched_tools: set | None = None,
    tier_counters: dict[str, TierCounters] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
    flow_traces: list[dict[str, Any]] | None = None,
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

    try:
        from .cwe_dispatch import (
            joern_applicable,
            sinks_for_cwe,
            smt_verb_for_cwe,
        )

        _has_cwe_dispatch = True
    except ImportError:
        _has_cwe_dispatch = False

    # Falls back to keyword inference over the hypothesis texts when
    # the review emitted an empty cwe (marked inferred in telemetry).
    cwe = _effective_cwe(outcome, tier_counters)

    if not cwe:
        return outcome

    dispatched = dispatched_tools or set()

    # Two evidence channels with different trust: outcome.evidence_tool
    # is pipeline-controlled (llm_review sanitizes LLM-supplied values
    # to llm-claimed:* before they land there; sweep/critique/dynamic
    # stamps are genuine) — a confirmed stamp there legitimately skips
    # re-validation. review["evidence_tool"] is the RAW LLM response:
    # a hallucinated "semgrep" must trigger validation, never bypass
    # it, so it is sanitized before any use. (Sanitizing the OUTCOME
    # value too was a regression: sanitize_llm_evidence_tool
    # namespaces unconditionally, so genuine stamps lost their
    # refutation-gate protection whenever the live sweep didn't
    # re-confirm.)
    outcome_et = outcome.evidence_tool or ""
    if _is_tool_confirmed(outcome_et):
        return outcome
    evidence_tool = _sanitize_llm_et(
        review.get("evidence_tool") or outcome_et,
    )

    confirmed_tools = []
    # Per-function dispatch record: which channels actually RAN here
    # (and which errored). Gate resolution's covered==ran check reads
    # these off the outcome — an installed-but-never-dispatched tool
    # must not count as class coverage.
    ran: set = set()
    errored: set = set()

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
            ran.add("smt")
            smt_result = run_smt_verb_direct(
                verb=smt_verb,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source_text,
                hypothesis=outcome.hypothesis or "",
                target_path=str(config.target_path),
            )
            if smt_result.outcome == "confirmed":
                confirmed_tools.append(f"smt:{smt_verb}")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "smt", "confirmed")
            elif smt_result.outcome == "refuted":
                if tier_counters:
                    _increment_tier_dict(tier_counters, "smt", "refuted")
            else:
                # inconclusive / error — count separately so the
                # diagnostics don't overstate SMT's refutation power.
                if smt_result.outcome == "error":
                    errored.add("smt")
                if tier_counters:
                    _increment_tier_dict(
                        tier_counters, "smt",
                        "errors" if smt_result.outcome == "error"
                        else "inconclusive",
                    )
        except Exception:
            logger.debug("proactive SMT failed for %s", cwe, exc_info=True)
            errored.add("smt")
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
                ran.add("joern")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "confirmed")
                pre_hit = True

        if not pre_hit and sinks and joern_server is not None:
            ran.add("joern")
            _live_errors: list = []
            live_hits = _joern_live_query(
                joern_server,
                outcome.function,
                sinks,
                errors_out=_live_errors,
            )
            if live_hits:
                confirmed_tools.append("joern:live")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "confirmed")
            elif _live_errors:
                # Degraded query — unanswered, not refuted.
                logger.debug(
                    "cwe-dispatch joern error %s:%s: %s",
                    outcome.file, outcome.function, _live_errors,
                )
                errored.add("joern")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "joern", "errors")
            elif tier_counters:
                _increment_tier_dict(tier_counters, "joern", "refuted")

    _cwe_db = _codeql_db_for(config, outcome.file)
    if _has_cwe_dispatch and "codeql" not in dispatched and _cwe_db:
        sinks = sinks_for_cwe(cwe)
        if sinks:
            try:
                from .sweep import run_codeql_sweep

                for sink in sinks[:2]:
                    ran.add("codeql")
                    codeql_result = run_codeql_sweep(
                        target_path=config.target_path,
                        file_path=outcome.file,
                        function_name=outcome.function,
                        query_path=f"cwe-{cwe.lower()}-{sink}",
                        database_path=_cwe_db,
                        line_start=outcome.line,
                        line_end=outcome.line + 50 if outcome.line else 0,
                    )
                    if codeql_result.outcome == "confirmed":
                        confirmed_tools.append(f"codeql:{sink}")
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "codeql", "confirmed")
                        break
                    if codeql_result.outcome == "error":
                        errored.add("codeql")
                        if tier_counters:
                            _increment_tier_dict(tier_counters, "codeql", "errors")
                    elif tier_counters:
                        _increment_tier_dict(tier_counters, "codeql", "refuted")
            except Exception:
                logger.debug("proactive CodeQL failed for %s", cwe, exc_info=True)
                errored.add("codeql")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "codeql", "errors")

    is_c_target = outcome.file.endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"))
    if "coccinelle" not in dispatched and is_c_target:
        mechanism = review.get("mechanism") or ""
        cocci_rule = _hypothesis_to_cocci_check(mechanism) if mechanism else None
        if cocci_rule:
            try:
                ran.add("coccinelle")
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
                    errored.add("coccinelle")
                    if tier_counters:
                        _increment_tier_dict(tier_counters, "coccinelle", "errors")
                elif tier_counters:
                    _increment_tier_dict(tier_counters, "coccinelle", "refuted")
            except Exception:
                logger.debug("proactive Coccinelle failed for %s", cwe, exc_info=True)
                errored.add("coccinelle")
                if tier_counters:
                    _increment_tier_dict(tier_counters, "coccinelle", "errors")

    # Cross-function verification (Joern CPG): interprocedural checks
    # that intra-function SMT/Coccinelle can't reach.
    if joern_server is not None and "cross_function" not in dispatched:
        try:
            from .cross_function_verify import cross_function_verify
            ran.add("cross_function")
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
            errored.add("cross_function")
            if tier_counters:
                _increment_tier_dict(tier_counters, "joern_xf", "errors")

    # Attach the dispatch record before any status-changing return so
    # gate resolution can tell "ran and silent" from "never ran".
    if ran:
        outcome.tools_dispatched = (outcome.tools_dispatched or set()) | ran
    if errored:
        outcome.tools_errored = (outcome.tools_errored or set()) | errored

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
    cwe_mechanism_findings: dict[str, list[ReviewOutcome]] = {}

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
        try:
            synth = synthesize_and_sweep(
                exemplars[0],
                config,
                seen_keys,
                synthesis_count=synthesis_count,
            )
        except Exception as exc:
            from core.llm.client import LLMAuthPersistentError
            if isinstance(exc, LLMAuthPersistentError):
                # Dead credential: abort the PHASE, keep the RUN. An
                # uncaught escape here reaches the CLI's generic
                # failure path — lifecycle=failed, no report, the
                # whole main loop's paid findings unreported — which
                # is strictly worse than the fail-open this machinery
                # replaced.
                _record_phase_abort(config, result, exc)
                return
            raise
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

    # Completed without an auth abort (the abort path returns early):
    # supersede any stale sidecar record from a prior segment.
    _clear_phase_abort(config, "checker-synthesis", result=result)


def _run_critique(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    sarif_cache: SarifCache | None = None,
    joern_server=None,
) -> None:
    """Periodic tool-grounded re-evaluation of recent findings.

    Checks that findings still have valid tool evidence, and that
    suspicious items haven't gained new tool evidence since emission.
    Runs every critique_interval functions.
    """
    # Interrupted pre-sweep awareness (once per run): when the Joern
    # pre-sweep window was lost to a server restart, critique's
    # taint-tier evidence base is incomplete — absence of flows means
    # "not swept", not "no flows". Surface it on the critique cadence,
    # not just as a startup log line.
    if not getattr(config, "_presweep_loss_warned", False) and config.out_dir:
        try:
            from .joern_backend import load_presweep_status
            presweep = load_presweep_status(config.out_dir)
        except Exception:  # noqa: BLE001 — critique must not fail on bookkeeping
            presweep = None
        if presweep and not presweep.get("recovered"):
            logger.warning(
                "critique: Joern pre-sweep window was LOST to a server "
                "restart (%d re-queue attempt(s) failed) — taint-flow "
                "evidence for this run is incomplete; treating missing "
                "flows as 'not swept'",
                presweep.get("requeued", 0),
            )
        if presweep is not None:
            config._presweep_loss_warned = True

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
        cwe = _effective_cwe(outcome, result.tier_counters)
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
            cwe=cwe,
        )
        if confirmed:
            # Same promotion discipline as _promote_suspicious: only
            # verification-role evidence may lift suspicious→finding,
            # and a fully-guarded sink blocks it. Critique previously
            # promoted on ANY confirmation, letting detection-role
            # heuristics (e.g. smt:check-overflow-to-oob) mint findings
            # through the critique door that the front door refused.
            high_prec = [t for t in confirmed if not _is_detection_only(t)]
            if not high_prec:
                logger.info(
                    "critique promotion blocked %s:%s — only "
                    "detection-role rules (%s)",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue
            _gblk = _guard_blocks_promotion(
                outcome.function, joern_server, result.tier_counters)
            if _gblk:
                logger.info(
                    "critique promotion blocked %s:%s — sink-guard veto: %s",
                    outcome.file, outcome.function, _gblk,
                )
                continue
            tool = "+".join(high_prec)
            # _run_critique runs from concurrent review workers —
            # mutate outcomes/counters under the result lock (like
            # _tally_outcome) and skip outcomes another worker already
            # replaced, so a shared critique_interval boundary cannot
            # double-promote or lose counter updates.
            with result._lock:
                if outcome not in result.outcomes:
                    continue
                idx = result.outcomes.index(outcome)
                result.outcomes[idx] = _promote_outcome(
                    outcome, f"critique:{tool}",
                )
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


def _collect_reviews_until_budget(
    prepared: list,
    do_review: Callable,
    should_stop: Callable[[], bool],
    max_workers: int,
    *,
    phase_label: str,
) -> list:
    """Dispatch *prepared* re-review items, harvesting EVERY completed
    call even when the budget cap fires mid-flight.

    Shared driver for the re-review phases (deepen, disagreement,
    iterative, joern-enriched, study-enriched). Contract:

    - single worker: ``should_stop`` gates BEFORE each dispatch — a
      call that would breach the cap is simply never made;
    - parallel: results are harvested as futures complete, and the
      budget check runs AFTER each harvest. When it fires, futures
      still PENDING are cancelled (never dispatched, nothing spent),
      but every call already dispatched — completed or in flight — is
      collected and flows into the caller's booking/journal loop. The
      money is spent and the text is paid for; pre-fix the check ran
      before the harvest and ``break`` threw away completed-at/after-
      cap results ($10.25 of finished deepen re-reviews discarded,
      journal-less, in the final comparison audit).
    """
    if max_workers <= 1:
        collected = []
        for item in prepared:
            if should_stop():
                break
            collected.append(do_review(item))
        return collected

    from concurrent.futures import ThreadPoolExecutor, as_completed

    collected = []
    stopped = False
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_item = {}
        try:
            for item in prepared:
                future_to_item[pool.submit(do_review, item)] = item
        except RuntimeError:
            # Interpreter shutdown between the budget check and
            # dispatch: the run is tearing down while a background
            # consumer thread is still queueing re-reviews. Observed
            # live as an unhandled crash that hung the run after
            # results were written. Anything already dispatched is
            # still harvested below; the rest was never sent and
            # nothing was spent on it.
            logger.info(
                "%s: executor rejected dispatch (shutdown in "
                "progress) — %d re-review(s) skipped",
                phase_label, len(prepared) - len(future_to_item),
            )
        for fut in as_completed(future_to_item):
            # Harvest first: a future yielded here has finished (or
            # was cancelled while pending). Cancelled == never
            # dispatched — the only class that may be dropped.
            if not fut.cancelled():
                collected.append(fut.result())
            if stopped:
                continue
            if should_stop():
                stopped = True
                cancelled = sum(1 for f in future_to_item if f.cancel())
                if cancelled:
                    logger.info(
                        "%s: budget exhausted — %d pending re-review(s) "
                        "cancelled before dispatch; already-dispatched "
                        "calls are booked and journaled as they complete",
                        phase_label, cancelled,
                    )
    return collected


def _prior_hypotheses_for(outcome: ReviewOutcome) -> list[dict[str, Any]]:
    """Prior-pass hypothesis array for re-review context injection.

    Returns the preserved hypotheses (mechanism / confidence / counter
    dicts) so re-review prompts can render the 'previously considered'
    block instead of letting the model re-derive already-refuted
    mechanisms or re-litigate counters it has already written.
    """
    hyps = getattr(outcome, "hypotheses", None) or []
    if not hyps and outcome.review_result:
        hyps = outcome.review_result.get("hypotheses") or []
    return [
        h for h in hyps
        if isinstance(h, dict) and (h.get("mechanism") or "").strip()
    ]


def _deepen_suspicious(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    review_fn: Callable,
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    fuzz_coverage: dict[str, Any] | None,
    session_observations: list[dict[str, str]],
    sarif_cache: Any | None,
    entry_points: set,
    start_time: float,
    on_progress: Callable | None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    audit_log: list[dict[str, Any]] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
    joern_server=None,
    project_learnings: list[dict[str, str]] | None = None,
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
    # Reduced-context verdicts (timeout strip-retry) are re-reviewed
    # at full context regardless of status: a "clean" formed without
    # block analysis / sibling / type-constraint context is exactly
    # the verdict most likely to have missed something. Suspicious
    # reduced outcomes are already in the list above.
    _selected = {id(o) for o in suspicious}
    suspicious.extend(
        o
        for o in result.outcomes
        if o.context_reduced
        and o.status == "clean"
        and id(o) not in _selected
    )
    if not suspicious:
        return result

    seen_hypotheses: dict[str, str] = {}
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
        if (
            sloc < _MIN_SLOC_FOR_DEEPEN
            and not has_evidence
            and not o.context_reduced
        ):
            # Reduced-context outcomes bypass the SLOC gate: the
            # whole point of the tag is a guaranteed full-context
            # re-review.
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

        prior_hyps = _prior_hypotheses_for(prior_outcome)
        if prior_hyps:
            ctx["prior_hypotheses"] = prior_hyps

        ctx["deepen"] = True
        prepared.append((deepen_idx, prior_outcome, gap, ctx))

    def _do_review(item):
        idx, _prior, _gap, ctx = item
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:  # noqa: BLE001
            return (idx, None, exc)

    raw_results = _collect_reviews_until_budget(
        prepared,
        _do_review,
        lambda: _check_budget(config, start_time, result),
        effective_workers,
        phase_label="deepen",
    )

    # --- Process results (always in main thread) ---
    idx_to_prepared = {item[0]: item for item in prepared}
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, prior_outcome, gap, ctx = idx_to_prepared[idx]

        if exc is not None:
            from core.llm.client import is_budget_exceeded_error

            if is_budget_exceeded_error(exc):
                # Terminal — the client-aware _check_budget above stops
                # further dispatch; keep the prior verdict quietly
                # instead of one warning per already-dispatched item.
                logger.debug(
                    "deepen skipped for %s:%s: LLM budget exhausted",
                    gap["file"], gap["name"],
                )
                continue
            logger.warning(
                "deepen failed for %s:%s: %s",
                gap["file"],
                gap["name"],
                exc,
            )
            continue

        outcome.line = gap.get("line_start", 0)
        # Phase ledger: deepen calls cost money whether or not the new
        # verdict is accepted below — without this the spend appeared
        # in result.total_cost_usd (when accepted) but in no phase of
        # cost-breakdown.json, so the ledgers couldn't reconcile.
        result.cost_tracker.record_call(
            "re_review",
            cost_usd=outcome.cost_usd,
            wall_time_s=outcome.duration_s,
        )

        # Accept the deepen verdict when it's non-clean, OR when
        # the clean came from a structured demotion (all-refuted or
        # rationale-consistency) rather than a bare LLM flip-flop.
        # A reduced-context prior is never dominated: a full-context
        # clean genuinely supersedes a clean formed with stripped
        # context (and clears the context_reduced tag).
        _rr = outcome.review_result or {}
        _structured_demotion = bool(
            _rr.get("all_refuted_demotion")
            or _rr.get("rationale_consistency_demotion")
        )
        _referee_holds = _deepen_demotion_refereed(prior_outcome, outcome)
        _deepen_dominated = (
            outcome.status == "clean"
            and not prior_outcome.context_reduced
            and not _structured_demotion
        )

        if _referee_holds:
            # The rejected deepen call still spent real money.
            with result._lock:
                result.total_cost_usd += outcome.cost_usd
            if prior_outcome.review_result is None:
                prior_outcome.review_result = {}
            prior_outcome.review_result["demotion_referee"] = (
                "probe-backed suspicious retained — deepen refutation "
                "was LLM-only"
            )
            prior_outcome.body = (
                "[demotion referee: the deepen re-review concluded "
                "clean on LLM argument alone, but this suspicious is "
                "backed by a fired probe — retained pending a "
                "verification-role refuter]\n\n"
                + (prior_outcome.body or "")
            )
            logger.info(
                "deepen [%d/%d] %s:%s: demotion referee — stays "
                "suspicious (probe-backed; LLM-only refutation)",
                idx,
                len(targets),
                gap["file"],
                gap["name"],
            )
        elif _deepen_dominated:
            # The discarded deepen call still spent real money; the
            # accepted path books it via _tally_outcome below.
            with result._lock:
                result.total_cost_usd += outcome.cost_usd
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
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    evidence_index: dict[str, EvidenceRecord] | None,
    start_time: float,
    _on_progress: Callable | None,
    *,
    audit_log: list[dict[str, Any]] | None = None,
    session_observations: list[dict[str, str]] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
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
        except Exception as exc:  # noqa: BLE001
            return (idx, None, exc)

    raw_results = _collect_reviews_until_budget(
        prepared,
        _do_review,
        lambda: _check_budget(config, start_time, result),
        effective_workers,
        phase_label="disagreement re-review",
    )

    re_reviewed = 0
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, key, prior, _ctx = prepared[idx]

        if exc is not None:
            # exc was captured in the worker; exc_info=True here predates
            # the lint sweep and is kept as-is (behaviour-free sweep).
            logger.debug(
                "disagreement re-review failed for %s", key, exc_info=True,  # noqa: LOG014
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


def _gap_index(checklist: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build file:function → gap dict from checklist."""
    index: dict[str, dict[str, Any]] = {}
    for item in checklist.get("files", []):
        # Checklist file records carry "path" (see the inventory
        # builder and _find_gap_in_checklist) — not "file".
        file_path = item.get("path", item.get("file", ""))
        for func in item.get("items", item.get("functions", [])):
            key = f"{file_path}:{func.get('name', '')}"
            index[key] = {
                "file": file_path,
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
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    fuzz_coverage: dict[str, Any] | None,
    entry_points: set,
    constraints: list,
    prop_config: Any,
    sarif_cache: SarifCache | None,
    start_time: float,
    on_progress: Callable | None,
    evidence_index: dict[str, EvidenceRecord] | None = None,
    audit_log: list[dict[str, Any]] | None = None,
    session_observations: list[dict[str, str]] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
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
                prior_hyps = _prior_hypotheses_for(prior)
                if prior_hyps:
                    ctx["prior_hypotheses"] = prior_hyps
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
            except Exception as review_exc:  # noqa: BLE001
                return (idx, None, review_exc)

        raw_results = _collect_reviews_until_budget(
            prepared,
            _do_review,
            lambda: _check_budget(config, start_time, result),
            effective_workers,
            phase_label="iterative re-review",
        )

        # --- Process results in main thread ---
        idx_to_prepared = {item[0]: item for item in prepared}
        for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
            _, gap, ctx = idx_to_prepared[idx]

            if exc is not None:
                from core.llm.client import is_budget_exceeded_error

                if is_budget_exceeded_error(exc):
                    # Terminal — keep the original outcome; do not
                    # overwrite it with an error verdict the budget
                    # kill never earned.
                    logger.debug(
                        "re-review skipped for %s:%s: LLM budget exhausted",
                        gap["file"], gap["name"],
                    )
                    continue
                logger.warning(
                    "re-review failed for %s:%s: %s",
                    gap["file"],
                    gap["name"],
                    type(exc).__name__,
                )
                outcome = _error_outcome(gap, exc)

            outcome.line = gap.get("line_start", 0)
            # Phase ledger — see the deepen loop for the rationale.
            result.cost_tracker.record_call(
                "re_review",
                cost_usd=outcome.cost_usd,
                wall_time_s=outcome.duration_s,
            )

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
    findings: list[ReviewOutcome],
    config: OrchestratorConfig,
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    reviewed_outcomes: dict[str, ReviewOutcome],
) -> list[dict[str, Any]]:
    """Find functions to re-review based on findings from the previous pass.

    Returns a list of dicts with 'gap' (checklist item) and
    'callee_findings' (the findings that triggered re-review).
    """
    targets: dict[str, dict[str, Any]] = {}

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
    context_map: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Find 1-hop callers using the same logic as context._find_callers."""
    callers: list[dict[str, Any]] = []
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
    checklist: dict[str, Any],
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
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
            save_json(p2_path, classifications)
    except Exception:
        logger.debug("Phase 2 classification failed", exc_info=True)

    try:
        from .chain_detector import evaluate_chains, find_chain_candidates
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
                save_json(chains_path, chains)
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
    reviewed_outcomes: dict[str, ReviewOutcome],
    call_edge_index: dict[str, list] | None = None,
) -> list[dict[str, str]]:
    """Collect findings from 1-hop neighbours for chain context.

    Returns a list of dicts suitable for the ``chain_findings`` context
    section — callers and callees that were already reviewed and found
    vulnerable or suspicious.

    When *call_edge_index* is provided (built once at loop setup),
    only edges involving *fn_key* are examined instead of the full
    edge list.
    """
    edges = call_edge_index.get(fn_key, ()) if call_edge_index else call_edges
    chain: list[dict[str, str]] = []
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
            entry: dict[str, str] = {
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
    checklist: dict[str, Any],
    reviewed_outcomes: dict[str, ReviewOutcome] | None = None,
    finding_priority: float = 0.0,
    call_edge_index: dict[str, list] | None = None,
    checklist_index: dict[tuple, dict] | None = None,
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
            gap = dict(gap) if gap is not None else None
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
    """Reverse a previously tallied outcome's VERDICT counters.

    Cost is deliberately NOT reversed: deepen / re-review replace the
    outcome, but the original call's money was still spent. Subtracting
    it made ``result.total_cost_usd`` a "cost of surviving outcomes"
    number that drifted below both the phase ledger and the LLM
    client's ledger (observed $2.82 vs $4.52 vs $8.08 for one run) and
    under-enforced the --max-cost gate.
    """
    with result._lock:
        if outcome.status == "finding":
            result.findings -= 1
        elif outcome.status == "suspicious":
            result.suspicious -= 1
        elif outcome.status == "clean":
            result.clean -= 1
        elif outcome.status in {"dormant", "dark"}:
            result.dormant -= 1
        elif outcome.status == "error":
            result.errors -= 1
            if outcome.error_class and outcome.error_class in result.error_counts:
                result.error_counts[outcome.error_class] -= 1
        result.reviewed -= 1


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


_sink_guard_cache: dict[str, str] = {}


def _check_sink_guarded_cached(function_name: str, joern_server) -> str:
    """Cache-wrapped sink guard check to avoid redundant Joern queries.

    Only definitive verdicts ("guarded"/"unguarded"/no-tested-sink
    ``None``) are cached.  :data:`GUARD_UNAVAILABLE` is TRANSIENT
    (server restarting, query timeout) — caching it pinned a single
    flaky moment as the function's guard answer for the whole run,
    so a later consultation with a recovered server never got to
    correct it.
    """
    if function_name in _sink_guard_cache:
        return _sink_guard_cache[function_name]
    verdict = check_sink_guarded(function_name, joern_server)
    if verdict != GUARD_UNAVAILABLE:
        _sink_guard_cache[function_name] = verdict
    return verdict


def _guard_blocks_promotion(
    function_name: str,
    joern_server,
    tier_counters: dict | None = None,
) -> str | None:
    """Consult the guarded-sink veto for a promotion decision.

    Returns a block reason ("guarded" or "guard-unavailable") or None
    when the promotion may proceed.

    Fail-closed doctrine: when the run has a Joern lane but the veto
    consultation degraded (:data:`GUARD_UNAVAILABLE`), the promotion
    is BLOCKED, not waved through.  Pre-fix the degraded consultation
    read as "not guarded" and the promotion proceeded — the confirming
    joern:live receipt requires a healthy server while its only
    mechanical counter-evidence channel evaporated on a sick one, a
    nondeterministic verdict-integrity asymmetry (observed as trap
    flaps keyed to server state).  Runs without a Joern lane are
    unaffected (``None`` from the gate, promotion proceeds as before).
    """
    verdict = _check_sink_guarded_cached(function_name, joern_server)
    if verdict == "guarded":
        return "guarded"
    if verdict == GUARD_UNAVAILABLE:
        if tier_counters is not None:
            _increment_tier_dict(tier_counters, "joern_guard", "errors")
        return "guard-unavailable"
    return None


def _correlated_mech_detector_tool(
    outcome: ReviewOutcome,
    hypothesis: str,
    cwe: str,
    mechanical_findings: dict[str, list[dict[str, Any]]] | None,
) -> str | None:
    """Sweep-grade tool id from a prep-phase mechanical detector hit.

    The prep phase runs standing Coccinelle rules over every source
    file and keys position-anchored hits by ``file:function``
    (mechanical-findings.json). Those hits were previously injected
    only as LLM review context — a ``cocci:use_after_free`` match on
    the exact lines of an LLM-claimed UAF never counted as the
    tool-grounded evidence G2 demands, so the finding stayed
    suspicious while the sweep re-ran other tools from scratch.

    A hit qualifies as promotion evidence under the same discipline
    as a tool-chain confirmation: only standing cocci rules (their
    ``@role`` is checked — detection-role rules never promote) and
    only when the rule's family correlates with the hypothesis/CWE.
    Bespoke heuristic detectors (callback_lifetime, condition chain)
    stay review context.
    """
    if not mechanical_findings:
        return None
    hits = mechanical_findings.get(f"{outcome.file}:{outcome.function}") or []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        detector = hit.get("detector", "")
        if detector in ("flag_mode_deviation", "cleanup_deviation"):
            # Consistency comparator hits carry their rule-id on the
            # entry. Same discipline as cocci hits: detection-role
            # rule-ids (-majority variants) never promote — they stay
            # review context / aggregation members. Correlation: the
            # hypothesis names the deviant callee, or the CWE matches.
            rule = hit.get("rule_id") or ""
            callee = hit.get("callee") or ""
            if not rule or _is_detection_only(rule):
                continue
            from .consistency_verify import consistency_applicable
            named = bool(callee) and callee in (hypothesis or "")
            if named or consistency_applicable(cwe) \
                    or (hit.get("cwe") and hit["cwe"] == cwe):
                return rule
            continue
        if not detector.startswith("cocci:"):
            continue
        stem = detector.split(":", 1)[1]
        tool_id = f"coccinelle:{stem}"
        if _is_detection_only(tool_id):
            continue
        if evidence_matches_hypothesis(family_for_rule(stem), hypothesis, cwe):
            return tool_id
    return None


# Design-pattern CWEs: a structural match asserts a code SHAPE
# (comparison style, API misuse pattern), not attacker-reachable data.
# A synthesized-checker receipt for one of these may promote only with
# a trust-boundary/taint receipt from the run's context map.
_DESIGN_PATTERN_CWES = frozenset({"CWE-697", "CWE-595", "CWE-486", "CWE-480"})

_TRUST_BOUNDARY_KEYS_CACHE: dict[str, frozenset] = {}


def _function_on_trust_boundary(
    outcome: ReviewOutcome, config: OrchestratorConfig,
) -> bool:
    """Does the run's context map place this function on a trust
    boundary (entry point or trust-boundary member)?"""
    out_dir = getattr(config, "out_dir", None)
    if not out_dir:
        return False
    cache_key = str(out_dir)
    keys = _TRUST_BOUNDARY_KEYS_CACHE.get(cache_key)
    if keys is None:
        try:
            context_map = load_context_map(Path(out_dir))
        except OSError:
            context_map = None
        keys = frozenset(
            extract_context_map_set(context_map, "entry_points")
            | extract_context_map_set(
                context_map, "trust_boundaries", nested_key="functions",
            ),
        )
        _TRUST_BOUNDARY_KEYS_CACHE[cache_key] = keys
    return f"{outcome.file}:{outcome.function}" in keys


def _synth_receipt_promotion_block_reason(
    tool_id: str,
    outcome: ReviewOutcome,
    cwe: str,
    config: OrchestratorConfig,
) -> str:
    """Why a synthesized-checker receipt may not promote this outcome
    ('' when it may).

    Two gates: (1) self-match exclusion — a rule synthesized from this
    function's own shape is a circular oracle on it; (2) design-pattern
    CWEs need a trust-boundary/taint receipt — the pattern match
    asserts a shape, not attacker-reachable data.
    """
    if ":synth-" not in (tool_id or ""):
        return ""
    from .checker_synthesis import is_self_match_synth_receipt
    if is_self_match_synth_receipt(tool_id, outcome.file, outcome.function):
        return "self-match: rule synthesized from this function's own shape"
    if (cwe or "").upper().strip() in _DESIGN_PATTERN_CWES:
        if outcome.provenance_all_trusted:
            return "design-pattern CWE with all-trusted provenance"
        if not _function_on_trust_boundary(outcome, config):
            return (
                "design-pattern CWE without a trust-boundary receipt "
                "from the context map"
            )
    return ""


def _promote_suspicious(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    sarif_cache: SarifCache | None = None,
    checklist: dict[str, Any] | None = None,
    joern_server=None,
    mechanical_findings: dict[str, list[dict[str, Any]]] | None = None,
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

        refuting_counter = _has_refuting_counter(outcome)

        # Premise binding for the primary hypothesis, same rule as the
        # secondary sweep below: a function-local confirm cannot
        # adjudicate a counter that rests on a cross-function premise
        # — it re-proves the lexical shape the reviewer already saw
        # and weighed. Blocked promotions stay suspicious and park the
        # premise on the reading list.
        premise_h = _primary_hypothesis_entry(outcome, hypothesis)

        gap = _find_gap_in_checklist(checklist or {}, outcome.file, outcome.function)
        line_end = gap.get("line_end") if gap else None

        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )

        cwe = _effective_cwe(outcome, result.tier_counters)

        if refuting_counter:
            if _hypothesis_to_tool_chain(hypothesis, outcome.file, cwe=cwe):
                logger.debug(
                    "sweep skipped %s:%s — LLM counter-hypothesis present",
                    outcome.file,
                    outcome.function,
                )
                continue
            # Empty-dispatch family: no static channel exists that
            # could adjudicate this hypothesis OR its counter, so the
            # only possible mechanical evidence is a synthesized
            # checker (full dual controls + guarded-sink gate apply
            # inside). Route the family to on-demand synthesis instead
            # of letting it die unverified.
            _synthesize_unmapped_suspicious(
                result, config, i, outcome,
                _synthesis_hypothesis_for_cwe(outcome, cwe, hypothesis),
                cwe, source,
                joern_server=joern_server,
            )
            continue

        mech_tool = _correlated_mech_detector_tool(
            outcome, hypothesis, cwe, mechanical_findings,
        )
        if mech_tool:
            _gblk = _guard_blocks_promotion(
                outcome.function, joern_server, result.tier_counters)
            if _gblk:
                logger.info(
                    "sweep promotion blocked %s:%s via %s — sink-guard veto: %s",
                    outcome.file,
                    outcome.function,
                    mech_tool,
                    _gblk,
                )
            elif _premise_blocks_confirm(premise_h, [mech_tool]):
                _note_premise_blocked_validation(
                    outcome, premise_h, [mech_tool],
                    config, result.tier_counters,
                    lane="sweep promotion", tier="primary_sweep",
                )
            else:
                result.outcomes[i] = _promote_outcome(outcome, mech_tool)
                result.sweep_promoted += 1
                result.suspicious -= 1
                result.findings += 1
                logger.info(
                    "sweep promoted %s:%s via %s (prep-phase detector hit)",
                    outcome.file,
                    outcome.function,
                    mech_tool,
                )
                continue

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
            # Promotion needs evidence in the hypothesis's family; an
            # unrelated pattern hit stays context and falls through to
            # the hypothesis-specific tool chain.
            correlated = [
                h for h in pf.hits
                if evidence_matches_hypothesis(
                    family_for_rule(h.rule_id), hypothesis, cwe,
                )
            ]
            if correlated:
                tool = f"prefilter:{correlated[0].rule_id}"
                if _premise_blocks_confirm(premise_h, [tool]):
                    _note_premise_blocked_validation(
                        outcome, premise_h, [tool],
                        config, result.tier_counters,
                        lane="sweep promotion", tier="primary_sweep",
                    )
                else:
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
            if pf.hits and not correlated:
                _record_uncorrelated_hits(outcome, pf.hits)
                logger.info(
                    "sweep promotion withheld %s:%s — prefilter hits (%s) "
                    "uncorrelated with hypothesis",
                    outcome.file,
                    outcome.function,
                    ",".join(h.rule_id for h in pf.hits[:3]),
                )

        chain = _hypothesis_to_tool_chain(hypothesis, outcome.file, cwe=cwe)
        if not chain:
            # No CWE dispatch entry and no cheap channel binds this
            # hypothesis — the static dispatch table has nothing to
            # test it with. On-demand Mode-2 synthesis generates a
            # one-off, negatively-controlled rule instead of letting
            # the hypothesis die untested.
            _synthesize_unmapped_suspicious(
                result, config, i, outcome,
                _synthesis_hypothesis_for_cwe(outcome, cwe, hypothesis),
                cwe, source,
                joern_server=joern_server,
            )
            continue
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
            cwe=cwe,
        )

        if confirmed:
            _synth_blocked = {
                t: reason for t in confirmed
                if (reason := _synth_receipt_promotion_block_reason(
                    t, outcome, cwe, config,
                ))
            }
            if _synth_blocked:
                for _t, _reason in _synth_blocked.items():
                    logger.info(
                        "sweep promotion: synth receipt %s excluded for "
                        "%s:%s — %s",
                        _t, outcome.file, outcome.function, _reason,
                    )
                confirmed = [t for t in confirmed if t not in _synth_blocked]
                if not confirmed:
                    _increment_tier_dict(
                        result.tier_counters, "adapter_aggregation",
                        "inconclusive",
                    )
                    continue
            if _premise_blocks_confirm(premise_h, confirmed):
                _note_premise_blocked_validation(
                    outcome, premise_h, list(confirmed),
                    config, result.tier_counters,
                    lane="sweep promotion", tier="primary_sweep",
                )
                continue
            high_prec = [
                t for t in confirmed
                if not _is_detection_only(t)
            ]
            if not high_prec:
                # Bayesian multi-channel aggregation: independent
                # detection-role channels agreeing on the hypothesis
                # can jointly cross the promote threshold even though
                # no single receipt is perfect.
                agg_channels, post_mean = _aggregate_channel_confirmations(
                    confirmed,
                )
                if agg_channels and not _guard_blocks_promotion(
                        outcome.function, joern_server,
                        result.tier_counters):
                    tool = "+".join(confirmed)
                    promoted = _promote_outcome(outcome, tool)
                    _record_aggregated_promotion(
                        promoted, agg_channels, post_mean, confirmed,
                    )
                    result.outcomes[i] = promoted
                    result.sweep_promoted += 1
                    result.aggregation_promoted += 1
                    result.suspicious -= 1
                    result.findings += 1
                    _increment_tier_dict(
                        result.tier_counters, "adapter_aggregation",
                        "confirmed",
                    )
                    logger.info(
                        "sweep promoted %s:%s via aggregated channels %s "
                        "(posterior %.2f > %.2f)",
                        outcome.file, outcome.function,
                        "+".join(agg_channels), post_mean,
                        _AGGREGATION_CONFIRM_THRESHOLD,
                    )
                    continue
                _increment_tier_dict(
                    result.tier_counters, "adapter_aggregation",
                    "inconclusive",
                )
                logger.info(
                    "sweep promotion blocked %s:%s — only detection-role "
                    "rules (%s)",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue
            _gblk = _guard_blocks_promotion(
                outcome.function, joern_server, result.tier_counters)
            if _gblk:
                logger.info(
                    "sweep promotion blocked %s:%s via %s — sink-guard veto: %s",
                    outcome.file,
                    outcome.function,
                    "+".join(confirmed),
                    _gblk,
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


def _record_synthesis_refusal(
    config: OrchestratorConfig,
    outcome: ReviewOutcome,
    cwe: str,
    refusal: str,
) -> None:
    """Persist a synthesis-policy refusal to ``suppressions.jsonl``.

    ``dropped=False`` — the outcome survives at suspicious grade; the
    record exists so an operator can tell policy-capped from ordinary
    suspicious after the run (the pre-sweep journal entry cannot carry
    it, and re-journal fires only on status change). Same single-writer
    shape as the oracle-triage skip trail; readers tolerate extra keys.
    """
    out_dir = getattr(config, "out_dir", None)
    if not out_dir:
        return
    try:
        from core.analysis.reach_chokepoint import record_suppression
    except ImportError:
        return
    key = f"{outcome.file}:{outcome.function}"
    record_suppression(
        Path(out_dir),
        finding={
            "finding_id": f"audit-synthesis-policy:{key}:{outcome.line or 0}",
            "rule_id": "audit:synthesis-policy",
            "file_path": outcome.file,
            "line": outcome.line or 0,
            "function": outcome.function,
        },
        verdict="synthesis_policy_refused",
        reason=refusal,
        dropped=False,
        extra={
            "stage": "on-demand-synthesis",
            "cwe": cwe or "",
            "status": outcome.status,
        },
    )


def _synthesis_hypothesis_for_cwe(
    outcome: ReviewOutcome,
    cwe: str,
    primary: str,
) -> str:
    """The hypothesis text that actually carries *cwe*, for synthesis.

    ``_effective_cwe`` may INFER the class from a non-primary
    hypothesis (first inferable mechanism wins), while the synthesis
    call sites pass the PRIMARY hypothesis string — pairing a checker
    seed CWE with prose that states a different (or no) mechanism.
    The long instrumented run synthesized a CWE-778 checker whose
    promotion logged the no-harm sibling's text, reading as an
    inverted promotion. Re-pair only when the class was inferred; a
    review-DECLARED CWE belongs to the review's primary hypothesis.
    """
    review = outcome.review_result or {}
    if not cwe or review.get("cwe_inferred") != cwe:
        return primary
    try:
        from .cwe_dispatch import infer_cwe_from_hypothesis
    except ImportError:
        return primary
    if primary and infer_cwe_from_hypothesis(primary) == cwe:
        return primary
    for h in outcome.hypotheses or review.get("hypotheses") or []:
        if not isinstance(h, dict):
            continue
        mechanism = h.get("mechanism") or ""
        if mechanism and infer_cwe_from_hypothesis(mechanism) == cwe:
            return mechanism
    return primary


def _synthesize_unmapped_suspicious(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    i: int,
    outcome: ReviewOutcome,
    hypothesis: str,
    cwe: str,
    source: str,
    joern_server=None,
) -> None:
    """On-demand Mode-2 synthesis for a chain-less suspicious hypothesis.

    Called by ``_promote_suspicious`` when ``_hypothesis_to_tool_chain``
    came back empty: no CWE dispatch entry exists and no cheap channel
    binds the hypothesis, so the static tool menu cannot verify it.
    Synthesizes a one-off rule from the hypothesis + function source
    (standard synthesis controls apply: positive control against the
    suspect function, dual control against generated fixtures) and
    treats a confirmation like any synthesized-checker receipt —
    promote suspicious → finding with the ``<engine>:synth-<id>`` stamp.

    Bounds: opt-out via ``config.on_demand_synthesis``; per-run attempt
    cap ``MAX_ONDEMAND_SYNTHESIS_PER_RUN``; suspicious/finding
    candidates only (enforced again in the helper — never clean).
    Every attempt is counted in tier telemetry under
    ``synthesis_on_demand``.
    """
    if not getattr(config, "on_demand_synthesis", True):
        return
    try:
        from .checker_synthesis import ondemand_synthesis_refusal_reason
    except ImportError:
        pass
    else:
        refusal = ondemand_synthesis_refusal_reason(
            cwe, hypothesis, outcome.review_result,
        )
        if refusal:
            # Policy parking, never silent: the durable surface is a
            # suppressions.jsonl record (dropped=false — the outcome
            # SURVIVES at suspicious grade; same shape as the
            # oracle-triage skip trail, /review surfaces it), plus the
            # tier-telemetry skip counter and this log line. The
            # in-memory review_result stamp additionally reaches any
            # consumer that serializes the outcome after the sweep
            # (checkpoints, corpus grader) — but the journal entry was
            # already written pre-sweep, so it is NOT the record of
            # this refusal.
            if outcome.review_result is not None:
                outcome.review_result["synthesis_refused"] = refusal
            _record_synthesis_refusal(config, outcome, cwe, refusal)
            _increment_tier_dict(
                result.tier_counters, "synthesis_on_demand", "skipped",
            )
            logger.info(
                "on-demand synthesis refused %s:%s — %s "
                "(outcome stays %s)",
                outcome.file, outcome.function, refusal, outcome.status,
            )
            return
    try:
        from .checker_synthesis import synthesize_verification_rule

        synth = synthesize_verification_rule(
            outcome,
            config,
            cwe=cwe,
            source_snippet=source,
            synthesis_count=result.ondemand_synthesized,
        )
    except Exception:
        logger.debug(
            "on-demand synthesis failed for %s:%s",
            outcome.file, outcome.function, exc_info=True,
        )
        _increment_tier_dict(
            result.tier_counters, "synthesis_on_demand", "errors",
        )
        return
    if synth is None:
        # Cap reached / ineligible / no LLM — nothing was attempted.
        return

    result.ondemand_synthesized += 1
    if synth.cost_usd:
        result.cost_tracker.record_call(
            "checker_synthesis_ondemand", cost_usd=synth.cost_usd,
        )
        result.total_cost_usd += synth.cost_usd

    if not synth.confirmed or not synth.stamp:
        _increment_tier_dict(
            result.tier_counters, "synthesis_on_demand", "inconclusive",
        )
        return
    _block = _synth_receipt_promotion_block_reason(
        synth.stamp, outcome, cwe, config,
    )
    if _block:
        # The rule survives (library persistence + variant sweeps on
        # OTHER functions); it just may not convict its own seed.
        _increment_tier_dict(
            result.tier_counters, "synthesis_on_demand", "inconclusive",
        )
        if outcome.review_result is not None:
            outcome.review_result["ondemand_synth_receipt"] = synth.stamp
            outcome.review_result["ondemand_synth_blocked"] = _block
        logger.info(
            "on-demand synthesis promotion blocked %s:%s via %s — %s",
            outcome.file, outcome.function, synth.stamp, _block,
        )
        return
    _gblk = _guard_blocks_promotion(
        outcome.function, joern_server, result.tier_counters)
    if _gblk:
        _increment_tier_dict(
            result.tier_counters, "synthesis_on_demand", "inconclusive",
        )
        logger.info(
            "on-demand synthesis promotion blocked %s:%s via %s — "
            "sink-guard veto: %s",
            outcome.file, outcome.function, synth.stamp, _gblk,
        )
        return
    _premise_h = _primary_hypothesis_entry(outcome, hypothesis)
    if _premise_blocks_confirm(_premise_h, [synth.stamp]):
        _increment_tier_dict(
            result.tier_counters, "synthesis_on_demand", "inconclusive",
        )
        _note_premise_blocked_validation(
            outcome, _premise_h, [synth.stamp],
            config, result.tier_counters,
            lane="on-demand synthesis promotion", tier="primary_sweep",
        )
        return

    _increment_tier_dict(
        result.tier_counters, "synthesis_on_demand", "confirmed",
    )
    result.outcomes[i] = _promote_outcome(outcome, synth.stamp)
    result.sweep_promoted += 1
    result.suspicious -= 1
    result.findings += 1
    logger.info(
        "on-demand synthesized checker confirmed %s:%s via %s — "
        "promoted suspicious → finding (hypothesis: %s)",
        outcome.file, outcome.function, synth.stamp, hypothesis[:120],
    )


# Load-bearing precondition check types: promotion requires at least one
# of these among the SUPPORTED checks. Regex absence of a sanitizer or
# bounds check alone does not prove the calling context is hostile —
# attacker reachability or a sink in the function body must also verify.
_LOAD_BEARING_PRECONDITIONS = frozenset({
    "attacker_controls_input",
    "function_reaches_sink",
})

# Bound the mechanical work per function: at most this many stated
# preconditions are checked (schema order preserved — the LLM states
# load-bearing assumptions first).
_MAX_PRECONDITION_CHECKS_PER_FN = 6


def _promote_suspicious_preconditions(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    context_map: dict[str, Any] | None = None,
) -> None:
    """Post-loop pass: verify LLM-stated preconditions on suspicious outcomes.

    "Suspicious" means "real bug, not proven exploitable in the current
    calling context". The review schema already collects mechanically
    testable preconditions, and the checking machinery already runs for
    findings — but only to demote on contradiction; SUPPORTED results
    were discarded. This pass runs the same checks on suspicious
    outcomes and uses the positive direction:

    - ALL stated preconditions verify in the vulnerability-supporting
      direction AND at least one load-bearing check
      (attacker_controls_input / function_reaches_sink) is among them
      AND at least one load-bearing supported check carries a
      TOOL-GROUNDED receipt (``grade == "structural"``: a call-shaped
      sink match on the sanitized source view) → promote suspicious →
      finding with a distinct precondition receipt recording which
      checks ran.
    - Partial support stays suspicious; the per-check results are
      recorded on the review result for the report and export layers.

    The receipt-tier requirement is what keeps this floor
    inside the "tool output is the verdict" doctrine: the LLM controls
    the check list, absence-supported arms are "no pattern found" (not
    a positive receipt), and attacker_controls_input corroborates via
    LLM-authored entry points — none of those may anchor the mint.
    Only the structural sink receipt is a mechanical fact about the
    code, so promotion requires it.

    No LLM calls — purely mechanical (regex + context-map reachability).
    Bounded per function via ``_MAX_PRECONDITION_CHECKS_PER_FN``;
    dispatches are counted in tier telemetry under
    ``precondition_promotion``.
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
            continue

        review = outcome.review_result or {}
        preconditions = [
            p for p in (review.get("preconditions") or [])
            if isinstance(p, dict) and p.get("check_type")
        ]
        if not preconditions:
            continue
        preconditions = preconditions[:_MAX_PRECONDITION_CHECKS_PER_FN]

        try:
            from .precondition_check import verify_preconditions

            verdict = verify_preconditions(
                preconditions,
                target_path=config.target_path,
                context_map=context_map,
            )
        except Exception:
            logger.debug(
                "precondition promotion check failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue

        checks = verdict.checks
        if not checks:
            continue

        # Record the per-check results regardless of the aggregate —
        # partial support is review money already spent; keep it.
        review["precondition_verification"] = {
            "checks": [
                {
                    "check_type": c.check_type,
                    "assumption": c.assumption,
                    "verdict": c.verdict,
                    "evidence": c.evidence,
                    "grade": getattr(c, "grade", ""),
                }
                for c in checks
            ],
            "all_supported": verdict.all_supported,
        }

        if verdict.any_contradicted:
            _increment_tier_dict(
                result.tier_counters, "precondition_promotion", "refuted",
            )
            continue

        supported_types = verdict.supported_types
        if not verdict.all_supported:
            _increment_tier_dict(
                result.tier_counters, "precondition_promotion",
                "inconclusive",
            )
            continue
        if not (supported_types & _LOAD_BEARING_PRECONDITIONS):
            _increment_tier_dict(
                result.tier_counters, "precondition_promotion",
                "inconclusive",
            )
            logger.debug(
                "precondition promotion withheld %s:%s — all supported "
                "but no load-bearing check among %s",
                outcome.file, outcome.function,
                ",".join(sorted(supported_types)),
            )
            continue

        # Receipt-tier floor: the load-bearing anchor must
        # be tool-grounded. Absence-supported arms and context-map
        # reachability (LLM-authored entry points) corroborate but
        # never anchor.
        from .precondition_check import GRADE_STRUCTURAL

        structural_anchor = any(
            c.verdict == "supported"
            and c.check_type in _LOAD_BEARING_PRECONDITIONS
            and getattr(c, "grade", "") == GRADE_STRUCTURAL
            for c in checks
        )
        if not structural_anchor:
            _increment_tier_dict(
                result.tier_counters, "precondition_promotion",
                "inconclusive",
            )
            logger.debug(
                "precondition promotion withheld %s:%s — no "
                "tool-grounded load-bearing receipt (grades: %s)",
                outcome.file, outcome.function,
                ",".join(
                    f"{c.check_type}={getattr(c, 'grade', '') or '-'}"
                    for c in checks if c.verdict == "supported"
                ),
            )
            continue

        tool = "precondition:" + ",".join(sorted(supported_types))
        summary = "; ".join(
            f"{c.check_type}: {c.evidence or c.assumption}" for c in checks
        )
        promoted = ReviewOutcome(
            file=outcome.file,
            function=outcome.function,
            status="finding",
            body=(
                f"[precondition-verified via {tool}] All {len(checks)} "
                f"stated precondition(s) verified in the "
                f"vulnerability-supporting direction: {summary}\n\n"
                f"{outcome.body}"
            ),
            hypothesis=outcome.hypothesis,
            hypotheses=outcome.hypotheses,
            evidence_tool=tool,
            cost_usd=outcome.cost_usd,
            model=outcome.model,
            duration_s=outcome.duration_s,
            review_result=outcome.review_result,
            line=outcome.line,
        )
        promoted.tools_dispatched = (
            (outcome.tools_dispatched or set()) | {"precondition"}
        )
        promoted.tools_errored = outcome.tools_errored
        promoted.semantic_confidence = outcome.semantic_confidence
        if promoted.review_result is not None:
            promoted.review_result["evidence_tool"] = tool
        result.outcomes[i] = promoted
        result.precondition_promoted += 1
        result.sweep_promoted += 1
        result.suspicious -= 1
        result.findings += 1
        _increment_tier_dict(
            result.tier_counters, "precondition_promotion", "confirmed",
        )
        append_audit_log(config.out_dir, {
            "action": "precondition_verified_promotion",
            "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
            "file": outcome.file,
            "function": outcome.function,
            "status": "finding",
            "prior_status": "suspicious",
            "evidence_tool": tool,
            "checks": [
                {"check_type": c.check_type, "verdict": c.verdict}
                for c in checks
            ],
        })
        logger.info(
            "precondition-verified %s:%s — promoted suspicious → finding "
            "via %s",
            outcome.file, outcome.function, tool,
        )


# Conservative default threshold for Bayesian multi-channel
# aggregation at the promote decision. Against the uniform Beta(1,1)
# prior, one confirming channel gives posterior mean 2/3 (below the
# threshold — a single detection-role receipt still cannot promote),
# two independent channels give 3/4 (above). I.e. two independent
# medium-confidence channels stand in for one perfect receipt.
_AGGREGATION_CONFIRM_THRESHOLD = 0.7


def _aggregate_channel_confirmations(
    confirmed: list[str],
) -> tuple[list[str], float]:
    """Bayesian aggregation of detection-role confirmations.

    A single detection-role confirmation is too imprecise to promote
    without LLM agreement — but N INDEPENDENT channels agreeing on the
    same hypothesis is a different quantity of evidence, and the
    first-wins promote decision used to discard it. Each DISTINCT
    channel namespace (coccinelle, smt, ...) contributes one Bernoulli
    confirmation to a Beta(1,1) posterior via the shipped
    ``packages.hypothesis_validation.posterior`` machinery; same-engine
    receipts collapse to one observation (two detection rules from one
    engine are correlated, not independent).

    The caller is expected to have established that every entry in
    ``confirmed`` is detection-role (the high-precision receipts
    promote directly and never reach this path).

    Returns ``(channels, posterior_mean)`` — ``channels`` is the sorted
    distinct namespaces when the combined posterior mean crosses
    ``_AGGREGATION_CONFIRM_THRESHOLD``, else an empty list.
    """
    namespaces = sorted({
        t.split(":")[0] for t in confirmed if t
    })
    if len(namespaces) < 2:
        return [], 0.0
    try:
        from packages.hypothesis_validation.posterior import (
            UNIFORM_PRIOR,
            update,
            verdict_from_posterior,
        )
    except ImportError:
        return [], 0.0
    p = UNIFORM_PRIOR
    for _ns in namespaces:
        p = update(p, confirms=True)
    verdict = verdict_from_posterior(
        p, confirm_threshold=_AGGREGATION_CONFIRM_THRESHOLD,
    )
    if verdict == "confirmed":
        return namespaces, p.mean
    return [], p.mean


def _record_aggregated_promotion(
    outcome: ReviewOutcome,
    channels: list[str],
    posterior_mean: float,
    confirmed: list[str],
) -> None:
    """Stamp the aggregation receipt onto the review result."""
    if outcome.review_result is None:
        return
    outcome.review_result["aggregated_promotion"] = {
        "channels": channels,
        "posterior_mean": round(posterior_mean, 4),
        "threshold": _AGGREGATION_CONFIRM_THRESHOLD,
        "receipts": list(confirmed),
    }


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

    if tool_id.startswith("joern:"):
        # Bare taint reachability (joern:live / joern:pre_sweep)
        # proves a source→sink dataflow EXISTS, and nothing about the
        # hypothesis mechanism — the live query returns flows for a
        # correctly clamped memcpy wrapper (guards/clamps on the path
        # are invisible to reachableByFlows), so it corroborates via
        # aggregation and never convicts alone. Hypothesis-bound
        # reachability (joern:flow / joern:guard-dominance /
        # joern:taint:*) keeps verification role. The joern channel
        # module is the single authority for the split — the
        # evidence-grade firewall (is_tool_evidence) consults the
        # same classifier via _DETECTION_CLASSIFIER_MODULES.
        from core.audit.joern_verify import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("smt:"):
        verb = tool_id.split("smt:", 1)[1]
        from core.audit.sweep import get_smt_verb_role
        return get_smt_verb_role(verb) == "detection"

    if tool_id.startswith("fail_open:"):
        # Detection-variant rule-ids (naming-only / uncorroborated
        # role evidence) may not promote alone; they participate in
        # _aggregate_channel_confirmations like other detection-role
        # channels. Registry-grade confirmations promote directly.
        from core.audit.fail_open_verify import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("consistency:"):
        # -majority variants (majority-only contract source) are
        # detection-role: a statistical prior corroborates, it does
        # not convict. Registry-grade contract-witness confirmations
        # promote directly. All consistency dimensions share ONE
        # namespace, so two of them can never satisfy the two-
        # independent-namespaces aggregation rule by themselves.
        # (The ptr_lifecycle field-parity leg emits under this
        # namespace by construction — the same rule applies to it
        # with zero extra code.)
        from core.audit.peer_evidence import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("ptr_lifecycle:"):
        # -naming variants (naming-stem event vocabulary / degraded
        # census) may not promote alone; registry-grade stale-alias
        # confirmations promote directly (the fail_open pattern).
        from core.audit.ptr_lifecycle import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("lock_region:"):
        # -naming variants (naming-stem lock pair / internal-only
        # setter) may not promote alone; registry-grade confirmations
        # promote through the both-escalators status rule.
        from core.audit.lock_region import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("resource_bounds:"):
        # -naming variants (seed-only vocabulary or unknown
        # reachability) may not promote alone; registry-grade
        # confirmations promote directly.
        from core.audit.resource_bounds import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("release_order:"):
        # -naming variants (seed-exemplar-only verify/release pairing)
        # may not promote alone; learned-pair confirmations promote
        # directly.
        from core.audit.release_order import is_detection_rule_id
        return is_detection_rule_id(tool_id)

    if tool_id.startswith("protocol_state:"):
        # The two lead rule-ids (dead-state-field /
        # unvalidated-peer-write) are PERMANENTLY detection-grade, and
        # -unreceipted invariant confirmations carry an uncorroborated
        # premise — none may promote alone. Only the study-receipted
        # invariant-violated rule promotes directly.
        from core.audit.protocol_state import is_detection_rule_id
        return is_detection_rule_id(tool_id)

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


# Cheap mechanical channels eligible for refuted-hypothesis
# re-verification.  Joern/CodeQL are excluded for confidently-refuted
# hypotheses: a CPG query or database sweep costs orders of magnitude
# more than a semgrep/SMT/coccinelle/compiler dispatch, and the
# refuted class is a demoted-priority queue, not a zero-priority one.
_REFUTED_CHEAP_CHANNELS = frozenset({
    "semgrep", "smt", "coccinelle", "coccinelle_flow", "compiler",
    "fail_open", "consistency", "ptr_lifecycle", "lock_region",
    "resource_bounds", "release_order", "protocol_state",
})

# Bound the extra tool work per function: at most this many hypotheses
# are dispatched, ranked by mechanism specificity. SHARED budget across
# the hypothesis dispatch lanes — the refuted lane
# (_promote_clean_refuted, clean outcomes) and the secondary lane
# (_dispatch_secondary_hypotheses, finding/suspicious outcomes). The
# statuses are disjoint, so a function never exceeds this many extra
# dispatches in total.
_MAX_REFUTED_DISPATCHES_PER_FN = 3

_IDENTIFIER_TOKEN_RE = re.compile(r"\b\w+_\w+\b|\b[A-Za-z_]\w*\(")
_CWE_TAG_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_LINE_REF_RE = re.compile(r"\bline\s+\d+|\b\d{2,}\b")


def _mechanism_specificity(mechanism: str) -> int:
    """Rank how mechanically testable a hypothesis mechanism is.

    Named identifiers, call sites, CWE tags, and line references make a
    mechanism concrete enough for a tool sweep; generic prose does not.
    Used only for ORDERING under the per-function dispatch cap — the
    absolute value carries no meaning.
    """
    if not mechanism:
        return 0
    score = min(len(mechanism), 200) // 20
    score += 4 * min(len(_IDENTIFIER_TOKEN_RE.findall(mechanism)), 5)
    if _CWE_TAG_RE.search(mechanism):
        score += 3
    if _LINE_REF_RE.search(mechanism):
        score += 2
    return score


def _refutation_is_high_confidence(h: dict[str, Any]) -> bool:
    """True when the self-refutation carries a substantive counter.

    A refuted hypothesis with a specific, non-dismissive counter-argument
    is a considered retraction — the cheap channels still get to test it,
    but the expensive Joern/CodeQL channels are skipped. A refutation
    with no counter (or a dismissive one-liner) is a weak retraction and
    keeps the full chain.
    """
    counter = (h.get("counter") or "").strip()
    if len(counter) < 20:
        return False
    lower = counter.lower()
    return not any(d in lower for d in _DISMISSIVE_COUNTERS)


# Tool-id families whose engines model ONE function at a time — they
# cannot see caller guarantees, callee behaviour, or lock domains.
# Joern/CodeQL (whole-program CPG/database), consistency (peer set)
# and callsite_deviation (caller corpus) are cross-function-capable.
_FUNCTION_LOCAL_TOOL_FAMILIES = frozenset({
    "smt", "coccinelle", "coccinelle_flow", "semgrep", "compiler",
    "ptr_lifecycle", "resource_bounds", "lock_region", "release_order",
    "protocol_state", "fail_open", "prefilter",
})


def _tool_sees_cross_function(tool_id: str) -> bool:
    """True when the confirming tool models more than one function."""
    fam = (tool_id or "").split(":", 1)[0].strip().lower()
    return bool(fam) and fam not in _FUNCTION_LOCAL_TOOL_FAMILIES


# Fallback prose markers for a refutation resting on facts OUTSIDE the
# reviewed function (used only when the structured ``counter_scope``
# field is absent). Two shapes: explicit caller/callee-contract
# language, or a named symbol coupled with a guarantee verb.
_EXTERNAL_PREMISE_WORDS = (
    "caller", "callers", "call site", "call sites", "callee",
    "callees", "upstream", "api contract", "api guarantees",
    "contract guarantees", "before this function", "before calling",
    "grace period", "pre-validate", "pre-validates",
)
_GUARANTEE_VERBS = (
    "caps", "clamps", "pins", "pinned", "validates", "ensures",
    "guarantees", "prevents", "serialises", "serializes",
    "serialised", "serialized", "protected by", "held across",
    "bounded by", "never returns", "never exceeds", "cannot exceed",
    "re-points", "repoints",
)
_EXTERNAL_SYMBOL_RE = re.compile(r"\b[a-z][a-z0-9]*_[a-z0-9_]+\b")


def _refutation_scope_cross_function(h: dict[str, Any]) -> bool:
    """Does this hypothesis's refutation rest on a cross-function premise?

    Prefers the structured ``counter_scope`` field emitted by the
    review model at generation time; falls back to a structural prose
    check for responses predating the field.
    """
    scope = str(h.get("counter_scope") or "").strip().lower()
    if scope == "cross_function":
        return True
    if scope == "local":
        return False
    counter = (h.get("counter") or "").strip().lower()
    if len(counter) < 20:
        return False
    if any(w in counter for w in _EXTERNAL_PREMISE_WORDS):
        return True
    return (
        bool(_EXTERNAL_SYMBOL_RE.search(counter))
        and any(v in counter for v in _GUARANTEE_VERBS)
    )


def _premise_blocks_confirm(
    h: dict[str, Any],
    confirmed: list[str] | tuple[str, ...],
) -> bool:
    """Premise binding for refuted/countered-hypothesis re-verification.

    A SAT/pattern confirm from a function-local engine encodes none of
    the refutation's cross-function premise ("the caller validates the
    level", "that helper caps the length") — it re-proves the lexical
    shape the LLM already saw and refuted. Such a confirm grades
    inconclusive: it may override the refutation only when at least
    one confirming channel actually models beyond the function, or
    when the refutation itself is function-local (the engine CAN see
    it, so SAT genuinely contradicts it).
    """
    if not confirmed:
        return False
    if not _refutation_scope_cross_function(h):
        return False
    return not any(_tool_sees_cross_function(t) for t in confirmed)


def _queue_premise_study_question(
    config: OrchestratorConfig,
    outcome: ReviewOutcome,
    h: dict[str, Any],
) -> None:
    """Best-effort: park the refutation's cross-function premise on the
    reading list so the study loop can verify it with a receipt. A
    resolved premise re-enters review; an unverified one stays visible
    instead of being silently trusted or silently overridden."""
    try:
        import uuid

        from core.concepts.reading_list import ReadingList, ReadingListItem

        counter = (h.get("counter") or "").strip()
        if not counter or config.out_dir is None:
            return
        rl_path = config.out_dir / "reading-list.json"
        rl = ReadingList.load(rl_path)
        question = (
            f"Does this hold: {counter[:400]} "
            f"(refutation premise for {outcome.function})?"
        )
        if any(it.question == question for it in rl.items):
            return
        rl.queue(ReadingListItem(
            id=f"premise-{uuid.uuid4().hex[:12]}",
            question=question,
            source_command="/audit",
            source_file=outcome.file,
            source_function=outcome.function,
            priority="high",
            context=(h.get("mechanism") or "")[:200],
        ))
        rl.save(rl_path)
    except Exception:
        logger.debug("premise study-question queueing failed", exc_info=True)


def _primary_hypothesis_entry(
    outcome: ReviewOutcome,
    hypothesis: str,
) -> dict[str, Any]:
    """Structured hypothesis entry backing the resolved primary mechanism.

    ``_sweep_validate`` grades a finding against its primary hypothesis
    string; premise binding needs the structured entry that carries
    ``counter``/``counter_scope``. Matches on mechanism text, falling
    back to the highest-confidence entry. Returns ``{}`` when the
    review has no structured hypotheses — the premise gate then no-ops
    (there is no counter to weigh a confirm against).
    """
    hyps = getattr(outcome, "hypotheses", None) or []
    if not hyps and outcome.review_result:
        hyps = outcome.review_result.get("hypotheses") or []
    entries = [h for h in hyps if isinstance(h, dict)]
    if not entries:
        return {}
    head = (hypothesis or "").strip()[:120]
    if head:
        for h in entries:
            mech = (h.get("mechanism") or "").strip()
            if mech and (
                mech.startswith(head) or head.startswith(mech[:120])
            ):
                return h
    rank = {"high": 0, "medium": 1, "low": 2}
    return min(
        entries,
        key=lambda h: rank.get((h.get("confidence") or "").lower(), 3),
    )


def _note_premise_blocked_validation(
    outcome: ReviewOutcome,
    h: dict[str, Any],
    tools: list[str],
    config: OrchestratorConfig,
    tier_counters: dict[str, TierCounters] | None,
    *,
    lane: str = "finding validation",
    tier: str = "sweep_validate",
) -> None:
    """Receipt + study question for a premise-blocked primary confirm.

    Mirrors the secondary-sweep premise block: the confirmation is
    recorded for the export (it is real local evidence) but does not
    ground or promote the verdict, and the unconsumed cross-function
    premise is parked on the reading list for a study receipt.
    """
    if outcome.review_result is not None:
        outcome.review_result.setdefault(
            "premise_blocked_confirms", [],
        ).append({
            "mechanism": (h.get("mechanism") or "")[:200],
            "evidence_tool": "+".join(tools),
            "premise_blocked": True,
        })
    logger.info(
        "%s blocked %s:%s via %s — the counter rests "
        "on a cross-function premise no confirming channel models",
        lane, outcome.file, outcome.function, "+".join(tools),
    )
    if tier_counters is not None:
        _increment_tier_dict(tier_counters, tier, "premise_blocked")
    _queue_premise_study_question(config, outcome, h)


def _promote_clean_refuted(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: dict[str, Any] | None = None,
    joern_server=None,
) -> None:
    """Post-loop pass: mechanically verify refuted hypotheses on clean outcomes.

    The LLM refuting its own hypothesis is exactly the claim tool
    sweeps exist to test — self-refutation demotes PRIORITY, not
    eligibility. Two verification lanes per refuted hypothesis with a
    concrete mechanism (capped at ``_MAX_REFUTED_DISPATCHES_PER_FN``
    per function, ranked by mechanism specificity):

    1. SMT verification-role verb (the historical lane): a confirm is
       strong enough to promote clean → finding.
    2. Cheap-channel tool chain (semgrep/SMT/coccinelle/compiler; the
       expensive Joern/CodeQL channels are included only when the
       refutation is NOT high-confidence): a confirm on a self-refuted
       hypothesis is a strong signal but pattern channels alone don't
       mint findings — promote clean → suspicious with the tool
       receipt, surfaced distinctly (body marker, audit log, counter),
       never silently.

    Dispatches are counted in tier telemetry under ``refuted_sweep``.
    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "clean":
            continue

        hypotheses = getattr(outcome, "hypotheses", None) or []
        if not hypotheses and outcome.review_result:
            hypotheses = outcome.review_result.get("hypotheses") or []

        refuted = [
            h for h in hypotheses
            if isinstance(h, dict)
            and (h.get("confidence") or "").lower() == "refuted"
            and h.get("mechanism")
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

        cwe = _effective_cwe(outcome, result.tier_counters)

        ranked = sorted(
            refuted,
            key=lambda h: _mechanism_specificity(h.get("mechanism", "")),
            reverse=True,
        )[:_MAX_REFUTED_DISPATCHES_PER_FN]

        promoted = False
        for h in ranked:
            if promoted:
                break
            mechanism = h.get("mechanism", "")

            # ── Lane 1: SMT verification-role verb (historical) ────
            smt_verb = None
            if cwe:
                try:
                    from .cwe_dispatch import smt_verb_for_cwe
                    smt_verb = smt_verb_for_cwe(cwe)
                except ImportError:
                    pass
            if not smt_verb:
                smt_verb = _hypothesis_to_smt_verb(mechanism)

            from core.audit.sweep import get_smt_verb_role
            if smt_verb and get_smt_verb_role(smt_verb) == "detection":
                logger.debug(
                    "clean-refuted skipped %s:%s — %s is detection-role "
                    "(cannot override LLM clean)",
                    outcome.file, outcome.function, smt_verb,
                )
                smt_verb = None

            if smt_verb:
                # No per-callsite vacuous-verb list here: the vacuity
                # policy for check-overflow / check-oob /
                # check-overflow-to-oob lives in the sweep layer
                # (core.audit.sweep.VACUOUS_SMT_VERBS).  SAT without
                # source-level guard premises comes back "inconclusive",
                # so _run_tool_chain reports no confirmation and the
                # promotion below never fires on a vacuous result.
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
                _increment_tier_dict(
                    result.tier_counters, "refuted_sweep",
                    "confirmed" if confirmed else "inconclusive",
                )
                if confirmed:
                    if _premise_blocks_confirm(h, confirmed):
                        logger.info(
                            "clean-refuted promotion blocked %s:%s via %s "
                            "— the refutation rests on a cross-function "
                            "premise no confirming channel models "
                            "(confirm grades inconclusive)",
                            outcome.file, outcome.function,
                            "+".join(confirmed),
                        )
                        _increment_tier_dict(
                            result.tier_counters, "refuted_sweep",
                            "premise_blocked",
                        )
                        _queue_premise_study_question(config, outcome, h)
                        continue
                    _gblk = _guard_blocks_promotion(
                        outcome.function, joern_server,
                        result.tier_counters)
                    if _gblk:
                        logger.info(
                            "clean-refuted promotion blocked %s:%s via %s "
                            "— sink-guard veto: %s",
                            outcome.file, outcome.function,
                            "+".join(confirmed), _gblk,
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
                    promoted = True
                    continue

            # ── Lane 2: cheap-channel chain (new) ──────────────────
            chain = _hypothesis_to_tool_chain(mechanism, outcome.file, cwe=cwe)
            # SMT already dispatched above for this hypothesis; don't
            # re-run it inside the chain.
            if smt_verb:
                chain = [e for e in chain if e.get("type") != "smt"]
            if _refutation_is_high_confidence(h):
                chain = [
                    e for e in chain
                    if e.get("type") in _REFUTED_CHEAP_CHANNELS
                ]
            if not chain:
                continue

            confirmed = _run_tool_chain(
                chain,
                config=config,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source,
                hypothesis=mechanism,
                line_start=outcome.line,
                sarif_cache=None,
                tier_counters=result.tier_counters,
                joern_server=joern_server,
                cwe=cwe,
            )
            _increment_tier_dict(
                result.tier_counters, "refuted_sweep",
                "confirmed" if confirmed else "inconclusive",
            )
            if not confirmed:
                continue

            high_prec = [
                t for t in confirmed
                if not _is_detection_only(t)
                # The fail-open channel's registry-grade confirm proves
                # the callee is fallible and its return discarded --
                # exactly the facts the model weighed when it REFUTED
                # the hypothesis (intentional cleanup-path discards are
                # the canonical counter). Re-arming the verdict off the
                # same channel that seeded the lead is circular: the
                # channel corroborates standing findings, it does not
                # overturn a completed model refutation on its own.
                and not t.startswith("fail_open:")
            ]
            if not high_prec:
                logger.info(
                    "refuted-hypothesis promotion blocked %s:%s — only "
                    "detection-role/seeding-channel rules (%s)",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue
            if _premise_blocks_confirm(h, high_prec):
                logger.info(
                    "refuted-hypothesis promotion blocked %s:%s via %s — "
                    "the refutation rests on a cross-function premise no "
                    "confirming channel models",
                    outcome.file, outcome.function, "+".join(high_prec),
                )
                _increment_tier_dict(
                    result.tier_counters, "refuted_sweep",
                    "premise_blocked",
                )
                _queue_premise_study_question(config, outcome, h)
                continue
            _gblk = _guard_blocks_promotion(
                outcome.function, joern_server, result.tier_counters)
            if _gblk:
                logger.info(
                    "refuted-hypothesis promotion blocked %s:%s via %s — "
                    "sink-guard veto: %s",
                    outcome.file, outcome.function, "+".join(high_prec),
                    _gblk,
                )
                continue

            tool = "+".join(high_prec)
            rescued = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="suspicious",
                body=(
                    f"[refuted-hypothesis-confirmed via {tool}] "
                    f"LLM self-refuted this hypothesis; a mechanical "
                    f"tool confirmed it: {mechanism[:200]}\n\n"
                    f"{outcome.body}"
                ),
                hypothesis=mechanism,
                hypotheses=outcome.hypotheses,
                evidence_tool=tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )
            rescued.function_qualified = getattr(
                outcome, "function_qualified", "",
            )
            if rescued.review_result is not None:
                rescued.review_result["evidence_tool"] = tool
                rescued.review_result["refuted_hypothesis_confirmed"] = True
            result.outcomes[i] = rescued
            result.refuted_rescued += 1
            result.clean -= 1
            result.suspicious += 1
            append_audit_log(config.out_dir, {
                "action": "refuted_hypothesis_confirmed",
                "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
                "file": outcome.file,
                "function": outcome.function,
                "status": "suspicious",
                "prior_status": "clean",
                "evidence_tool": tool,
                "hypothesis": mechanism,
            })
            logger.info(
                "refuted-hypothesis confirmed %s:%s via %s — promoted "
                "clean → suspicious (LLM self-refutation overridden by "
                "tool receipt)",
                outcome.file, outcome.function, tool,
            )
            promoted = True


_SECONDARY_CONFIDENCES = frozenset({"high", "medium"})


def _dispatch_secondary_hypotheses(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: dict[str, Any] | None = None,
    joern_server=None,
) -> None:
    """Post-loop pass: dispatch non-primary hypotheses through tool chains.

    Reviews return a ``hypotheses`` array, but only the primary
    hypothesis ever drove dispatch — a function with an integer
    overflow AND a missing bounds check got exactly one mechanical
    test. This pass walks the preserved array on finding/suspicious
    outcomes and dispatches the top-N non-primary medium/high-confidence
    entries through the standard tool chains (refuted-confidence
    entries belong to ``_promote_clean_refuted``; clean outcomes with
    live hypotheses are handled by ``_promote_hypothesis_inconsistent``).

    Confirmation handling mirrors the sweep discipline:

    - suspicious outcome + non-detection-role confirmation → promote to
      finding with the tool receipt, the confirmed mechanism as the
      lead hypothesis, and a distinct body marker;
    - finding outcome → already promoted; the extra confirmation is
      recorded under ``review_result.secondary_confirmations`` so the
      export surfaces the additional mechanism;
    - detection-role-only confirmations never promote.

    Bounded per function by ``_MAX_REFUTED_DISPATCHES_PER_FN`` (the
    budget shared with the refuted lane — statuses are disjoint, so the
    per-function total stays capped), ranked by confidence then
    mechanism specificity. Dispatches are counted in tier telemetry
    under ``secondary_sweep``.
    """
    for i, outcome in enumerate(result.outcomes):
        if outcome.status not in ("finding", "suspicious"):
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
            continue

        hypotheses = getattr(outcome, "hypotheses", None) or []
        if not hypotheses and outcome.review_result:
            hypotheses = outcome.review_result.get("hypotheses") or []

        primary = (
            (outcome.review_result or {}).get("hypothesis")
            or outcome.hypothesis
            or ""
        ).strip().lower()

        secondary = []
        seen_mechanisms = {primary} if primary else set()
        for h in hypotheses:
            if not isinstance(h, dict):
                continue
            mechanism = (h.get("mechanism") or "").strip()
            if not mechanism:
                continue
            if (h.get("confidence") or "").lower() not in _SECONDARY_CONFIDENCES:
                continue
            norm = mechanism.lower()
            if norm in seen_mechanisms:
                continue
            seen_mechanisms.add(norm)
            secondary.append(h)
        if not secondary:
            continue

        ranked = sorted(
            secondary,
            key=lambda h: (
                (h.get("confidence") or "").lower() == "high",
                _mechanism_specificity(h.get("mechanism", "")),
            ),
            reverse=True,
        )[:_MAX_REFUTED_DISPATCHES_PER_FN]

        gap = _find_gap_in_checklist(
            checklist or {}, outcome.file, outcome.function,
        )
        line_end = gap.get("line_end") if gap else None
        source = _read_raw_source(
            config.target_path,
            outcome.file,
            outcome.line,
            line_end,
        )
        fallback_cwe = _effective_cwe(outcome, result.tier_counters)

        promoted = False
        for h in ranked:
            if promoted:
                break
            mechanism = h.get("mechanism", "")

            # Per-hypothesis CWE: the secondary mechanism may belong to
            # a different class than the review-level tag.
            cwe = ""
            try:
                from .cwe_dispatch import infer_cwe_from_hypothesis
                cwe = infer_cwe_from_hypothesis(mechanism) or ""
            except ImportError:
                pass
            if not cwe:
                cwe = fallback_cwe

            chain = _hypothesis_to_tool_chain(mechanism, outcome.file, cwe=cwe)
            if not chain:
                _increment_tier_dict(
                    result.tier_counters, "secondary_sweep", "skipped",
                )
                continue

            confirmed = _run_tool_chain(
                chain,
                config=config,
                file_path=outcome.file,
                function_name=outcome.function,
                source=source,
                hypothesis=mechanism,
                line_start=outcome.line,
                sarif_cache=None,
                tier_counters=result.tier_counters,
                joern_server=joern_server,
                cwe=cwe,
            )
            _increment_tier_dict(
                result.tier_counters, "secondary_sweep",
                "confirmed" if confirmed else "inconclusive",
            )
            if not confirmed:
                continue

            high_prec = [t for t in confirmed if not _is_detection_only(t)]
            if not high_prec:
                logger.info(
                    "secondary-hypothesis promotion blocked %s:%s — only "
                    "detection-role rules (%s)",
                    outcome.file, outcome.function, "+".join(confirmed),
                )
                continue
            _gblk = _guard_blocks_promotion(
                outcome.function, joern_server, result.tier_counters)
            if _gblk:
                logger.info(
                    "secondary-hypothesis promotion blocked %s:%s via %s — "
                    "sink-guard veto: %s",
                    outcome.file, outcome.function, "+".join(high_prec),
                    _gblk,
                )
                continue
            if _premise_blocks_confirm(h, high_prec):
                # The LLM's own counter on this hypothesis rests on a
                # cross-function premise (e.g. "the setsockopt path
                # validates the level, the default branch is
                # unreachable") that no confirming channel models. The
                # confirmation is recorded for the export but may not
                # outrank the unconsumed premise.
                if outcome.review_result is not None:
                    outcome.review_result.setdefault(
                        "secondary_confirmations", [],
                    ).append({
                        "mechanism": mechanism[:200],
                        "evidence_tool": "+".join(high_prec),
                        "confidence": (h.get("confidence") or "").lower(),
                        "premise_blocked": True,
                    })
                logger.info(
                    "secondary-hypothesis promotion blocked %s:%s via %s "
                    "— the counter rests on a cross-function premise no "
                    "confirming channel models",
                    outcome.file, outcome.function, "+".join(high_prec),
                )
                _increment_tier_dict(
                    result.tier_counters, "secondary_sweep",
                    "premise_blocked",
                )
                _queue_premise_study_question(config, outcome, h)
                continue

            tool = "+".join(high_prec)
            if outcome.review_result is not None:
                outcome.review_result.setdefault(
                    "secondary_confirmations", [],
                ).append({
                    "mechanism": mechanism[:200],
                    "evidence_tool": tool,
                    "confidence": (h.get("confidence") or "").lower(),
                })
            result.secondary_confirmed += 1

            if outcome.status == "finding":
                # Already promoted — the extra mechanism is recorded
                # above and exported; nothing else to change.
                logger.info(
                    "secondary hypothesis confirmed on finding %s:%s "
                    "via %s: %s",
                    outcome.file, outcome.function, tool, mechanism[:120],
                )
                continue

            rescued = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="finding",
                body=(
                    f"[secondary-hypothesis-confirmed via {tool}] "
                    f"A non-primary hypothesis was mechanically "
                    f"confirmed: {mechanism[:200]}\n\n{outcome.body}"
                ),
                hypothesis=mechanism,
                hypotheses=outcome.hypotheses,
                evidence_tool=tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )
            rescued.tools_dispatched = outcome.tools_dispatched
            rescued.tools_errored = outcome.tools_errored
            rescued.semantic_confidence = outcome.semantic_confidence
            if rescued.review_result is not None:
                rescued.review_result["evidence_tool"] = tool
                rescued.review_result["secondary_hypothesis_confirmed"] = True
            result.outcomes[i] = rescued
            result.sweep_promoted += 1
            result.suspicious -= 1
            result.findings += 1
            append_audit_log(config.out_dir, {
                "action": "secondary_hypothesis_confirmed",
                "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
                "file": outcome.file,
                "function": outcome.function,
                "status": "finding",
                "prior_status": "suspicious",
                "evidence_tool": tool,
                "hypothesis": mechanism,
            })
            logger.info(
                "secondary hypothesis confirmed %s:%s via %s — promoted "
                "suspicious → finding: %s",
                outcome.file, outcome.function, tool, mechanism[:120],
            )
            promoted = True


# Bound the adversarial refuter's extra LLM spend: at most this many
# finding/suspicious outcomes are attacked per run.
_MAX_ADVERSARIAL_REFUTATIONS = 64

# Sweep/gate body markers whose outcomes already carry a mechanical
# resolution — re-attacking them wastes refuter budget.
_ADVERSARIAL_SKIP_PREFIXES = (
    "[gate violation:",
    "[sink-unreachability:",
    "[guarded-sink:",
    "[smt-infeasible:",
    "[entry-unreachability:",
    "[self-contradiction:",
)


def _adversarial_refute_pass(
    result: OrchestratorResult,
    config: OrchestratorConfig,
    checklist: dict[str, Any] | None = None,
    *,
    joern_server=None,
    start_time: float | None = None,
) -> None:
    """Post-loop pass: genuinely attack finding/suspicious hypotheses.

    For each positive outcome, a SEPARATE LLM call with a purpose-built
    refutation prompt (``core.audit.adversarial_refute``) attacks the
    specific hypothesis. Verdict routing:

    - ``stands`` — annotate and keep. The refuter could not defeat it.
    - ``refuted`` with named mechanical evidence — dispatch the
      hypothesis through the standard tool chains: a non-detection-role
      confirmation OVERTURNS the refutation (the outcome keeps its
      status and gains the tool receipt); an unconfirmed chain
      corroborates the refuter and the outcome is demoted.
    - ``refuted`` textually only — demote one level with the refuter's
      argument recorded: finding → suspicious, suspicious → clean.
      Tool-backed outcomes never demote below suspicious
      (``is_tool_evidence`` guard) and are never silently dropped.
    - ``needs_evidence`` — mark the outcome for dark verification (the
      dark pass runs later and executes a witness).

    Single-model runs are self-adversarial (same model, adversarial
    prompt); multi-model runs prefer a refuter model different from the
    producer. Refuter failures are no-ops — an errored refutation must
    never demote anything.
    """
    from .adversarial_refute import (
        VERDICT_NEEDS_EVIDENCE,
        VERDICT_STANDS,
        pick_refuter_model,
        run_refutation,
    )
    from .evidence_grade import is_tool_evidence

    llm_client = config.llm_client
    if llm_client is None:
        try:
            llm_client = _run_llm_client(config)
        except Exception:  # noqa: BLE001 — pass is best-effort
            logger.warning(
                "adversarial refutation skipped — no LLM client available",
            )
            return

    # Per-finding refuter failures are no-ops by contract, but a
    # PERSISTENT auth refusal (dead dispatcher token) is a different
    # animal: the tracker distinguishes it and the pass aborts loudly
    # below instead of no-op'ing through every positive outcome.
    from core.llm.client import AuthFailureTracker
    auth_tracker = AuthFailureTracker("adversarial-refute")

    dispatched = 0
    for i, outcome in enumerate(result.outcomes):
        if outcome.status not in ("finding", "suspicious"):
            continue
        if outcome.body.startswith(_ADVERSARIAL_SKIP_PREFIXES):
            continue
        review = outcome.review_result or {}
        if review.get("adversarial_review"):
            continue  # already refuted by the in-loop multi-model pass
        hypothesis = (outcome.hypothesis or "").strip()
        if not hypothesis:
            continue
        if dispatched >= _MAX_ADVERSARIAL_REFUTATIONS:
            logger.info(
                "adversarial refutation cap reached (%d) — remaining "
                "positive outcomes keep their verdicts",
                _MAX_ADVERSARIAL_REFUTATIONS,
            )
            break
        if start_time is not None and _check_budget(config, start_time, result):
            break

        gap = _find_gap_in_checklist(
            checklist or {}, outcome.file, outcome.function,
        )
        line_end = gap.get("line_end") if gap else None
        if outcome.line == 0 and gap:
            outcome.line = gap.get("line_start", 0)
        source = _read_raw_source(
            config.target_path, outcome.file, outcome.line, line_end,
        )

        refuter_model = pick_refuter_model(
            config.models, outcome.model or "",
        )
        dispatched += 1
        ref = run_refutation(
            llm_client,
            file=outcome.file,
            function=outcome.function,
            hypothesis=hypothesis,
            body=outcome.body,
            source=source,
            model_name=refuter_model,
            auth_tracker=auth_tracker,
        )
        if ref is None:
            _increment_tier_dict(
                result.tier_counters, "adversarial_refute", "errors",
            )
            if auth_tracker.tripped:
                # Not N independent refuter hiccups — the auth layer
                # is refusing every call. Abort the pass loudly; a
                # silently no-op'd adversarial pass ships findings
                # unchallenged while claiming they were attacked.
                try:
                    auth_tracker.raise_if_tripped()
                except Exception as exc:  # noqa: BLE001 — typed abort from the tracker
                    _record_phase_abort(config, result, exc)
                return
            continue

        result.cost_tracker.record_call(
            "adversarial", cost_usd=ref.cost_usd,
        )
        with result._lock:
            result.total_cost_usd += ref.cost_usd

        if outcome.review_result is None:
            outcome.review_result = {}
        outcome.review_result["adversarial_review"] = {
            "verdict": ref.verdict,
            "counter_argument": ref.counter_argument[:500],
            "defeating_mechanism": ref.defeating_mechanism[:300],
            "settling_evidence": ref.settling_evidence[:300],
            "refuter_model": ref.model or refuter_model or "",
        }

        log_entry = {
            "action": "adversarial_refutation",
            "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
            "file": outcome.file,
            "function": outcome.function,
            "verdict": ref.verdict,
            "prior_status": outcome.status,
            "status": outcome.status,
        }

        if ref.verdict == VERDICT_STANDS:
            result.adversarial_stands += 1
            _increment_tier_dict(
                result.tier_counters, "adversarial_refute", "inconclusive",
            )
            append_audit_log(config.out_dir, log_entry)
            continue

        if ref.verdict == VERDICT_NEEDS_EVIDENCE:
            # Route to dark verification — the dark pass runs after
            # this one and executes a concrete witness.
            outcome.review_result["adversarial_needs_evidence"] = True
            _increment_tier_dict(
                result.tier_counters, "adversarial_refute", "skipped",
            )
            append_audit_log(config.out_dir, log_entry)
            continue

        # ── verdict == refuted ─────────────────────────────────────
        # Named mechanical evidence: give the tools the last word.
        # A chain confirmation of the ORIGINAL hypothesis overturns
        # the textual refutation.
        named_evidence = ref.settling_evidence or ref.defeating_mechanism
        overturned = False
        if named_evidence:
            cwe = _effective_cwe(outcome, result.tier_counters)
            chain = _hypothesis_to_tool_chain(
                hypothesis, outcome.file, cwe=cwe,
            )
            if not chain:
                chain = _hypothesis_to_tool_chain(
                    named_evidence, outcome.file, cwe=cwe,
                )
            if chain:
                confirmed = _run_tool_chain(
                    chain,
                    config=config,
                    file_path=outcome.file,
                    function_name=outcome.function,
                    source=source,
                    hypothesis=hypothesis,
                    line_start=outcome.line,
                    sarif_cache=None,
                    tier_counters=result.tier_counters,
                    joern_server=joern_server,
                    cwe=cwe,
                )
                high_prec = [
                    t for t in (confirmed or [])
                    if not _is_detection_only(t)
                ]
                if high_prec:
                    overturned = True
                    tool = "+".join(high_prec)
                    if not outcome.evidence_tool:
                        outcome.evidence_tool = tool
                        outcome.review_result["evidence_tool"] = tool
                    outcome.review_result["adversarial_review"][
                        "overturned_by"] = tool
                    result.adversarial_stands += 1
                    _increment_tier_dict(
                        result.tier_counters, "adversarial_refute",
                        "confirmed",
                    )
                    log_entry["verdict"] = "refutation_overturned"
                    log_entry["evidence_tool"] = tool
                    append_audit_log(config.out_dir, log_entry)
                    logger.info(
                        "adversarial refutation overturned %s:%s — tool "
                        "receipt %s confirms the hypothesis",
                        outcome.file, outcome.function, tool,
                    )
        if overturned:
            continue

        # Demote one level, never silently below a tool receipt.
        reason = (
            f"[adversarial-refuted: "
            f"{(ref.defeating_mechanism or ref.counter_argument)[:200]}]"
        )
        tool_backed = is_tool_evidence(outcome.evidence_tool or "")
        if outcome.status == "finding":
            demoted = _demote_outcome(outcome, reason)
            demoted.review_result = outcome.review_result
            result.outcomes[i] = demoted
            result.findings -= 1
            result.suspicious += 1
            result.adversarial_refuted += 1
            log_entry["status"] = "suspicious"
        elif tool_backed:
            # suspicious + mechanical receipt: record the refutation,
            # keep the outcome queued for re-review / validate.
            outcome.body = f"{reason}\n\n{outcome.body}"
            log_entry["status"] = "suspicious"
        else:
            cleaned = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="clean",
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
            cleaned.tools_dispatched = outcome.tools_dispatched
            cleaned.tools_errored = outcome.tools_errored
            result.outcomes[i] = cleaned
            result.suspicious -= 1
            result.clean += 1
            result.adversarial_refuted += 1
            log_entry["status"] = "clean"

        _increment_tier_dict(
            result.tier_counters, "adversarial_refute", "refuted",
        )
        append_audit_log(config.out_dir, log_entry)
        logger.info(
            "adversarial refuter demoted %s:%s (%s → %s): %s",
            outcome.file, outcome.function,
            log_entry["prior_status"], log_entry["status"],
            (ref.defeating_mechanism or ref.counter_argument)[:120],
        )

    # Completed without an auth abort (the abort path returns early):
    # supersede any stale sidecar record from a prior segment.
    _clear_phase_abort(config, "adversarial-refute", result=result)


_C_EXTS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx"})


def _pre_loop_smt_screen(
    workqueue: list,
    config: OrchestratorConfig,
    result: OrchestratorResult,
    checklist: dict[str, Any] | None = None,
) -> list:
    """Run SMT checks before the LLM loop.

    Functions with a confirmed SMT finding are recorded as outcomes
    immediately and removed from the workqueue so they never reach the
    (expensive) LLM review.  Returns the filtered workqueue.
    """
    try:
        from .condition_smt import (
            DomainVocabulary,
            build_consumer_width_index,
            check_auth_bypass,
            check_early_release,
            check_integer_narrowing,
            check_lock_discipline,
            check_null_propagation,
            check_parsed_int_contract,
            check_resource_leak,
            check_toctou,
        )
    except Exception:  # noqa: BLE001
        return workqueue

    # Cross-file width bindings for the parsed-int contract check:
    # callee signatures come from the checklist (the callee usually
    # lives in another file than the parse).
    consumer_widths = build_consumer_width_index(checklist)

    _extract_sg = None
    _check_pf = None
    with contextlib.suppress(ImportError):
        from .condition_extraction import extract_sink_guards as _extract_sg
        from .condition_smt import check_path_feasibility as _check_pf

    dm = None
    if getattr(config, "out_dir", None):
        with contextlib.suppress(OSError):
            dm = _load_domain_model(config)
    vocab = DomainVocabulary.from_domain_model(
        dm, target_path=config.target_path,
    )

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
        with contextlib.suppress(*_SMT_SCREEN_ERRORS):
            abr = check_auth_bypass(source, vocab)
            if abr.bypass_found:
                tool_hit = "smt:check-auth-bypass"
                if abr.witness:
                    tool_hit += ":witness"

        if not tool_hit and is_c:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                ldr = check_lock_discipline(source, vocab)
                if ldr.violation_found:
                    tool_hit = "smt:check-lock-discipline"
                    if ldr.witness:
                        tool_hit += ":witness"

        if not tool_hit and is_c:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                rlr = check_resource_leak(source, vocab)
                if rlr.leak_found:
                    tool_hit = "smt:check-resource-leak"
                    if rlr.witness:
                        tool_hit += ":witness"

        if not tool_hit and is_c:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                npr = check_null_propagation(source, vocab)
                if npr.null_deref_found:
                    tool_hit = "smt:check-null-propagation"

        if not tool_hit and is_c_or_go:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                inr = check_integer_narrowing(source)
                if inr.narrowing_found:
                    tool_hit = "smt:check-integer-narrowing"
                    if inr.witness:
                        tool_hit += ":witness"

        if not tool_hit and is_c_or_go:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                # Same-file parse wrappers (the stdlib idiom puts the
                # strconv call one helper away from the consumer):
                # derived once per file, mechanically, from the file
                # itself — never from a name list.
                _wkey = str(config.target_path / file_path)
                wrappers = _parse_wrapper_cache.get(_wkey)
                if wrappers is None:
                    from .condition_smt import derive_parse_wrappers
                    _full_src = _read_raw_source(
                        config.target_path, file_path, 1, 10**7,
                    )
                    wrappers = derive_parse_wrappers(_full_src)
                    _parse_wrapper_cache[_wkey] = wrappers
                pir = check_parsed_int_contract(
                    source, consumer_widths=consumer_widths,
                    parse_wrappers=wrappers,
                )
                if pir.narrowing_found:
                    tool_hit = "smt:check-parsed-int-contract"

        if not tool_hit and is_c_or_go:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                err = check_early_release(source, vocab)
                if err.early_release_found:
                    tool_hit = "smt:check-early-release"

        if not tool_hit and is_c:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                from .callback_lifetime import check_callback_lifetime_local
                clr = check_callback_lifetime_local(source, vocab)
                if clr.violation_found:
                    tool_hit = "smt:check-callback-lifetime"

        # check-lock-domain: too noisy for hard-classify (FP on
        # aead_check_key).  Runs in inject-mode via _run_mechanical_detectors
        # instead — results go to the LLM as context, not as verdicts.

        if not tool_hit and is_c:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                ttr = check_toctou(source)
                if ttr.toctou_found:
                    tool_hit = "smt:check-toctou"

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
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
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
                        # Safety contract: condition_smt is NOT in
                        # SUPPRESS_SOURCES, so a dead-path verdict may
                        # only BOOST/INFORM — it must never resolve the
                        # function without LLM review.  Inject the
                        # evidence and keep the gap in the workqueue;
                        # the reviewer sees the infeasibility proof as
                        # context and decides the verdict.
                        gap["_smt_pre_evidence"] = "smt:dead-path"
                        screened += 1
                        logger.info(
                            "pre-loop SMT screen: %s:%s → dead-path "
                            "evidence injected (all sink paths "
                            "infeasible per conjunctive guard model); "
                            "kept in workqueue per safety contract",
                            file_path, func_name,
                        )
                        kept.append(gap)
                        continue

        if is_c and not tool_hit:
            with contextlib.suppress(*_SMT_SCREEN_ERRORS):
                from .condition_smt import check_race_protection
                rpr = check_race_protection(source, vocab)
                if rpr.protected:
                    gap["_race_protected"] = True
                    gap["_race_protection_detail"] = rpr.reasoning

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
    checklist: dict[str, Any] | None = None,
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
            check_early_release,
            check_integer_narrowing,
            check_lock_discipline,
            check_lock_domain,
            check_null_propagation,
            check_resource_leak,
        )
    except Exception:  # noqa: BLE001
        return

    dm = None
    if getattr(config, "out_dir", None):
        with contextlib.suppress(OSError):
            dm = _load_domain_model(config)
    vocab = DomainVocabulary.from_domain_model(
        dm, target_path=config.target_path,
    )

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
            abr = check_auth_bypass(source, vocab)
            if abr.bypass_found:
                tool_hit = "smt:check-auth-bypass"
                if abr.witness:
                    tool_hit += ":model"  # Z3 model, not an executed witness
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
                        tool_hit += ":model"  # Z3 model, not an executed witness
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
                        tool_hit += ":model"  # Z3 model, not an executed witness
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
                        tool_hit += ":model"  # Z3 model, not an executed witness
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
                clr = check_callback_lifetime_local(source, vocab)
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
            # Premise binding, same rule as the clean-refuted lanes: a
            # function-local checker hit may not re-arm a clean whose
            # own refutation rests on a cross-function premise the
            # checker cannot see — the hit re-proves the lexical shape
            # the reviewer already saw and argued past (caller
            # contract, callee guarantee, lock domain). Escalation
            # stays for local refutations and unrefuted cleans.
            _hyps = getattr(outcome, "hypotheses", None) or []
            if not _hyps and outcome.review_result:
                _hyps = outcome.review_result.get("hypotheses") or []
            _premise_held = any(
                isinstance(h, dict)
                and (h.get("confidence") or "").lower() == "refuted"
                and _premise_blocks_confirm(h, [tool_hit])
                for h in _hyps
            )
            if _premise_held:
                logger.info(
                    "smt-clean escalation blocked %s:%s via %s — the "
                    "clean's refutation rests on a cross-function "
                    "premise the checker cannot see",
                    outcome.file, outcome.function, tool_hit,
                )
                _increment_tier_dict(
                    result.tier_counters, "refuted_sweep",
                    "premise_blocked",
                )
                continue
            # The LLM reviewed this function and said clean; these
            # checkers are heuristic/detection-grade. Overriding clean
            # straight to finding contradicted the documented invariant
            # that detection rules can't promote without LLM agreement
            # — surface as suspicious so the re-review/validate leg
            # adjudicates instead.
            promoted = _promote_outcome(outcome, tool_hit)
            promoted.status = "suspicious"
            promoted.body = promoted.body.replace(
                "[sweep promoted via", "[smt-clean escalated via", 1)
            result.outcomes[i] = promoted
            result.sweep_promoted += 1
            result.clean -= 1
            result.suspicious += 1
            logger.info(
                "smt-clean escalated %s:%s to suspicious via %s",
                outcome.file, outcome.function, tool_hit,
            )


def _demote_self_contradictions(result: OrchestratorResult) -> None:
    """Demote suspicious outcomes where every hypothesis is refuted.

    When the LLM marks all hypotheses as refuted yet still returns
    'suspicious' with no tool evidence, the verdict is self-
    contradictory.  Verified safe: all corpus TPs with no evidence
    have at least one unrefuted hypothesis.
    """
    from .evidence_grade import is_tool_evidence
    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "suspicious":
            continue
        # Truthiness let "llm-claimed:X" (the LLM's own assertion)
        # shield the outcome from its own self-contradiction check.
        if is_tool_evidence(outcome.evidence_tool or ""):
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
        promoted = ReviewOutcome(
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
        promoted.function_qualified = getattr(
            outcome, "function_qualified", "",
        )
        result.outcomes[i] = promoted
        result.clean -= 1
        result.suspicious += 1
        logger.info(
            "hypothesis-consistency promotion: %s:%s — %d unrefuted "
            "high-confidence hypothesis(es) despite clean verdict (%s)",
            outcome.file, outcome.function, len(unrefuted), mechanism,
        )


def _demote_absent_promotions(
    result: OrchestratorResult,
    config: OrchestratorConfig,
) -> int:
    """Demote sweep-promoted findings inside oracle-absent functions.

    A static sweep promotion (semgrep/cocci/joern/SMT) proves the code
    pattern exists, not that the code runs — the binary oracle's
    full-DWARF absent verdict is mechanical proof the compiler removed
    the function. Runtime-confirmed evidence (dark-verify witness,
    dynamic crash, frida, imported /validate runtime) vetoes the
    demotion — chokepoint precedence: runtime evidence beats a stale
    absent verdict. Each demotion carries the verdict as mechanical
    evidence and one suppressions.jsonl record.
    """
    if not (config.binary_verdicts or (
        isinstance(config.inventory, dict)
        and config.inventory.get("binary_oracle")
    )):
        return 0

    promoted_idx = [
        i for i, o in enumerate(result.outcomes)
        if o.status == "finding"
        and o.body.startswith("[sweep promoted via ")
    ]
    if not promoted_idx:
        return 0

    context_map = None
    # load_context_map self-handles malformed JSON; only OSErrors on
    # the read itself can legitimately escape.
    with contextlib.suppress(OSError):
        context_map = load_context_map(config.out_dir)
    fake_gaps = [
        {
            "file": result.outcomes[i].file,
            "name": result.outcomes[i].function,
            "line_start": result.outcomes[i].line or 0,
        }
        for i in promoted_idx
    ]
    absent_keys = _binary_absent_gap_keys(
        fake_gaps, None, config, context_map,
    )
    if not absent_keys:
        return 0

    demoted_count = 0
    for i in promoted_idx:
        outcome = result.outcomes[i]
        key = f"{outcome.file}:{outcome.function}"
        if key not in absent_keys:
            continue
        if outcome.compute_tier() == VerificationTier.CONFIRMED.value:
            # Runtime evidence vetoes the absent verdict.
            continue

        demoted = ReviewOutcome(
            file=outcome.file,
            function=outcome.function,
            status="dormant",
            body=(
                "[binary-oracle demotion: promoted finding is in a "
                "function absent from every analysed binary "
                "(full-DWARF tier)]\n\n" + outcome.body
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
        demoted.tools_dispatched = outcome.tools_dispatched
        demoted.tools_errored = outcome.tools_errored
        # Pure in-repo grading over constant inputs — only a partial
        # install (import failure) can legitimately fail here.
        with contextlib.suppress(ImportError):
            from .evidence_grade import EvidenceSource, grade_evidence

            ev = grade_evidence(
                EvidenceSource.BINARY_ORACLE,
                "binary oracle: function absent from every analysed "
                "binary (full-DWARF tier) — sweep promotion demoted",
            )
            if isinstance(demoted.review_result, dict):
                demoted.review_result.setdefault(
                    "evidence_chain", [],
                ).append(ev.to_dict())

        result.outcomes[i] = demoted
        with result._lock:
            result.findings -= 1
            result.dormant += 1
        demoted_count += 1

        if config.out_dir:
            # Best-effort audit trail; record_suppression self-handles
            # IO — only path-level OSErrors can legitimately escape.
            with contextlib.suppress(OSError):
                from core.analysis.reach_chokepoint import record_suppression

                record_suppression(
                    config.out_dir,
                    finding={
                        "finding_id": f"audit-promotion:{key}:{outcome.line or 0}",
                        "rule_id": "audit:sweep-promotion",
                        "file_path": outcome.file,
                        "line": outcome.line or 0,
                        "function": outcome.function,
                    },
                    verdict="binary_oracle_absent",
                    reason=(
                        "sweep promotion demoted to dormant: binary "
                        "oracle says the function is absent from every "
                        "analysed binary (full-DWARF tier)"
                    ),
                    dropped=False,
                    extra={"stage": "promotion-demotion"},
                )
        logger.info(
            "binary oracle: demoted promoted finding %s (absent)", key,
        )

    return demoted_count


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
    promoted.tools_dispatched = outcome.tools_dispatched
    promoted.tools_errored = outcome.tools_errored
    promoted.semantic_confidence = outcome.semantic_confidence
    promoted.function_qualified = getattr(
        outcome, "function_qualified", "",
    )
    if promoted.review_result:
        promoted.review_result["evidence_tool"] = tool
    return promoted


# Structural negative-space checkers whose receipts are precise enough
# to outrank an unverified self-refutation (the same families the
# review-time gate consumes via ctx["negative_space"]).
_STRUCTURAL_RECEIPT_CHECKS = frozenset({
    "auth_mode_registration",
    "url_boundary_composition",
    "shared_writer_race",
})


# A structural receipt names the concrete call sites whose gating is
# asymmetric ("2 add_view_no_menu() call(s) are gated on ...").
_RECEIPT_CALL_NAME_RE = re.compile(r"\b(\w+)\(\)\s+(?:call|perform)")

# Family bridge: the hypothesis must talk about the receipt's bug
# family, in the reviewer's own words — receipt check-type token stems
# rarely survive natural phrasing ("two Write calls without a lock"
# carries none of shared/writer/race).
_RECEIPT_FAMILY_HYP_RES = {
    "auth_mode_registration": re.compile(
        r"auth[\s_-]*(?:mode|type)|regist|reset|unconditional", re.IGNORECASE,
    ),
    "shared_writer_race": re.compile(
        r"concurren|race|interleav|unsynchron|\block\b|mutex|goroutine",
        re.IGNORECASE,
    ),
    "url_boundary_composition": re.compile(
        r"\burl\b|boundar|redirect|\bhost\b|origin", re.IGNORECASE,
    ),
}


def _receipt_corroborated_hypothesis(
    outcome, receipts, *, config=None, source=None,
):
    """Floor a clean verdict when the reviewer RAISED the receipt's
    exact shape and dismissed it without tool evidence.

    The anti-self-refutation gate only consumes confidence=refuted;
    the observed dismissal mode is different — the reviewer holds the
    matching hypothesis at low confidence and rules clean, so the
    receipt never reaches the verdict. Preconditions are deliberately
    tighter than the refuted clause: the hypothesis must name at least
    one of the concrete call sites the receipt flagged AND match the
    receipt family's token stems, and the outcome must carry no tool
    evidence. Returns a RefutationVerdict-shaped object or None.

    Same dominance rule as the in-gate receipt floors: the receipt
    outranks an UNVERIFIED dismissal, not a mechanical refuter. A
    proof-grade refuter of the receipt's claim family, or the
    race-protection witness corroborating a shared-writer dismissal
    on *source*, overrides the floor — the clean verdict stands and
    the overridden receipt is persisted (``dropped: false``) through
    the suppressions chokepoint.  Record-or-refuse: an override whose
    record cannot be written is refused and the floor stands.
    """
    from .evidence_grade import is_tool_evidence
    from .refutation import (
        RefutationVerdict,
        _dominating_refuter,
        _ProbeContext,
        _receipt_matches_mechanism,
        _record_floor_dominance,
    )

    if is_tool_evidence(outcome.evidence_tool or ""):
        return None
    hypotheses = getattr(outcome, "hypotheses", None) or []
    if not hypotheses and outcome.review_result:
        hypotheses = outcome.review_result.get("hypotheses") or []

    probe_ctx = _ProbeContext(
        source=source,
        target_path=getattr(config, "target_path", None) if config else None,
        repo_trusted=bool(getattr(config, "repo_trusted", False)),
    )

    race_protected = False
    if source:
        try:
            from .condition_smt import check_race_protection
            race_protected = check_race_protection(source).protected
        except Exception:
            logger.debug("race-protection probe failed", exc_info=True)

    for receipt in receipts:
        check_type = receipt.get("check_type", "")
        called = set(
            _RECEIPT_CALL_NAME_RE.findall(receipt.get("evidence", "")),
        )
        if not called:
            continue
        family_re = _RECEIPT_FAMILY_HYP_RES.get(check_type)
        for h in hypotheses:
            if not isinstance(h, dict):
                continue
            mechanism = h.get("mechanism", "") or ""
            call_overlap = any(
                re.search(rf"\b{re.escape(c)}\b", mechanism)
                for c in called
            )
            # Two corroboration routes: the check-type's own token
            # stems in the hypothesis (strong — reviewer used the
            # receipt's vocabulary), or the concrete call-site overlap
            # plus the family keyword bridge (natural phrasing).
            strong_stem = _receipt_matches_mechanism(
                check_type, mechanism,
            )
            if not (
                strong_stem
                or (call_overlap and family_re
                    and family_re.search(mechanism))
            ):
                continue
            # Dominance: a proof-grade refuter of the receipt's
            # family outranks the detection-grade receipt — the
            # clean verdict stands, demote-with-record.
            # Record-or-refuse: an override whose record cannot be
            # written is refused (the floor stands) — an unrecorded
            # override would be silent.
            refuter = _dominating_refuter(
                outcome, h, check_type, ctx=probe_ctx,
            )
            if refuter is not None and _record_floor_dominance(
                outcome, config,
                refuter=refuter, receipt=check_type,
                floor_gate="receipt_corroborated_hypothesis",
            ):
                logger.info(
                    "receipt floor overridden for %s:%s — %s (%s) "
                    "dominates %s",
                    outcome.file, outcome.function,
                    refuter.gate, refuter.refuter_grade, check_type,
                )
                continue
            if refuter is not None:
                logger.info(
                    "receipt floor dominance for %s:%s refused — "
                    "demote-with-record could not write its record",
                    outcome.file, outcome.function,
                )
            # Witness discharge, same authority the anti-self-
            # refutation gate grants mechanically corroborated
            # dismissals: when every shared-state access in the
            # source is lock-protected, a shared-writer dismissal
            # is corroborated, not unverified — re-flooring it
            # manufactures a false positive.  Accept-with-record or
            # nothing, same as the dominance route.
            if (
                refuter is None
                and race_protected
                and check_type == "shared_writer_race"
                and _record_floor_dominance(
                    outcome, config,
                    refuter=RefutationVerdict(
                        gate="race_protection_witness",
                        reason=(
                            "every shared-state access in the "
                            "function is mechanically lock-protected"
                        ),
                        demote_to="clean",
                    ),
                    receipt=check_type,
                    floor_gate="receipt_corroborated_hypothesis",
                    verdict="witness_corroborates_dismissal",
                    reason=(
                        f"receipt floor overridden: the dismissal is "
                        f"mechanically corroborated by the race-"
                        f"protection witness (every shared-state "
                        f"access lock-protected); the {check_type} "
                        f"receipt does not outrank a corroborated "
                        f"dismissal"
                    ),
                )
            ):
                logger.info(
                    "receipt floor overridden for %s:%s — race-"
                    "protection witness corroborates the dismissal "
                    "(%s receipt does not outrank it)",
                    outcome.file, outcome.function, check_type,
                )
                continue
            return RefutationVerdict(
                gate="receipt_corroborated_hypothesis",
                reason=(
                    f"reviewer raised the exact shape an active "
                    f"{check_type} receipt flags (same call sites: "
                    f"{', '.join(sorted(called & _mechanism_calls(mechanism, called)))}) "
                    f"and dismissed it without tool evidence; the "
                    f"structural receipt outranks the dismissal"
                ),
                demote_to="suspicious",
            )
    return None


def _mechanism_calls(mechanism: str, called: set) -> set:
    """Subset of *called* names the hypothesis mechanism mentions."""
    return {
        c for c in called
        if re.search(rf"\b{re.escape(c)}\b", mechanism)
    }


def _post_loop_receipt_rescue(
    result: OrchestratorResult,
    post_loop_findings: list,
    config: OrchestratorConfig,
    mechanical_findings: dict | None = None,
    gaps: list | None = None,
) -> int:
    """Re-run the anti-self-refutation gate with post-loop receipts.

    For every clean outcome on a function that carries a structural
    negative-space receipt from the post-loop pass, evaluate
    :func:`rescue_self_refuted` with those receipts. The review-time
    gate already saw ctx["negative_space"]; this pass is the durable
    backstop for receipts that did not reach (or survive to) the
    review-time gate. Fired rescues mutate the outcome in place; the
    corrective journal/audit-log passes that run afterwards propagate
    the new status to every last-row-wins consumer.

    Returns the number of outcomes flipped.
    """
    receipts_by_fn: dict[tuple[str, str], list] = {}
    for plf in post_loop_findings:
        if not isinstance(plf, dict):
            continue
        if plf.get("check_type") not in _STRUCTURAL_RECEIPT_CHECKS:
            continue
        f, fn = plf.get("file", ""), plf.get("function", "")
        if f and fn:
            receipts_by_fn.setdefault((f, fn), []).append(plf)
    pre_evidence_by_fn: dict[str, str] = {}
    for g in gaps or []:
        pe = g.get("_smt_pre_evidence")
        if pe:
            pre_evidence_by_fn[f"{g.get('file')}:{g.get('name')}"] = pe

    if (
        not receipts_by_fn
        and not mechanical_findings
        and not pre_evidence_by_fn
    ):
        return 0

    from .refutation import rescue_self_refuted

    # Keyed by line as well: a file can hold several same-named
    # functions (Go methods named after their interface — five
    # receivers each defining Scan is the canonical shape), and a
    # (file, name) key silently handed every one of them the FIRST
    # gap's span — the gate's mechanical probes then ran on the wrong
    # function body and re-floored discharges the mid-loop gate had
    # accepted with the right source in hand.  The bare (file, name)
    # fallback below stays for outcomes without a line, but only when
    # the name is unambiguous in that file.
    spans_by_line: dict[tuple[str, str, int], tuple[int, int]] = {}
    spans_by_fn: dict[tuple[str, str], tuple[int, int] | None] = {}
    for g in gaps or []:
        gf, gn = g.get("file", ""), g.get("name", "")
        if gf and gn and g.get("line_start"):
            span = (g["line_start"], g.get("line_end") or 0)
            spans_by_line.setdefault((gf, gn, g["line_start"]), span)
            if (gf, gn) in spans_by_fn:
                spans_by_fn[(gf, gn)] = None  # ambiguous — never guess
            else:
                spans_by_fn[(gf, gn)] = span

    flipped = 0
    for outcome in result.outcomes:
        if outcome.status != "clean":
            continue
        receipts = receipts_by_fn.get((outcome.file, outcome.function))
        fn_key = f"{outcome.file}:{outcome.function}"
        detectors = (mechanical_findings or {}).get(fn_key)
        pre_evidence = pre_evidence_by_fn.get(fn_key)
        if not receipts and not detectors and not pre_evidence:
            continue
        # Raw disk span, same as the review-time gate: without it the
        # gate's mechanical acceptance probes (race protection, safe
        # teardown) cannot run, so this backstop RE-FLOORED exactly the
        # self-refutations the mid-loop gate had accepted with source
        # in hand.
        _span = spans_by_line.get(
            (outcome.file, outcome.function, outcome.line or 0),
        ) or spans_by_fn.get((outcome.file, outcome.function))
        _rescue_src = (
            _read_raw_source(
                config.target_path, outcome.file, _span[0],
                _span[1] or None,
            )
            if _span
            else None
        )
        try:
            # Detector findings and screen receipts ride along: a
            # mid-loop floor can be clobbered by a later re-review
            # whose synthetic context lacks the injections — the
            # receipts themselves are deterministic, so this pass
            # re-applies them to whatever verdict is current.
            rv = rescue_self_refuted(
                outcome,
                config=config,
                negative_space=receipts or [],
                detector_findings=detectors or None,
                pre_evidence=pre_evidence,
                source=_rescue_src or None,
                target_path=config.target_path,
                out_dir=config.out_dir,
                repo_trusted=config.repo_trusted,
            )
        except Exception:
            logger.debug(
                "post-loop rescue failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
            continue
        if rv is None and receipts:
            rv = _receipt_corroborated_hypothesis(
                outcome, receipts,
                config=config, source=_rescue_src or None,
            )
        if rv is None:
            continue
        append_audit_log(config.out_dir, {
            "action": "refutation_gate",
            "gate": rv.gate,
            "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
            "file": outcome.file,
            "function": outcome.function,
            "reason": rv.reason,
            "demote_to": rv.demote_to,
            "original_status": outcome.status,
            "applied": True,
            "stage": "post-loop",
        })
        logger.info(
            "anti-self-refutation (post-loop) %s:%s — %s → %s",
            outcome.file, outcome.function, rv.reason, rv.demote_to,
        )
        outcome.status = rv.demote_to
        outcome.body = f"[{rv.gate}: {rv.reason}]\n\n" + (outcome.body or "")
        # Keep the tally counters in step with the flip — the final
        # "Audit complete" line prints from them, and without this it
        # said "0 suspicious" while the re-journalled verdicts (the
        # authoritative record) held the flips.
        with result._lock:
            result.clean -= 1
            if rv.demote_to == "finding":
                result.findings += 1
            elif rv.demote_to in ("dormant", "dark"):
                result.dormant += 1
            else:
                result.suspicious += 1
        flipped += 1
    return flipped


def _rejournal_final_statuses(
    result: OrchestratorResult,
    config: OrchestratorConfig,
) -> int:
    """Append updated journal entries for post-resolution status changes.

    Journal entries are committed mid-loop, BEFORE the post-loop passes
    (sweep promotion, gate resolution, dark verification) change
    statuses — so the journal said "suspicious" for outcomes the run
    finally resolved to clean/dark/finding. Append one corrective entry
    per drifted outcome; ``latest_entries`` semantics make the newest
    entry authoritative. Returns the number of entries appended.
    """
    if not config.out_dir:
        return 0
    try:
        from .collector import append_journal_for_outcome
        from .journal import (
            is_mechanical_echo,
            load_entries,
            make_function_key,
        )
    except ImportError:
        return 0
    try:
        # Two collapses over one journal read: the latest entry per
        # key (any kind) decides WHETHER the final status drifted and
        # needs a corrective row; the latest NON-echo entry per key is
        # the field DONOR. A post-loop mechanical echo is routinely
        # the newest row for exactly the keys being corrected (the
        # echo's verdict IS the drift), and adopting its fields
        # stamped the corrective row with the ``post-loop-mechanical``
        # tag and an echo-shaped span — every ``is_mechanical_echo``
        # consumer then read the function's final verdict as a
        # non-review (dropped from the report's reviewed/clean counts,
        # excluded from gap coverage, refused by cross-run reuse).
        entries: dict[str, Any] = {}
        donors: dict[str, Any] = {}
        for e in load_entries(config.out_dir):
            prev = entries.get(e.key)
            if prev is None or e.ts > prev.ts:
                entries[e.key] = e
            if not is_mechanical_echo(e):
                prev = donors.get(e.key)
                if prev is None or e.ts > prev.ts:
                    donors[e.key] = e
    except Exception:
        logger.debug("re-journal: journal load failed", exc_info=True)
        return 0

    updated = 0
    for outcome in result.outcomes:
        if outcome.status == "error":
            continue
        key = make_function_key(outcome.file, outcome.function)
        prior = entries.get(key)
        if prior is None or prior.verdict == outcome.status:
            continue
        # Carry the corrected entry's span AND strategy record
        # forward. The old minimal gap ({"line_start": line})
        # journaled the corrective row with strategies=[] and a
        # single-line source hash; the latest-per-site collapse then
        # handed cross-run verdict reuse an empty strategy set for a
        # fully-briefed review, refusing it as strategy_changed on
        # every later run, and the one-line hash weakened staleness
        # evidence to near nothing. The donor is the latest NON-echo
        # row (see the collapse above): the corrective row describes
        # the REVIEW's final status, never the mechanical echo that
        # triggered the correction. Same-named siblings: only adopt
        # the donor row's fields when it describes the SAME site —
        # a mismatched sibling keeps the minimal-gap behaviour
        # (the collector's sibling-inheritance fallback still fills
        # strategies when it can).
        donor = donors.get(key)
        gap: dict[str, Any] = {"line_start": outcome.line or 0}
        if donor is not None and (
                not outcome.line
                or (donor.line_start or 0) in (0, outcome.line)):
            gap = {
                "line_start": donor.line_start or (outcome.line or 0),
                "line_end": donor.line_end,
                "strategies": list(donor.strategies or []),
            }
        try:
            append_journal_for_outcome(
                out_dir=config.out_dir,
                target_path=config.target_path,
                run_id=(config.out_dir.name if config.out_dir else ""),
                outcome=outcome,
                gap=gap,
            )
            updated += 1
        except Exception:
            logger.debug(
                "re-journal failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
    if updated:
        logger.info(
            "re-journal: %d post-resolution final statuses appended",
            updated,
        )
    return updated


def _relog_final_statuses(
    result: OrchestratorResult,
    config: OrchestratorConfig,
) -> int:
    """Audit-log twin of ``_rejournal_final_statuses``.

    ``orchestrator_review`` rows are written mid-loop, BEFORE the
    post-loop passes (sweep promotion happens early enough to log its
    own rows, but gate resolution, confidence propagation and dark
    verification do not) — so the log's last review row said
    "suspicious" for outcomes the run finally resolved to clean/dark.
    The journal gets its corrective entries; every ``.audit-log.jsonl``
    consumer that takes the last review row per key (corpus scoring,
    resume dedup) kept reading the retracted verdict. Append one
    corrective row per drifted outcome. Rows deliberately omit
    ``strategies`` so strategy_stats never double-counts a function.
    Must run AFTER the collector flush — the buffered mid-loop rows
    have to land first for last-row-wins ordering to hold.
    """
    if not config.out_dir:
        return 0
    try:
        last_status: dict[str, str] = {}
        for entry in load_audit_log(config.out_dir):
            if entry.get("action") not in (
                "orchestrator_review", "sweep_promotion",
            ):
                continue
            key = entry.get("key") or ""
            if not key:
                continue
            head, _, tail = key.rpartition(":")
            base = head if (head and tail.isdigit()) else key
            last_status[base] = str(entry.get("status", ""))
    except Exception:
        logger.debug("re-log: audit log read failed", exc_info=True)
        return 0

    updated = 0
    for outcome in result.outcomes:
        if outcome.status == "error":
            continue
        base = f"{outcome.file}:{outcome.function}"
        prior = last_status.get(base)
        if prior is None or prior == outcome.status:
            continue
        entry = {
            "action": "orchestrator_review",
            "key": f"{outcome.file}:{outcome.function}:{outcome.line or 0}",
            "status": outcome.status,
            "prior_status": prior,
            "final_status_correction": True,
            "model": outcome.model or "",
            "cost_usd": outcome.cost_usd,
            "duration_s": outcome.duration_s,
        }
        if getattr(outcome, "function_qualified", ""):
            entry["function_qualified"] = outcome.function_qualified
        if outcome.hypothesis:
            entry["hypothesis"] = outcome.hypothesis
        if outcome.evidence_tool:
            entry["evidence_tool"] = outcome.evidence_tool
        try:
            append_audit_log(config.out_dir, entry)
            updated += 1
        except Exception:
            logger.debug(
                "re-log failed for %s:%s",
                outcome.file, outcome.function, exc_info=True,
            )
    if updated:
        logger.info(
            "re-log: %d post-resolution final statuses appended "
            "to the audit log",
            updated,
        )
    return updated


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
    sarif_cache: SarifCache | None = None,
    checklist: dict[str, Any] | None = None,
    *,
    domain_model: dict[str, Any] | None = None,
    available_tools: dict[str, bool] | None = None,
    mechanical_findings: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    """Resolve gate-demoted AND evidence-free suspicious outcomes.

    Gate demotions (G2 no-evidence, self-contradiction) catch LLM
    hallucinations.  But they leave the outcome as "suspicious" with no
    path to resolution — deepen and sweep both skip them.  Plain
    suspicious outcomes without verification evidence used to be
    demoted to clean by an in-loop gate whenever Joern was up — class-
    and error-blind; they are resolved here instead (only when Joern
    was available this run, preserving the old gate's activation
    condition, and only AFTER deepen/sweep had their chance).

    This pass checks whether ANY mechanical tool independently flags the
    same function.  If nothing corroborates the LLM's retracted claim:
    - If a tool that covers the class actually RAN for this function
      (dispatch record / SARIF file hit, minus errored channels) →
      resolved to clean (a tool looked and stayed silent — disconfirmed).
    - Otherwise → resolved to dark (no tool ever looked, the class is
      tool-blind, or the covering channel errored — needs concrete
      verification). A tool that errored or timed out did NOT run:
      converting a Joern timeout into a clean verdict is a failure
      mode masquerading as a refutation.

    No LLM calls.
    """
    joern_up = bool((available_tools or {}).get("joern"))

    for i, outcome in enumerate(result.outcomes):
        if outcome.status != "suspicious":
            continue
        gate_demoted = outcome.body.startswith(_GATE_DEMOTED_PREFIXES)
        if not gate_demoted and _is_machine_raised(outcome):
            # Counter-escalation evidence floor. This suspicious was
            # machine-raised off the review's own counter_hypothesis:
            # the model's verdict was clean, with a completed
            # hypothesis-refutation ladder behind it. The escalation
            # exists so deepen/verification can convict a lead the
            # model may have talked itself out of — by the time this
            # end-of-run pass runs, they have had their chance. If no
            # receipt materialised, shipping suspicious would mint an
            # LLM-only verdict that even the LLM did not make.
            #
            # Retention requires a receipt: verification-role evidence
            # or a fired probe (the demotion-referee floor — a tool
            # observation is never erased by this pass). Pattern-prior
            # corroboration (_has_mechanical_corroboration: pre-sweep
            # detector hits, prefilter sink scans) deliberately does
            # NOT retain here — those priors seeded the very review
            # that adjudicated them clean, so recycling them re-arms
            # the verdict off its own input (corpus case: a cocci
            # missing_bounds_check lead on a correct strlcpy-shaped
            # helper kept a receipt-less machine-escalated suspicious
            # alive to export). Resolves to clean, never dark: the
            # review completed and concluded clean, so "no channel
            # ever looked" is false. Model-emitted suspicious verdicts
            # never carry the flag and are untouched.
            if _is_verification_evidence_for_gate(outcome):
                continue
            # A detection-role probe receipt does NOT retain a
            # machine-raised row: the escalation was created to force
            # verification, and a lexical/heuristic "confirmed" merely
            # echoes the speculation the model already adjudicated
            # clean (observed corpus family: anti-self-refutation +
            # heuristic smt confirm shipped a cluster of kernel FPs
            # that no lane could demote). Model-emitted suspicious
            # keeps the demotion-referee floor unchanged — there the
            # probe corroborates a conviction the model itself holds.
            resolved = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="clean",
                body=(
                    "[machine-escalation resolution: machine-raised "
                    "suspicious earned no verification-grade receipt "
                    "— model verdict clean restored]\n\n" + outcome.body
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
            resolved.tools_dispatched = outcome.tools_dispatched
            resolved.tools_errored = outcome.tools_errored
            result.outcomes[i] = resolved
            result.suspicious -= 1
            result.clean += 1
            logger.info(
                "counter-escalation floor: %s:%s → clean "
                "(machine-raised suspicious, no receipt survived "
                "verification)",
                outcome.file,
                outcome.function,
            )
            continue
        if not gate_demoted:
            # Replacement for the removed in-loop suspicious-demotion
            # gate: evidence-free suspicious outcomes resolve here,
            # class- and error-aware, only when Joern was available
            # (matching the old gate's activation condition).
            if not joern_up:
                continue
            if _is_verification_evidence_for_gate(outcome):
                continue

        if _has_mechanical_corroboration(
            outcome, config, sarif_cache, checklist,
            domain_model=domain_model,
            mechanical_findings=mechanical_findings,
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
        elif _probe_backed_suspicious(outcome):
            # Demotion referee: no fresh corroboration turned up, but
            # the verdict is backed by a probe that FIRED during the
            # review (mid-loop SMT/cocci receipt, possibly recorded
            # under llm-claimed: with the dispatch record as witness).
            # Silence elsewhere is not a verification-role refuter —
            # resolving this to clean/dark would let an LLM-only
            # argument erase a tool observation. The trusted-provenance
            # override above is unaffected: it only fires WITH
            # corroboration.
            logger.info(
                "demotion referee: %s:%s stays suspicious — "
                "probe-backed, no verification-role refuter",
                outcome.file,
                outcome.function,
            )
            continue

        # Determine if a tool covering the vulnerability class actually
        # RAN for this function. The dispatch record comes from
        # sweep/proactive validation; a SARIF hit for the file means a
        # scan pass ran over it; errored channels did not run.
        class_covered = False
        if available_tools is not None:
            try:
                from .tool_coverage import is_class_covered

                ran: set = set(outcome.tools_dispatched or set())
                if (
                    sarif_cache is not None
                    and sarif_cache.lookup(outcome.file) is not None
                ):
                    ran.add("sarif_cache")
                errored = set(outcome.tools_errored or set())
                if errored:
                    logger.debug(
                        "gate resolution %s:%s — channels errored (%s), "
                        "excluded from coverage",
                        outcome.file, outcome.function,
                        ",".join(sorted(errored)),
                    )
                ran -= errored

                rr = outcome.review_result or {}
                class_covered = is_class_covered(
                    cwe_field=rr.get("cwe", ""),
                    mechanism=rr.get("mechanism", outcome.hypothesis or ""),
                    hypothesis=outcome.hypothesis or "",
                    available_tools=available_tools,
                    ran_tools=ran,
                )
            except Exception:
                logger.warning(
                    "tool_coverage check failed for %s:%s",
                    outcome.file,
                    outcome.function,
                    exc_info=True,
                )

        marker = "" if gate_demoted else (
            "[suspicious-resolution: no verification evidence]\n\n"
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
                body=marker + outcome.body,
                hypothesis=outcome.hypothesis,
                hypotheses=outcome.hypotheses,
                evidence_tool=outcome.evidence_tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )
            resolved.tools_dispatched = outcome.tools_dispatched
            resolved.tools_errored = outcome.tools_errored
            result.outcomes[i] = resolved
            result.suspicious -= 1
            result.clean += 1
            logger.info(
                "gate-resolved %s:%s → clean "
                "(no mechanical corroboration, covering channel ran silent)",
                outcome.file,
                outcome.function,
            )
        else:
            resolved = ReviewOutcome(
                file=outcome.file,
                function=outcome.function,
                status="dark",
                body=marker + outcome.body,
                hypothesis=outcome.hypothesis,
                hypotheses=outcome.hypotheses,
                evidence_tool=outcome.evidence_tool,
                cost_usd=outcome.cost_usd,
                model=outcome.model,
                duration_s=outcome.duration_s,
                review_result=outcome.review_result,
                line=outcome.line,
            )
            resolved.tools_dispatched = outcome.tools_dispatched
            resolved.tools_errored = outcome.tools_errored
            result.outcomes[i] = resolved
            result.suspicious -= 1
            result.dormant += 1
            logger.info(
                "gate-resolved %s:%s → dark "
                "(no mechanical corroboration, no covering channel ran)",
                outcome.file,
                outcome.function,
            )


def _try_block_level_context(
    gap: dict[str, Any],
    ctx: dict[str, Any],
    config: OrchestratorConfig,
    evidence_index: dict[str, EvidenceRecord] | None = None,
) -> str | None:
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
) -> list[dict[str, str]]:
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
    _checklist: dict[str, Any],
    evidence_index: dict[str, EvidenceRecord] | None = None,
    joern_server=None,
    sarif_cache: SarifCache | None = None,
    domain_model=None,
    audit_log: list | None = None,
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

    traces_reviewed = 0
    for trace_file in trace_files[:10]:
        if start_time and _check_budget(config, start_time, result):
            break

        trace = load_json(trace_file, max_bytes=_MAX_ARTIFACT_BYTES)
        if not isinstance(trace, dict):
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
        except Exception as exc:  # noqa: BLE001
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
        finding: dict[str, Any] = {
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
    session_observations: list[dict[str, str]],
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
        # _accumulate_observations tags tool-confirmed observations
        # with kind="tool_confirmation" (no producer ever set a
        # "tool_confirmed" flag).
        if obs.get("kind") == "tool_confirmation":
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
        # review["evidence_tool"] is the RAW LLM response — sanitize it
        # so sentinels ("none", "manual") collapse to empty and free-form
        # claims land under llm-claimed:, never as verification evidence.
        # Per "+"-part: namespacing the joined string whole would leave
        # parts after the first un-prefixed once the split below runs.
        review = outcome.review_result or {}
        raw = str(review.get("evidence_tool", "") or "")
        ev = "+".join(
            p for p in (_sanitize_llm_et(part.strip()) for part in raw.split("+"))
            if p
        )
    if not ev:
        return False
    from .pipeline import _is_verification_evidence
    return any(_is_verification_evidence(part.strip()) for part in ev.split("+"))


_COUNTER_ESCALATION_PREFIX = "[counter-hypothesis escalation:"
_ANTI_SELF_REFUTATION_PREFIX = "[anti_self_refutation:"


def _is_machine_raised(outcome: ReviewOutcome) -> bool:
    """True when this suspicious verdict was machine-raised from a
    model-clean verdict — by the counter-hypothesis escalation OR the
    anti-self-refutation gate. Both lanes exist to force verification
    of a claim the model talked itself out of; neither is a model
    conviction, so end-of-run retention demands verification-grade
    evidence (see the resolution pass)."""
    if _is_counter_escalated(outcome):
        return True
    return (outcome.body or "").startswith(_ANTI_SELF_REFUTATION_PREFIX)


def _is_counter_escalated(outcome: ReviewOutcome) -> bool:
    """True when this suspicious verdict was machine-raised off the
    review's own counter_hypothesis (the model's verdict was clean).

    Reads the structured ``counter_escalated`` flag stamped by the
    review path; the body-prefix check covers outcomes rebuilt from a
    journal or checkpoint where ``review_result`` was dropped (the
    escalation marker is always the first prefix written, and an
    outcome that a later structured demotion re-prefixed is no longer
    suspicious, so the startswith test cannot misfire on it).
    """
    rr = outcome.review_result or {}
    if rr.get("counter_escalated"):
        return True
    return (outcome.body or "").startswith(_COUNTER_ESCALATION_PREFIX)


def _deepen_demotion_refereed(
    prior_outcome: ReviewOutcome,
    outcome: ReviewOutcome,
) -> bool:
    """Demotion referee for the deepen pass.

    True when a deepen re-review's clean may NOT supersede the prior
    suspicious: the clean's only basis is the LLM's own refutation
    (all-refuted / rationale-consistency structured demotion), the
    prior verdict is backed by a fired probe, and the deepen outcome
    carries no verification-role refuter. A fired probe's receipt is
    a tool observation; overriding it takes a verification-role
    receipt (an unsat counter-witness, a consistency counter-example),
    not an argument — the same principle as the dark-verify
    tool-backed floor.
    """
    _rr = outcome.review_result or {}
    structured = bool(
        _rr.get("all_refuted_demotion")
        or _rr.get("rationale_consistency_demotion")
    )
    return (
        outcome.status == "clean"
        and structured
        and prior_outcome.status == "suspicious"
        and _probe_backed_suspicious(prior_outcome)
        and not _is_verification_evidence_for_gate(outcome)
    )


def _probe_backed_suspicious(outcome: ReviewOutcome) -> bool:
    """True when a suspicious verdict is backed by a fired probe/tool.

    Detection-role receipts count here, unlike the verification-role
    gate: a fired probe that flagged the mechanism is a tool
    observation, and an LLM argument alone must not erase it (it may
    only be answered by a verification-role refuter). ``llm-claimed:``
    probe references qualify only when the orchestrator's own dispatch
    record shows that tool family actually ran for this outcome — the
    claim is then corroborated by the run's own records, not taken on
    faith. ``prefilter:`` stamps never qualify: a pattern-scan prior
    is not a fired probe.
    """
    from .evidence_grade import LLM_CLAIM_PREFIX, is_tool_evidence

    ev = outcome.evidence_tool or ""
    if not ev:
        review = outcome.review_result or {}
        raw = str(review.get("evidence_tool", "") or "")
        ev = "+".join(
            p
            for p in (_sanitize_llm_et(part.strip()) for part in raw.split("+"))
            if p
        )
    if not ev:
        return False
    dispatched = {
        str(t).strip().lower()
        for t in (outcome.tools_dispatched or set())
        if str(t).strip()
    }
    detection_namespaces: set[str] = set()
    for part in (p.strip() for p in ev.split("+")):
        if not part:
            continue
        if part.lower().startswith(LLM_CLAIM_PREFIX):
            claimed = part[len(LLM_CLAIM_PREFIX):].strip().lower()
            fam = claimed.split(":", 1)[0].strip()
            if fam and any(
                d == fam or d.startswith(fam) for d in dispatched
            ):
                return True
            continue
        if part.startswith("prefilter:"):
            continue
        if _is_detection_only(part):
            # A single detection-role receipt (inject-mode checker,
            # -majority consistency variant) surfaces a candidate but
            # is documented as too imprecise to convict alone; a
            # deepen re-review that examined the mechanism and
            # concluded clean may answer it. Two INDEPENDENT
            # detection namespaces agreeing keep the floor — that is
            # the aggregation-promotion shape.
            detection_namespaces.add(part.split(":", 1)[0].lower())
            continue
        if is_tool_evidence(part):
            return True
    return len(detection_namespaces) >= 2


def _stamp_evidence(outcome: ReviewOutcome, tool: str) -> ReviewOutcome:
    """Stamp evidence_tool onto an outcome."""
    outcome.evidence_tool = tool
    if outcome.review_result:
        outcome.review_result["evidence_tool"] = tool
    return outcome


def _record_uncorrelated_hits(outcome: ReviewOutcome, hits) -> None:
    """Keep tool hits that don't correlate with the hypothesis as context.

    They stay visible for review but never stamp evidence_tool or
    drive status changes.
    """
    if outcome.review_result is None:
        outcome.review_result = {}
    ctx = outcome.review_result.setdefault("uncorrelated_tool_hits", [])
    seen = {(h.get("tool"), h.get("rule_id"), h.get("line")) for h in ctx}
    for hit in hits:
        key = (
            getattr(hit, "tool", "prefilter"),
            getattr(hit, "rule_id", ""),
            getattr(hit, "line", 0),
        )
        if key in seen:
            continue
        seen.add(key)
        ctx.append({
            "tool": key[0],
            "rule_id": key[1],
            "line": key[2],
            "message": getattr(hit, "message", ""),
        })


def _has_mechanical_corroboration(
    outcome: ReviewOutcome,
    config: OrchestratorConfig,
    sarif_cache: SarifCache | None,
    checklist: dict[str, Any] | None,
    *,
    domain_model: dict[str, Any] | None = None,
    mechanical_findings: dict[str, list[dict[str, Any]]] | None = None,
) -> bool:
    """Check if any mechanical tool independently flags this function.

    Used to bypass reasoning-chain gates (precondition checks) when
    code-level evidence already confirms the bug pattern.
    Domain-model invariants count as mechanical corroboration because
    they have provenance from the study pipeline.
    """
    # Prep-phase mechanical detector hits (standing cocci rules,
    # condition chain, callback lifetime) are keyed by file:function
    # and position-anchored — they ARE independent mechanical flags.
    if mechanical_findings and mechanical_findings.get(
        f"{outcome.file}:{outcome.function}",
    ):
        return True

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
    checklist: dict[str, Any],
) -> str | None:
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
    """Demote a finding to suspicious with a reason prefix.

    Carries the dispatch record (tools_dispatched / tools_errored) and
    semantic confidence through the demotion — gate resolution reads
    them off the demoted outcome to decide clean vs dark.
    """
    demoted = ReviewOutcome(
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
    demoted.tools_dispatched = outcome.tools_dispatched
    demoted.tools_errored = outcome.tools_errored
    demoted.semantic_confidence = outcome.semantic_confidence
    demoted.provenance_all_trusted = outcome.provenance_all_trusted
    demoted.function_qualified = getattr(
        outcome, "function_qualified", "",
    )
    return demoted


_MAX_PROPAGATION_ROUNDS = 5


def _extract_and_propagate(
    outcome: ReviewOutcome,
    constraints: list,
    checklist: dict[str, Any],
    entry_points: set,
    prop_config: PropagationConfig,
    tier_counters: dict[str, TierCounters] | None = None,
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


def _try_understand_bridge(config: OrchestratorConfig) -> dict[str, Any] | None:
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
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    fuzz_coverage: dict[str, Any] | None,
    evidence_index: dict[str, EvidenceRecord],
    sarif_cache: SarifCache | None,
    entry_points: set,
    gaps_before_joern: list[dict[str, Any]],
    start_time: float,
    on_progress: Callable | None,
    audit_log: list[dict[str, Any]] | None = None,
    session_observations: list[dict[str, str]] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
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
    seen_candidate_keys: set[str] = set()
    for gap in gaps_before_joern:
        key = f"{gap['file']}:{gap['name']}"
        # Duplicate gaps (same function under two keys, e.g. same name
        # at different lines) resolve to the same prior outcome — the
        # second replace would raise ValueError from outcomes.index().
        if key in seen_candidate_keys:
            continue
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
            seen_candidate_keys.add(key)
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
        prior_hyps = _prior_hypotheses_for(prior_outcome)
        if prior_hyps:
            ctx["prior_hypotheses"] = prior_hyps
        prepared.append((len(prepared), gap, prior_outcome, ctx))

    def _do_review(item):
        idx, _gap, _prior, ctx = item
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:  # noqa: BLE001
            return (idx, None, exc)

    raw_results = _collect_reviews_until_budget(
        prepared,
        _do_review,
        lambda: _check_budget(config, start_time, result),
        effective_workers,
        phase_label="joern re-review",
    )

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

            # Guarded like the sibling passes (_iterative_re_review,
            # _callee_contract_requeue): the prior outcome may no
            # longer be in the list by replace time.
            if prior_outcome in result.outcomes:
                _untally_outcome(result, prior_outcome)
                oi = result.outcomes.index(prior_outcome)
                result.outcomes[oi] = outcome
                _tally_outcome(result, outcome, append=False)
            else:
                result.outcomes.append(outcome)
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
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    fuzz_coverage: dict[str, Any] | None,
    evidence_index: dict[str, Any],
    discovered_evidence: dict[str, Any] | None = None,
    session_observations: list[dict[str, str]] | None = None,
    joern_server=None,
    start_time: float = 0.0,
    on_progress: Callable | None = None,
    max_workers: int = 1,
) -> int:
    """Re-review callers whose callee assumptions were contradicted.

    Scans outcomes for ``relies_on`` references.  When a callee was
    reviewed and found to have a finding/suspicious status, any caller
    that assumed the callee was safe is re-reviewed with the callee's
    actual result injected as context.

    Returns the count of callers re-reviewed.
    """
    callee_outcomes: dict[str, ReviewOutcome] = {}
    for o in result.outcomes:
        callee_outcomes[o.function] = o
        callee_outcomes[f"{o.file}:{o.function}"] = o

    candidates: list[tuple] = []
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
        # Poll the budget/SIGTERM rails before EACH dispatch — this
        # pass runs after the main loop, exactly where a budget-
        # stopped run would otherwise overrun the drain margin.
        if _check_budget(config, start_time, result):
            return (idx, None, None)
        try:
            outcome = review_fn(ctx, config)
            return (idx, outcome, None)
        except Exception as exc:  # noqa: BLE001
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
            futs = {pool.submit(_do_review, item): item
                    for item in prepared}
            for fut in as_completed(futs):
                raw_results.append(fut.result())

    re_reviewed = 0
    for idx, outcome, exc in sorted(raw_results, key=lambda r: r[0]):
        _, gap, prior_outcome, _ctx = prepared[idx]
        if outcome is None and exc is None:
            continue  # budget-skipped — never dispatched
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
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    evidence_index: dict[str, EvidenceRecord],
    sarif_cache: SarifCache | None,
    entry_points: set,
    reading_list_functions: set,
    start_time: float,
    on_progress: Callable | None,
    audit_log: list[dict[str, Any]] | None = None,
    session_observations: list[dict[str, str]] | None = None,
    discovered_evidence: dict[str, Any] | None = None,
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
    seen_candidate_keys: set[str] = set()
    for key in reading_list_functions:
        parts = key.split(":", 1)
        if len(parts) != 2:
            continue
        file_path, func_name = parts

        # Duplicate entries (same function listed twice) resolve to the
        # same prior outcome — without dedupe the second replace would
        # raise ValueError from outcomes.index() (same pattern as
        # _re_review_joern_enriched).
        candidate_key = f"{file_path}:{func_name}"
        if candidate_key in seen_candidate_keys:
            continue

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
        seen_candidate_keys.add(candidate_key)
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
        # Contradiction quarantine: the re-review sees BOTH the
        # original assumption and the sourced study answer (with its
        # receipt and tier) — never a silent substitution.
        # Keyed by THIS candidate's gap (the stale
        # file_path/func_name bindings from the candidate-collection
        # loop above handed every prepared context the LAST-iterated
        # function's answers — wrong sourced answers shown to the
        # reviewer, wrong receipts threaded into study_receipts,
        # _record_study_flip fired off another function's answers).
        if config.out_dir is not None:
            try:
                from core.concepts.study_answers import (
                    answers_for_function,
                )
                sa = answers_for_function(
                    config.out_dir, gap["file"], gap["name"],
                )
                if sa:
                    ctx["study_answers"] = sa
            except Exception:
                logger.debug(
                    "study answers load failed for %s:%s",
                    gap["file"], gap["name"], exc_info=True,
                )
        prior_hyps = _prior_hypotheses_for(prior_outcome)
        if prior_hyps:
            ctx["prior_hypotheses"] = prior_hyps
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
        except Exception as exc:  # noqa: BLE001
            return (idx, None, exc)

    raw_results = _collect_reviews_until_budget(
        prepared,
        _do_review,
        lambda: _check_budget(config, start_time, result),
        effective_workers,
        phase_label="study re-review",
    )

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

        # Receipt threading: a verdict whose re-review was triggered
        # by study answers embeds their receipts in its evidence
        # chain, so one bad answer's blast radius is traceable.
        study_answers = ctx.get("study_answers") or []
        if study_answers and isinstance(outcome.review_result, dict):
            receipts = []
            for a in study_answers:
                if a.get("status") != "resolved":
                    continue
                receipt = a.get("receipt") or {}
                receipts.append({
                    "question": str(a.get("question", ""))[:200],
                    "tier": a.get("tier", ""),
                    "file": receipt.get("file", ""),
                    "line": receipt.get("line"),
                    "sha256": receipt.get("sha256", ""),
                    "verified": bool(receipt.get("verified")),
                })
            if receipts:
                outcome.review_result["study_receipts"] = receipts

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
            # Guarded like the sibling passes (_re_review_joern_enriched,
            # _callee_contract_requeue): the prior outcome may no longer
            # be in the list by replace time.
            if prior_outcome in result.outcomes:
                _untally_outcome(result, prior_outcome)
                oi = result.outcomes.index(prior_outcome)
                result.outcomes[oi] = outcome
                _tally_outcome(result, outcome, append=False)
            else:
                result.outcomes.append(outcome)
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
            if ctx.get("study_answers"):
                _record_study_flip(config, outcome)

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


def _fuse_all_evidence(ctx: dict[str, Any]) -> None:
    """Fuse mechanical, negative-space, typestate, postcondition, and spec evidence.

    Converts per-capability domain objects into GradedEvidence, then runs
    cross-source fusion to corroborate signals before the LLM review.
    Populates ctx["fused_evidence"] with the rendered text.
    """
    from .evidence_fusion import format_fused_evidence, fuse_evidence
    from .evidence_grade import Confidence, EvidenceSource, GradedEvidence

    mechanical = ctx.pop("_graded_mechanical", [])

    spec_ev: list[GradedEvidence] = []
    spec = ctx.get("inferred_spec")
    if spec:
        spec_ev.extend(GradedEvidence(
                    source=EvidenceSource.LLM_SPEC,
                    confidence=Confidence.LOW,
                    description=f"spec precondition: {pc}",
                ) for pc in getattr(spec, "preconditions", []) or [])
        spec_ev.extend(GradedEvidence(
                    source=EvidenceSource.LLM_SPEC,
                    confidence=Confidence.LOW,
                    description=f"spec negative: {ns}",
                ) for ns in getattr(spec, "negative_specs", []) or [])

    ns_ev: list[GradedEvidence] = []
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

    contract_ev: list[GradedEvidence] = []
    for viol in ctx.get("postcondition_violations", []):
        desc = getattr(viol, "description", "") or str(viol)
        contract_ev.append(
            GradedEvidence(
                source=EvidenceSource.COCCINELLE,
                confidence=Confidence.MEDIUM,
                description=f"postcondition violation: {desc}",
            )
        )

    ts_ev: list[GradedEvidence] = []
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


def _merge_validate_evidence(bridge_result, evidence_index) -> None:
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
    llm_client: Callable | None = None,
    start_time: float | None = None,
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
        from .cwe_dispatch import dark_verify_applicable, dark_verify_statuses
    except ImportError:
        def dark_verify_applicable(_cwe) -> bool:
            return False

        def dark_verify_statuses(_cwe) -> None:
            return None

    def _eligible(o: ReviewOutcome) -> bool:
        if o.status == "dark":
            return True
        # The adversarial refuter concluded the hypothesis cannot be
        # settled by reading the code — witness execution is exactly
        # the evidence it asked for.
        if (o.review_result or {}).get("adversarial_needs_evidence"):
            return True
        cwe = (
            (o.review_result or {}).get("cwe_class")
            or (o.review_result or {}).get("cwe")
            or ""
        )
        if not (cwe and dark_verify_applicable(cwe)):
            return False
        # P10 families declare a status filter bounding witness-call
        # cost: a clean outcome in those classes does not spend an LLM
        # call. Families without a filter keep the original behaviour.
        allowed = dark_verify_statuses(cwe)
        return allowed is None or o.status in allowed

    dark_outcomes = [o for o in result.outcomes if _eligible(o)]
    if not dark_outcomes:
        return

    records: list[dict[str, Any]] = []

    for outcome in dark_outcomes:
        # Poll the budget/SIGTERM rails before each witness dispatch:
        # this post-loop pass multiplies with the expanded CWE
        # eligibility, and without polling neither the SIGTERM drain
        # nor max_seconds could stop it — budget exhaustion just made
        # every remaining iteration a failed LLM call.
        if start_time is not None and _check_budget(
            config, start_time, result,
        ):
            logger.info(
                "dark verification stopped — budget/deadline exhausted "
                "(%d/%d outcomes verified)",
                len(records), len(dark_outcomes),
            )
            break
        lang = language_for_file(outcome.file)
        if lang is None:
            continue

        prompt, system = build_witness_prompt(
            file=outcome.file,
            function=outcome.function,
            hypothesis=outcome.hypothesis,
            body=outcome.body,
            language=lang,
            model_id=(
                config.models[0]
                if config.models and config.models[0] != "default"
                else ""
            ),
        )

        try:
            llm_response = llm_client(prompt, system)
        # Silent skip is intentional: an LLM failure just drops this
        # outcome from dark verification.
        except Exception:  # noqa: BLE001, S112
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

        # The run dir keeps sandbox --audit evidence for the witness's
        # compile/run steps persistent — without it the tracer writes
        # into the step's throwaway scratch dir, swept on completion.
        verify_result = execute_witness(
            spec, config.target_path, audit_run_dir=config.out_dir,
        )

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
            # Tool-backed floor: an executed witness is ONE LLM-guessed
            # input. It can refute its own prediction, but it cannot
            # erase a deterministic engine receipt (SMT / Coccinelle /
            # Semgrep / CodeQL verification) — an overflow that doesn't
            # crash on the guessed input is still an overflow. Findings
            # with verification-grade evidence cap at suspicious with
            # the refute recorded; everything else demotes to clean as
            # before. Mirrors the dampening rule ("tool-backed findings
            # are never demoted") and the runtime-veto floor.
            from .evidence_grade import is_tool_evidence

            prior_evidence = outcome.evidence_tool or ""
            tool_backed = (
                prior in ("finding", "suspicious")
                and is_tool_evidence(prior_evidence)
            )
            if tool_backed:
                outcome.status = "suspicious"
                if "dark_verify:refuted" not in prior_evidence:
                    outcome.evidence_tool = (
                        f"{prior_evidence}+dark_verify:refuted"
                    )
                if prior == "finding":
                    result.findings -= 1
                    result.suspicious += 1
            else:
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
        save_json(results_path, records)
