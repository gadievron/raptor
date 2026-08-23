"""Shared audit pipeline entry point.

Both ``libexec/raptor-audit run`` and the corpus runner call
``run_audit_pipeline()`` so setup logic lives in one place and the
corpus runner can run in-process (no subprocess, no cold-start).
"""

from __future__ import annotations

import contextlib
import enum
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class ReviewMode(str, enum.Enum):
    SECURITY = "security"
    BUG_FIRST = "bug_first"
    QUALITY = "quality"
    ENSEMBLE = "ensemble"

    @property
    def is_defect_oriented(self) -> bool:
        return self in (ReviewMode.BUG_FIRST, ReviewMode.QUALITY)

    @property
    def has_security_phase(self) -> bool:
        return self == ReviewMode.BUG_FIRST


class VerificationTier(str, enum.Enum):
    CONFIRMED = "confirmed"
    TOOL_BACKED = "tool_backed"
    LLM_ONLY = "llm_only"
    SPECULATIVE = "speculative"

    @property
    def max_severity(self) -> str:
        return _TIER_SEVERITY_CAP[self]


_TIER_SEVERITY_CAP = {
    VerificationTier.CONFIRMED: "critical",
    VerificationTier.TOOL_BACKED: "high",
    VerificationTier.LLM_ONLY: "medium",
    VerificationTier.SPECULATIVE: "low",
}


@dataclass
class AuditPipelineOpts:
    """Plain-data options for ``run_audit_pipeline``.

    Every field has a sensible default so callers only set what they need.
    """

    target_path: Path = field(default_factory=lambda: Path("."))
    out_dir: Path = field(default_factory=lambda: Path("out"))
    scope: list[str] | None = None
    scope_floor: bool = True
    # ``--pin file:function`` (repeatable): guaranteed review slots
    # hoisted ahead of the budget cut; never excludes other gaps.
    pins: list[str] | None = None
    functions: list[str] | None = None
    models: list[str] | None = None
    max_cost_usd: float | None = None
    max_seconds: float | None = None
    budget: int | None = None
    strategy_filter: str | None = None
    review_passes: int = 1
    batch_sloc_threshold: int | None = None
    include_kinds: set | None = None
    adversarial: bool = False
    # Opt-in LLM re-rank of the gap-queue head within priority tiers
    # (core.audit.gap_ranking) — forwarded to OrchestratorConfig.
    rank_gaps: bool = False
    max_propagation_depth: int | None = None
    subsystem_depth: int = 0
    validate: bool = True
    no_binary_oracle: bool = False
    binary_verdicts: dict[str, str] | None = None
    inventory: dict[str, Any] | None = None
    annotations_dir: Path | None = None
    codeql_db_path: str | None = None
    # Repeatable --codeql-db (one database per language).
    codeql_db_paths: list[str] | None = None
    threat_model: dict[str, Any] | None = None
    joern_overrides: dict[str, Any] | None = None
    joern_server: Any | None = None
    on_progress: Callable | None = None
    study_root: Path | None = None
    mode: ReviewMode = ReviewMode.ENSEMBLE
    max_workers: int = 0
    # Tri-state: True/False = explicit per-run choice (--dynamic /
    # --no-dynamic); None = defer to the active project's 'dynamic'
    # trust marker, else off. Resolved via
    # core.project.trust.resolve_dynamic_validation at config build.
    dynamic_validation: bool | None = None
    # Cross-run verdict reuse (--no-verdict-reuse to disable): import
    # prior-run verdicts for functions whose source hash is unchanged
    # instead of silently suppressing them.
    verdict_reuse: bool = True
    # Cross-function edge obligations (--edges): flag-gated review of
    # tier-1 edge contracts + tier-2 folded edge verdicts.
    edges: bool = False
    # Ignore all prior review state — coverage records, the per-run
    # review journal, the project journal index, and recall caches —
    # so every scheduled function is re-reviewed. The corpus runner
    # sets this: a label pin must never be suppressed by state left
    # behind by an earlier run. Production default unchanged (off).
    force: bool = False
    # Prefilter skip_llm shortcut. False keeps the prefilter running
    # (hits still feed review context) but its skip verdict no longer
    # resolves a scheduled function clean without review. The corpus
    # runner defaults this off for the same reason as ``triage``:
    # labels encode deep-mechanism expectations that a mechanical skip
    # can never exercise. Production default unchanged (on).
    prefilter_skip: bool = True
    # Triage-classifier SKIP shortcut. False disables the skip so every
    # scheduled function receives a real review. The corpus runner
    # defaults this off: labels encode deep-mechanism expectations
    # that a classifier skip can never exercise. Production default
    # unchanged (on).
    triage: bool = True
    # Vendored/generated-code triage tier (--no-vendored-triage to
    # disable): corroborated generator provenance → skip tier;
    # uncorroborated banners / vendored paths / generated-shape
    # structure → glance tier. Every decision leaves a
    # suppressions.jsonl record; pinned gaps are exempt.
    vendored_triage: bool = True
    # ── Accumulated-knowledge gates (see OrchestratorConfig) ────────
    # All default ON — production behaviour unchanged. The corpus
    # runner's cold profile turns them off so a measurement run sees
    # what a first-time user with default flags and cold caches would
    # see. ``profile`` is the label stamped into the per-gate disable
    # log lines.
    profile: str = "deployed"
    # IRIS: spec synthesis, sink-store reads, refinement (incl.
    # prior_specs store reads), heuristic assumption passes.
    iris: bool = True
    # SAGE recall reads (hypothesis verdicts, prior-run observations,
    # proven-rule replay). Writes unaffected.
    sage_recall: bool = True
    # Graduated-rule library replay (find_replayable). In-run
    # on-demand synthesis and library writes stay on.
    library_replay: bool = True
    # Cross-run journal reads: verdict-reuse eligibility + sibling/
    # project journal sources for external synthesis seeds.
    cross_run_import: bool = True
    # Prior domain-model import (in-run study output still read).
    domain_model_import: bool = True
    # Operator annotation reads.
    annotations_read: bool = True
    # Opt-in (--pre-scan): bounded semgrep baseline pass when no scan
    # SARIF exists in this run or any fresh sibling run.
    pre_scan: bool = False
    # Caller-contract call-site digest in the review context
    # (--no-caller-contract-context to disable).
    caller_contract_context: bool = True
    # Parallel review scheduling: "cost" = most-expensive-first
    # makespan packing (default), "priority" = time-to-first-finding.
    schedule: str = "cost"
    # On-demand Mode-2 checker synthesis for chain-less suspicious
    # hypotheses (--no-on-demand-synthesis to disable). Capped per run.
    on_demand_synthesis: bool = True
    # Determine-value compile probes (--probe-determine-value):
    # bisection over static assertions for claim-less constant study
    # questions. Default off (up to ~66 sandboxed compiles/constant).
    probe_determine_value: bool = False
    # Slice of --max-cost held back for the deepen phase so announced
    # re-reviews can execute (None = orchestrator default).
    deepen_reserve_fraction: float | None = None
    # Slice of --max-cost held back from the pre-review bulk passes
    # so the review loop is guaranteed headroom (None = orchestrator
    # default, off). The corpus runner sets it per group.
    review_reserve_fraction: float | None = None
    # Same-run resume (raptor-audit resume): re-import this run's own
    # journal verdicts at $0 and re-review only the remaining gaps.
    same_run_reuse: bool = False
    # Prior segments' reconciled cost-breakdown.json contents; booked
    # into the run ledger at reconciliation so the rewritten ledger
    # covers all segments.
    prior_cost_breakdown: dict[str, Any] | None = None
    # RESOLVED whole-run prior-segment spend (core.audit.resume.
    # resolve_prior_spend): reconciled ledger, else journal floor,
    # raised to the incremental spend floor. Booked at reconciliation
    # even when no prior ledger exists — a hard-killed segment's
    # spend must survive into every later segment's rewritten ledger.
    prior_booked_spend_usd: float = 0.0
    # Segment number for a resumed run (from core.run.metadata.
    # resume_run); 1 for a first run.
    resume_segment: int = 1
    # Extra run dirs whose review journals feed prior finding-grade
    # claims (/agentic per-finding analyses) into review context
    # (--prior-journal, repeatable). Covers journals not yet merged
    # into the project index.
    prior_journal_dirs: list[Path] | None = None
    # Per-function cap on prior finding-grade claims in review context
    # (--prior-claims; 0 disables) and the per-claim body excerpt.
    prior_claims_per_function: int = 3
    prior_claim_excerpt_chars: int = 600



def _resolve_dynamic(opts: AuditPipelineOpts) -> bool:
    """Resolve ``dynamic_validation``: explicit per-run choice wins;
    else the active project's ``dynamic`` trust marker (with the
    trust banner); else off. Best-effort — a project-substrate error
    must never break the audit."""
    try:
        from core.project.trust import resolve_dynamic_validation
        return resolve_dynamic_validation(
            opts.dynamic_validation, target_path=opts.target_path,
        )
    except Exception:  # noqa: BLE001 — fail-closed to off
        return bool(opts.dynamic_validation)


def _make_llm_client(opts: AuditPipelineOpts):
    """Build the budget-capped LLM client both entry points share.

    Returns ``(client, models, primary_model)``.
    """
    from core.llm.client import LLMClient
    from core.llm.config import LLMConfig

    models = opts.models or ["default"]
    primary_model = models[0] if models[0] != "default" else None
    max_cost = opts.max_cost_usd if opts.max_cost_usd is not None else float("inf")

    if primary_model:
        client = LLMClient(pinned_model=primary_model)
        client.config.max_cost_per_scan = max_cost
    else:
        llm_cfg = LLMConfig(max_cost_per_scan=max_cost)
        client = LLMClient(config=llm_cfg)
    _ensure_dispatcher_route(client, models)
    return client, models, primary_model


def _ensure_dispatcher_route(client, models: list[str]) -> None:
    """Self-serve an in-process dispatcher for dispatcher-only models.

    Bedrock is dispatcher-only (this process holds the AWS
    credentials; the SDK client itself never does).  Pipeline runs get
    the dispatcher from ``raptor.py``'s launcher, but the audit
    entry points (``raptor-audit run``, the corpus runner) call the
    LLM in-process — without a route every Bedrock-routed review dies
    with 'requires the RAPTOR LLM dispatcher' and the client silently
    falls back to the claudecode transport.  Same gate and lifecycle
    as the ``raptor-llm-ask`` self-serve.

    Scans the resolved primary + fallbacks AND every ``--model`` panel
    member (multi-model runs dispatch per-name via
    ``config_for_model``).  Best-effort: a dispatcher start failure
    must not kill the audit — the provider surfaces its own error.
    """
    import os

    if os.environ.get("RAPTOR_LLM_SOCKET"):
        return
    candidates = [client.config.primary_model]
    candidates.extend(client.config.fallback_models or [])
    for name in models:
        if name == "default":
            continue
        try:
            candidates.append(client.config.config_for_model(name))
        except Exception:  # unresolvable name surfaces later
            logger.debug("config_for_model(%r) failed", name, exc_info=True)
    try:
        from core.llm.dispatcher.lifecycle import (
            ensure_route_for_model_configs,
        )
        ensure_route_for_model_configs(candidates, label="raptor-audit")
    except Exception:  # provider errors surface downstream
        logger.warning(
            "could not start in-process LLM dispatcher for "
            "Bedrock-routed models", exc_info=True,
        )


def _build_orchestrator_config(
    opts: AuditPipelineOpts,
    client: Any,
    models: list[str],
    mode: ReviewMode,
):
    """Thread AuditPipelineOpts into an OrchestratorConfig.

    Single source of truth for the opts → config mapping — a new
    OrchestratorConfig field only needs wiring here for both
    ``run_audit_pipeline`` and ``run_ensemble_pipeline`` to pick it up.
    """
    from core.audit.orchestrator import OrchestratorConfig

    return OrchestratorConfig(
        target_path=opts.target_path,
        out_dir=opts.out_dir,
        budget=opts.budget,
        scope=opts.scope,
        scope_floor=opts.scope_floor,
        pins=opts.pins,
        strategy_filter=opts.strategy_filter,
        models=models,
        multi_model=len(models) > 1,
        adversarial=opts.adversarial,
        rank_gaps=opts.rank_gaps,
        max_cost_usd=opts.max_cost_usd,
        max_seconds=opts.max_seconds,
        review_passes=opts.review_passes,
        subsystem_depth=opts.subsystem_depth,
        **({"batch_sloc_threshold": opts.batch_sloc_threshold}
           if opts.batch_sloc_threshold is not None else {}),
        include_kinds=opts.include_kinds,
        max_propagation_depth=opts.max_propagation_depth,
        validate=opts.validate,
        no_binary_oracle=opts.no_binary_oracle,
        binary_verdicts=opts.binary_verdicts,
        inventory=opts.inventory,
        codeql_db_path=opts.codeql_db_path,
        codeql_db_paths=opts.codeql_db_paths,
        threat_model=opts.threat_model,
        annotations_dir=opts.annotations_dir,
        functions=opts.functions,
        joern_overrides=opts.joern_overrides,
        joern_server=opts.joern_server,
        study_root=opts.study_root,
        mode=mode,
        max_workers=opts.max_workers,
        dynamic_validation=_resolve_dynamic(opts),
        verdict_reuse=opts.verdict_reuse,
        edges=opts.edges,
        force=opts.force,
        prefilter_skip=opts.prefilter_skip,
        triage=opts.triage,
        vendored_triage=opts.vendored_triage,
        profile=opts.profile,
        iris=opts.iris,
        sage_recall=opts.sage_recall,
        library_replay=opts.library_replay,
        cross_run_import=opts.cross_run_import,
        domain_model_import=opts.domain_model_import,
        annotations_read=opts.annotations_read,
        pre_scan=opts.pre_scan,
        caller_contract_context=opts.caller_contract_context,
        schedule=opts.schedule,
        on_demand_synthesis=opts.on_demand_synthesis,
        probe_determine_value=opts.probe_determine_value,
        **({"deepen_reserve_fraction": opts.deepen_reserve_fraction}
           if opts.deepen_reserve_fraction is not None else {}),
        **({"review_reserve_fraction": opts.review_reserve_fraction}
           if opts.review_reserve_fraction is not None else {}),
        same_run_reuse=opts.same_run_reuse,
        prior_cost_breakdown=opts.prior_cost_breakdown,
        prior_booked_spend_usd=opts.prior_booked_spend_usd,
        resume_segment=opts.resume_segment,
        prior_journal_dirs=opts.prior_journal_dirs,
        prior_claims_per_function=opts.prior_claims_per_function,
        prior_claim_excerpt_chars=opts.prior_claim_excerpt_chars,
        llm_budget_client=client,
        llm_client=client,
    )


def run_audit_pipeline(opts: AuditPipelineOpts, *, prep_cache=None):
    """Run the audit orchestrator and return its result.

    Sets up the LLM client, builds the OrchestratorConfig, and calls
    ``run_orchestrator``.  Returns the ``OrchestratorResult``.
    """
    from core.llm.log_quiet import quiet_noisy_loggers

    quiet_noisy_loggers()

    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import run_orchestrator

    client, models, primary_model = _make_llm_client(opts)

    review_fn = make_review_fn(
        client, task_type="audit", model_name=primary_model,
        mode=opts.mode, out_dir=opts.out_dir,
    )
    config = _build_orchestrator_config(opts, client, models, opts.mode)

    if len(models) > 1:
        # Cross-model panel: one review_fn per configured model so the
        # multi-model dispatch actually invokes each model. Without
        # this map every panel member ran the models[0]-pinned
        # review_fn — the other configured models were never called.
        config.review_fns_by_model = {
            m: make_review_fn(
                client, task_type="audit",
                model_name=(m if m != "default" else None),
                mode=opts.mode, out_dir=opts.out_dir,
            )
            for m in models
        }

    return run_orchestrator(
        config, review_fn, on_progress=opts.on_progress, prep_cache=prep_cache,
    )


STATUS_RANK = {"clean": 1, "dormant": 2, "suspicious": 3, "finding": 4, "error": 0}
_STATUS_RANK = STATUS_RANK
NON_MECHANICAL = ("prefilter:", "llm-claimed:")
_NON_MECHANICAL = NON_MECHANICAL


def _is_verification_evidence(ev: str) -> bool:
    """True when evidence is strong enough to break a merge tie.

    Non-mechanical prefixes (prefilter, llm-claimed) are never
    verification.  Coccinelle and SMT evidence is verification only
    when the underlying rule/verb has verification role — detection-role
    rules are too imprecise to override a clean verdict.
    """
    if not ev or ev.startswith(_NON_MECHANICAL):
        return False
    # Import guard only: pipeline↔orchestrator is a potential import
    # cycle; _is_detection_only itself is a pure string check.
    with contextlib.suppress(ImportError):
        from core.audit.orchestrator import _is_detection_only
        if _is_detection_only(ev):
            return False
    return True


def _has_any_mechanical_evidence(ev: str) -> bool:
    """True when evidence comes from any mechanical tool (including detection-role).

    Weaker than ``_is_verification_evidence`` — accepts detection-role
    SMT/Coccinelle evidence.  Used by the ensemble merge to prevent
    discarding findings that have real tool support even if the tool's
    role is detection rather than verification.
    """
    return bool(ev) and not ev.startswith(_NON_MECHANICAL)


# ---------------------------------------------------------------------------
# Dual-mode accessor — works on ReviewOutcome objects and plain dicts
# ---------------------------------------------------------------------------

def _get(item, attr, dict_key=None, default: str=""):
    """Read a field from an object (attribute) or a dict (key)."""
    if isinstance(item, dict):
        return item.get(dict_key or attr, default)
    val = getattr(item, attr, default)
    if val is None:
        return default
    return val


def _set(item, attr, dict_key=None, value=None) -> None:
    """Write a field to an object or dict."""
    if isinstance(item, dict):
        item[dict_key or attr] = value
    else:
        setattr(item, attr, value)


def _get_status(item):
    if isinstance(item, dict):
        return item.get("actual", item.get("status", ""))
    return getattr(item, "status", "")


def _set_status(item, status) -> None:
    if isinstance(item, dict):
        item["actual"] = status
    else:
        item.status = status


def _get_file(item):
    if isinstance(item, dict):
        fid = item.get("function_id", "")
        return fid.rsplit(":", 1)[0] if ":" in fid else item.get("file", "")
    return getattr(item, "file", "")


def _get_evidence(item):
    if isinstance(item, dict):
        return item.get("evidence_tool", "") or item.get("evidence", "")
    return getattr(item, "evidence_tool", "") or ""


def _get_hypothesis(item):
    if isinstance(item, dict):
        return item.get("hypothesis", "") or ""
    return getattr(item, "hypothesis", "") or ""


def _get_counter(item):
    if isinstance(item, dict):
        return item.get("counter_hypothesis", "") or ""
    rr = getattr(item, "review_result", None) or {}
    return rr.get("counter_hypothesis", "") or ""


def _get_bug_class_rr(item):
    if isinstance(item, dict):
        return item.get("bug_class", "") or ""
    rr = getattr(item, "review_result", None) or {}
    return rr.get("bug_class", "") or ""



def _needs_second_pass(outcome) -> bool:
    """True when pass 1 result is uncertain enough to warrant pass 2."""
    if outcome.status != "clean":
        return True
    ev = outcome.evidence_tool or ""
    return bool(ev) and not ev.startswith(NON_MECHANICAL)


def _merge_outcomes(sec_outcomes, bf_outcomes):
    """Merge ReviewOutcome lists: max-alarm with evidence preservation."""
    from copy import copy

    sec_by_key = {(o.file, o.function): o for o in sec_outcomes}
    bf_by_key = {(o.file, o.function): o for o in bf_outcomes}
    all_keys = set(sec_by_key) | set(bf_by_key)
    merged = []

    for key in sorted(all_keys):
        sec = sec_by_key.get(key)
        bf = bf_by_key.get(key)
        if sec and bf:
            sr = _STATUS_RANK.get(sec.status, 0)
            br = _STATUS_RANK.get(bf.status, 0)
            higher = sec.status if sr >= br else bf.status

            use_max = True
            if higher in ("suspicious", "finding") and not (sr >= 3 and br >= 3):
                sec_ev = sec.evidence_tool or ""
                bf_ev = bf.evidence_tool or ""
                has_evidence = (
                    _is_verification_evidence(sec_ev)
                    or _is_verification_evidence(bf_ev)
                )
                if not has_evidence:
                    use_max = False

            if use_max:
                winner = copy(bf if br > sr else sec)
            else:
                # Conservative merge: the lower-ranked outcome wins.
                # It can never be a finding here — use_max is only
                # False when exactly one side is >= suspicious, so the
                # lower side is at most dormant.
                winner = copy(sec if sr <= br else bf)

            if br > sr and winner.evidence_tool and sec.evidence_tool:
                winner.evidence_tool = (
                    bf.evidence_tool + "+" + sec.evidence_tool
                )
            elif sr > br and winner.evidence_tool and bf.evidence_tool:
                winner.evidence_tool = (
                    sec.evidence_tool + "+" + bf.evidence_tool
                )

            winner.cost_usd = sec.cost_usd + bf.cost_usd
            merged.append(winner)
        else:
            merged.append(copy(sec or bf))
    return merged


def run_ensemble_pipeline(opts: AuditPipelineOpts):
    """Per-function pipelined ensemble: pass 1 → conditional pass 2 → merge.

    Each function is reviewed in security mode first.  If the result is not
    a confident clean (non-clean status or has evidence), a bug_first
    review runs immediately and the two outcomes are merged.  The executor parallelises across functions, so
    pass-2 reviews for early functions overlap with pass-1 reviews for
    later ones — wall-clock ≈ max(per-function chains), not sum-of-passes.
    """
    import threading
    import time

    from core.llm.log_quiet import quiet_noisy_loggers

    quiet_noisy_loggers()

    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import run_orchestrator

    t0 = time.monotonic()

    client, models, primary_model = _make_llm_client(opts)

    sec_review = make_review_fn(
        client, task_type="audit", model_name=primary_model,
        mode=ReviewMode.SECURITY, out_dir=opts.out_dir,
    )
    bf_review = make_review_fn(
        client, task_type="audit", model_name=primary_model,
        mode=ReviewMode.BUG_FIRST, out_dir=opts.out_dir,
    )

    _counters = {"pass2_skipped": 0, "pass2_run": 0}
    _lock = threading.Lock()

    def ensemble_review_fn(ctx, config):
        outcome1 = sec_review(ctx, config)

        if not _needs_second_pass(outcome1):
            with _lock:
                _counters["pass2_skipped"] += 1
            return outcome1

        with _lock:
            _counters["pass2_run"] += 1

        outcome2 = bf_review(ctx, config)
        merged = _merge_outcomes([outcome1], [outcome2])
        if not merged:
            return outcome1
        result = merged[0]
        result.cost_usd = outcome1.cost_usd + outcome2.cost_usd
        result.duration_s = outcome1.duration_s + outcome2.duration_s
        return result

    config = _build_orchestrator_config(
        opts, client, models, ReviewMode.SECURITY,
    )
    # File-level pile-up dampening runs as a pre-export hook INSIDE the
    # orchestrator so the journal correction pass, findings-graded.json
    # and the summary counters all see the same (dampened) statuses.
    # Running it post-hoc here left the export disagreeing with stats.
    config.pre_export_hooks = [dampen_pileup_pre_export]

    result = run_orchestrator(
        config, ensemble_review_fn, on_progress=opts.on_progress,
    )

    logger.info(
        "Pipelined ensemble: %d pass2 skipped, %d pass2 run",
        _counters["pass2_skipped"], _counters["pass2_run"],
    )

    result.total_duration_s = time.monotonic() - t0

    return result


# -- #4: file-level over-alert dampening ----------------------------------

HYPOTHESIS_CLASS_KW = {
    "arithmetic": ("overflow", "underflow", "integer", "wraparound", "truncat"),
    "bounds": ("bounds", "oob", "out-of-bound", "buffer", "off-by-one"),
    "null_deref": ("null", "nullptr", "nil deref", "null pointer"),
    "concurrency": ("race", "toctou", "concurrent", "deadlock", "mutex", "atomic"),
    "memory_safety": ("free", "use-after", "double-free", "dangling", "uninitiali"),
    "injection": ("inject", "sql", "xss", "command inject", "format string"),
    "auth": ("auth", "permission", "privilege", "bypass", "acl", "access control"),
    "resource_leak": ("leak", "resource", "handle", "descriptor"),
    "type_confusion": ("type confus", "cast", "downcast"),
    "crypto": ("crypto", "random", "weak key", "iv reuse"),
    "information_disclosure": ("disclosure", "information leak", "expose"),
}
_HYPOTHESIS_CLASS_KW = HYPOTHESIS_CLASS_KW


def extract_bug_class(item) -> str:
    """Extract a bug-class label from review result or hypothesis.

    Works on both ReviewOutcome objects and plain dicts.
    """
    bc = _get_bug_class_rr(item)
    if bc and bc != "other":
        return bc
    hyp = _get_hypothesis(item).lower()
    for cls, keywords in HYPOTHESIS_CLASS_KW.items():
        if any(kw in hyp for kw in keywords):
            return cls
    return "other"

_extract_bug_class = extract_bug_class


FILE_CLASS_THRESHOLD = 3
FILE_AGNOSTIC_THRESHOLD = 4
FILE_AGNOSTIC_KEEP = 2
FILE_HEAVY_THRESHOLD = 6
FILE_HEAVY_KEEP = 1
_FILE_CLASS_THRESHOLD = FILE_CLASS_THRESHOLD
_FILE_AGNOSTIC_THRESHOLD = FILE_AGNOSTIC_THRESHOLD
_FILE_AGNOSTIC_KEEP = FILE_AGNOSTIC_KEEP
_FILE_HEAVY_THRESHOLD = FILE_HEAVY_THRESHOLD
_FILE_HEAVY_KEEP = FILE_HEAVY_KEEP


NEAR_DUP_JACCARD = 0.6
DAMPENING_MARKER = "[file-dampening]"
DAMPENING_LOG = "dampening-log.jsonl"


def _hypothesis_tokens(item) -> frozenset:
    import re

    return frozenset(re.findall(r"[a-z0-9_]+", _get_hypothesis(item).lower()))


def _near_duplicate(a: frozenset, b: frozenset) -> bool:
    """Token-Jaccard near-duplicate check between two hypotheses."""
    if not a or not b:
        return False
    union = len(a | b)
    return union > 0 and (len(a & b) / union) >= NEAR_DUP_JACCARD


def _get_function(item):
    if isinstance(item, dict):
        fid = item.get("function_id", "")
        if ":" in fid:
            return fid.rsplit(":", 1)[1]
        return item.get("function", "")
    return getattr(item, "function", "")


def _mark_dampened(item, info: dict) -> None:
    """Stamp a body marker + structured record on a dampened outcome."""
    hyp = _get_hypothesis(item)
    if DAMPENING_MARKER not in hyp:
        _set(item, "hypothesis", value=(hyp + " " + DAMPENING_MARKER).strip())
    if isinstance(item, dict):
        item["file_dampening"] = info
        return
    rr = getattr(item, "review_result", None)
    if isinstance(rr, dict):
        rr["file_dampening"] = info
    else:
        # Outcome objects vary (dicts, dataclasses, mocks); slotted or
        # frozen ones reject the attribute — dampening info is optional.
        with contextlib.suppress(AttributeError):
            item.review_result = {"file_dampening": info}


def dampen_file_pileup(outcomes, records: list | None = None) -> int:
    """Soften evidence-free pile-up findings — never demote to clean.

    Works on both ReviewOutcome objects and plain dicts.

    Vulnerability density is heavy-tailed: the one legacy file with six
    genuine issues is where audits earn their keep, so demotion is at
    most one step (finding→suspicious) and ``suspicious`` outcomes are
    never silenced to ``clean``.

    Two tiers:
    1. Near-duplicate collapse: >=3 evidence-free suspicious/finding
       outcomes in the same file whose hypotheses are near-duplicates
       (token Jaccard >= NEAR_DUP_JACCARD) -> keep strongest, demote
       finding-status rest to suspicious. Suspicious members keep
       their status but are marked as collapsed into the survivor.
    2. File-level cap: >=4 evidence-free findings in the same file ->
       keep top 2 (top 1 at >=6 heavy pile-up), demote the excess
       finding→suspicious.

    Tool-backed findings are never demoted. Every affected outcome
    gets a ``[file-dampening]`` hypothesis/body marker plus a
    structured ``file_dampening`` record, and — when ``records`` is
    supplied — an audit-trail row appended to it.

    Returns the number of status DEMOTIONS (marker-only collapses of
    suspicious siblings are recorded but not counted).
    """
    from collections import defaultdict

    if records is None:
        records = []

    def _has_mechanical(i):
        ev = _get_evidence(outcomes[i])
        return ev and not ev.startswith(NON_MECHANICAL)

    tokens: dict[int, frozenset] = {}

    def _rank_key(i):
        return (
            STATUS_RANK.get(_get_status(outcomes[i]), 0),
            len(tokens.get(i, ())),
            len(_get_hypothesis(outcomes[i])),
        )

    def _dampen(idx, tier, group_size, kept_idx) -> int:
        cur = _get_status(outcomes[idx])
        new = "suspicious" if cur == "finding" else cur
        info = {
            "tier": tier,
            "from_status": cur,
            "to_status": new,
            "group_size": group_size,
            "kept_function": _get_function(outcomes[kept_idx]),
        }
        if new != cur:
            _set_status(outcomes[idx], new)
        _mark_dampened(outcomes[idx], info)
        records.append(
            {
                "file": _get_file(outcomes[idx]),
                "function": _get_function(outcomes[idx]),
                "hypothesis": _get_hypothesis(outcomes[idx]),
                **info,
            }
        )
        return 1 if new != cur else 0

    # Evidence-free suspicious/finding outcomes per file.
    file_groups: dict[str, list[int]] = defaultdict(list)
    for i, o in enumerate(outcomes):
        if _get_status(o) in ("suspicious", "finding") and not _has_mechanical(i):
            file_groups[_get_file(o)].append(i)
            tokens[i] = _hypothesis_tokens(o)

    already_dampened: set[int] = set()
    dampened = 0

    # --- Tier 1: near-duplicate hypothesis collapse ---
    for indices in file_groups.values():
        # Greedy clustering: an outcome joins the first cluster with a
        # near-duplicate member.
        clusters: list[list[int]] = []
        for i in indices:
            for cluster in clusters:
                if any(_near_duplicate(tokens[i], tokens[j]) for j in cluster):
                    cluster.append(i)
                    break
            else:
                clusters.append([i])

        for cluster in clusters:
            if len(cluster) < FILE_CLASS_THRESHOLD:
                continue
            ranked = sorted(cluster, key=_rank_key, reverse=True)
            for idx in ranked[1:]:
                dampened += _dampen(
                    idx, "near_duplicate", len(cluster), ranked[0],
                )
                already_dampened.add(idx)

    # --- Tier 2: file-level cap on evidence-free findings ---
    for indices in file_groups.values():
        if len(indices) < FILE_AGNOSTIC_THRESHOLD:
            continue
        ranked = sorted(indices, key=_rank_key, reverse=True)
        heavy = len(indices) >= FILE_HEAVY_THRESHOLD
        keep = FILE_HEAVY_KEEP if heavy else FILE_AGNOSTIC_KEEP
        tier = "file_cap_heavy" if heavy else "file_cap"
        for idx in ranked[keep:]:
            if idx in already_dampened:
                continue
            if _get_status(outcomes[idx]) != "finding":
                continue
            dampened += _dampen(idx, tier, len(indices), ranked[0])
            already_dampened.add(idx)

    return dampened

_dampen_file_pileup = dampen_file_pileup


def dampen_pileup_pre_export(result, config) -> None:
    """Pre-export hook: dampen pile-ups and write the audit trail.

    Runs inside the orchestrator BEFORE the journal correction pass
    and the graded findings export, so journal, export and summary
    counters all agree on the dampened statuses. One JSONL row per
    affected finding lands in ``<out_dir>/dampening-log.jsonl``.
    """
    import json

    records: list[dict] = []
    dampened = dampen_file_pileup(result.outcomes, records=records)

    out_dir = getattr(config, "out_dir", None)
    if records and out_dir:
        try:
            path = Path(out_dir) / DAMPENING_LOG
            with path.open("a", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec, sort_keys=True) + "\n")
        except Exception:
            logger.debug("dampening audit log write failed", exc_info=True)

    if dampened:
        logger.info(
            "file-level dampening: demoted %d pile-up findings "
            "(%d marked; see %s)",
            dampened, len(records), DAMPENING_LOG,
        )
        result.findings = sum(
            1 for o in result.outcomes if o.status == "finding"
        )
        result.suspicious = sum(
            1 for o in result.outcomes if o.status == "suspicious"
        )


# -- Counter-hypothesis veto -----------------------------------------------

COUNTER_PROTECTION_KW = (
    "prevented by", "prevented because", "guaranteed by", "ensured by",
    "enforced by", "validated by", "checked by", "protected by",
    "constrained by", "bounded by", "limited by", "cannot occur because",
    "impossible because", "initialization guarantees", "always set",
    "always valid", "always non-null", "never null",
    "invariant", "precondition", "postcondition",
    "write_once", "rcu_read_lock", "spin_lock", "mutex_lock",
    "bounds check", "length check", "size check", "range check",
)
_COUNTER_PROTECTION_KW = COUNTER_PROTECTION_KW


COUNTER_VETO_EXEMPT_KW = (
    "replay", "freshness", "nonce", "re-key", "rekey",
    "sequence number", "credential", "privilege escalation",
    "capability check", "capability bypass",
)


# Refutation-direction markers: the counter-hypothesis argues AGAINST
# the vulnerability (supports clean), not for it. Direction matters —
# a refuting counter is stuffed with vulnerability vocabulary
# ("refcount", "use-after-free", "TOCTOU") because it names the
# mechanisms it defeats, which fooled the vocabulary-only heuristics
# on both sides of this gate (live corpus case: a review that refuted
# an SMT check-early-release signal and every fresh mechanism was
# re-escalated to suspicious off its own refuting counter).
COUNTER_REFUTATION_KW = (
    "was refuted", "were refuted", "is refuted", "are refuted",
    "has been refuted", "have been refuted",
    "refuted with", "refuted by",
    "not a vulnerability", "not a security concern",
    "not a security issue", "not a security bug",
    "no security impact", "not security-relevant",
    "not security relevant", "not exploitable",
    "cannot be exploited", "defeating it as a security",
    "quality wart",
)


def counter_refutes_vulnerability(counter: str) -> bool:
    """True when the counter-hypothesis argues the vulnerability is NOT
    real (refutation direction), rather than arguing the verdict
    under-calls a real one."""
    lower = (counter or "").lower()
    return any(kw in lower for kw in COUNTER_REFUTATION_KW)


def _get_counter_direction(item) -> str:
    """Structured ``counter_direction`` emitted by the review model
    (``supports_vuln`` / ``refutes_vuln``), or "" when absent."""
    if isinstance(item, dict):
        raw = item.get("counter_direction", "") or ""
    else:
        rr = getattr(item, "review_result", None) or {}
        raw = rr.get("counter_direction", "") or ""
    return str(raw).strip().lower()


def counter_hypothesis_vetoes(item) -> bool:
    """True when a strong counter-hypothesis should veto a speculative finding.

    Works on both ReviewOutcome objects and plain dicts.
    Conditions: (1) no mechanical evidence, (2) counter-hypothesis is
    substantial and names a concrete protection mechanism,
    (3) hypothesis does not name a security-primitive pattern that
    counter-hypotheses are unreliable for.

    The structured ``counter_direction`` field, when present, replaces
    the prose re-derivation: refutes_vuln vetoes, supports_vuln never
    does. The keyword paths remain as the fallback for responses
    predating the field.
    """
    ev = _get_evidence(item)
    if ev and not ev.startswith(NON_MECHANICAL):
        return False

    counter = _get_counter(item)
    hyp = _get_hypothesis(item)

    if not counter:
        return False

    hyp_lower = hyp.lower()
    if any(kw in hyp_lower for kw in COUNTER_VETO_EXEMPT_KW):
        return False

    direction = _get_counter_direction(item)
    if direction == "supports_vuln":
        # The counter argues FOR the vulnerability — it corroborates
        # rather than refutes; there is nothing to veto with.
        return False
    if direction == "refutes_vuln":
        return True

    if len(counter) < 40:
        return False
    if len(counter) < len(hyp) * 0.6:
        return False

    lower = counter.lower()
    # A counter that asserts the hypothesis was refuted / is not a
    # security issue vetoes just like one naming a concrete protection
    # mechanism — both argue the speculative verdict is wrong in the
    # clean direction.
    return any(kw in lower for kw in COUNTER_PROTECTION_KW) or \
        counter_refutes_vulnerability(lower)

_counter_hypothesis_vetoes = counter_hypothesis_vetoes


def apply_counter_hypothesis_veto(outcomes) -> int:
    """Demote speculative findings/suspicious to clean via counter-hypothesis.

    Works on both ReviewOutcome objects and plain dicts.
    """
    vetoed = 0
    for o in outcomes:
        if _get_status(o) not in ("finding", "suspicious"):
            continue
        if counter_hypothesis_vetoes(o):
            _set_status(o, "clean")
            vetoed += 1
    return vetoed

_apply_counter_hypothesis_veto = apply_counter_hypothesis_veto


# -- Speculative-race gate --------------------------------------------------

RACE_HYPOTHESIS_KW = (
    "race condition", "toctou", "time-of-check", "time of check",
    "concurrent", "concurrently", "data race",
    "deadlock", "livelock",
)

RACE_EVIDENCE_ALLOWLIST = (
    "smt:", "coccinelle:", "semgrep:", "codeql:", "joern:",
    "sarif:", "prefilter:lock", "prefilter:race",
)


def is_speculative_race(item) -> bool:
    """True when a race/TOCTOU hypothesis lacks mechanical backing."""
    hyp = _get_hypothesis(item).lower()
    if not any(kw in hyp for kw in RACE_HYPOTHESIS_KW):
        return False

    ev = _get_evidence(item)
    return not (ev and any(ev.startswith(p) for p in RACE_EVIDENCE_ALLOWLIST))


def apply_speculative_race_gate(outcomes) -> int:
    """Demote evidence-free race/TOCTOU findings to suspicious.

    Only touches ``finding`` → ``suspicious``.
    Works on both ReviewOutcome objects and plain dicts.
    """
    gated = 0
    for o in outcomes:
        if _get_status(o) != "finding":
            continue
        if is_speculative_race(o):
            _set_status(o, "suspicious")
            gated += 1
    return gated


_apply_speculative_race_gate = apply_speculative_race_gate
_is_speculative_race = is_speculative_race
