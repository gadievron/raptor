"""Shared audit pipeline entry point.

Both ``libexec/raptor-audit run`` and the corpus runner call
``run_audit_pipeline()`` so setup logic lives in one place and the
corpus runner can run in-process (no subprocess, no cold-start).
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional

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
    scope: Optional[list[str]] = None
    functions: Optional[list[str]] = None
    models: Optional[list[str]] = None
    max_cost_usd: Optional[float] = None
    max_seconds: Optional[float] = None
    budget: Optional[int] = None
    strategy_filter: Optional[str] = None
    review_passes: int = 1
    adversarial: bool = False
    max_propagation_depth: Optional[int] = None
    subsystem_depth: int = 0
    validate: bool = True
    no_binary_oracle: bool = False
    binary_verdicts: Optional[Dict[str, str]] = None
    inventory: Optional[Dict[str, Any]] = None
    annotations_dir: Optional[Path] = None
    codeql_db_path: Optional[str] = None
    threat_model: Optional[Dict[str, Any]] = None
    joern_overrides: Optional[Dict[str, Any]] = None
    joern_server: Optional[Any] = None
    on_progress: Optional[Callable] = None
    study_root: Optional[Path] = None
    mode: ReviewMode = ReviewMode.ENSEMBLE
    max_workers: int = 0


def run_audit_pipeline(opts: AuditPipelineOpts, *, prep_cache=None):
    """Run the audit orchestrator and return its result.

    Sets up the LLM client, builds the OrchestratorConfig, and calls
    ``run_orchestrator``.  Returns the ``OrchestratorResult``.
    """
    from core.llm.log_quiet import quiet_noisy_loggers

    quiet_noisy_loggers()

    from core.llm.client import LLMClient
    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig, run_orchestrator

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

    review_fn = make_review_fn(
        client, task_type="audit", model_name=primary_model,
        mode=opts.mode, out_dir=opts.out_dir,
    )
    config = OrchestratorConfig(
        target_path=opts.target_path,
        out_dir=opts.out_dir,
        budget=opts.budget,
        scope=opts.scope,
        strategy_filter=opts.strategy_filter,
        models=models,
        multi_model=len(models) > 1,
        adversarial=opts.adversarial,
        max_cost_usd=opts.max_cost_usd,
        max_seconds=opts.max_seconds,
        review_passes=opts.review_passes,
        subsystem_depth=opts.subsystem_depth,
        max_propagation_depth=opts.max_propagation_depth,
        validate=opts.validate,
        no_binary_oracle=opts.no_binary_oracle,
        binary_verdicts=opts.binary_verdicts,
        inventory=opts.inventory,
        codeql_db_path=opts.codeql_db_path,
        threat_model=opts.threat_model,
        annotations_dir=opts.annotations_dir,
        functions=opts.functions,
        joern_overrides=opts.joern_overrides,
        joern_server=opts.joern_server,
        study_root=opts.study_root,
        mode=opts.mode,
        max_workers=opts.max_workers,
    )

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
    try:
        from core.audit.orchestrator import _is_detection_only
        if _is_detection_only(ev):
            return False
    except Exception:
        pass
    return True


def _has_any_mechanical_evidence(ev: str) -> bool:
    """True when evidence comes from any mechanical tool (including detection-role).

    Weaker than ``_is_verification_evidence`` — accepts detection-role
    SMT/Coccinelle evidence.  Used by the ensemble merge to prevent
    discarding findings that have real tool support even if the tool's
    role is detection rather than verification.
    """
    if not ev or ev.startswith(_NON_MECHANICAL):
        return False
    return True


# ---------------------------------------------------------------------------
# Dual-mode accessor — works on ReviewOutcome objects and plain dicts
# ---------------------------------------------------------------------------

def _get(item, attr, dict_key=None, default=""):
    """Read a field from an object (attribute) or a dict (key)."""
    if isinstance(item, dict):
        return item.get(dict_key or attr, default)
    val = getattr(item, attr, default)
    if val is None:
        return default
    return val


def _set(item, attr, dict_key=None, value=None):
    """Write a field to an object or dict."""
    if isinstance(item, dict):
        item[dict_key or attr] = value
    else:
        setattr(item, attr, value)


def _get_status(item):
    if isinstance(item, dict):
        return item.get("actual", item.get("status", ""))
    return getattr(item, "status", "")


def _set_status(item, status):
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
    if ev and not ev.startswith(NON_MECHANICAL):
        return True
    return False


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
                winner = copy(sec if sr <= br else bf)
                if winner.status == "finding":
                    winner.status = "suspicious"

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
    a confident clean (non-clean status, has evidence, or compelling
    counter-hypothesis), a bug_first review runs immediately and the two
    outcomes are merged.  The executor parallelises across functions, so
    pass-2 reviews for early functions overlap with pass-1 reviews for
    later ones — wall-clock ≈ max(per-function chains), not sum-of-passes.
    """
    import time
    import threading

    from core.llm.log_quiet import quiet_noisy_loggers

    quiet_noisy_loggers()

    from core.llm.client import LLMClient
    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig, run_orchestrator

    t0 = time.monotonic()

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

    config = OrchestratorConfig(
        target_path=opts.target_path,
        out_dir=opts.out_dir,
        budget=opts.budget,
        scope=opts.scope,
        strategy_filter=opts.strategy_filter,
        models=models,
        multi_model=len(models) > 1,
        adversarial=opts.adversarial,
        max_cost_usd=opts.max_cost_usd,
        max_seconds=opts.max_seconds,
        review_passes=opts.review_passes,
        subsystem_depth=opts.subsystem_depth,
        max_propagation_depth=opts.max_propagation_depth,
        validate=opts.validate,
        no_binary_oracle=opts.no_binary_oracle,
        binary_verdicts=opts.binary_verdicts,
        inventory=opts.inventory,
        codeql_db_path=opts.codeql_db_path,
        threat_model=opts.threat_model,
        annotations_dir=opts.annotations_dir,
        functions=opts.functions,
        joern_overrides=opts.joern_overrides,
        joern_server=opts.joern_server,
        study_root=opts.study_root,
        mode=ReviewMode.SECURITY,
        max_workers=opts.max_workers,
    )

    result = run_orchestrator(
        config, ensemble_review_fn, on_progress=opts.on_progress,
    )

    logger.info(
        "Pipelined ensemble: %d pass2 skipped, %d pass2 run",
        _counters["pass2_skipped"], _counters["pass2_run"],
    )

    result.total_duration_s = time.monotonic() - t0

    dampened = _dampen_file_pileup(result.outcomes)
    if dampened:
        logger.info(
            "file-level dampening: demoted %d pile-up findings", dampened,
        )

    any_gate = dampened
    if any_gate:
        result.findings = sum(
            1 for o in result.outcomes if o.status == "finding"
        )
        result.suspicious = sum(
            1 for o in result.outcomes if o.status == "suspicious"
        )

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


def dampen_file_pileup(outcomes) -> int:
    """Demote evidence-free pile-up findings.

    Works on both ReviewOutcome objects and plain dicts.

    Three tiers:
    1. Same-class: >=3 findings in the same file sharing a bug class
       and none having mechanical evidence -> keep strongest, demote rest
       (finding→suspicious, suspicious→clean).
    2. Class-agnostic: >=4 evidence-free findings in the same file
       (regardless of class) -> keep top 2, demote rest
       (finding→suspicious, suspicious→clean).
    3. Heavy pile-up: >=6 evidence-free findings in the same file ->
       demote ALL excess beyond top 1 to clean outright.

    Tool-backed findings are never demoted.
    """
    from collections import defaultdict

    def _has_mechanical(i):
        ev = _get_evidence(outcomes[i])
        return ev and not ev.startswith(NON_MECHANICAL)

    def _rank_key(i):
        return (
            STATUS_RANK.get(_get_status(outcomes[i]), 0),
            len(_get_hypothesis(outcomes[i])),
        )

    already_dampened: set[int] = set()
    dampened = 0

    # --- Tier 1: same-class dampening ---
    class_groups: dict[tuple, list[int]] = defaultdict(list)
    for i, o in enumerate(outcomes):
        if _get_status(o) in ("suspicious", "finding"):
            bc = extract_bug_class(o)
            class_groups[(_get_file(o), bc)].append(i)

    for indices in class_groups.values():
        if len(indices) < FILE_CLASS_THRESHOLD:
            continue
        if any(_has_mechanical(i) for i in indices):
            continue
        ranked = sorted(indices, key=_rank_key, reverse=True)
        for idx in ranked[1:]:
            cur = _get_status(outcomes[idx])
            if cur == "finding":
                _set_status(outcomes[idx], "suspicious")
                already_dampened.add(idx)
                dampened += 1
            elif cur == "suspicious":
                _set_status(outcomes[idx], "clean")
                already_dampened.add(idx)
                dampened += 1

    # --- Tier 2: class-agnostic file-level cap ---
    file_groups: dict[str, list[int]] = defaultdict(list)
    for i, o in enumerate(outcomes):
        if _get_status(o) in ("suspicious", "finding") and not _has_mechanical(i):
            file_groups[_get_file(o)].append(i)

    for indices in file_groups.values():
        if len(indices) < FILE_AGNOSTIC_THRESHOLD:
            continue
        ranked = sorted(indices, key=_rank_key, reverse=True)
        keep = FILE_AGNOSTIC_KEEP
        heavy = len(indices) >= FILE_HEAVY_THRESHOLD
        if heavy:
            keep = FILE_HEAVY_KEEP
        for idx in ranked[keep:]:
            if idx in already_dampened:
                continue
            cur = _get_status(outcomes[idx])
            if cur == "finding":
                _set_status(outcomes[idx], "suspicious" if not heavy else "clean")
                dampened += 1
            elif cur == "suspicious":
                _set_status(outcomes[idx], "clean")
                dampened += 1

    return dampened

_dampen_file_pileup = dampen_file_pileup


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


def counter_hypothesis_vetoes(item) -> bool:
    """True when a strong counter-hypothesis should veto a speculative finding.

    Works on both ReviewOutcome objects and plain dicts.
    Conditions: (1) no mechanical evidence, (2) counter-hypothesis is
    substantial and names a concrete protection mechanism,
    (3) hypothesis does not name a security-primitive pattern that
    counter-hypotheses are unreliable for.
    """
    ev = _get_evidence(item)
    if ev and not ev.startswith(NON_MECHANICAL):
        return False

    counter = _get_counter(item)
    hyp = _get_hypothesis(item)

    if not counter or len(counter) < 40:
        return False
    if len(counter) < len(hyp) * 0.6:
        return False

    hyp_lower = hyp.lower()
    if any(kw in hyp_lower for kw in COUNTER_VETO_EXEMPT_KW):
        return False

    lower = counter.lower()
    return any(kw in lower for kw in COUNTER_PROTECTION_KW)

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

RACE_EVIDENCE_WHITELIST = (
    "smt:", "coccinelle:", "semgrep:", "codeql:", "joern:",
    "sarif:", "prefilter:lock", "prefilter:race",
)


def is_speculative_race(item) -> bool:
    """True when a race/TOCTOU hypothesis lacks mechanical backing."""
    hyp = _get_hypothesis(item).lower()
    if not any(kw in hyp for kw in RACE_HYPOTHESIS_KW):
        return False

    ev = _get_evidence(item)
    if ev and any(ev.startswith(p) for p in RACE_EVIDENCE_WHITELIST):
        return False

    return True


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
