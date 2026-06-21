"""L3 retrieval over the LabeledAttempt corpus.

Phase B unit #3 of the /exploit Phase 2 plan
. Reads verified-success
records from the three-tier pool (bundled / project / global), ranks
them against a CWE query with a recency weight + diversity bonus, and
returns top-k as :class:`RetrievedExemplar` for the prompt's few-shot
slot.

Ranking criteria (from the plan):
  * Verified-success filter — only ``outcome="success"`` records on a
    decisive oracle outcome (sanitizer_report, flag_captured,
    exit_signal).
  * Exact-CWE filter — match the query CWE. Family fallback (e.g.
    787 → 119) deferred until measurement shows we need it.
  * Recency weight — exponential decay, default half-life 90 days.
  * Dedup by exploit-code hash — duplicate candidates don't dominate.
  * Diversity bonus — prefer top-k spanning distinct findings rather
    than k copies of the same exploit shape.

Not yet wired into the engine. The retriever is a pure read; the
producer (labeled_attempt_bridge) is already writing records. Wiring
into the engine happens in unit #4 (rendering as Exemplar in the
prompt slot + exemplar_id feedback for A/B).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .store import read_all
from .types import FailureMode, LabeledAttempt

__all__ = [
    "RetrievedExemplar",
    "recent_failure_summary",
    "retrieve_exemplars",
]


# Decisive sandbox outcomes — match generate-and-verify-loop.md's
# governing rule for "this run produced a real, attestable bug."
_DECISIVE_SANDBOX_OUTCOMES = frozenset({
    "sanitizer_report",
    "flag_captured",
    "exit_signal",
})


@dataclass(frozen=True)
class RetrievedExemplar:
    """One past attempt rendered for the few-shot prompt slot.

    Shape lines 117-124:
    a self-contained exemplar that names the bug, shows the exploit,
    explains the evidence, and notes the environment. The
    ``exemplar_id`` lets the engine record which exemplars were in
    the prompt at success time so A/B feedback can attribute
    contribution.
    """

    exemplar_id: str           # signature short prefix + record timestamp
    cwe: str
    finding_summary: str       # CWE + file + function (best-effort)
    exploit_code: str          # the candidate that worked
    evidence: str              # observed outcome + verdict summary
    environment: str           # mitigations + arch + libc (when known)
    timestamp: str             # for downstream display + recency check
    # Provenance tier for prompt rendering. Maps directly to the
    # reproducer/exploit distinction every exploit author works in:
    #   "exploit"    — full chain that achieved the run's controlled-
    #                  effect goal (overall outcome == "success" plus
    #                  decisive sandbox evidence). The exploit_code
    #                  is a complete, weaponized chain.
    #   "reproducer" — input that drives the bug to fire (sanitizer
    #                  report / exit signal / flag captured at the
    #                  sandbox layer) without necessarily achieving
    #                  the run's goal. Fuzz-harness-class output —
    #                  shows HOW TO REACH THE BUG, not how to
    #                  weaponize it. Render must surface this
    #                  distinction so the model treats reproducers
    #                  as starting points, not as finished work.
    tier: str = "exploit"


# --------------------------------------------------------------------------
# Filtering
# --------------------------------------------------------------------------


def _is_verified_success(record: LabeledAttempt) -> bool:
    """Decisive-oracle success per generate-and-verify-loop.md."""
    if record.outcome != "success":
        return False
    # Sandbox: outcome must be one of the decisive markers.
    if record.sandbox_evidence is not None:
        return record.sandbox_evidence.observed_outcome in _DECISIVE_SANDBOX_OUTCOMES
    # CodeQL: success means the barrier query confirmed soundness.
    if record.codeql_evidence is not None:
        return bool(record.codeql_evidence.is_sound)
    # Web: point-in-time evidence; treat as verified if record carries
    # response_evidence (the producer's contract is that web records
    # only land when concrete evidence was observed).
    if record.web_evidence is not None:
        return bool(record.web_evidence.response_evidence)
    return False


def _is_verified_trigger_or_beyond(record: LabeledAttempt) -> bool:
    """The candidate code drove the sandbox to a decisive outcome —
    sanitizer report, exit signal, or flag captured — irrespective of
    whether the run's overall goal was met.

    Wider net than :func:`_is_verified_success`:
      * a goal=flag run that fires a sanitizer but doesn't print the
        marker has ``outcome == "reasoned_failure"`` but still
        represents real, reproducible bug-reaching work; the
        candidate's input shape IS a working trigger for the bug
      * cross-Problem learning: a weaponization Problem retrieving
        from related-CWE pool sees "here's a working trigger for
        this bug class" exemplars, not just full-chain wins

    Limited to sandbox-oracle records — CodeQL/web evidence has no
    notion of partial progress.

    Excludes records classified as ``HARNESS_SIDE_CHANNEL`` — those
    incidentally trigger ASAN (because the bug input got passed
    through) but their candidate code is a side-channel cheat, not a
    useful trigger exemplar; surfacing them as exemplars propagates
    the cheat to future runs.
    """
    if record.sandbox_evidence is None:
        return False
    if record.failure_mode is FailureMode.HARNESS_SIDE_CHANNEL:
        return False
    return record.sandbox_evidence.observed_outcome in _DECISIVE_SANDBOX_OUTCOMES


def _cwe_matches(record: LabeledAttempt, query_cwe: str) -> bool:
    return record.cwe.strip().upper() == query_cwe.strip().upper()


# --------------------------------------------------------------------------
# Ranking
# --------------------------------------------------------------------------


def _record_age_days(record: LabeledAttempt, now: datetime) -> float:
    """Age in days of a record's timestamp. Defensive: returns 0 when
    the timestamp can't be parsed."""
    try:
        ts = datetime.fromisoformat(record.timestamp)
    except (ValueError, TypeError):
        return 0.0
    # Normalise both to UTC for the diff.
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now_utc = now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)
    delta = now_utc - ts
    return max(delta.total_seconds() / 86400.0, 0.0)


def _recency_weight(age_days: float, half_life_days: float) -> float:
    """Exponential decay: 1.0 at age=0, 0.5 at age=half_life."""
    if half_life_days <= 0:
        return 1.0
    return math.exp(-age_days * math.log(2) / half_life_days)


def _exploit_code(record: LabeledAttempt) -> str:
    """Best-effort retrieval of the candidate code from the record.
    Empty string when the record's oracle doesn't carry one (e.g.
    a CodeQL-adjudicated barrier — no executable artefact)."""
    if record.sandbox_evidence and record.sandbox_evidence.exploit_code:
        return record.sandbox_evidence.exploit_code
    return ""


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _summarise_finding(record: LabeledAttempt) -> str:
    """Compact descriptor of what the past finding was. Used as the
    exemplar's ``finding_summary`` slot."""
    parts = [record.cwe]
    if record.finding_id:
        parts.append(f"finding={record.finding_id}")
    return " · ".join(parts)


def _describe_evidence(record: LabeledAttempt) -> str:
    sb = record.sandbox_evidence
    if sb is not None:
        bits = [f"observed={sb.observed_outcome}"]
        verdict = sb.outcome_detail.get("engine_verdict_summary")
        if verdict:
            bits.append(f"verdict={verdict}")
        return " · ".join(bits)
    if record.codeql_evidence is not None:
        cq = record.codeql_evidence
        return (
            f"codeql barrier sound (before={cq.before_count}, "
            f"after={cq.after_count})"
        )
    if record.web_evidence is not None:
        return f"web {record.web_evidence.evidence_type}"
    return "unknown"


def _describe_environment(record: LabeledAttempt) -> str:
    sb = record.sandbox_evidence
    if sb is None:
        return ""
    bits: list[str] = []
    if sb.arch:
        bits.append(sb.arch)
    if sb.libc_version:
        bits.append(f"libc {sb.libc_version}")
    if sb.mitigations_active:
        bits.append("mitigations: " + ",".join(sb.mitigations_active))
    return " · ".join(bits) if bits else ""


def _render(record: LabeledAttempt) -> RetrievedExemplar:
    sig_prefix = record.finding_signature[:8]
    # Tier — exploit if the overall outcome was success, otherwise
    # reproducer (the record was admitted because the sandbox saw a
    # decisive outcome but the run goal wasn't met).
    tier = "exploit" if _is_verified_success(record) else "reproducer"
    return RetrievedExemplar(
        exemplar_id=f"{sig_prefix}-{record.timestamp}",
        cwe=record.cwe,
        finding_summary=_summarise_finding(record),
        exploit_code=_exploit_code(record),
        evidence=_describe_evidence(record),
        environment=_describe_environment(record),
        timestamp=record.timestamp,
        tier=tier,
    )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def retrieve_exemplars(
    *,
    cwe: str,
    project_dir: Optional[Path] = None,
    k: int = 3,
    include_bundled: bool = True,
    include_global: bool = False,
    recency_half_life_days: float = 90.0,
    now: Optional[datetime] = None,
) -> list[RetrievedExemplar]:
    """L3 retrieval entry point.

    Reads the three-tier pool, filters to records that drove the
    sandbox to a decisive outcome (sanitizer report / exit signal /
    flag captured) on the requested ``cwe`` — irrespective of
    whether the overall run goal was met. This includes both
    verified-success records (full-chain wins) AND partial-progress
    records where the trigger fired but the controlled-effect goal
    wasn't reached. The wider net matches how real exploit-dev
    iterates: every weaponization attempt implicitly does trigger
    derivation, so trigger-class records ARE concrete worked
    examples for the bug-reach step.

    Ranks by recency, dedups by exploit-code text, applies a
    per-finding diversity bonus, and returns the top-k as
    :class:`RetrievedExemplar` ready for prompt rendering.

    ``now`` is injected for deterministic tests; defaults to
    :func:`datetime.now(timezone.utc)`.
    """
    if k <= 0:
        return []

    now_dt = now or datetime.now(timezone.utc)

    candidates = list(read_all(
        project_dir=project_dir,
        include_bundled=include_bundled,
        include_global=include_global,
    ))

    # Decisive-outcome records on the requested CWE. ``_is_verified_
    # trigger_or_beyond`` admits both full-chain successes and partial-
    # progress (trigger-only) sandbox records; CodeQL and web records
    # still require ``_is_verified_success`` (no partial-progress
    # concept on those oracles).
    candidates = [
        r for r in candidates
        if _cwe_matches(r, cwe)
        and (_is_verified_success(r) or _is_verified_trigger_or_beyond(r))
    ]

    # Dedup by exploit-code text. Multiple successful runs of the
    # same exploit shouldn't crowd out variety. Empty codes (CodeQL
    # adjudications, web evidence) are NOT deduped here — those
    # records derive uniqueness from their finding_signature and the
    # diversity bonus below handles per-finding spread.
    seen_codes: set[str] = set()
    unique: list[LabeledAttempt] = []
    for r in candidates:
        code = _exploit_code(r)
        if code and code in seen_codes:
            continue
        if code:
            seen_codes.add(code)
        unique.append(r)

    # Score: recency weight only for now. Diversity is applied at
    # selection time below by spreading across finding_signatures.
    scored = [
        (_recency_weight(_record_age_days(r, now_dt), recency_half_life_days), r)
        for r in unique
    ]
    scored.sort(key=lambda pair: pair[0], reverse=True)

    # Diversity selection: walk the recency-sorted list and pick at
    # most one record per finding_signature until we hit k. If we
    # exhaust unique signatures before k, fall back to filling from
    # the remainder (preserves recency order).
    chosen: list[LabeledAttempt] = []
    used_signatures: set[str] = set()
    leftover: list[LabeledAttempt] = []
    for _, r in scored:
        if r.finding_signature in used_signatures:
            leftover.append(r)
            continue
        used_signatures.add(r.finding_signature)
        chosen.append(r)
        if len(chosen) >= k:
            break
    if len(chosen) < k:
        chosen.extend(leftover[: k - len(chosen)])

    return [_render(r) for r in chosen]


# --------------------------------------------------------------------------
# Failure summary — "what's been failing for this CWE recently"
# --------------------------------------------------------------------------


def recent_failure_summary(
    cwe: str,
    *,
    project_dir: Optional[Path] = None,
    window_days: float = 30.0,
    include_bundled: bool = True,
    include_global: bool = False,
    now: Optional[datetime] = None,
) -> dict[FailureMode, int]:
    """Count classified failure modes for a CWE within a recency window.

    Returns a dict mapping each :class:`FailureMode` that appears at
    least once to its count among reasoned-failure records on the
    requested CWE within ``window_days``. Failure records without a
    classification (``failure_mode=None`` — old records or unclassified
    new ones) are skipped.

    Decoupled from :func:`retrieve_exemplars` by design: the retriever
    surfaces *successes* (exemplars to learn from); this helper
    surfaces *failures* (what's been going wrong). Callers compose
    them — e.g. cli.py could log a warning if recent failures cluster
    on one mode, or surface them in report.md as a "recently failing"
    note.

    ``now`` is injected for deterministic tests; defaults to
    :func:`datetime.now(timezone.utc)`.
    """
    if math.isnan(window_days):
        raise ValueError(
            "window_days must be a finite or +infinity value, not NaN. "
            "NaN comparisons return False which would silently include "
            "every record in the pool — defended at the entry."
        )
    now_dt = now or datetime.now(timezone.utc)
    cwe_norm = cwe.strip().upper()
    counts: dict[FailureMode, int] = {}

    for r in read_all(
        project_dir=project_dir,
        include_bundled=include_bundled,
        include_global=include_global,
    ):
        if r.outcome != "reasoned_failure":
            continue
        if r.failure_mode is None:
            continue
        if r.cwe.strip().upper() != cwe_norm:
            continue
        age_days = _record_age_days(r, now_dt)
        if age_days > window_days:
            continue
        counts[r.failure_mode] = counts.get(r.failure_mode, 0) + 1

    return counts
