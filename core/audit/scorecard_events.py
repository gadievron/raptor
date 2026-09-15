"""Scorecard producer for /audit's graded adjudication points.

Records per-model reliability events into the shared scorecard sidecar
(``core.llm.scorecard.ModelScorecard``) at the points where a later,
stronger signal genuinely grades an earlier model decision:

* ``tool_evidence`` — a deterministic receipt settled the model's
  hypothesis: a proof-grade mechanical refutation grades the positive
  verdict ``incorrect``; a shipped finding backed by a promotion-grade
  receipt grades the hypothesis ``correct``. This is the ONLY event
  type this producer writes into ``calibrated_merge``'s
  ``RELIABILITY_EVENT_TYPES`` pool, and it is only ever earned by a
  receipt — never by an LLM ruling alone.
* ``cross_family_consistency`` — a cross-model adversarial refuter
  upheld (``stands`` → ``correct``) or overruled (demotion applied →
  ``incorrect``) a positive verdict WITHOUT a settling receipt. A
  1-vs-1 refuter ruling is policy, not ground truth (the registry's
  own judge producer refuses single-judge shapes, and the
  ``CROSS_FAMILY_CHECK`` registry comment routes 1-vs-1 disagreement
  to this consistency axis), so the event records the dispute/uphold
  on an axis deliberately outside the correctness-graded reliability
  pools. "Family" here means a different configured model — the
  independence is weaker than a true cross-family pair, which is
  exactly why the consistency axis, not ``judge_review``, is used.
  Attribution nuance vs the registry's own cross-family producer:
  that one grades the CHECKER's cell under ``agentic:*`` classes;
  this producer grades the PRODUCER's cell under ``audit:*`` classes
  — the disjoint decision-class namespaces keep the two conventions
  from ever colliding in one cell.
* ``self_consistency`` — same-model adversarial re-examination
  (single-model runs are self-adversarial: held → ``correct``,
  flipped → ``incorrect``) and verdict-vs-own-output contradictions
  (all-refuted-yet-suspicious, clean-with-live-hypotheses,
  safety-self-contradiction demotions → ``incorrect``). Also a
  consistency axis, never a merge weight.

Where a graded outcome does NOT genuinely exist, nothing is emitted:
``needs_evidence`` refuter verdicts; refutations floored by a tool
receipt (conflicting receipts, unresolved); heuristic-grade
refutation-gate demotions (keyword/partial-graph/unverified-claim
refuters — only ``refuter_grade == "proof"`` grades); reachability
demotions (entry/sink-unreachability and binary-oracle absent
verdicts are triage facts about the graph/build, not model
competence); the sweep's hypothesis-less schema demotion (discipline,
not refutation); demotion-referee floors (they block a demotion for
missing evidence, they don't falsify it); and dark-verify refutations
where any deterministic stamp is retained (one guessed witness input
refutes its own prediction, not an engine receipt).

Emission contract (the orchestrator depends on all three):

* **Never raises.** Every entry point catches and logs at debug —
  scorecard telemetry must never break an audit run.
* **Buffered.** Events append to an in-memory list on the run result
  (plain ``list.append``, atomic under the GIL for the parallel
  passes) and are flushed ONCE at end of run through the public
  batch API (``ModelScorecard.record_events`` — one lock/load/write
  cycle), after the run's primary artifacts (findings persist,
  journal correction, graded export) are already on disk, so no
  sidecar I/O or lock wait can stall the hot path or the exports.
* **Reconciled.** ``tool_evidence`` grades are checked against the
  final finding set both ways: an ``incorrect`` whose function ends
  the run as a finding is dropped (the refutation was itself
  overturned), and a ``correct`` whose function does NOT end as a
  finding is dropped (the run no longer stands behind it). Events
  grading the REFUTER are exempt — that grade is settled by the
  receipt itself. Consistency-axis events are NOT reconciled: they
  record that a flip/dispute/contradiction happened, which a later
  rescue does not un-happen.

Decision classes follow the audit convention (``audit:<CWE>``, falling
back to ``audit:review``) via ``calibrated_merge.decision_class_for``,
so the cells written here are the same cells the calibrated merge
reads.
"""

from __future__ import annotations

import logging
import re
from typing import Any, TYPE_CHECKING

from core.llm.scorecard import _MAX_REASONING_CHARS

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Private bookkeeping keys stripped before the batch write.
_PRIVATE_KEYS = ("_key", "_grades_refuter", "_flushed")

# Cap on the ``file:function`` key. The key is target-controlled (a
# hostile repo can mint megabyte function names) and rides into the
# shared cross-run sidecar via the sample's ``function_id`` — every
# future scorecard consult re-reads the whole file, so an unbounded
# key is a permanent ledger-bloat primitive. Same budget as the
# canonical reasoning cap so all producer-written free text shares one
# size class.
_MAX_KEY_CHARS = _MAX_REASONING_CHARS

# Self-consistency panel handles run the SAME model under suffixed
# names (``<model>#sc<i>``, see ``multi_review.run_self_consistency``)
# and the merged primary can carry that suffix — cells must key on the
# real model, not the sample handle.
_SC_HANDLE_SUFFIX = re.compile(r"#sc\d+$")

# OrchestratorConfig's unconfigured sentinel. Not a model name: it can
# reach ``outcome.model`` verbatim through the panel-result fallback
# (``_outcome_to_panel_result``), so it is rejected post-normalization
# in ``buffer_event``, not just in the ``lone_model`` fallback.
_PLACEHOLDER_MODEL = "default"


def _normalize_model(model: str) -> str:
    name = _SC_HANDLE_SUFFIX.sub("", str(model or "").strip())
    return "" if name == _PLACEHOLDER_MODEL else name


def lone_model(models: Any) -> str:
    """The single configured model name, or ``""`` when the run is
    multi-model / unconfigured. Used as the attribution fallback for
    outcomes that lost their ``model`` stamp — on a single-model run
    the attribution is still factual; on a multi-model run it would
    be a guess, so the event is skipped instead. The ``"default"``
    placeholder never attributes."""
    try:
        if models and len(models) == 1 and models[0]:
            return _normalize_model(str(models[0]))
    except Exception:  # noqa: BLE001 — attribution fallback, never raise
        logger.debug("lone_model resolution failed", exc_info=True)
    return ""


def cap_key(key: str) -> str:
    """THE key truncation — the only ``_MAX_KEY_CHARS`` slice.

    Both sides of the flush reconciliation must go through this:
    events cap their ``_key`` at buffer time, so a finding-key set
    built from raw ``file:function`` strings would silently stop
    matching any function whose key exceeds the cap — leaking
    refutations for rescued findings and dropping confirmations for
    real ones. One shared helper means the two sides cannot drift."""
    return str(key or "")[:_MAX_KEY_CHARS]


def outcome_key(outcome: Any) -> str:
    """Canonical (capped) event key for one outcome. The orchestrator
    builds the flush's ``finding_keys`` set with this so membership
    tests match buffered ``_key`` values exactly."""
    return cap_key(
        f"{getattr(outcome, 'file', '')}:{getattr(outcome, 'function', '')}",
    )


def _outcome_cwe(outcome: Any) -> str:
    """Review-supplied CWE (raw, no keyword inference — this reader
    must not mutate ``review_result`` the way ``_effective_cwe``
    does). Mirrors its precedence: explicit class first, then a
    previously stamped inference."""
    review = getattr(outcome, "review_result", None) or {}
    return str(
        review.get("cwe_class")
        or review.get("cwe")
        or review.get("cwe_inferred")
        or "",
    )


def _decision_class(cwe: str) -> str:
    try:
        from .calibrated_merge import DEFAULT_DECISION_CLASS, decision_class_for
    except ImportError:  # pragma: no cover — sibling module always ships
        return "audit:review"
    try:
        return decision_class_for([{"cwe": cwe or ""}])
    except Exception:  # noqa: BLE001 — class derivation must never raise
        logger.debug("decision-class derivation failed", exc_info=True)
        return DEFAULT_DECISION_CLASS


def buffer_event(
    events: list[dict[str, Any]],
    *,
    model: str,
    cwe: str,
    event_type: str,
    grade: str,
    key: str,
    this_reasoning: str = "",
    other_reasoning: str = "",
    grades_refuter: bool = False,
) -> bool:
    """Append one pending scorecard event. Returns True when buffered.

    Skip cases (False): missing model attribution (including the
    ``"default"`` placeholder), or a grade outside the
    correct/incorrect vocabulary. The target-controlled key is capped
    at :data:`_MAX_KEY_CHARS`. Never raises.
    """
    try:
        model = _normalize_model(model)
        if not model or grade not in ("correct", "incorrect"):
            return False
        key = cap_key(key)
        sample = None
        if grade == "incorrect":
            sample = {
                "function_id": key,
                "this_reasoning": (
                    this_reasoning or ""
                )[:_MAX_REASONING_CHARS],
                "other_reasoning": (
                    other_reasoning or ""
                )[:_MAX_REASONING_CHARS],
            }
        events.append({
            "decision_class": _decision_class(cwe),
            "model": str(model),
            "event_type": event_type,
            "outcome": grade,
            "sample": sample,
            "_key": key,
            "_grades_refuter": grades_refuter,
        })
        return True
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("scorecard event buffering failed", exc_info=True)
        return False


def record_mechanical_refutation(
    events: list[dict[str, Any]],
    outcome: Any,
    *,
    gate: str,
    reason: str,
    models: Any = None,
) -> bool:
    """A proof-grade mechanical check overturned the model's positive
    verdict → ``tool_evidence``/``incorrect``. Callers own the grade
    gate: only refuters that are mechanically true regardless of
    hypothesis interpretation (proof-grade refutation gates, Z3 UNSAT,
    guarded-sink Joern receipts, executed witnesses with no retained
    deterministic stamp) may call this. Never raises."""
    try:
        from core.llm.scorecard import EventType

        model = getattr(outcome, "model", "") or lone_model(models)
        return buffer_event(
            events,
            model=model,
            cwe=_outcome_cwe(outcome),
            event_type=EventType.TOOL_EVIDENCE,
            grade="incorrect",
            key=outcome_key(outcome),
            this_reasoning=getattr(outcome, "hypothesis", "") or "",
            other_reasoning=f"{gate}: {reason}",
        )
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("mechanical-refutation event failed", exc_info=True)
        return False


def record_self_consistency_violation(
    events: list[dict[str, Any]],
    outcome: Any,
    *,
    detail: str,
    models: Any = None,
) -> bool:
    """The model's verdict contradicted its own output →
    ``self_consistency``/``incorrect``. Never raises."""
    try:
        from core.llm.scorecard import EventType

        model = getattr(outcome, "model", "") or lone_model(models)
        return buffer_event(
            events,
            model=model,
            cwe=_outcome_cwe(outcome),
            event_type=EventType.SELF_CONSISTENCY,
            grade="incorrect",
            key=outcome_key(outcome),
            this_reasoning=getattr(outcome, "hypothesis", "") or "",
            other_reasoning=detail,
        )
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("self-consistency event failed", exc_info=True)
        return False


def record_adversarial_outcome(
    events: list[dict[str, Any]],
    outcome: Any,
    *,
    producer_model: str,
    refuter_model: str,
    verdict: str,
    defeating_mechanism: str = "",
    overturned_by: str = "",
    models: Any = None,
) -> int:
    """Grade one adversarial-refutation adjudication. Returns the
    number of events buffered. Never raises.

    * ``overturned_by`` non-empty (a verification-role receipt
      confirmed the original hypothesis): the producer's claim earns
      ``tool_evidence``/``correct``; the refuter's refutation claim
      was contradicted by the same receipt → ``tool_evidence``/
      ``incorrect`` (flagged so flush's finding-reconciliation never
      drops it — the surviving finding IS the evidence). This is the
      only adversarial shape that reaches the reliability pool,
      because it is the only one settled by a receipt.
    * ``verdict == "stands"`` / ``"refuted"`` without a receipt:
      consistency axes only. Self-adversarial (same or unresolved
      refuter) → ``self_consistency`` held/flipped; cross-model
      refuter → ``cross_family_consistency`` upheld/disputed. A
      1-vs-1 LLM ruling never grades correctness, even though the
      pipeline acts on it.

    Callers must NOT invoke this for ``needs_evidence`` verdicts or
    for refutations floored by an existing tool receipt — those
    adjudications are unresolved and carry no grade.
    """
    try:
        from core.llm.scorecard import EventType

        producer = producer_model or lone_model(models)
        key = outcome_key(outcome)
        cwe = _outcome_cwe(outcome)
        hypothesis = getattr(outcome, "hypothesis", "") or ""
        n = 0

        if overturned_by:
            n += buffer_event(
                events,
                model=producer,
                cwe=cwe,
                event_type=EventType.TOOL_EVIDENCE,
                grade="correct",
                key=key,
            )
            n += buffer_event(
                events,
                model=refuter_model,
                cwe=cwe,
                event_type=EventType.TOOL_EVIDENCE,
                grade="incorrect",
                key=key,
                this_reasoning=defeating_mechanism,
                other_reasoning=(
                    f"refutation overturned — {overturned_by} confirmed "
                    "the original hypothesis"
                ),
                grades_refuter=True,
            )
            return n

        if verdict not in ("stands", "refuted"):
            return 0
        upheld = verdict == "stands"
        self_adversarial = (
            not _normalize_model(refuter_model)
            or _normalize_model(refuter_model) == _normalize_model(producer)
        )
        event_type = (
            EventType.SELF_CONSISTENCY
            if self_adversarial
            else EventType.CROSS_FAMILY_CONSISTENCY
        )
        n += buffer_event(
            events,
            model=producer,
            cwe=cwe,
            event_type=event_type,
            grade="correct" if upheld else "incorrect",
            key=key,
            this_reasoning=hypothesis,
            other_reasoning=(
                f"adversarial refuter {refuter_model or producer} named "
                f"a defeating mechanism: {defeating_mechanism}"
                if not upheld
                else ""
            ),
        )
        return n
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("adversarial-outcome event failed", exc_info=True)
        return 0


def buffer_confirmed_findings(
    events: list[dict[str, Any]],
    outcomes: Any,
    *,
    models: Any = None,
    receipt_check: Callable[[str], bool] | None = None,
) -> int:
    """End-of-run confirmed direction: every shipped finding backed by
    a promotion-grade receipt grades its model's hypothesis
    ``tool_evidence``/``correct``.

    ``receipt_check`` decides what counts as a receipt; the
    orchestrator passes its ``_promotion_grade_receipt`` (verification
    role AND not detection-only — the same bar the promotion and
    overturn sites use), and that is also the default. A bare
    ``is_tool_evidence`` is deliberately NOT used: it admits
    detection-role stamps that may not convict alone, and a grade must
    clear the same bar as the status it grades. Findings without such
    a receipt or without model attribution carry no grade and are
    skipped. Returns the number of events buffered. Never raises."""
    try:
        from core.llm.scorecard import EventType

        if receipt_check is None:
            # Lazy: this module is imported at orchestrator import time,
            # so the reverse import must not run at module scope.
            from .orchestrator import _promotion_grade_receipt
            receipt_check = _promotion_grade_receipt

        n = 0
        for outcome in outcomes or ():
            if getattr(outcome, "status", "") != "finding":
                continue
            if not (getattr(outcome, "hypothesis", "") or "").strip():
                continue
            if not receipt_check(
                getattr(outcome, "evidence_tool", "") or "",
            ):
                continue
            model = getattr(outcome, "model", "") or lone_model(models)
            n += buffer_event(
                events,
                model=model,
                cwe=_outcome_cwe(outcome),
                event_type=EventType.TOOL_EVIDENCE,
                grade="correct",
                key=outcome_key(outcome),
            )
        return n
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("confirmed-findings buffering failed", exc_info=True)
        return 0


def resolve_scorecard_store(client: Any) -> tuple[Any, bool]:
    """Resolve the run's scorecard store from its LLM client.

    Returns ``(store, disabled)``: ``store`` is the client's own
    ``ModelScorecard`` when it exposes one (property or zero-arg
    method); ``disabled`` is True when the client's config explicitly
    turned the scorecard off — the flush must then write nothing
    rather than fall back to the default sidecar. Never raises."""
    try:
        if client is None:
            return None, False
        store = getattr(client, "scorecard", None)
        if callable(store):
            store = store()
        if store is not None:
            return store, False
        cfg = getattr(client, "config", None)
        if cfg is not None and getattr(cfg, "scorecard_enabled", True) is False:
            return None, True
        return None, False
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("scorecard store resolution failed", exc_info=True)
        return None, False


def is_reconcilable(ev: dict[str, Any]) -> bool:
    """True when the flush reconciles this event against the final
    finding set — a ``tool_evidence`` grade that does not grade the
    refuter. Reconciliation is only decidable at END of run (a
    buffered refutation is dropped when its function ends as a
    finding), so reconcilable events must never ship in an
    incremental mid-run flush: consistency-axis events and refuter
    grades are settled the moment they buffer, these are not."""
    try:
        from core.llm.scorecard import EventType

        return (
            ev.get("event_type") == EventType.TOOL_EVIDENCE
            and not ev.get("_grades_refuter")
        )
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug("reconcilability probe failed", exc_info=True)
        # Fail toward holding the event for the final flush, which
        # applies the full reconciliation rules.
        return True


def _valid_pending(ev: dict[str, Any], all_event_types: Any) -> bool:
    """Pre-flight the shape ``record_events`` validates pre-lock.

    ``record_events`` is all-or-nothing: ONE invalid entry raises
    before the lock and the whole batch — the run's entire telemetry —
    is lost. Filter per entry instead so one malformed dict costs only
    itself."""
    if ev.get("event_type") not in all_event_types:
        return False
    if ev.get("outcome") not in ("correct", "incorrect"):
        return False
    return bool(ev.get("model")) and bool(ev.get("decision_class"))


def flush_scorecard_events(
    events: list[dict[str, Any]],
    *,
    finding_keys: Any = frozenset(),
    scorecard: Any = None,
    seen: set[tuple[str, str, str, str, str]] | None = None,
) -> int:
    """Reconcile the buffered events and write them in ONE batch.

    * ``tool_evidence`` grades (except refuter grades) reconcile
      against the final finding set both ways: ``incorrect`` dropped
      when the function ends the run as a finding (the refutation was
      itself overturned), ``correct`` dropped when it does not (the
      run no longer stands behind the confirmation). Consistency-axis
      events are never reconciled — the flip/dispute happened.
    * Dedups on ``(model, decision_class, event_type, outcome, key)``
      — first-buffered wins, so one function demoted by several
      mechanical passes counts one miss, not several, while an
      opposite-direction grade for the same cell is preserved for the
      reconciliation above to arbitrate.
    * ``seen``: caller-owned cross-flush dedup state. A run that
      flushes incrementally passes the same set to every flush so a
      cell already written by an earlier flush is never re-written by
      a later one — the per-call dedup alone cannot see across calls.
      Tuples for this call's events are committed into the caller's
      set only AFTER the batch write succeeds, so a failed write
      leaves them retryable instead of silently dropped.
    * Drops entries that would fail ``record_events``' pre-lock
      validation per entry, instead of letting one malformed dict
      abort the whole batch.
    * Resolves the default sidecar (shared-path resolver) only when
      the caller supplied no store.

    Returns the number of events written; 0 on any failure (the
    events are telemetry — an unwritable sidecar must never fail the
    run). Never raises.
    """
    try:
        from core.llm.scorecard import EventType, ModelScorecard
        from core.llm.scorecard.scorecard import ALL_EVENT_TYPES

        keys = set(finding_keys or ())
        pending: list[dict[str, Any]] = []
        seen_local: set[tuple[str, str, str, str, str]] = (
            set(seen) if seen else set()
        )
        for ev in events or ():
            if not isinstance(ev, dict):
                continue
            key = str(ev.get("_key") or "")
            if (
                ev.get("event_type") == EventType.TOOL_EVIDENCE
                and not ev.get("_grades_refuter")
            ):
                is_finding = key in keys
                if ev.get("outcome") == "incorrect" and is_finding:
                    continue
                if ev.get("outcome") == "correct" and not is_finding:
                    continue
            if not _valid_pending(ev, ALL_EVENT_TYPES):
                logger.debug("dropping malformed scorecard event: %r", ev)
                continue
            dedup = (
                str(ev.get("model") or ""),
                str(ev.get("decision_class") or ""),
                str(ev.get("event_type") or ""),
                str(ev.get("outcome") or ""),
                key,
            )
            if key and dedup in seen_local:
                continue
            seen_local.add(dedup)
            pending.append({
                k: v for k, v in ev.items() if k not in _PRIVATE_KEYS
            })
        if not pending:
            return 0
        if scorecard is None:
            from core.llm.scorecard.paths import default_scorecard_path

            scorecard = ModelScorecard(default_scorecard_path())
        scorecard.record_events(pending)
        if seen is not None:
            seen.update(seen_local)
        logger.info(
            "audit scorecard: recorded %d reliability event(s)",
            len(pending),
        )
        return len(pending)
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.warning(
            "audit scorecard flush failed — reliability events dropped "
            "for this run",
            exc_info=True,
        )
        return 0


__all__ = [
    "buffer_confirmed_findings",
    "buffer_event",
    "cap_key",
    "flush_scorecard_events",
    "is_reconcilable",
    "lone_model",
    "outcome_key",
    "record_adversarial_outcome",
    "record_mechanical_refutation",
    "record_self_consistency_violation",
    "resolve_scorecard_store",
]
