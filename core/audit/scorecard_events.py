"""Scorecard producer for /audit's graded adjudication points.

Records per-model reliability events into the shared scorecard sidecar
(``core.llm.scorecard.ModelScorecard``) at the points where a later,
stronger signal genuinely grades an earlier model decision:

* ``tool_evidence`` — a deterministic receipt settled the model's
  hypothesis: a named mechanical refutation (in-loop refutation gate,
  sweep re-validation, dynamic harness, post-deepen demotion gate,
  dark-verify witness) grades the positive verdict ``incorrect``; a
  shipped finding backed by a verification-grade receipt grades the
  hypothesis ``correct``.
* ``judge_review`` — the adversarial refuter (a different model)
  reviewed a positive verdict and overruled (demotion applied →
  ``incorrect``) or upheld it (``stands`` → ``correct``). Unlike the
  single-judge /agentic path, the audit pipeline ACTS on the refuter's
  ruling, so the adjudication is resolved, not merely flagged.
* ``self_consistency`` — same-model adversarial re-examination
  (single-model runs are self-adversarial: held → ``correct``,
  flipped → ``incorrect``), and mechanical verdict-vs-own-hypotheses
  contradictions (all-refuted-yet-suspicious, clean-with-live-
  hypotheses → ``incorrect``). Deliberately a consistency axis:
  ``self_consistency`` is not in ``calibrated_merge``'s
  ``RELIABILITY_EVENT_TYPES``, so these never move merge weights.

Where a graded outcome does NOT genuinely exist, nothing is emitted:
``needs_evidence`` refuter verdicts, refutations floored by a tool
receipt (conflicting receipts, unresolved), demotion-referee floors
(they block a demotion for missing evidence, they don't falsify it),
and binary-oracle absent demotions (a build-reachability fact, not a
model-competence grade).

Emission contract (the orchestrator depends on all three):

* **Never raises.** Every entry point catches and logs at debug —
  scorecard telemetry must never break an audit run.
* **Buffered.** Events append to an in-memory list on the run result
  (plain ``list.append``, atomic under the GIL for the parallel
  passes) and are flushed ONCE at end of run through the public
  batch API (``ModelScorecard.record_events`` — one lock/load/write
  cycle), so no sidecar I/O lands on the per-function hot path.
* **Reconciled.** At flush, a ``tool_evidence``/``incorrect`` event
  against a function that ends the run as a finding is dropped — a
  later pass overturned the refutation, so the run no longer stands
  behind the signal that graded the model wrong. Events grading the
  REFUTER (its refutation contradicted by a tool receipt) are exempt:
  that grade is settled by the receipt itself, and the finding
  surviving is precisely the evidence.

Decision classes follow the audit convention (``audit:<CWE>``, falling
back to ``audit:review``) via ``calibrated_merge.decision_class_for``,
so the cells written here are the same cells the calibrated merge
reads.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from core.llm.scorecard import _MAX_REASONING_CHARS

logger = logging.getLogger(__name__)

# Private bookkeeping keys stripped before the batch write.
_PRIVATE_KEYS = ("_key", "_grades_refuter")

# Self-consistency panel handles run the SAME model under suffixed
# names (``<model>#sc<i>``, see ``multi_review.run_self_consistency``)
# and the merged primary can carry that suffix — cells must key on the
# real model, not the sample handle.
_SC_HANDLE_SUFFIX = re.compile(r"#sc\d+$")


def _normalize_model(model: str) -> str:
    return _SC_HANDLE_SUFFIX.sub("", str(model or "").strip())


def lone_model(models: Any) -> str:
    """The single configured model name, or ``""`` when the run is
    multi-model / unconfigured. Used as the attribution fallback for
    outcomes that lost their ``model`` stamp — on a single-model run
    the attribution is still factual; on a multi-model run it would
    be a guess, so the event is skipped instead. The ``"default"``
    placeholder (OrchestratorConfig's unconfigured sentinel, not a
    model name) never attributes."""
    try:
        if models and len(models) == 1 and models[0]:
            name = str(models[0])
            if name != "default":
                return name
    except Exception:  # noqa: BLE001 — attribution fallback, never raise
        logger.debug("lone_model resolution failed", exc_info=True)
    return ""


def _outcome_key(outcome: Any) -> str:
    return (
        f"{getattr(outcome, 'file', '')}:{getattr(outcome, 'function', '')}"
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

    Skip cases (False): missing model attribution, or a grade outside
    the correct/incorrect vocabulary. Never raises.
    """
    try:
        model = _normalize_model(model)
        if not model or grade not in ("correct", "incorrect"):
            return False
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
    """A named mechanical check overturned the model's positive
    verdict → ``tool_evidence``/``incorrect``. Never raises."""
    try:
        from core.llm.scorecard import EventType

        model = getattr(outcome, "model", "") or lone_model(models)
        return buffer_event(
            events,
            model=model,
            cwe=_outcome_cwe(outcome),
            event_type=EventType.TOOL_EVIDENCE,
            grade="incorrect",
            key=_outcome_key(outcome),
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
    """The model's verdict contradicted its own hypothesis record →
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
            key=_outcome_key(outcome),
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
      drops it — the surviving finding IS the evidence).
    * ``verdict == "stands"``: upheld. Cross-model refuter →
      ``judge_review``/``correct``; self-adversarial →
      ``self_consistency``/``correct`` (verdict held under re-ask).
    * ``verdict == "refuted"`` (demotion applied): overruled.
      Cross-model → ``judge_review``/``incorrect``; self-adversarial
      → ``self_consistency``/``incorrect`` (verdict flipped).

    Callers must NOT invoke this for ``needs_evidence`` verdicts or
    for refutations floored by an existing tool receipt — those
    adjudications are unresolved and carry no grade.
    """
    try:
        from core.llm.scorecard import EventType

        producer = producer_model or lone_model(models)
        key = _outcome_key(outcome)
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
            else EventType.JUDGE_REVIEW
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
) -> int:
    """End-of-run confirmed direction: every shipped finding backed by
    a verification-grade receipt grades its model's hypothesis
    ``tool_evidence``/``correct``. Findings without such a receipt or
    without model attribution carry no grade and are skipped. Returns
    the number of events buffered. Never raises."""
    try:
        from core.llm.scorecard import EventType

        from .evidence_grade import is_tool_evidence

        n = 0
        for outcome in outcomes or ():
            if getattr(outcome, "status", "") != "finding":
                continue
            if not (getattr(outcome, "hypothesis", "") or "").strip():
                continue
            if not is_tool_evidence(getattr(outcome, "evidence_tool", "") or ""):
                continue
            model = getattr(outcome, "model", "") or lone_model(models)
            n += buffer_event(
                events,
                model=model,
                cwe=_outcome_cwe(outcome),
                event_type=EventType.TOOL_EVIDENCE,
                grade="correct",
                key=_outcome_key(outcome),
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


def flush_scorecard_events(
    events: list[dict[str, Any]],
    *,
    finding_keys: Any = frozenset(),
    scorecard: Any = None,
) -> int:
    """Reconcile the buffered events and write them in ONE batch.

    * Drops ``tool_evidence``/``incorrect`` events (except refuter
      grades) whose function ends the run as a finding — the
      refutation was itself overturned by a later rescue.
    * Dedups on ``(model, decision_class, event_type, key)`` —
      first-buffered wins, so one function demoted by several
      mechanical passes counts one miss, not several.
    * Resolves the default sidecar (shared-path resolver) only when
      the caller supplied no store.

    Returns the number of events written; 0 on any failure (the
    events are telemetry — an unwritable sidecar must never fail the
    run). Never raises.
    """
    try:
        from core.llm.scorecard import EventType, ModelScorecard

        keys = set(finding_keys or ())
        pending: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for ev in events or ():
            if not isinstance(ev, dict):
                continue
            key = str(ev.get("_key") or "")
            if (
                key in keys
                and ev.get("outcome") == "incorrect"
                and ev.get("event_type") == EventType.TOOL_EVIDENCE
                and not ev.get("_grades_refuter")
            ):
                continue
            dedup = (
                str(ev.get("model") or ""),
                str(ev.get("decision_class") or ""),
                str(ev.get("event_type") or ""),
                key,
            )
            if key and dedup in seen:
                continue
            seen.add(dedup)
            pending.append({
                k: v for k, v in ev.items() if k not in _PRIVATE_KEYS
            })
        if not pending:
            return 0
        if scorecard is None:
            from core.llm.scorecard.paths import default_scorecard_path

            scorecard = ModelScorecard(default_scorecard_path())
        scorecard.record_events(pending)
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
    "flush_scorecard_events",
    "lone_model",
    "record_adversarial_outcome",
    "record_mechanical_refutation",
    "record_self_consistency_violation",
    "resolve_scorecard_store",
]
