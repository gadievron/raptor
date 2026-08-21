"""Promotion-without-tool-evidence alarm.

The mechanical-verdict principle makes ``finding`` a tool-gated claim:
every in-loop finding passes the G2 gate (demoted to suspicious unless
``is_tool_evidence`` holds or a domain-model invariant match is
recorded), and every post-loop promotion (sweep, SMT, dark-verify,
integer-narrowing) stamps the confirming tool via ``_promote_outcome``
or an explicit receipt.  A ``finding`` that reaches the journal or the
findings export WITHOUT qualifying tool evidence is therefore the
signature of either a successful prompt injection steering the verdict
machinery or a policy-bypass bug — this event class is EMPTY on every
legitimate run.

``suspicious`` is deliberately NOT alarmed: it is the designed
LLM-guess bucket ("suspicious-only verdicts are LLM guesses"), so an
evidence-less suspicious entry is routine and alarming it would break
the empty-on-legitimate-runs invariant this detector relies on.

The alarm both records AND gates.  Each violation emits a CRITICAL
log line and appends a structured record to
``<out_dir>/promotion-alarms.jsonl`` (same one-writer JSONL pattern as
``suppressions.jsonl``); the report surfaces the count.  Chokepoint
callers (journal-write, findings-export) pass ``enforce=True`` so a
violating ``finding`` is demoted to ``suspicious`` before it ships —
an alarm that logs CRITICAL and then writes the promotion anyway is
not a gate (a corpus run shipped a false-positive ``finding`` through
exactly that gap).  ``suspicious`` is the designed LLM-guess bucket,
so the demotion keeps the claim visible without minting a tool-gated
verdict.  Best-effort throughout: alarm failures must never lose a
review outcome.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import append_jsonl, load_jsonl

logger = logging.getLogger(__name__)

ALARM_EVENT = "promotion_without_tool_evidence"
ALARM_FILENAME = "promotion-alarms.jsonl"

# Journal verdict class the alarm applies to.  Mirrors the tool-gated
# claim class — see module docstring for why ``suspicious`` is out.
ALARMED_VERDICTS = frozenset({"finding"})

# review_result key stamped by the orchestrator's G2 gate when a
# finding is allowed through on a domain-model invariant match instead
# of tool evidence.  A designed exception, not a bypass — the alarm
# honours it and records nothing.
G2_BYPASS_KEY = "g2_invariant_bypass"


def _has_tool_evidence(evidence_tool: str) -> bool:
    from .evidence_grade import is_tool_evidence

    return is_tool_evidence(evidence_tool or "")


def build_alarm_record(
    *,
    stage: str,
    file: str,
    function: str,
    verdict: str,
    evidence_tool: str,
    review_result: dict[str, Any] | None = None,
    hypothesis: str = "",
    run_id: str = "",
) -> dict[str, Any] | None:
    """Return an alarm record when the outcome violates the
    tool-gated-promotion invariant, else None.

    ``evidence_tool`` must be the CONFIRMING receipt stamp
    (``outcome.evidence_tool``), never the ``tools_dispatched`` union —
    a dispatched-but-unconfirmed tool is not evidence.
    """
    if verdict not in ALARMED_VERDICTS:
        return None
    if _has_tool_evidence(evidence_tool):
        return None
    bypass = (review_result or {}).get(G2_BYPASS_KEY)
    if bypass:
        return None
    return {
        "event": ALARM_EVENT,
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "run_id": run_id,
        "file": file,
        "function": function,
        "verdict": verdict,
        "evidence_tool": evidence_tool or "",
        "hypothesis": (hypothesis or "")[:500],
    }


def emit_alarm(out_dir: Path, record: dict[str, Any]) -> None:
    """CRITICAL log + one JSONL line in the run's audit artifacts.

    Same single-purpose append pattern as ``suppressions.jsonl`` —
    ``core.json.append_jsonl``'s O_APPEND keeps concurrent writers
    line-atomic and its O_NOFOLLOW refuses a symlink planted at the
    trail path.  IO errors are logged at debug and swallowed
    (alarm-only, never load-bearing).
    """
    logger.critical(
        "%s: %s:%s reached verdict %r without qualifying tool evidence "
        "(evidence_tool=%r, stage=%s) — the mechanical-verdict gate was "
        "bypassed; treat as possible injection or policy bug",
        ALARM_EVENT,
        record.get("file"),
        record.get("function"),
        record.get("verdict"),
        record.get("evidence_tool"),
        record.get("stage"),
    )
    try:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(out_dir / ALARM_FILENAME, record, sort_keys=True)
    except OSError:
        logger.debug("promotion alarm write failed", exc_info=True)


DEMOTION_MARKER = "[promotion-gate: demoted finding -> suspicious — no qualifying tool evidence]"


def _enforce_demotion(outcome: Any, record: dict[str, Any]) -> None:
    """Demote a violating ``finding`` to ``suspicious`` in place.

    The demotion is stamped on the outcome (body marker +
    ``review_result["promotion_gate_demoted"]``) and on the alarm
    record (``"blocked": True``) so the JSONL trail says whether the
    gate observed or acted.  Never raises — a gate that loses the
    outcome is worse than a gate that ships it.
    """
    outcome.status = "suspicious"
    record["blocked"] = True
    try:
        body = getattr(outcome, "body", "") or ""
        outcome.body = f"{DEMOTION_MARKER}\n{body}" if body else DEMOTION_MARKER
    except Exception:
        logger.debug("promotion gate body marker failed", exc_info=True)
    rr = getattr(outcome, "review_result", None)
    if isinstance(rr, dict):
        rr["promotion_gate_demoted"] = True
    logger.warning(
        "promotion gate: %s:%s demoted finding -> suspicious at %s — "
        "no qualifying tool evidence (evidence_tool=%r)",
        record.get("file"), record.get("function"),
        record.get("stage"), record.get("evidence_tool"),
    )


def check_and_emit(
    out_dir: Path,
    outcome: Any,
    *,
    stage: str,
    run_id: str = "",
    enforce: bool = False,
) -> dict[str, Any] | None:
    """Chokepoint hook: alarm if *outcome* is an evidence-less finding.

    With ``enforce=True`` (the journal-write and findings-export
    chokepoints) a violating outcome is also demoted to ``suspicious``
    before the caller writes it — see the module docstring.  Returns
    the emitted record (for tests / callers that aggregate), or None
    when the outcome is legitimate.
    """
    try:
        record = build_alarm_record(
            stage=stage,
            file=getattr(outcome, "file", "") or "",
            function=getattr(outcome, "function", "") or "",
            verdict=getattr(outcome, "status", "") or "",
            evidence_tool=getattr(outcome, "evidence_tool", "") or "",
            review_result=getattr(outcome, "review_result", None),
            hypothesis=getattr(outcome, "hypothesis", "") or "",
            run_id=run_id,
        )
        if record is not None:
            if enforce:
                _enforce_demotion(outcome, record)
            emit_alarm(Path(out_dir), record)
        return record
    except Exception:  # alarm must never break the write path
        logger.debug("promotion alarm check failed", exc_info=True)
        return None


def load_alarms(out_dir: Path) -> list[dict[str, Any]]:
    """Read back the run's alarm records (report / test surface)."""
    path = Path(out_dir) / ALARM_FILENAME
    return [rec for rec in load_jsonl(path) if isinstance(rec, dict)]


def check_outcomes(
    out_dir: Path,
    outcomes: Iterable[Any],
    *,
    stage: str,
    run_id: str = "",
    enforce: bool = False,
) -> list[dict[str, Any]]:
    """Sweep a batch of outcomes (post-loop export surface)."""
    emitted: list[dict[str, Any]] = []
    for outcome in outcomes:
        rec = check_and_emit(
            out_dir, outcome, stage=stage, run_id=run_id, enforce=enforce,
        )
        if rec is not None:
            emitted.append(rec)
    return emitted
