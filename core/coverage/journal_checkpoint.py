"""Mid-audit journal checkpoint — bounded, quiesced, crash-atomic.

The loader's per-shard retained budgets (``core.coverage.journal``)
are a wall: a journal that grows past them mid-run degrades every
read-only consumer to a partial view and refuses the next resume's
spend authorization — historically a manual drain / ``journal
compact`` / resume cycle, paying the full re-init cost (Joern/CPG
reload, prep-cache rebuild, dispatcher restart) for what is seconds
of compaction. This module is the ONE checkpoint implementation all
call sites share:

* **resume-time** (``raptor-audit resume``, segment start) — absorbs
  the former inline segment-start auto-compact;
* **segment boundaries** in the orchestrator (post-review drain,
  post-loop passes) — the executor has returned, workers are joined;
* **quiesce points** inside the review executor — the trigger is
  evaluated at dispatch points during the segment, and when it fires
  the executor stops issuing reviews, drains inflight work (bounded),
  and runs the checkpoint synchronously in its own driving thread
  before resuming dispatch (``core.audit.journal_quiesce``).

TRIGGER: largest single shard over
``_CHECKPOINT_TRIGGER_FRACTION`` of the loader's per-shard retained
byte budget — the same axis the budgets themselves bound, evaluated
by ``stat`` only (never a parse).

TIERS: dedup + supersede run automatically — both are spend-safe by
the compactor's loss contract (protected row classes retained
outright, spend floor re-verified against the written bytes, full
archive per shard). The slim tier moves row CONTENT out of the live
journal and stays under its existing operator consent surface
(``raptor-audit journal compact --slim-clean``); the checkpoint
never widens that consent — ``slim_consent`` exists for callers that
already hold it, no RAPTOR call site passes True today, and the
incompressible-journal advisory routes operators to the existing
command instead.

HYSTERESIS: a checkpoint that freed less than
``_CHECKPOINT_MIN_FREED_FRACTION`` of its input marks the journal
"legitimately large" in the run-dir state record
(:data:`CHECKPOINT_STATE_FILENAME` — run-dir state, not process
memory: segments span processes). Later evaluations do NOT re-fire
until the journal grows by ``_CHECKPOINT_REARM_FRACTION`` of the
budget past the recorded post-checkpoint size — an incompressible
journal of live distinct verdicts must not thrash a full two-pass
rewrite at every boundary; it gets one loud advisory instead.

SAFETY (each pinned in core/coverage/tests/test_journal_checkpoint*):

1. The checkpoint runs SYNCHRONOUSLY in the caller's own thread and
   REFUSES to enter while review work is in flight — an enforced
   guard (:class:`CheckpointBusy` on
   ``core.audit.executor.review_work_inflight() > 0`` or any caller
   busy-probe), not a convention. It is never submitted to the
   executor and never waits on executor-produced state (the
   studywedge self-deadlock class).
2. LOCK ORDER (enforced in :func:`checkpoint_journal`, stated where
   acquired): collector drained and PROVABLY empty → journal state
   read → compactor locks (sidecar flock before the per-shard journal
   flocks — the compactor's own documented order). The checkpoint
   acquires no lock before the collector assertion passes and holds
   no lock while waiting on anything.
3. Foreign appenders (SAGE hooks, subprocesses) blocked across the
   compactor's rename land their rows in the LIVE journal — the
   appender's post-flock inode re-validation
   (``journal.append_entry``).
4. CRASH ATOMICITY: the compactor's tmp + re-parse + rename
   discipline is unchanged; a SIGKILL at any phase leaves the old or
   the new journal COMPLETE, archives intact, spend floor preserved,
   and the run resumable (kill-matrix suite).
5. DRAIN INTERPLAY: the checkpoint is drain-aware — ``should_abort``
   (wired to the orchestrator's SIGTERM request) is polled at entry
   and inside the compactor's abort seams, which all sit OUTSIDE the
   backup+rename window; a signal before the swap aborts with the
   journal byte-identical, a signal after the swap lets the completed
   swap stand. Forced exits (second TERM, watchdog ``os._exit``) are
   the kill-matrix case.
6. CONSUMER INVALIDATION: the compactor drops the process-local load
   cache per swapped shard — one cold reload of the journal per
   checkpoint, and nothing else: no Joern, dispatcher, or prep-cache
   surface is touched (prep-cache doctrine already forbids
   journal-derived fingerprints; the no-restart spy suite pins it).
7. BOUNDED: ``_CHECKPOINT_WALL_BOUND_S`` rides the compactor's
   deadline seams — on exceeding, the current shard aborts
   byte-identical, one loud line, and the run continues to the next
   evaluation. The run never blocks indefinitely on its own hygiene.
"""

from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from . import journal as _journal
from .journal_compact import (
    CompactAborted,
    CompactRefused,
    CompactStats,
    compact_journal,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

logger = logging.getLogger(__name__)

#: Run-dir state record: the last checkpoint's outcome, read by the
#: NEXT trigger evaluation (hysteresis) — run-dir state because
#: resume segments span processes. Attacker-tolerant on read: the
#: record can only SUPPRESS a checkpoint (worst case is the pre-
#: checkpoint status quo), never widen consent or authorize spend.
CHECKPOINT_STATE_FILENAME = ".journal-checkpoint-state.json"
_STATE_SCHEMA_VERSION = 1
_MAX_STATE_BYTES = 64 * 1024

#: Trigger threshold as a fraction of the loader's per-shard retained
#: byte budget. Trade-off, both directions: LOWER fires checkpoints
#: on journals with plenty of headroom (each is a full two-pass
#: rewrite of the shard set — wasted I/O and a needless cold reload
#: for every read-only consumer); HIGHER narrows the margin to the
#: appender's roll threshold (75% of the budget) and the loader's
#: prune-exit margin (90%) — past the roll threshold the oversized
#: shard is SEALED and no later checkpoint can shrink what a reader
#: must still parse. 65% fires before any of those walls with one
#: evaluation interval of growth to spare.
_CHECKPOINT_TRIGGER_FRACTION = 0.65

#: Hysteresis floor: a checkpoint that freed less than this fraction
#: of its input bytes counts as INEFFECTIVE — the journal is
#: dominated by live distinct verdicts the automatic tiers must not
#: touch. Trade-off, both directions: LOWER lets near-no-op
#: checkpoints re-fire at every boundary (the thrash this floor
#: exists to stop); HIGHER writes off checkpoints that reclaimed
#: real headroom (10% of the budget is ~26 MiB — several segments of
#: appends) and goes advisory too early. One-tenth of the input is
#: the smallest win that meaningfully delays the next trigger.
_CHECKPOINT_MIN_FREED_FRACTION = 0.10

#: Re-arm growth after an ineffective checkpoint, as a fraction of
#: the loader budget: the journal must grow this many bytes past the
#: recorded post-checkpoint size before the trigger fires again.
#: Trade-off, both directions: LOWER re-fires a provably-ineffective
#: rewrite after trivial growth (thrash); HIGHER sits on a journal
#: whose NEW growth may be full of foldable re-emissions while it
#: drifts toward the roll threshold. 10% of the budget bounds the
#: rewrite cadence to once per ~26 MiB of genuinely new rows.
_CHECKPOINT_REARM_FRACTION = 0.10

#: Hard wall-clock bound on one checkpoint's transform. Trade-off,
#: both directions: LOWER aborts legitimate compactions of
#: at-threshold shards (a ~170 MiB shard is two full streaming
#: parses plus a re-parse floor check — tens of seconds on slow
#: disks, and the slim tier adds sidecar writes); HIGHER lets the
#: run stall on its own hygiene — the checkpoint runs synchronously
#: in the main loop, so every second here is a second of paused
#: reviews. 300s is ~10x the measured at-threshold compaction and
#: still small against the drain/resume cycle it replaces.
_CHECKPOINT_WALL_BOUND_S = 300.0


class CheckpointBusy(RuntimeError):
    """A checkpoint precondition failed — review work in flight or
    the collector not provably empty. Raised (never silently
    ignored): entering the checkpoint in that state risks the
    studywedge deadlock class or losing buffered rows across the
    swap. Callers at run boundaries catch it, log loudly, and skip —
    the run continues on the old journal."""


@dataclass
class CheckpointOutcome:
    """One checkpoint attempt's result (all paths return one)."""

    fired: bool = False
    advisory: bool = False
    aborted: bool = False
    #: The compactor refused (live foreign worker, unreadable run
    #: metadata, ...). Distinct from ``aborted`` so pollers can arm a
    #: retry cooldown: a persistent refusal must not re-fire — and,
    #: in the async executor, re-pay the full inflight drain — at
    #: every evaluation interval.
    refused: bool = False
    reason: str = ""
    stats: CompactStats | None = None
    duration_s: float = 0.0
    freed_fraction: float = 0.0


def trigger_bytes() -> int:
    """The retained-size trigger, derived at call time so it always
    tracks the loader budget (tests monkeypatch the budget)."""
    return int(_journal._MAX_JOURNAL_BYTES * _CHECKPOINT_TRIGGER_FRACTION)


def rearm_bytes() -> int:
    """Growth required past an ineffective checkpoint's recorded size
    before the trigger re-arms."""
    return int(_journal._MAX_JOURNAL_BYTES * _CHECKPOINT_REARM_FRACTION)


def max_shard_bytes(out_dir: Path) -> int:
    """Largest single shard's size — the trigger's measured axis (the
    loader budgets are PER-SHARD bounds; total size is expected to
    exceed any one of them on multi-shard journals)."""
    largest = 0
    for shard in _journal.journal_shard_paths(out_dir):
        try:
            largest = max(largest, shard.stat().st_size)
        except OSError:
            continue
    return largest


def _load_state(out_dir: Path) -> dict[str, Any] | None:
    """The last checkpoint's state record, or None. Hostile-tolerant:
    the file lives in the sandbox-writable run dir, and every failure
    (absent, oversize, unparseable, wrong-typed fields) reads as "no
    state" — which can only make the trigger FIRE more, never less,
    and firing is the safe direction (a checkpoint on a healthy
    journal is wasted I/O, not lost data)."""
    from core.json import load_json
    path = Path(out_dir) / CHECKPOINT_STATE_FILENAME
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_STATE_BYTES)
    except Exception:  # noqa: BLE001 — run-dir content; containment boundary
        return None
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != _STATE_SCHEMA_VERSION:
        return None
    for key in ("max_shard_bytes_after", "bytes_before", "bytes_after"):
        v = data.get(key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return None
    if not isinstance(data.get("effective"), bool):
        return None
    # freed_fraction feeds a % format in the advisory reason — a
    # non-numeric / non-finite / out-of-range value must read as "no
    # state" (fire more, the safe direction), never reach a caller.
    ff = data.get("freed_fraction", 0.0)
    if (isinstance(ff, bool) or not isinstance(ff, (int, float))
            or not math.isfinite(ff) or not 0.0 <= ff <= 1.0):
        return None
    return data


def _write_state(out_dir: Path, record: dict[str, Any]) -> None:
    """Persist the outcome record (atomic tempfile+rename via
    save_json). Best-effort: a persist failure costs hysteresis for
    one boundary, never the run."""
    from core.json import save_json
    try:
        save_json(Path(out_dir) / CHECKPOINT_STATE_FILENAME, record)
    except Exception:  # noqa: BLE001 — state is an optimization, never run-critical
        logger.warning(
            "journal checkpoint: state persist failed for %s",
            out_dir, exc_info=True,
        )


@dataclass
class TriggerDecision:
    fire: bool
    advisory: bool
    reason: str
    size: int


def evaluate_trigger(out_dir: Path) -> TriggerDecision:
    """Whether a checkpoint should fire for *out_dir* right now.

    stat-only (never parses the journal): callers poll this at
    dispatch points. Hysteresis: an ineffective last checkpoint
    suppresses re-fire until the journal grows past its recorded
    post-checkpoint size by :func:`rearm_bytes` — the advisory arm.
    An ABORTED last attempt never arms the hysteresis (nothing was
    measured), so the next evaluation retries.
    """
    size = max_shard_bytes(out_dir)
    threshold = trigger_bytes()
    if size <= threshold:
        return TriggerDecision(
            False, False,
            f"under threshold ({size} <= {threshold} bytes)", size)
    state = _load_state(out_dir)
    if (state is not None and not state["effective"]
            and size <= state["max_shard_bytes_after"] + rearm_bytes()):
        return TriggerDecision(
            False, True,
            "journal legitimately large: the last checkpoint freed "
            f"{state.get('freed_fraction', 0.0):.1%} "
            f"(< {_CHECKPOINT_MIN_FREED_FRACTION:.0%} floor) — live "
            "distinct verdicts dominate; not re-firing until the "
            f"journal grows past {state['max_shard_bytes_after'] + rearm_bytes()} "
            "bytes", size)
    return TriggerDecision(
        True, False, f"over threshold ({size} > {threshold} bytes)", size)


def preflight_refusal(
    out_dir: Path, *, allow_worker_pid: int | None = None,
) -> str | None:
    """Cheap poll-time restatement of the compactor's live-run /
    run-metadata refusal guard (one small JSON read plus a liveness
    check — no locks, no parse of the journal). Returns the refusal
    reason, or None when that guard would pass.

    Advisory only: the compactor re-asserts the same guard under its
    own locks, so a pass here authorizes nothing. It exists so
    dispatch-point pollers can skip the expensive quiesce drain (the
    async executor stops dispatch and waits for inflight reviews)
    when the attempt is already known to end in a refusal. Other
    refusal classes surface later and are handled by the refused-
    outcome cooldown."""
    from .journal_compact import _refuse_live_run
    try:
        _refuse_live_run(Path(out_dir), allow_worker_pid=allow_worker_pid)
    except CompactRefused as exc:
        return str(exc)
    return None


def _assert_quiesced(
    collector: Any | None,
    busy_probes: Sequence[Callable[[], str | None]],
) -> None:
    """The enforced precondition guard (charter: assertion, not
    convention). Raises :class:`CheckpointBusy` when review work is
    in flight or the collector cannot be proven empty.

    LOCK ORDER RULE (stated here, where the order begins): this guard
    — collector flush + provably-empty assertion, no locks held —
    runs strictly BEFORE any compactor lock (sidecar flock, then the
    per-shard journal flocks, in the compactor's own documented
    order). No checkpoint path acquires a journal lock and then
    waits on worker or collector state, so the collector/appender can
    never deadlock against the checkpoint.
    """
    try:
        from core.audit.executor import review_work_inflight
        inflight = review_work_inflight()
    except ImportError:      # journal-only installs have no executor
        inflight = 0
    if inflight > 0:
        raise CheckpointBusy(
            f"{inflight} review task(s) in flight — the checkpoint "
            "must only run with the executor drained (studywedge "
            "deadlock class); quiesce first"
        )
    for probe in busy_probes:
        detail = probe()
        if detail:
            raise CheckpointBusy(detail)
    if collector is not None:
        collector.flush()
        pending = collector.pending_count()
        if pending:
            raise CheckpointBusy(
                f"collector retained {pending} buffered row(s) after "
                "flush — cannot prove the write path empty; skipping "
                "the checkpoint (rows flush at the next boundary)"
            )


def checkpoint_journal(
    out_dir: Path,
    *,
    boundary: str,
    collector: Any | None = None,
    slim_consent: bool = False,
    allow_worker_pid: int | None = None,
    should_abort: Callable[[], bool] | None = None,
    busy_probes: Sequence[Callable[[], str | None]] = (),
    wall_bound_s: float = _CHECKPOINT_WALL_BOUND_S,
) -> CheckpointOutcome:
    """Run one checkpoint attempt at a quiesced point.

    *boundary* labels the call site in logs and the state record
    (``segment-start`` / ``post-review-drain`` / ``quiesce`` / ...).
    Raises :class:`CheckpointBusy` on a violated precondition;
    everything else resolves to a :class:`CheckpointOutcome` (the
    compactor's own refusals included — the journal stands).
    """
    out_dir = Path(out_dir)
    start = time.monotonic()
    _assert_quiesced(collector, busy_probes)

    if should_abort is not None and should_abort():
        return CheckpointOutcome(
            reason="drain requested — checkpoint skipped")

    decision = evaluate_trigger(out_dir)
    if decision.advisory:
        logger.warning(
            "journal checkpoint (%s): %s; the automatic tiers cannot "
            "shrink it further — if the loader budget is at risk, "
            "%s", boundary, decision.reason,
            _journal.compact_hint(out_dir),
        )
        return CheckpointOutcome(advisory=True, reason=decision.reason)
    if not decision.fire:
        return CheckpointOutcome(reason=decision.reason)

    logger.info(
        "journal checkpoint (%s): largest shard %d bytes > %d-byte "
        "trigger — compacting (dedup + supersede%s; bounded %.0fs)",
        boundary, decision.size, trigger_bytes(),
        " + slim" if slim_consent else "", wall_bound_s,
    )
    try:
        stats = compact_journal(
            out_dir,
            supersede=True,
            slim_clean=slim_consent,
            deadline_monotonic=start + wall_bound_s,
            should_abort=should_abort,
            allow_worker_pid=allow_worker_pid,
        )
    except CompactAborted as exc:
        # Loud, clean abort: the in-progress shard is byte-identical
        # (pinned by test), the run continues, and the NEXT evaluation
        # retries — no state write, so an abort never arms hysteresis.
        logger.warning(
            "journal checkpoint (%s): aborted — %s; the journal "
            "stands and the next evaluation point retries",
            boundary, exc,
        )
        return CheckpointOutcome(
            aborted=True, reason=str(exc),
            duration_s=time.monotonic() - start)
    except CompactRefused as exc:
        # WARNING, not info: a refusal at a fired trigger means the
        # journal keeps growing toward the roll threshold while the
        # stated condition persists — the operator should see why.
        logger.warning(
            "journal checkpoint (%s): compactor refused — %s",
            boundary, exc,
        )
        return CheckpointOutcome(
            refused=True, reason=str(exc),
            duration_s=time.monotonic() - start)

    duration = time.monotonic() - start
    freed = stats.bytes_before - stats.bytes_after
    freed_fraction = (
        freed / stats.bytes_before if stats.bytes_before else 0.0
    )
    effective = freed_fraction >= _CHECKPOINT_MIN_FREED_FRACTION
    _write_state(out_dir, {
        "schema_version": _STATE_SCHEMA_VERSION,
        "ts": _journal.now_iso(),
        "boundary": boundary,
        "max_shard_bytes_before": decision.size,
        "max_shard_bytes_after": max_shard_bytes(out_dir),
        "bytes_before": stats.bytes_before,
        "bytes_after": stats.bytes_after,
        "freed_fraction": round(freed_fraction, 4),
        "effective": effective,
        "duration_s": round(duration, 3),
        "pid": os.getpid(),
    })
    log = logger.info if effective else logger.warning
    log(
        "journal checkpoint (%s): %d -> %d rows, %d -> %d bytes "
        "(freed %.1f%%) in %.1fs%s",
        boundary, stats.rows_before, stats.rows_after,
        stats.bytes_before, stats.bytes_after,
        freed_fraction * 100.0, duration,
        "" if effective else (
            " — under the effectiveness floor; the journal is "
            "legitimately large (live distinct verdicts) and the "
            "trigger will not re-fire until it grows; "
            + _journal.compact_hint(out_dir)
        ),
    )
    return CheckpointOutcome(
        fired=True, reason=decision.reason, stats=stats,
        duration_s=duration, freed_fraction=freed_fraction,
    )


__all__ = [
    "CHECKPOINT_STATE_FILENAME",
    "CheckpointBusy",
    "CheckpointOutcome",
    "TriggerDecision",
    "checkpoint_journal",
    "evaluate_trigger",
    "max_shard_bytes",
    "preflight_refusal",
    "rearm_bytes",
    "trigger_bytes",
]
