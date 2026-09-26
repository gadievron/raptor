"""Quiesce coordinator for the mid-audit journal checkpoint.

One object per orchestrator run, shared by every call site so the
trigger cadence, hysteresis, and cooldowns are a single state
machine (never two implementations):

* the review executor's quiesce points (``core.audit.executor`` —
  serial loop head, async loop head after a bounded inflight drain);
* the orchestrator's segment boundaries (post-review drain, post-
  loop passes);
* ``raptor-audit resume`` runs the checkpoint core directly at
  segment start (no executor exists yet, nothing to quiesce).

The transform itself lives in
``core.coverage.journal_checkpoint.checkpoint_journal`` — this class
adds what only the audit side knows: the study consumer's park /
resume protocol, the run's own worker-pid self-permit, the SIGTERM
drain signal, and the executor-facing cadence (evaluation interval,
drain bound, retry cooldown).

The whole point is the NO-RESTART property: the run pauses for
seconds of compaction instead of paying a drain/resume cycle
(Joern/CPG reload, prep-cache rebuild, dispatcher re-init — tens of
minutes). The checkpoint touches the journal shards, the sidecar,
their archives, the load cache (one cold reload), and its own state
record — nothing else (pinned by the no-restart spy suite).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, TYPE_CHECKING

from core.coverage.journal_checkpoint import (
    CheckpointBusy,
    CheckpointOutcome,
    checkpoint_journal,
    evaluate_trigger,
    preflight_refusal,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = logging.getLogger(__name__)

#: How often the executor's dispatch-point polls re-evaluate the
#: trigger (a handful of ``stat`` calls). Trade-off, both directions:
#: LOWER stats the shard set on every dispatch of a hot serial loop
#: for a threshold that moves megabytes per minute at most; HIGHER
#: lets the journal overshoot the trigger by a whole interval of
#: appends — the 65% trigger's margin below the 75% roll threshold
#: is sized to absorb exactly that. 60s costs microseconds per
#: minute and bounds the overshoot to one interval of review output.
_QUIESCE_EVAL_INTERVAL_S = 60.0

#: Bound on the executor's wait for inflight → 0 once the trigger
#: fires — sized to the longest single review (a full-context review
#: with tool chains runs minutes; the review-side timeouts cap it
#: well under this). Trade-off, both directions: LOWER abandons
#: quiesce attempts whenever one slow-but-live review is in flight
#: (the checkpoint then only ever runs at boundaries — the mid-
#: segment wall this exists to remove); HIGHER holds dispatch
#: stopped behind a wedged review for that much longer before giving
#: up (workers idle, spend paused — bounded, but pure lost
#: throughput). 900s outlasts every sanctioned review timeout while
#: capping a wedge's cost to one review-length pause.
_QUIESCE_DRAIN_BOUND_S = 900.0

#: Cooldown after a failed attempt (drain timeout, park timeout,
#: checkpoint abort): do not re-attempt for this long. Trade-off,
#: both directions: LOWER re-runs the drain dance straight into the
#: same slow review (stop-start dispatch thrash); HIGHER leaves the
#: journal growing past an already-fired trigger with the roll
#: threshold approaching. 300s ≈ a few reviews' worth of settling.
_QUIESCE_RETRY_COOLDOWN_S = 300.0

#: Minimum spacing between repeated "journal legitimately large"
#: advisory lines from the quiesce evaluation path (boundaries always
#: emit theirs). Trade-off, both directions: LOWER turns a standing
#: hysteresis state into a log flood at the evaluation cadence;
#: HIGHER hides from a live tail that the journal is pinned over
#: threshold. One line per half hour keeps it visible, not noisy.
_ADVISORY_REPEAT_S = 1800.0


class JournalCheckpointQuiescer:
    """Single-threaded coordinator (all methods run on the
    orchestrator/executor driving thread; the study queue's own lock
    covers the one cross-thread handshake)."""

    drain_bound_s = _QUIESCE_DRAIN_BOUND_S

    def __init__(
        self,
        out_dir: Path | None,
        *,
        enabled: bool = True,
        collector: Any | None = None,
        study_queue: Any | None = None,
        should_abort: Callable[[], bool] | None = None,
        slim_consent: bool = False,
    ) -> None:
        self.out_dir = out_dir
        self.enabled = bool(enabled) and out_dir is not None
        self.collector = collector
        self.study_queue = study_queue
        self.should_abort = should_abort
        self.slim_consent = slim_consent
        self._next_eval = 0.0
        self._cooldown_until = 0.0
        self._advisory_next = 0.0

    # ── executor-facing cadence ──────────────────────────────────────

    def should_attempt(self) -> bool:
        """Cheap dispatch-point poll: True only when a quiesce +
        checkpoint should start now. Rate-limited; advisory states
        log (spaced) and never quiesce — there is nothing a drain
        would achieve for a journal the tiers cannot shrink.

        Never raises: this is the executors' bare loop-head call, so
        any evaluation failure (the state record and run metadata are
        run-dir content any writer can corrupt) is contained here —
        fail toward "no checkpoint this cycle", warn, cool down."""
        out_dir = self.out_dir
        if not self.enabled or out_dir is None:
            return False
        now = time.monotonic()
        if now < self._next_eval or now < self._cooldown_until:
            return False
        self._next_eval = now + _QUIESCE_EVAL_INTERVAL_S
        if self.should_abort is not None and self.should_abort():
            return False
        try:
            decision = evaluate_trigger(out_dir)
            if decision.advisory:
                if now >= self._advisory_next:
                    self._advisory_next = now + _ADVISORY_REPEAT_S
                    logger.warning(
                        "journal checkpoint (quiesce poll): %s",
                        decision.reason,
                    )
                return False
            if not decision.fire:
                return False
            # Fired: preflight the compactor's cheap refusal guard
            # BEFORE the caller pays the quiesce drain — a knowable
            # refusal (live foreign worker, unreadable run metadata)
            # must not stall dispatch just to be refused.
            refusal = preflight_refusal(
                out_dir, allow_worker_pid=os.getpid())
        except Exception:  # noqa: BLE001 — hygiene must never cost the run
            self._cooldown_until = now + _QUIESCE_RETRY_COOLDOWN_S
            logger.warning(
                "journal checkpoint (quiesce poll): trigger evaluation "
                "failed — no checkpoint this cycle; retrying after "
                "%.0fs", _QUIESCE_RETRY_COOLDOWN_S, exc_info=True,
            )
            return False
        if refusal is not None:
            self._cooldown_until = now + _QUIESCE_RETRY_COOLDOWN_S
            logger.warning(
                "journal checkpoint (quiesce poll): compactor would "
                "refuse — %s; skipping the quiesce drain, retrying "
                "after %.0fs", refusal, _QUIESCE_RETRY_COOLDOWN_S,
            )
            return False
        return True

    def note_drain_timeout(self, still_inflight: int) -> None:
        """The executor could not reach inflight → 0 within the drain
        bound: abort this attempt, resume dispatch, retry after the
        cooldown (the next evaluation point re-fires the trigger)."""
        self._cooldown_until = time.monotonic() + _QUIESCE_RETRY_COOLDOWN_S
        logger.warning(
            "journal checkpoint: quiesce drain timed out with %d "
            "review(s) still in flight after %.0fs — attempt "
            "abandoned, dispatch resumes; retrying after %.0fs",
            still_inflight, self.drain_bound_s,
            _QUIESCE_RETRY_COOLDOWN_S,
        )

    # ── the shared quiesce primitive ─────────────────────────────────

    def _study_busy_probe(self) -> str | None:
        """Busy probe handed to the checkpoint core: the study
        consumer must be parked, drained, or absent."""
        q = self.study_queue
        if q is None or q.consumer_done:
            return None
        progress, _queue_empty, working = q.drain_state()
        del progress
        if working:
            return "study consumer is mid-batch (not parked)"
        return None

    def run_quiesced(self, boundary: str = "quiesce") -> CheckpointOutcome | None:
        """Park the study consumer, run the checkpoint core, resume.

        Called with review work provably drained (the executor's
        drain loop, or a segment boundary where the passes have
        joined) — the checkpoint core re-asserts that itself and
        raises :class:`CheckpointBusy` if the claim is wrong; this
        wrapper converts every failure into a loud skip so a paid run
        never dies on its own hygiene. Never raises."""
        out_dir = self.out_dir
        if not self.enabled or out_dir is None:
            return None
        try:
            decision = evaluate_trigger(out_dir)
            if decision.advisory:
                logger.warning(
                    "journal checkpoint (%s): %s; %s",
                    boundary, decision.reason,
                    _compact_hint(out_dir),
                )
                return CheckpointOutcome(
                    advisory=True, reason=decision.reason)
            if not decision.fire:
                return CheckpointOutcome(reason=decision.reason)
            parked = self._park_study()
            if not parked:
                # Lift the pause request before abandoning: with no
                # checkpoint coming, a latched pause would starve the
                # study consumer for the rest of the segment.
                self._resume_study()
                self._cooldown_until = (
                    time.monotonic() + _QUIESCE_RETRY_COOLDOWN_S)
                logger.warning(
                    "journal checkpoint (%s): study consumer did not "
                    "park within the drain bound — attempt abandoned, "
                    "retrying after %.0fs",
                    boundary, _QUIESCE_RETRY_COOLDOWN_S,
                )
                return None
            try:
                outcome = checkpoint_journal(
                    out_dir,
                    boundary=boundary,
                    collector=self.collector,
                    slim_consent=self.slim_consent,
                    allow_worker_pid=os.getpid(),
                    should_abort=self.should_abort,
                    busy_probes=(self._study_busy_probe,),
                )
            finally:
                self._resume_study()
            if outcome.aborted or outcome.refused:
                # Refusals cool down like aborts: the refusal condition
                # (live foreign worker, unreadable run metadata) tends
                # to persist, and each async re-fire would first pay
                # the full inflight drain just to be refused again.
                self._cooldown_until = (
                    time.monotonic() + _QUIESCE_RETRY_COOLDOWN_S)
            return outcome
        except CheckpointBusy as exc:
            # The quiesce claim was wrong — a guard bug, not a run
            # failure. Loud, skip, cool down.
            self._cooldown_until = (
                time.monotonic() + _QUIESCE_RETRY_COOLDOWN_S)
            logger.error(
                "journal checkpoint (%s): precondition guard refused "
                "a supposedly-quiesced call — %s", boundary, exc,
            )
            return None
        except Exception:  # noqa: BLE001 — hygiene must never cost the run
            self._cooldown_until = (
                time.monotonic() + _QUIESCE_RETRY_COOLDOWN_S)
            logger.warning(
                "journal checkpoint (%s): unexpected failure — the "
                "journal stands and the run continues", boundary,
                exc_info=True,
            )
            return None

    def maybe_run_quiesced(self, boundary: str = "quiesce") -> None:
        """Serial-loop quiesce point: rate-limited poll + run. The
        serial executor is quiesced between reviews by construction,
        so there is no drain step."""
        if self.should_attempt():
            self.run_quiesced(boundary)

    def run_at_boundary(self, boundary: str) -> CheckpointOutcome | None:
        """Segment-boundary call site: bypasses the evaluation-rate
        limit (boundaries are rare and are the charter's original
        trigger points) but shares everything else — trigger,
        hysteresis, park protocol, guard."""
        return self.run_quiesced(boundary)

    # ── study consumer park protocol ─────────────────────────────────

    def _park_study(self) -> bool:
        q = self.study_queue
        if q is None or q.consumer_done:
            return True
        q.request_pause()
        return q.wait_quiescent(self.drain_bound_s)

    def _resume_study(self) -> None:
        q = self.study_queue
        if q is not None:
            q.resume_from_pause()


def _compact_hint(out_dir: Path | None) -> str:
    from core.coverage.journal import compact_hint
    return compact_hint(out_dir if out_dir is not None else ".")


__all__ = ["JournalCheckpointQuiescer"]
