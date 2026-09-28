"""Run-scoped health gate for the Joern verification channel.

A restarting or CPG-less Joern server fails every dispatch — either
instantly (fail-fast branches) or after a full client-side timeout —
but the tool chain keeps offering joern steps to every hypothesis, so
one bad restart can turn into hundreds of dead-channel round trips
over a run while producing zero receipts.  The gate counts
CONSECUTIVE dispatch failures across all joern tool types; once the
threshold is crossed the channel reports itself unhealthy.  Dispatch
sites consult :func:`dispatch_blocked` and skip (counted as
``skipped`` in tier diagnostics AND recorded in the caller's
``skipped_types`` so the channel leaves the dispatch record), and the
trip is surfaced in ``tier-diagnostics.json`` and the report's
degradation section so the missing receipts read as "channel down",
never as refutations.

Two robustness rules keep the gate from silencing a healthy server:

* **Distinct-key trip rule** — the failure streak must span at least
  :data:`MIN_DISTINCT_TRIP_KEYS` distinct dispatch keys
  (``file:function``).  A pile of failures against one function can
  be a single pathological query shape (one bad identifier or CWE
  class) on a perfectly healthy server; a dead server fails
  everything it is offered.
* **Half-open re-probe schedule** — after a trip, one dispatch is
  let through once :data:`REPROBE_AFTER_SKIPS` dispatches have been
  skipped.  A success clears the trip (the server recovered — e.g.
  its CPG re-import finished, a dead forwarder socket was
  re-created) and dispatch resumes; a failure widens the spacing to
  the next probe by :data:`REPROBE_BACKOFF_FACTOR`, capped at
  :data:`REPROBE_MAX_SPACING`.  A genuinely dead channel therefore
  costs a short geometric burst of probes and then at most one probe
  per cap window for the rest of the run, while a channel that comes
  back is picked up within one spacing window.  (The previous
  one-probe-per-run budget left a restartable channel dead for over
  a thousand reviews on a long run — every verdict after the trip
  was issued without this validation leg.)
* **Escalating reset base across recover→re-trip cycles** — each
  recovery re-arms the schedule at a reset base that itself grows by
  :data:`REPROBE_BACKOFF_FACTOR` per recovery (cycle *k* re-enters at
  ``min(REPROBE_AFTER_SKIPS * REPROBE_BACKOFF_FACTOR**k,
  REPROBE_MAX_SPACING)``).  The first cycle is unchanged, so a
  genuine one-time outage still gets fast pickup; a flapping backend
  (one that answers exactly the half-open probes while failing every
  open-gate dispatch) cannot re-run the cheap base-spacing cycle
  forever.  Honest whole-run worst case over *N* dispatch
  opportunities: at most ``unhealthy_after + 1`` round trips per
  cycle, across the geometric growth cycles (a handful — the reset
  base reaches the cap after ``log(REPROBE_MAX_SPACING /
  REPROBE_AFTER_SKIPS, REPROBE_BACKOFF_FACTOR)`` recoveries) plus
  ``N // (unhealthy_after + REPROBE_MAX_SPACING)`` capped cycles —
  the amortised burn converges to the capped rate instead of staying
  proportional to *N* at the base rate.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# Consecutive dispatch failures before the channel trips.  Too low and
# a transient blip (one stuck query while the server restarts and
# recovers) silences a channel that would have answered the rest of
# the run; too high and a genuinely dead server burns its full client
# timeout per hypothesis for most of the run before the gate helps.
# Distinct hypotheses dispatch independently, so a healthy server
# interleaves successes and resets the streak long before 8.
DEFAULT_UNHEALTHY_AFTER = 8

# The failure streak must span at least this many distinct dispatch
# keys before the gate trips.  Lower (1) lets one pathological
# function/query shape silence the channel for the whole run; higher
# makes a genuinely dead server burn failures across more hypotheses
# before the gate helps.  Two is enough to prove "not just that one
# query" while a dead server crosses it immediately.
MIN_DISTINCT_TRIP_KEYS = 2

# Skipped dispatches before the FIRST half-open probe after a trip —
# also the base (and post-recovery reset value) of the backoff
# schedule below.  Smaller re-probes while a multi-minute CPG
# re-import is still likely in flight (the probe then just burns a
# failure against a still-restarting server and widens the schedule
# for nothing); larger leaves a quickly-recovered server dark for
# more of the run than necessary.
REPROBE_AFTER_SKIPS = 25

# Each FAILED probe multiplies the spacing to the next probe by this
# factor.  Smaller (1 = fixed spacing) probes a genuinely dead
# channel at the full base rate for the whole run — sustained burn
# the trip exists to stop, since one probe can hold a full
# client-side query timeout; larger reaches the cap in fewer probes,
# leaving a mid-outage recovery undetected for longer during the
# growth phase while saving almost nothing (the whole doubling phase
# already costs only a handful of probes).
REPROBE_BACKOFF_FACTOR = 2

# Ceiling on the probe spacing.  Lower re-opens the per-hypothesis
# burn on a dead channel over a long run (each probe can hold a full
# client-side query timeout, so the cap bounds the steady-state
# waste: one dispatch per 400 skips = 0.25%); higher — or uncapped
# doubling — leaves a late-restored server dark for a window that
# grows with the outage length, recreating the observed failure mode
# (a channel down for the rest of a multi-day run) in the limit.
REPROBE_MAX_SPACING = 400


class JoernChannelHealth:
    """Thread-safe consecutive-failure tracker for the joern channel.

    Dispatch sites ask :meth:`allow_dispatch` before dialing (it
    consumes the half-open probe when tripped), then call
    :meth:`record_error` on a failed round trip and
    :meth:`record_success` on any completed one (confirmed, refuted
    or inconclusive — the outcome does not matter, reaching the
    server does).  Workers dispatch in parallel, so all state
    mutations take the instance lock.
    """

    def __init__(self, unhealthy_after: int = DEFAULT_UNHEALTHY_AFTER) -> None:
        self.unhealthy_after: int = max(1, int(unhealthy_after))
        self._lock = threading.Lock()
        self._consecutive_errors: int = 0
        self._streak_keys: set[str] = set()
        self._total_errors: int = 0
        self._total_successes: int = 0
        self._tripped: bool = False
        self._trip_reason: str | None = None
        self._skips_since_trip: int = 0
        self._skips_since_probe: int = 0
        self._probe_spacing: int = REPROBE_AFTER_SKIPS
        # Reset base the schedule re-arms to on recovery; escalates
        # per recovery (see record_success) so the first cycle keeps
        # the fast base pickup while repeated recover→re-trip cycles
        # cannot re-run the cheap start forever.
        self._reset_spacing: int = REPROBE_AFTER_SKIPS
        self._probes_attempted: int = 0
        self._recovered_once: bool = False
        self._gated_spends: list[str] = []

    def allow_dispatch(self) -> bool:
        """True when the channel may dispatch.

        Healthy: always.  Tripped: counts the skip and grants a
        half-open probe on the backoff schedule.  The spacing widens
        at grant time, not on the probe's outcome — a granted probe
        the caller then does not dispatch (e.g. its own deadline
        clamp skips the query) is simply spent (bounded waste, never
        a wedged gate), a failed probe leaves the widened spacing in
        place, and a successful probe resets the whole schedule via
        :meth:`record_success`.
        """
        with self._lock:
            if not self._tripped:
                return True
            if self._skips_since_probe + 1 < self._probe_spacing:
                # An ordinary gated skip.  Granted probes are NOT
                # counted here: ``skips_since_trip`` feeds the
                # report's ``skipped_dispatches`` — verdicts issued
                # WITHOUT the leg — and a granted probe dispatches.
                self._skips_since_trip += 1
                self._skips_since_probe += 1
                return False
            self._skips_since_probe = 0
            self._probes_attempted += 1
            self._probe_spacing = min(
                self._probe_spacing * REPROBE_BACKOFF_FACTOR,
                REPROBE_MAX_SPACING,
            )
            probes = self._probes_attempted
            skips = self._skips_since_trip
        logger.info(
            "joern channel half-open probe %d: one dispatch allowed "
            "through the tripped gate (%d skips since trip)",
            probes, skips,
        )
        return True

    def record_error(self, detail: str = "", key: str = "") -> None:
        """Record a failed joern round trip; trips the gate when the
        streak crosses the threshold across distinct keys (loud,
        once).  While tripped, a failure is the half-open probe
        failing — the gate stays sealed."""
        with self._lock:
            self._total_errors += 1
            self._consecutive_errors += 1
            if key:
                self._streak_keys.add(key)
            if self._tripped:
                return
            if self._consecutive_errors < self.unhealthy_after:
                return
            if len(self._streak_keys) < MIN_DISTINCT_TRIP_KEYS:
                return
            self._tripped = True
            self._trip_reason = (
                f"{self._consecutive_errors} consecutive dispatch "
                f"failures across {len(self._streak_keys)} functions"
                + (f" (last: {detail[:200]})" if detail else "")
            )
            spacing = self._probe_spacing
        logger.warning(
            "joern channel unhealthy — %s; joern dispatches for this "
            "run are skipped (skipped, not refuted — see the report's "
            "degradation section; half-open re-probes on a backoff "
            "schedule starting after %d skips)",
            self._trip_reason, spacing,
        )

    def record_success(self) -> None:
        """Record a completed round trip (any verdict) — resets the
        consecutive-failure streak.  While tripped, a success is the
        half-open probe succeeding: the server recovered, clear the
        trip and re-arm the probe schedule at the escalated reset
        base — far below the previous outage's widened spacing (the
        next outage is a new outage and earns prompt pickup), but
        never back at the cheap first-cycle start once the run has
        already seen a recovery."""
        recovered = False
        with self._lock:
            self._total_successes += 1
            self._consecutive_errors = 0
            self._streak_keys.clear()
            if self._tripped:
                self._tripped = False
                self._recovered_once = True
                self._skips_since_trip = 0
                self._skips_since_probe = 0
                # Escalate the reset base per recovery.  Escalating
                # less (or resetting straight to base) lets a
                # flapping backend — answers exactly the probes,
                # fails every open-gate dispatch — repeat the cheap
                # base-spacing cycle forever, so whole-run burn grows
                # linearly with run length; escalating more (jumping
                # straight to the cap) makes the SECOND genuine
                # outage of a run wait a full cap window for its
                # first probe, punishing an honestly twice-restarted
                # backend as if it were a flapper.  Geometric growth
                # by the existing factor keeps early re-trips fast
                # while the amortised flap burn converges to the
                # capped rate within a handful of cycles.
                self._reset_spacing = min(
                    self._reset_spacing * REPROBE_BACKOFF_FACTOR,
                    REPROBE_MAX_SPACING,
                )
                self._probe_spacing = self._reset_spacing
                recovered = True
        if recovered:
            logger.info(
                "joern channel recovered — half-open probe completed; "
                "dispatch re-enabled (a re-trip re-enters the probe "
                "schedule at an escalated reset base)",
            )

    def note_gated_spend(self, phase: str) -> None:
        """Record that a paid phase was skipped because the channel is
        down — surfaced in diagnostics/report so the $0 skip is an
        operator-visible decision, never a silent absence."""
        with self._lock:
            if phase not in self._gated_spends:
                self._gated_spends.append(phase)

    @property
    def tripped(self) -> bool:
        with self._lock:
            return self._tripped

    @property
    def trip_reason(self) -> str | None:
        with self._lock:
            return self._trip_reason

    @property
    def total_errors(self) -> int:
        with self._lock:
            return self._total_errors

    @property
    def total_successes(self) -> int:
        with self._lock:
            return self._total_successes

    @property
    def gated_spends(self) -> list[str]:
        with self._lock:
            return list(self._gated_spends)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            data: dict[str, Any] = {
                "tripped": self._tripped,
                "trip_reason": self._trip_reason,
                "consecutive_errors": self._consecutive_errors,
                "total_errors": self._total_errors,
                "total_successes": self._total_successes,
                "unhealthy_after": self.unhealthy_after,
            }
            if self._skips_since_trip:
                data["skips_since_trip"] = self._skips_since_trip
            if self._probes_attempted:
                data["probes_attempted"] = self._probes_attempted
            if self._tripped:
                data["next_probe_in_skips"] = max(
                    0, self._probe_spacing - self._skips_since_probe,
                )
            if self._recovered_once:
                data["recovered_once"] = True
            if self._gated_spends:
                data["gated_spends"] = list(self._gated_spends)
            return data


def channel_unhealthy(config: Any) -> bool:
    """True when *config* carries a currently-tripped joern gate.

    Read-only (never consumes the half-open probe) — for spend gates
    and reporting.  ``getattr``-tolerant: minimal test configs and
    external callers without the field read as healthy (the pre-gate
    behaviour).
    """
    health = getattr(config, "joern_health", None)
    return health is not None and health.tripped


def dispatch_blocked(config: Any) -> bool:
    """Consuming dispatch-permission check for joern dispatch sites.

    False = dispatch (healthy, or the half-open probe was granted);
    True = skip.  ``getattr``-tolerant like :func:`channel_unhealthy`.
    """
    health = getattr(config, "joern_health", None)
    if health is None:
        return False
    return not health.allow_dispatch()


def record_outcome(
    config: Any, *, error: bool, detail: str = "", key: str = "",
) -> None:
    """Feed one joern round-trip outcome into *config*'s gate, if any.

    ``key`` (``file:function``) feeds the distinct-key trip rule.
    """
    health = getattr(config, "joern_health", None)
    if health is None:
        return
    if error:
        health.record_error(detail, key=key)
    else:
        health.record_success()


def health_snapshot(config: Any) -> dict[str, dict[str, Any]] | None:
    """Channel-health block for tier diagnostics.

    Only worth writing once the channel saw at least one error —
    healthy silence stays out of the artifact.
    """
    health = getattr(config, "joern_health", None)
    if health is None:
        return None
    if (
        health.total_errors == 0
        and not health.tripped
        and not health.gated_spends
    ):
        return None
    return {"joern": health.to_dict()}
