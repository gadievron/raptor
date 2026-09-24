"""Run-level degraded-mode breaker for LLM calls.

The per-call layers already handle POINT failures: the client's retry
ladder re-buys transient errors with backoff, ``AdaptiveThrottle``
ramps concurrency down/up around 429 storms, the auth-streak tracker
aborts a phase on consecutive credential refusals, and budget
exhaustion terminates the run through ``LLMBudgetExceededError``.
None of them sees AGGREGATE degradation: a provider brown-out where
half of all attempts fail with retryable errors, or a systematic
truncation/parse loop, burns failed-attempt spend indefinitely — each
call individually "handled", the run as a whole going nowhere until
the budget or wall cap finally lands.

This module watches the run's provider outcomes through a sliding
time window. When counted transport-class failures make up a
sustained majority of recent attempts, the breaker latches and every
subsequent dispatch raises ``LLMDegradedModeError`` — a subclass of
``LLMBudgetExceededError``, so the existing graceful run-terminal
path applies unchanged: loop drivers stop dispatching, in-flight
calls drain, run state and per-attempt spend evidence persist.

Feeding and checking happen at the ``LLMClient`` seams (one
``note_llm_outcome`` beside each telemetry emit; one
``check_degraded_mode`` beside each entry budget check). The monitor
is process-wide, like the throttle registry — transports that build a
client per call (claude CLI) would never accumulate a window on
per-client state.
"""

from __future__ import annotations

import logging
import math
import os
import sys
import threading
import time
from collections import Counter, deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Failure classes counted toward the trip fraction — the telemetry
# disposition labels ``core.llm.client._failure_disposition`` assigns
# to failed attempts:
#
#   timeout    — transport read/deadline expiries; each one already
#                burned a full per-call read budget (600s on the
#                bedrock/claudecode transports).
#   retryable  — wire/5xx failures AND response-shape failures
#                (malformed JSON, schema violations): the systematic
#                max_tokens-truncation loop lands here. Residual,
#                accepted deliberately: response-shape failures can be
#                CONTENT-driven too, so a corpus that steers the model
#                into systematic non-JSON output can count toward the
#                fraction — the denial-of-analysis lever is narrowed
#                by excluding refusals below, not fully closed. The
#                alternative (excluding shape failures) would blind
#                the breaker to the truncation-loop incident class it
#                exists for.
#   consumed   — mid-response wire deaths: billed upstream, nothing
#                received (see MidResponseDeathError).
#
# Deliberately NOT counted (they still enter the DENOMINATOR, so a
# stream dominated by them cannot trip on a few stray transport
# failures):
#
#   blocked — refusals / content filters are a MODEL boundary: a
#             hostile corpus legitimately drives a high blocked
#             fraction, and stopping the run would hand that corpus a
#             denial-of-analysis lever. Provider health is not in
#             question.
#   auth    — the consecutive-auth-streak tracker
#             (``AuthFailureTracker``) already aborts the phase with
#             better-targeted semantics.
#   budget  — already run-terminal via ``LLMBudgetExceededError``.
#   quota   — 429s feed the AdaptiveThrottle ramp and the daily-quota
#             session latch; a rejected-at-the-door attempt also
#             bills nothing, unlike every counted class.
#   fatal   — non-retryable 400-class / empty-content outcomes are
#             usually prompt-specific (oversized payload, bad
#             params), not provider degradation.
#
# Denominator subtlety: because the excluded classes still count as
# outcomes, heavy blocked/quota traffic DILUTES the fraction — a
# brown-out accompanied by a 429 storm trips later than the same
# brown-out alone. That is the intended direction of error: the
# excluded lanes have their own handling, and the breaker only stops
# runs whose counted transport failures dominate everything observed.
COUNTED_DISPOSITIONS = frozenset({"timeout", "retryable", "consumed"})

# ── Tuned thresholds ──────────────────────────────────────────────
#
# Churn-prone limits: each carries its both-directions trade-off here
# at the definition site (the evaluation reads them together in
# ``DegradedModeBreaker._evaluate_locked``), an env override resolved
# in ``from_env``, and two-direction regression tests in
# ``core/llm/tests/test_degraded_breaker.py``.

# Trip fraction: counted failures / all recorded provider outcomes in
# the window. LOWER catches shallower brown-outs sooner but starts
# tripping runs a lumpy-yet-recoverable provider is still carrying (a
# 30-40% flake rate that retries and fallbacks absorb while progress
# continues); HIGHER burns more failed-attempt spend before stopping
# — at 0.75 a brown-out failing every second call for hours (the
# shape this breaker exists for) would never trip. 0.5 = the majority
# of attempts are failing: the run is buying more failure than
# progress. The fraction is per-ATTEMPT, not per-call: a dead primary
# whose retries all fail can trip even while calls complete through a
# healthy fallback — deliberate, because a run crawling at N failed
# attempts per completed call is burning spend an operator should
# rule on.
_DEFAULT_FAILURE_FRACTION = 0.5

# Sliding window (seconds) the fraction is computed over. SHORTER
# forgets healthy history too fast, so one concurrency-burst of
# failures dominates the sample; LONGER dilutes a real brown-out with
# pre-incident successes and delays the trip by roughly the window
# length. 10 minutes holds a few hundred outcomes on a parallel run
# and a meaningful handful on a serial one.
_DEFAULT_WINDOW_S = 600.0

# Minimum outcomes in the window before the fraction is evaluated —
# the low-volume floor. LOWER lets a small run trip on coincidence
# (3 of 5 attempts failing is ordinary retry weather); HIGHER makes a
# low-throughput run (serial audit at ~1 call/min) wait
# proportionally longer for protection. 20 samples at the 0.5
# fraction needs 10 counted failures — past plausible coincidence,
# still reached within minutes of a genuine brown-out.
_DEFAULT_MIN_SAMPLES = 20

# Minimum span (seconds) between the window's oldest outcome and the
# tripping one — what separates SUSTAINED degradation from the short
# blips the retry ladder and AdaptiveThrottle already handle: N
# parallel workers all failing during a brief network hiccup can
# satisfy fraction + min-samples within seconds. LOWER trips on
# outages the per-call exponential backoff (capped at 30s) would have
# ridden out; HIGHER buys failed attempts that much longer before
# stopping (a multi-hour brown-out is the shape being defended
# against — 5 minutes caps the waste at a small slice of that, where
# a wall/budget cap alone would let it run to exhaustion). Clamped
# to 90% of the window
# at construction: eviction keeps the observable span strictly under
# the window between record arrivals, so a sustain at or beyond it
# would make the breaker dead weight.
_DEFAULT_SUSTAIN_S = 300.0

# Hard cap on retained window entries — a pathological tight loop
# (thousands of instant failures per second) must bound memory. Not a
# tuning knob: at 10k entries the fraction over the retained suffix
# is still representative of the window.
_MAX_WINDOW_ENTRIES = 10_000


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    """Env override for a float knob — non-numeric or out-of-range
    values warn and keep the default (a typo must never disable the
    breaker silently or trip it instantly)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number — using %s", name, raw, default)
        return default
    if not math.isfinite(val) or not (lo <= val <= hi):
        logger.warning(
            "%s=%r outside [%s, %s] — using %s", name, raw, lo, hi, default,
        )
        return default
    return val


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not an integer — using %s", name, raw, default,
        )
        return default
    if not (lo <= val <= hi):
        logger.warning(
            "%s=%r outside [%s, %s] — using %s", name, raw, lo, hi, default,
        )
        return default
    return val


class DegradedModeBreaker:
    """Sliding-window failure-fraction monitor with latching trip.

    Trips when, over the last ``window_s`` seconds of provider
    outcomes, counted transport-class failures (see
    ``COUNTED_DISPOSITIONS``) reach ``failure_fraction`` of ALL
    outcomes, with at least ``min_samples`` outcomes observed and the
    degradation spanning at least ``sustain_s`` seconds. Once tripped
    it stays tripped (like ``AuthFailureTracker``) — recovery within
    the same run would let the run oscillate between draining and
    dispatching.

    Thread-safe: outcomes arrive from parallel worker threads.
    ``clock`` is injectable (monotonic) so tests choreograph window
    aging without racing wall time — same pattern as
    ``AdaptiveThrottle``.
    """

    def __init__(
        self,
        *,
        failure_fraction: float = _DEFAULT_FAILURE_FRACTION,
        window_s: float = _DEFAULT_WINDOW_S,
        min_samples: int = _DEFAULT_MIN_SAMPLES,
        sustain_s: float = _DEFAULT_SUSTAIN_S,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._failure_fraction = min(max(float(failure_fraction), 0.0), 1.0)
        self._window_s = max(float(window_s), 1.0)
        self._min_samples = max(int(min_samples), 1)
        # A sustain at/beyond the window can never be satisfied —
        # eviction keeps the span strictly under the window between
        # record arrivals. 90% leaves working margin.
        self._sustain_s = min(
            max(float(sustain_s), 0.0), self._window_s * 0.9,
        )
        # Resolved at construction (not in the signature default) so a
        # caller that patches ``time.monotonic`` before constructing
        # still takes effect — same convention as AdaptiveThrottle.
        self._clock: Callable[[], float] = (
            clock if clock is not None else time.monotonic
        )
        self._lock = threading.Lock()
        # (timestamp, disposition, counted) per provider outcome.
        self._entries: deque[tuple[float, str, bool]] = deque(
            maxlen=_MAX_WINDOW_ENTRIES,
        )
        self._tripped = False
        self._trip_message = ""
        self._trip_stats: dict[str, object] = {}

    @classmethod
    def from_env(cls) -> "DegradedModeBreaker":
        """Construct with env-overridable thresholds.

        Bounds keep an override inside the regime the design reasons
        about: a fraction below 0.05 trips on background flake noise;
        a window under 30s cannot express "sustained"; caps at a day
        bound accidental extra zeroes.
        """
        return cls(
            failure_fraction=_env_float(
                "RAPTOR_LLM_BREAKER_THRESHOLD",
                _DEFAULT_FAILURE_FRACTION, 0.05, 1.0,
            ),
            window_s=_env_float(
                "RAPTOR_LLM_BREAKER_WINDOW_S",
                _DEFAULT_WINDOW_S, 30.0, 86400.0,
            ),
            min_samples=_env_int(
                "RAPTOR_LLM_BREAKER_MIN_SAMPLES",
                _DEFAULT_MIN_SAMPLES, 1, 100_000,
            ),
            sustain_s=_env_float(
                "RAPTOR_LLM_BREAKER_SUSTAIN_S",
                _DEFAULT_SUSTAIN_S, 0.0, 86400.0,
            ),
        )

    @property
    def tripped(self) -> bool:
        return self._tripped

    @property
    def trip_message(self) -> str:
        """Operator-facing trip summary; empty until tripped."""
        return self._trip_message

    def record(self, disposition: str) -> bool:
        """Record one provider outcome; returns the (possibly new)
        tripped state.

        ``disposition`` is the telemetry label: ``"ok"`` for a
        completed call, or the failed attempt's
        ``_failure_disposition`` / ``"consumed"`` label. Cache hits
        are never recorded — they fire no provider call and say
        nothing about provider health.
        """
        now = self._clock()
        with self._lock:
            if self._tripped:
                return True
            label = str(disposition or "unknown")
            self._entries.append(
                (now, label, label in COUNTED_DISPOSITIONS),
            )
            self._evict_locked(now)
            self._evaluate_locked(now)
            return self._tripped

    def _evict_locked(self, now: float) -> None:
        cutoff = now - self._window_s
        entries = self._entries
        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def _evaluate_locked(self, now: float) -> None:
        """Trip condition — reads the tuned thresholds together; see
        their definition-site trade-off comments above."""
        samples = len(self._entries)
        if samples < self._min_samples:
            return
        counted = sum(1 for _, _, c in self._entries if c)
        # A zero-failure window is never degraded, whatever the
        # configured fraction (a direct construction may pass 0.0).
        if counted == 0:
            return
        fraction = counted / samples
        if fraction < self._failure_fraction:
            return
        span = now - self._entries[0][0]
        if span < self._sustain_s:
            return
        dominant, dominant_n = Counter(
            label for _, label, c in self._entries if c
        ).most_common(1)[0]
        excluded = samples - counted - sum(
            1 for _, label, _ in self._entries if label == "ok"
        )
        self._tripped = True
        self._trip_stats = {
            "failed": counted,
            "samples": samples,
            "fraction": round(fraction, 3),
            "window_span_s": round(span, 1),
            "dominant": dominant,
            "dominant_n": dominant_n,
        }
        self._trip_message = (
            f"LLM degraded-mode breaker tripped: {counted} of {samples} "
            f"provider attempts over the last {span / 60:.1f} min failed "
            f"with transport-class errors (fraction {fraction:.2f} >= "
            f"{self._failure_fraction:.2f}; dominant failure class: "
            f"{dominant} x{dominant_n}"
            + (
                f"; {excluded} refusal/quota/other outcome(s) not counted "
                f"toward the fraction" if excluded else ""
            )
            + "). Stopping the run on the budget-exhaustion contract: "
            "in-flight calls drain, new LLM calls refuse, completed work "
            "and per-attempt spend evidence persist (llm-telemetry.jsonl "
            "in the run output directory). Check provider status, "
            "network egress, and max_tokens sizing, then re-run — cached "
            "completions replay free. Tune with "
            "RAPTOR_LLM_BREAKER_THRESHOLD / RAPTOR_LLM_BREAKER_WINDOW_S "
            "/ RAPTOR_LLM_BREAKER_MIN_SAMPLES / "
            "RAPTOR_LLM_BREAKER_SUSTAIN_S; RAPTOR_LLM_BREAKER=0 disables "
            "the breaker for a run."
        )
        # Operator-facing: ERROR (unlike the budget stop's INFO — that
        # one is a designed cap working; this is a provider incident).
        logger.error("%s", self._trip_message)
        # Persist the trip verdict beside the per-attempt records it
        # was computed from. ``event="breaker_tripped"`` aggregates as
        # one $0 call in its own ``run_breaker`` class — visible in
        # the rollup, never mixed into a real call class.
        try:
            from core.llm.telemetry import emit as _t_emit
            _t_emit(
                event="breaker_tripped",
                call_class="run_breaker",
                cost_usd=0.0,
                **{str(k): v for k, v in self._trip_stats.items()},
            )
        except Exception:  # noqa: BLE001 — evidence is best-effort
            logger.debug("breaker trip telemetry emit failed", exc_info=True)

    def raise_if_tripped(self) -> None:
        """Convert a tripped state into the run-terminal error.

        ``LLMDegradedModeError`` subclasses ``LLMBudgetExceededError``
        deliberately — consumers key their graceful stop (drain,
        checkpoint persistence) on that type via
        ``is_budget_exceeded_error``.
        """
        if not self._tripped:
            return
        from core.llm.client import LLMDegradedModeError
        raise LLMDegradedModeError(self._trip_message)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "tripped": self._tripped,
                "samples": len(self._entries),
                "failure_fraction": self._failure_fraction,
                "window_s": self._window_s,
                "min_samples": self._min_samples,
                "sustain_s": self._sustain_s,
                "trip_stats": dict(self._trip_stats),
            }


# ── Process-wide breaker registry ─────────────────────────────────────
#
# One breaker per process, like the throttle's broadcast registry:
# the claude-CLI transport constructs an LLMClient per call, so
# per-client state would never accumulate a window.

_singleton_lock = threading.Lock()
_singleton: DegradedModeBreaker | None = None


def _suppressed_under_pytest() -> bool:
    """Mirror of the scorecard atexit suppression: the breaker is
    process-wide state and the test suite deliberately drives
    thousands of failed fake attempts — without this, one test's
    failure stream could trip the breaker and fail every later test
    that dispatches through a real ``LLMClient``.
    ``RAPTOR_LLM_BREAKER_TEST=1`` opts back in for tests that
    exercise the breaker end-to-end (they install their own isolated
    instance via :func:`set_degradation_breaker`)."""
    if os.environ.get("RAPTOR_LLM_BREAKER_TEST"):
        return False
    return "pytest" in sys.modules


def breaker_enabled() -> bool:
    """True when the run-level breaker participates in this process.

    ``RAPTOR_LLM_BREAKER=0`` is the operator kill switch — for runs
    where degraded-but-crawling is preferable to stopping (unattended
    long soaks on a flaky provider, with the budget cap as the only
    backstop)."""
    from core.config import env_flag
    if not env_flag("RAPTOR_LLM_BREAKER", True):
        return False
    return not _suppressed_under_pytest()


def get_degradation_breaker() -> DegradedModeBreaker:
    """The process-wide breaker, created from env on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = DegradedModeBreaker.from_env()
        return _singleton


def set_degradation_breaker(breaker: DegradedModeBreaker | None) -> None:
    """Install (or clear — recreated lazily) the process breaker.

    Test seam, and the embedding surface for a caller that needs
    bespoke thresholds or a fake clock."""
    global _singleton
    with _singleton_lock:
        _singleton = breaker


def note_llm_outcome(disposition: str) -> None:
    """Feed one provider outcome to the process breaker.

    Never raises and never alters call control flow (same contract as
    ``telemetry.emit``); no-op when the breaker is disabled."""
    try:
        if not breaker_enabled():
            return
        get_degradation_breaker().record(disposition)
    except Exception:  # noqa: BLE001 — monitoring must not break calls
        logger.debug("degraded-mode breaker record failed", exc_info=True)


def check_degraded_mode() -> None:
    """Dispatch-entry gate: raise ``LLMDegradedModeError`` when the
    process breaker has tripped.

    Sits beside the entry budget check in ``generate`` /
    ``generate_structured`` — in-flight calls run to completion
    (drain), every NEW dispatch refuses with the uniform terminal
    error, exactly the budget-exhaustion shape loop drivers already
    stop on. Reads the singleton without creating it: an
    outcome-free process has nothing to check."""
    if not breaker_enabled():
        return
    breaker = _singleton
    if breaker is None:
        return
    breaker.raise_if_tripped()
