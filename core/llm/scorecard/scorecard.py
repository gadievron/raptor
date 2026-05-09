"""ModelScorecard — per-model reliability tracking across decision classes.

See package docstring (``__init__.py``) for the design overview.
This module owns the persistence shape, event recording, and the
trust-policy query (``should_short_circuit``).

Persistence shape (JSON, ``out/llm_scorecard.json`` by default)::

    {
      "version": 1,
      "models": {
        "claude-haiku-4-5": {
          "codeql:py/sql-injection": {
            "first_seen_at": "2026-04-12T...",
            "last_seen_at":  "2026-05-06T...",
            "model_version": "claude-haiku-4-5-20251001",
            "policy_override": "auto",          // auto | force_short_circuit | force_fall_through
            "events": {
              "cheap_short_circuit":   {"correct": 47, "incorrect": 1},
              "multi_model_consensus": {"correct":  0, "incorrect": 0},
              "judge_review":          {"correct":  0, "incorrect": 0},
              "tool_evidence":         {"correct":  0, "incorrect": 0},
              "operator_feedback":     {"correct":  0, "incorrect": 0}
            },
            "disagreement_samples": [
              {
                "ts": "...",
                "event_type": "cheap_short_circuit",
                "this_reasoning":  "...short text...",
                "other_reasoning": "...short text..."
              }
            ]
          }
        }
      }
    }

Concurrency: all writes go through :func:`_with_lock`, which holds
an ``flock`` on the sidecar for the duration of read-modify-write.
Multi-process raptor runs can update independent cells without
losing each other's increments. The lock file is the sidecar
itself — no separate lock file to manage.
"""

from __future__ import annotations

import fcntl
import math
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Literal, Optional, Tuple

from core.json import load_json, save_json
from core.logging import get_logger

logger = get_logger()


SCHEMA_VERSION = 1

# Wilson 95% upper bound is the gate; this many failures (or failure
# rate, computed by Wilson on the success/failure split) above this
# threshold means the (decision_class, model) cell falls back to
# full ANALYSE rather than short-circuiting on cheap.
DEFAULT_MISS_RATE_CEILING = 0.05

# How many disagreement reasoning samples to keep per cell.
# Trade-off: larger → richer research surface but bigger sidecar
# and more reasoning text on disk (privacy concern). 5 is plenty
# for the operator to scan a representative spread of failures.
MAX_DISAGREEMENT_SAMPLES = 5


class EventType:
    """Canonical event_type strings recorded against scorecard cells.

    See package docstring + the ``scorecard unwired producers``
    project memory for what "correct" / "incorrect" means for each.
    """
    CHEAP_SHORT_CIRCUIT = "cheap_short_circuit"
    MULTI_MODEL_CONSENSUS = "multi_model_consensus"
    JUDGE_REVIEW = "judge_review"
    TOOL_EVIDENCE = "tool_evidence"
    OPERATOR_FEEDBACK = "operator_feedback"
    # Sister of MULTI_MODEL_CONSENSUS for the agreed-verdict case:
    # panel landed on the same is_exploitable answer but their
    # reasoning text diverged beyond a configured threshold. The
    # outlier model — the one whose reasoning sits farthest from
    # the rest — gets ``incorrect``; non-outliers get ``correct``.
    # Threshold + outlier identification live in
    # :mod:`core.llm.semantic_entropy`.
    REASONING_DIVERGENCE = "reasoning_divergence"


ALL_EVENT_TYPES: Tuple[str, ...] = (
    EventType.CHEAP_SHORT_CIRCUIT,
    EventType.MULTI_MODEL_CONSENSUS,
    EventType.JUDGE_REVIEW,
    EventType.TOOL_EVIDENCE,
    EventType.OPERATOR_FEEDBACK,
    EventType.REASONING_DIVERGENCE,
)


# Outcome value passed to ``record_event``.
Outcome = Literal["correct", "incorrect"]


# Policy override values stored on each cell.
PolicyOverride = Literal["auto", "force_short_circuit", "force_fall_through"]


class Policy:
    """Policy decisions returned by ``should_short_circuit``.

    ``SHADOW`` is a per-call sampling decision: a cell whose stored
    state is short-circuit-worthy still runs full ANALYSE on a
    fraction of calls so fresh ground-truth comparison data keeps
    flowing in. Without this, once trusted, a cell never sees full
    again, and silent drift (cheap-model behaviour change, prompt
    change, model upgrade) goes undetected. From the consumer's
    perspective ``SHADOW`` and ``LEARNING`` behave identically —
    run both and record the outcome.
    """
    SHORT_CIRCUIT = "short_circuit"   # cheap verdict trusted; skip full
    FALL_THROUGH = "fall_through"     # always run full
    LEARNING = "learning"             # not enough data; run both
    SHADOW = "shadow"                 # trusted, but re-validate this call


@dataclass
class _EventCounts:
    """Per-event-type tallies on a single cell."""
    correct: int = 0
    incorrect: int = 0

    def total(self) -> int:
        return self.correct + self.incorrect


@dataclass
class DecisionClassStats:
    """All recorded data for a single ``(model, decision_class)`` cell.

    A read of this dataclass is intended for CLI / introspection;
    the scorecard's internal storage is a nested dict that this
    object materialises from. Keep the fields read-only —
    mutations go through :class:`ModelScorecard` so the lock and
    persistence stay correct.
    """
    decision_class: str
    model: str
    first_seen_at: str
    last_seen_at: str
    model_version: str
    policy_override: PolicyOverride
    events: Dict[str, _EventCounts]
    disagreement_samples: List[Dict[str, str]] = field(default_factory=list)

    def cheap_total(self) -> int:
        """Convenience: total observations for the cheap-short-circuit
        event type. The denominator for the trust gate."""
        return self.events[EventType.CHEAP_SHORT_CIRCUIT].total()

    def cheap_miss_count(self) -> int:
        """Convenience: count of times cheap was wrong (the cell's
        ``incorrect`` count for cheap_short_circuit)."""
        return self.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect


def _wilson_upper_bound(successes: int, failures: int, *,
                         z: float = 1.96) -> float:
    """Wilson 95% upper bound on the failure-rate parameter.

    Treats ``failures`` as the "successes" of the failure-rate trial
    (we're computing CI on miss-rate, so failures ARE the events of
    interest). Returns 1.0 when total observations is 0 — caller
    should treat that as "no data, can't gate".

    Why Wilson rather than e.g. exact Clopper-Pearson:
      * Wilson is symmetric and well-behaved at small n.
      * Closed-form, no special functions needed.
      * Standard for proportion confidence in stats literature
        (Wilson, 1927) — operators reading "Wilson 95% UB" know
        what's meant.

    z=1.96 corresponds to 95%. Hardcoded rather than parametrised
    because changing it would invalidate accumulated cells'
    interpretation; if we ever need a different confidence level,
    bump SCHEMA_VERSION and migrate.
    """
    n = successes + failures
    if n == 0:
        return 1.0
    p = failures / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + spread) / denom


def _now_iso() -> str:
    """UTC now in ISO 8601, second precision. Used for first/last
    seen timestamps. Stable across timezones — operators inspecting
    the JSON across machines see consistent ordering."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _empty_events() -> Dict[str, Dict[str, int]]:
    """A fresh ``events`` dict with all known event types initialised
    to zero counts. Ensures the JSON shape is identical for cells
    that have only seen one event type vs cells that have seen all
    five — operators don't have to wonder "why is this key missing?"
    when scanning the file."""
    return {et: {"correct": 0, "incorrect": 0} for et in ALL_EVENT_TYPES}


# ---------------------------------------------------------------------------


class ModelScorecard:
    """Per-model reliability tracker. See package docstring.

    Construct one per process; the object holds an in-memory cache
    of the latest disk state, refreshed on every operation that
    touches the lock. Concurrent processes coordinate via flock on
    the sidecar.

    Operations:
      * :meth:`record_event` — record one observation for a cell.
      * :meth:`should_short_circuit` — query trust policy for a cell.
      * :meth:`get_stats` — read all cells (for CLI / introspection).
      * :meth:`set_policy_override` — pin a cell's policy.
      * :meth:`reset` — clear cells matching given criteria.
    """

    def __init__(
        self,
        path: Path,
        *,
        retain_samples: bool = True,
        miss_rate_ceiling: float = DEFAULT_MISS_RATE_CEILING,
        shadow_rate: float = 0.0,
        rng=None,
    ):
        """``shadow_rate`` is the probability (0-1) that a call to a
        trusted cell returns ``Policy.SHADOW`` instead of
        ``SHORT_CIRCUIT``. The consumer then runs full ANALYSE
        alongside cheap and records the outcome — keeping fresh
        signal flowing in even on cells that have been short-
        circuiting for a while. Default 0.0 (no shadowing) for
        substrate determinism in tests; LLMClient defaults to a
        small non-zero rate for production use.

        ``rng`` is a callable returning a float in [0, 1). Tests
        inject a deterministic stub; production uses
        ``random.random``.
        """
        if not 0.0 <= shadow_rate <= 1.0:
            raise ValueError(
                f"shadow_rate must be in [0, 1], got {shadow_rate}"
            )
        self.path = Path(path)
        self.retain_samples = retain_samples
        self.miss_rate_ceiling = miss_rate_ceiling
        self.shadow_rate = shadow_rate
        self._rng = rng if rng is not None else random.random

    # ----- public API -----

    def record_event(
        self,
        decision_class: str,
        model: str,
        event_type: str,
        outcome: Outcome,
        *,
        model_version: Optional[str] = None,
        sample: Optional[Dict[str, str]] = None,
    ) -> None:
        """Record one observation for a ``(model, decision_class)``
        cell.

        ``sample`` is an optional disagreement-reasoning record kept
        for the operator's research surface. Keep the strings short
        (the LLM's reasoning, not the prompt) and never include
        source code under analysis. The sample is appended only on
        ``outcome="incorrect"`` and only when ``self.retain_samples``
        is true; capped at :data:`MAX_DISAGREEMENT_SAMPLES` per
        cell on a most-recent-wins basis.
        """
        if event_type not in ALL_EVENT_TYPES:
            raise ValueError(
                f"unknown event_type {event_type!r} — must be one of "
                f"{sorted(ALL_EVENT_TYPES)}"
            )
        if outcome not in ("correct", "incorrect"):
            raise ValueError(
                f"outcome must be 'correct' or 'incorrect', got {outcome!r}"
            )
        with self._with_lock() as data:
            cell = self._ensure_cell(data, model, decision_class)
            cell["events"][event_type][outcome] += 1
            cell["last_seen_at"] = _now_iso()
            if model_version:
                cell["model_version"] = model_version
            if (outcome == "incorrect"
                    and self.retain_samples
                    and sample is not None):
                samples = cell.setdefault("disagreement_samples", [])
                samples.append({
                    "ts": _now_iso(),
                    "event_type": event_type,
                    **sample,
                })
                # Trim to most-recent N. We cap rather than rotate
                # because operators inspecting samples want the
                # latest failure modes — older samples may reflect
                # an earlier model snapshot.
                if len(samples) > MAX_DISAGREEMENT_SAMPLES:
                    cell["disagreement_samples"] = (
                        samples[-MAX_DISAGREEMENT_SAMPLES:]
                    )

    def should_short_circuit(
        self,
        decision_class: str,
        model: str,
        *,
        sample_size_floor: int = 10,
    ) -> str:
        """Return a :class:`Policy` value for whether to trust the
        cheap-tier verdict on this cell.

        The decision is from **measured miss-rate**, never from a
        model's self-reported confidence. We compute the Wilson 95%
        upper bound on the failure rate of cheap_short_circuit
        events for this cell; if that upper bound is at or below
        :attr:`miss_rate_ceiling`, the cell is trustworthy. With
        too few observations to compute a tight CI, return
        ``Policy.LEARNING`` so the consumer runs both cheap and
        full and we accumulate ground-truth comparison data.

        Operator pins via ``policy_override`` short-circuit the
        computation entirely; explicit operator intent beats
        measured drift.
        """
        with self._with_lock(write=False) as data:
            cell = self._read_cell(data, model, decision_class)
        if cell is None:
            return Policy.LEARNING

        override = cell.get("policy_override", "auto")
        if override == "force_short_circuit":
            return Policy.SHORT_CIRCUIT
        if override == "force_fall_through":
            return Policy.FALL_THROUGH

        ev = cell["events"].get(EventType.CHEAP_SHORT_CIRCUIT, {})
        correct = int(ev.get("correct", 0))
        incorrect = int(ev.get("incorrect", 0))
        n = correct + incorrect
        if n < sample_size_floor:
            return Policy.LEARNING

        upper = _wilson_upper_bound(correct, incorrect)
        if upper > self.miss_rate_ceiling:
            return Policy.FALL_THROUGH
        # Cell is short-circuit-worthy. Roll the re-shadowing dice:
        # with probability ``shadow_rate`` we run full anyway so the
        # cell keeps accumulating fresh ground-truth signal and we
        # detect drift if cheap-model behaviour changes. Operator
        # pins (``policy_override``) sit above this — explicit intent
        # is never sampled away.
        if self.shadow_rate > 0 and self._rng() < self.shadow_rate:
            return Policy.SHADOW
        return Policy.SHORT_CIRCUIT

    def set_policy_override(
        self,
        decision_class: str,
        model: str,
        policy_override: PolicyOverride,
    ) -> None:
        """Pin a cell's policy. ``"auto"`` releases the pin and
        returns the cell to data-driven behaviour."""
        if policy_override not in ("auto", "force_short_circuit",
                                    "force_fall_through"):
            raise ValueError(
                f"policy_override must be auto/force_short_circuit/"
                f"force_fall_through, got {policy_override!r}"
            )
        with self._with_lock() as data:
            cell = self._ensure_cell(data, model, decision_class)
            cell["policy_override"] = policy_override

    def get_stats(self) -> List[DecisionClassStats]:
        """Materialise every cell as :class:`DecisionClassStats`.
        Used by the CLI; not the hot path."""
        out: List[DecisionClassStats] = []
        with self._with_lock(write=False) as data:
            for model, by_dc in (data.get("models") or {}).items():
                for dc, cell in by_dc.items():
                    out.append(self._cell_to_stats(model, dc, cell))
        return out

    def get_stat(
        self, decision_class: str, model: str,
    ) -> Optional[DecisionClassStats]:
        """Return one cell's stats, or None if absent."""
        with self._with_lock(write=False) as data:
            cell = self._read_cell(data, model, decision_class)
            if cell is None:
                return None
            return self._cell_to_stats(model, decision_class, cell)

    def reset(
        self,
        *,
        decision_class: Optional[str] = None,
        model: Optional[str] = None,
        older_than_days: Optional[int] = None,
        all_: bool = False,
    ) -> int:
        """Delete cells matching the given criteria.

        Exactly one of: a specific ``decision_class`` (with optional
        ``model`` to scope), ``model`` only (clear everything for
        that model — the model-switch case), ``older_than_days``
        (cells whose ``last_seen_at`` is older), or ``all_=True``.

        Returns the number of cells deleted.
        """
        if (decision_class is None and model is None
                and older_than_days is None and not all_):
            raise ValueError(
                "reset() requires a filter — pass decision_class, "
                "model, older_than_days, or all_=True"
            )

        deleted = 0
        with self._with_lock() as data:
            models = data.get("models") or {}

            if all_:
                deleted = sum(len(by_dc) for by_dc in models.values())
                data["models"] = {}
                return deleted

            cutoff_iso: Optional[str] = None
            if older_than_days is not None:
                cutoff = time.time() - older_than_days * 86400
                cutoff_iso = datetime.fromtimestamp(
                    cutoff, tz=timezone.utc,
                ).replace(microsecond=0).isoformat()

            # Walk a snapshot of model keys so deletions during
            # iteration don't trip RuntimeError.
            for m_key in list(models.keys()):
                if model is not None and m_key != model:
                    continue
                by_dc = models[m_key]
                for dc_key in list(by_dc.keys()):
                    if (decision_class is not None
                            and dc_key != decision_class):
                        continue
                    if cutoff_iso is not None:
                        seen = by_dc[dc_key].get("last_seen_at", "")
                        if seen >= cutoff_iso:
                            continue
                    del by_dc[dc_key]
                    deleted += 1
                if not by_dc:
                    del models[m_key]
        return deleted

    # ----- internals -----

    def _read_cell(
        self, data: Dict, model: str, decision_class: str,
    ) -> Optional[Dict]:
        """Return the raw cell dict if it exists, else None.
        Caller holds the lock."""
        return (
            data.get("models", {})
                .get(model, {})
                .get(decision_class)
        )

    def _ensure_cell(
        self, data: Dict, model: str, decision_class: str,
    ) -> Dict:
        """Return the raw cell dict, creating with defaults if
        absent. Caller holds the lock."""
        models = data.setdefault("models", {})
        by_dc = models.setdefault(model, {})
        cell = by_dc.get(decision_class)
        if cell is None:
            now = _now_iso()
            cell = {
                "first_seen_at": now,
                "last_seen_at": now,
                "model_version": "",
                "policy_override": "auto",
                "events": _empty_events(),
                "disagreement_samples": [],
            }
            by_dc[decision_class] = cell
        else:
            # Defensive: a hand-edited or older-version cell may be
            # missing newer keys. Fill them in so downstream reads
            # don't have to defend.
            cell.setdefault("first_seen_at", _now_iso())
            cell.setdefault("model_version", "")
            cell.setdefault("policy_override", "auto")
            cell.setdefault("disagreement_samples", [])
            events = cell.setdefault("events", {})
            for et in ALL_EVENT_TYPES:
                events.setdefault(et, {"correct": 0, "incorrect": 0})
        return cell

    def _cell_to_stats(
        self, model: str, decision_class: str, cell: Dict,
    ) -> DecisionClassStats:
        events = {
            et: _EventCounts(
                correct=int(cell["events"].get(et, {}).get("correct", 0)),
                incorrect=int(cell["events"].get(et, {}).get("incorrect", 0)),
            )
            for et in ALL_EVENT_TYPES
        }
        return DecisionClassStats(
            decision_class=decision_class,
            model=model,
            first_seen_at=cell.get("first_seen_at", ""),
            last_seen_at=cell.get("last_seen_at", ""),
            model_version=cell.get("model_version", ""),
            policy_override=cell.get("policy_override", "auto"),
            events=events,
            disagreement_samples=list(cell.get("disagreement_samples", [])),
        )

    # ----- locked read-modify-write helper -----

    class _LockCtx:
        """Locked read-modify-write context. Yields the in-memory
        ``data`` dict. On exit (no exception), persists the dict
        back to disk via ``core.json.save_json`` (atomic rename).

        ``flock`` is taken on a sibling ``.lock`` file rather than
        on the data file itself. The data file is rewritten via
        atomic rename (tempfile then ``os.replace``), which would
        change its inode mid-flock — so a flock on the data file
        wouldn't actually serialise across the rename boundary.
        The ``.lock`` file is never renamed; flock on its inode is
        stable across the lifetime of the scorecard.
        """
        def __init__(self, scorecard: "ModelScorecard", *, write: bool):
            self.scorecard = scorecard
            self.write = write
            self.lock_fh = None
            self.data: Dict = {"version": SCHEMA_VERSION, "models": {}}

        def __enter__(self) -> Dict:
            path = self.scorecard.path
            path.parent.mkdir(parents=True, exist_ok=True)
            # Lock file is a stable-inode sibling. ``a+`` create-if-
            # absent semantics, then we never write to it — flock
            # is a kernel-level construct that doesn't need file
            # contents.
            lock_path = path.with_suffix(path.suffix + ".lock")
            self.lock_fh = open(lock_path, "a+", encoding="utf-8")
            try:
                fcntl.flock(
                    self.lock_fh.fileno(),
                    fcntl.LOCK_EX if self.write else fcntl.LOCK_SH,
                )
            except OSError as e:
                # NFS / unusual filesystems may not support flock.
                # Log once and proceed lock-free; correctness in that
                # environment depends on operator running serially.
                logger.warning(
                    f"scorecard: flock not available on "
                    f"{lock_path} — concurrent updates may race "
                    f"(error: {e})"
                )
            # Read the data file under lock. May not exist on cold
            # start; treat as empty. Doesn't matter that this is a
            # different fd from the lock — the lock guarantees we
            # have exclusive access to the rename-replace dance.
            content = ""
            try:
                with open(path, "r", encoding="utf-8") as data_fh:
                    content = data_fh.read()
            except FileNotFoundError:
                pass
            if content.strip():
                try:
                    import json
                    self.data = json.loads(content)
                except (ValueError, TypeError) as e:
                    # Corrupt sidecar — degrade gracefully. We do
                    # NOT raise: a corrupt scorecard should never
                    # block a scan. Operator can inspect / restore
                    # via the CLI's reset --all if needed.
                    logger.warning(
                        f"scorecard: corrupt JSON at {path} — "
                        f"reading as empty (error: {e})"
                    )
                    self.data = {"version": SCHEMA_VERSION, "models": {}}
            # Schema version guard. Refuse to write back data we
            # don't recognise — better to surface a hard error than
            # silently downgrade.
            existing_version = self.data.get("version")
            if existing_version is None:
                # Cold-start file or hand-edited — accept and stamp.
                self.data["version"] = SCHEMA_VERSION
            elif existing_version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"scorecard: schema version mismatch at {path}: "
                    f"file has version={existing_version}, code "
                    f"expects {SCHEMA_VERSION}. Migrate or delete "
                    f"the sidecar to continue."
                )
            self.data.setdefault("models", {})
            return self.data

        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type is None and self.write:
                    # Atomic write via save_json (tempfile + rename).
                    # We're under flock on the sibling ``.lock``
                    # file, which stays stable across this rename;
                    # other processes block on the same .lock until
                    # we exit and release.
                    save_json(self.scorecard.path, self.data)
            finally:
                if self.lock_fh is not None:
                    try:
                        fcntl.flock(self.lock_fh.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                    self.lock_fh.close()
            return False

    def _with_lock(self, *, write: bool = True) -> "_LockCtx":
        return ModelScorecard._LockCtx(self, write=write)


__all__ = [
    "ModelScorecard",
    "EventType",
    "Policy",
    "Outcome",
    "PolicyOverride",
    "DecisionClassStats",
    "ALL_EVENT_TYPES",
    "SCHEMA_VERSION",
    "MAX_DISAGREEMENT_SAMPLES",
]
