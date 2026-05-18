"""Tests for :class:`ModelScorecard`.

Covers:
* Schema invariants (version field, all-event-types-present).
* Wilson-CI gating behaviour (cold start → learning →
  trustworthy → fall-through as miss-rate rises).
* Policy overrides preempt measured behaviour.
* Persistence round-trip (write, reopen, observe).
* Concurrent process safety via flock.
* Reset (single, --model, --older-than, --all).
* Disagreement-sample retention + cap + privacy flag.
"""

from __future__ import annotations

import json
import multiprocessing
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from core.llm.scorecard import (
    ModelScorecard,
    EventType,
    Policy,
)
from core.llm.scorecard.scorecard import (
    ALL_EVENT_TYPES,
    SCHEMA_VERSION,
    MAX_DISAGREEMENT_SAMPLES,
    _wilson_upper_bound,
)


# ---------------------------------------------------------------------------
# Wilson — sanity bounds
# ---------------------------------------------------------------------------


def test_wilson_zero_observations_returns_one():
    """Empty cell → upper bound is 1.0 (no information). Caller
    treats this as 'no data', not 'miss-rate is 100%'."""
    assert _wilson_upper_bound(0, 0) == 1.0


def test_wilson_all_correct_small_n_is_loose():
    """0 misses out of 12 — Wilson UB is well above the 5%
    ceiling. Sample-size floor in the gate is what stops short-
    circuit at this point; Wilson alone wouldn't."""
    ub = _wilson_upper_bound(12, 0)
    assert ub > 0.05, (
        f"Wilson UB at n=12 should still be > 5%, got {ub}"
    )


def test_wilson_all_correct_large_n_tightens():
    """0 misses out of 200 — UB drops below 5% so short-circuit."""
    ub = _wilson_upper_bound(200, 0)
    assert ub < 0.05


def test_wilson_misses_widen_bound():
    """Adding misses to a healthy cell pushes the upper bound back
    over the ceiling."""
    healthy = _wilson_upper_bound(100, 0)
    with_misses = _wilson_upper_bound(100, 8)
    assert with_misses > healthy
    assert with_misses > 0.05


# ---------------------------------------------------------------------------
# Cold start + learning mode
# ---------------------------------------------------------------------------


def test_cold_start_returns_learning(tmp_path):
    """Cell that's never been observed → LEARNING so the consumer
    runs both cheap and full and accumulates ground-truth data."""
    sc = ModelScorecard(tmp_path / "sc.json")
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.LEARNING


def test_below_floor_returns_learning(tmp_path):
    """n below sample_size_floor → LEARNING regardless of how good
    the cheap model has looked so far. Defends against premature
    trust on a tiny sample."""
    sc = ModelScorecard(tmp_path / "sc.json")
    for _ in range(5):
        sc.record_event(
            "codeql:py/sql-injection", "haiku",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.LEARNING


# ---------------------------------------------------------------------------
# Wilson-driven trust transitions
# ---------------------------------------------------------------------------


def _record_correct(sc, dc, model, n):
    for _ in range(n):
        sc.record_event(dc, model, EventType.CHEAP_SHORT_CIRCUIT, "correct")


def _record_incorrect(sc, dc, model, n):
    for _ in range(n):
        sc.record_event(dc, model, EventType.CHEAP_SHORT_CIRCUIT, "incorrect")


def test_clean_run_eventually_trusted(tmp_path):
    """After enough clean observations the cell becomes trusted.
    Exact n where this transitions depends on Wilson — ~70 correct
    is comfortably past the 5% ceiling."""
    sc = ModelScorecard(tmp_path / "sc.json")
    _record_correct(sc, "codeql:py/sql-injection", "haiku", 100)
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.SHORT_CIRCUIT


def test_misses_revert_to_fall_through(tmp_path):
    """A trusted cell that starts seeing misses goes back to
    fall-through. Without this we'd lock in stale trust."""
    sc = ModelScorecard(tmp_path / "sc.json")
    _record_correct(sc, "codeql:py/sql-injection", "haiku", 100)
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.SHORT_CIRCUIT
    _record_incorrect(sc, "codeql:py/sql-injection", "haiku", 10)
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.FALL_THROUGH


# ---------------------------------------------------------------------------
# Policy overrides preempt measured behaviour
# ---------------------------------------------------------------------------


def test_force_short_circuit_overrides_bad_data(tmp_path):
    """Operator pinned: even with a terrible track record, force
    short-circuit. Used for cases the operator KNOWS the cheap
    model handles well despite the data being noisy (e.g., the
    misses were due to a since-fixed bug in the cheap prompt)."""
    sc = ModelScorecard(tmp_path / "sc.json")
    _record_incorrect(sc, "codeql:py/sql-injection", "haiku", 50)
    sc.set_policy_override(
        "codeql:py/sql-injection", "haiku", "force_short_circuit",
    )
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.SHORT_CIRCUIT


def test_force_fall_through_overrides_good_data(tmp_path):
    """Operator pinned away from fast-tier despite good track
    record. The operator knows something the data doesn't —
    perhaps the rule changed semantics."""
    sc = ModelScorecard(tmp_path / "sc.json")
    _record_correct(sc, "codeql:py/sql-injection", "haiku", 200)
    sc.set_policy_override(
        "codeql:py/sql-injection", "haiku", "force_fall_through",
    )
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.FALL_THROUGH


def test_auto_releases_pin(tmp_path):
    """Setting back to ``"auto"`` returns to data-driven policy."""
    sc = ModelScorecard(tmp_path / "sc.json")
    _record_correct(sc, "codeql:py/sql-injection", "haiku", 200)
    sc.set_policy_override(
        "codeql:py/sql-injection", "haiku", "force_fall_through",
    )
    sc.set_policy_override(
        "codeql:py/sql-injection", "haiku", "auto",
    )
    assert sc.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.SHORT_CIRCUIT


# ---------------------------------------------------------------------------
# Persistence + schema invariants
# ---------------------------------------------------------------------------


def test_round_trip_persistence(tmp_path):
    """Reopen the same path and the recorded data is still there."""
    path = tmp_path / "sc.json"
    sc1 = ModelScorecard(path)
    _record_correct(sc1, "codeql:py/sql-injection", "haiku", 100)

    sc2 = ModelScorecard(path)
    assert sc2.should_short_circuit("codeql:py/sql-injection", "haiku") == Policy.SHORT_CIRCUIT


def test_schema_includes_version_field(tmp_path):
    """Every persisted file carries the schema version. Future
    breaking changes can refuse to read incompatible versions."""
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    _record_correct(sc, "x:y", "m", 1)
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["version"] == SCHEMA_VERSION


def test_all_event_types_present_in_cells(tmp_path):
    """A cell that's only seen ``cheap_short_circuit`` still has
    zero-counts for the other 4 event types so operators inspecting
    the JSON see a uniform shape, not 'why is `tool_evidence`
    missing?'"""
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    sc.record_event(
        "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
    )
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    cell = on_disk["models"]["m"]["x:y"]
    for et in ALL_EVENT_TYPES:
        assert et in cell["events"]
        assert "correct" in cell["events"][et]
        assert "incorrect" in cell["events"][et]


def test_model_first_layout(tmp_path):
    """JSON top level under ``models`` is keyed by model first,
    decision_class second. Locks in the Option-B layout we picked
    so a future reorganisation is a deliberate choice."""
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    sc.record_event("dc1", "modelA", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc2", "modelA", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc1", "modelB", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert set(on_disk["models"].keys()) == {"modelA", "modelB"}
    assert set(on_disk["models"]["modelA"].keys()) == {"dc1", "dc2"}
    assert set(on_disk["models"]["modelB"].keys()) == {"dc1"}


def test_corrupt_json_falls_through_to_empty(tmp_path):
    """A corrupted sidecar must NOT block the consumer's scan —
    we degrade to empty and continue."""
    path = tmp_path / "sc.json"
    path.write_text("{not valid json", encoding="utf-8")
    sc = ModelScorecard(path)
    # Should not raise.
    assert sc.should_short_circuit("x:y", "m") == Policy.LEARNING
    # And subsequent records should work.
    sc.record_event("x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")


def test_schema_version_mismatch_raises(tmp_path):
    """A sidecar from a future schema version refuses to be opened
    — surfacing a hard error beats silently downgrading data."""
    path = tmp_path / "sc.json"
    path.write_text(
        json.dumps({"version": SCHEMA_VERSION + 99, "models": {}}),
        encoding="utf-8",
    )
    sc = ModelScorecard(path)
    with pytest.raises(RuntimeError, match="schema version mismatch"):
        sc.should_short_circuit("x:y", "m")


# ---------------------------------------------------------------------------
# Disagreement samples
# ---------------------------------------------------------------------------


def test_samples_recorded_on_incorrect_only(tmp_path):
    """Samples accumulate only on ``outcome="incorrect"``. Successful
    runs don't bloat the log."""
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.record_event(
        "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        sample={"this_reasoning": "should NOT be recorded"},
    )
    sc.record_event(
        "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "incorrect",
        sample={"this_reasoning": "should be recorded"},
    )
    stats = sc.get_stat("x:y", "m")
    assert len(stats.disagreement_samples) == 1
    assert stats.disagreement_samples[0]["this_reasoning"] == "should be recorded"


def test_samples_capped_at_max(tmp_path):
    """Beyond MAX_DISAGREEMENT_SAMPLES we keep the most recent —
    older entries reflect older model snapshots, less useful."""
    sc = ModelScorecard(tmp_path / "sc.json")
    for i in range(MAX_DISAGREEMENT_SAMPLES + 5):
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "incorrect",
            sample={"this_reasoning": f"sample-{i}"},
        )
    stats = sc.get_stat("x:y", "m")
    assert len(stats.disagreement_samples) == MAX_DISAGREEMENT_SAMPLES
    # Most recent kept.
    last = stats.disagreement_samples[-1]
    assert last["this_reasoning"] == f"sample-{MAX_DISAGREEMENT_SAMPLES + 4}"


def test_retain_samples_disable(tmp_path):
    """``retain_samples=False`` suppresses the log entirely — for
    operators on shared infrastructure where reasoning text can't
    persist (privacy guard)."""
    sc = ModelScorecard(tmp_path / "sc.json", retain_samples=False)
    sc.record_event(
        "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "incorrect",
        sample={"this_reasoning": "must not be retained"},
    )
    stats = sc.get_stat("x:y", "m")
    assert stats.disagreement_samples == []


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_single_decision_class(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.record_event("dc1", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc2", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    n = sc.reset(decision_class="dc1")
    assert n == 1
    stats = {s.decision_class for s in sc.get_stats()}
    assert stats == {"dc2"}


def test_reset_by_model_clears_everything_for_model(tmp_path):
    """The model-switch case: operator changed their fast model
    and wants a clean slate for the new one."""
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.record_event("dc1", "modelA", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc2", "modelA", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc1", "modelB", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    n = sc.reset(model="modelA")
    assert n == 2
    remaining = {(s.model, s.decision_class) for s in sc.get_stats()}
    assert remaining == {("modelB", "dc1")}


def test_reset_older_than(tmp_path):
    """Stale-pruning: cells whose ``last_seen_at`` is older than N
    days are removed; fresh ones survive."""
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    sc.record_event("old", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("new", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    # Hand-edit "old" to look 200 days old. We do this rather than
    # time.sleep'ing because tests must stay fast.
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    long_ago = (
        datetime.now(timezone.utc) - timedelta(days=200)
    ).replace(microsecond=0).isoformat()
    on_disk["models"]["m"]["old"]["last_seen_at"] = long_ago
    path.write_text(json.dumps(on_disk), encoding="utf-8")

    n = sc.reset(older_than_days=90)
    assert n == 1
    remaining = {s.decision_class for s in sc.get_stats()}
    assert remaining == {"new"}


def test_reset_all_clears_everything(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.record_event("dc1", "m1", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc2", "m2", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    n = sc.reset(all_=True)
    assert n == 2
    assert sc.get_stats() == []


def test_reset_requires_a_filter(tmp_path):
    """Defensive: refuse to reset without an explicit filter or
    ``all_=True``. Prevents accidental wipe."""
    sc = ModelScorecard(tmp_path / "sc.json")
    with pytest.raises(ValueError, match="filter"):
        sc.reset()


# ---------------------------------------------------------------------------
# Concurrency — flock prevents lost updates
# ---------------------------------------------------------------------------


def _bump_in_subprocess(path_str: str, dc: str, model: str, n: int):
    """Module-level so multiprocessing.Pool can pickle it."""
    sc = ModelScorecard(Path(path_str))
    for _ in range(n):
        sc.record_event(
            dc, model, EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )


def test_concurrent_writes_do_not_lose_updates(tmp_path):
    """Two processes recording on different cells of the same
    sidecar must each see all of their own increments preserved.
    Without flock, a read-modify-write race would lose one set of
    increments."""
    path = tmp_path / "sc.json"

    procs = []
    # 4 processes, each bumping a distinct cell 25 times.
    for i in range(4):
        p = multiprocessing.Process(
            target=_bump_in_subprocess,
            args=(str(path), f"dc{i}", "m", 25),
        )
        p.start()
        procs.append(p)
    for p in procs:
        p.join()
        assert p.exitcode == 0, f"subprocess exited {p.exitcode}"

    sc = ModelScorecard(path)
    stats = {s.decision_class: s for s in sc.get_stats()}
    assert set(stats.keys()) == {"dc0", "dc1", "dc2", "dc3"}
    for dc, s in stats.items():
        ev = s.events[EventType.CHEAP_SHORT_CIRCUIT]
        assert ev.correct == 25, (
            f"{dc}: expected 25 increments, got {ev.correct}"
        )


# ---------------------------------------------------------------------------
# Smoke: get_stat / get_stats shape
# ---------------------------------------------------------------------------


def test_get_stat_returns_none_for_absent_cell(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    assert sc.get_stat("nope", "nope") is None


def test_get_stats_materialises_all_cells(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.record_event("dc1", "m1", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.record_event("dc2", "m2", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    stats = sc.get_stats()
    assert len(stats) == 2
    pairs = {(s.model, s.decision_class) for s in stats}
    assert pairs == {("m1", "dc1"), ("m2", "dc2")}


# ---------------------------------------------------------------------------
# Re-shadowing — drift detection via probabilistic re-validation
# ---------------------------------------------------------------------------


def _trusted_cell(sc, dc="x:y", model="m"):
    """Build out a trustworthy cell: 200 correct → Wilson UB safely
    under 5%, so without any shadow_rate the cell should
    short-circuit deterministically."""
    for _ in range(200):
        sc.record_event(dc, model, EventType.CHEAP_SHORT_CIRCUIT, "correct")


def test_shadow_rate_zero_never_shadows(tmp_path):
    """``shadow_rate=0`` (and the substrate default) preserves the
    legacy behaviour — a trusted cell always returns SHORT_CIRCUIT."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    _trusted_cell(sc)
    seen = {sc.should_short_circuit("x:y", "m") for _ in range(50)}
    assert seen == {Policy.SHORT_CIRCUIT}, (
        f"shadow_rate=0 must never shadow; saw {seen}"
    )


def test_shadow_rate_one_always_shadows(tmp_path):
    """``shadow_rate=1`` always returns SHADOW on a trusted cell.
    Useful for tests + for operators who want to fully re-validate
    a cell before re-trusting it."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=1.0)
    _trusted_cell(sc)
    seen = {sc.should_short_circuit("x:y", "m") for _ in range(50)}
    assert seen == {Policy.SHADOW}


def test_shadow_rate_does_not_affect_fall_through(tmp_path):
    """Re-shadowing only applies to cells that would otherwise
    short-circuit. A fall-through cell already runs full on every
    call, so SHADOW would be redundant — and confusing."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=1.0)
    # 50/50 → Wilson UB way over ceiling → fall through
    for _ in range(50):
        sc.record_event("x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    for _ in range(50):
        sc.record_event("x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "incorrect")
    # Even with shadow_rate=1, this never returns SHADOW because
    # the cell is fall-through.
    seen = {sc.should_short_circuit("x:y", "m") for _ in range(50)}
    assert seen == {Policy.FALL_THROUGH}


def test_shadow_rate_does_not_affect_learning(tmp_path):
    """Same defence for learning-mode cells: SHADOW only makes sense
    once the cell has accumulated enough data to be considered
    trusted. Below the floor, LEARNING wins."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=1.0)
    sc.record_event("x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct")
    seen = {sc.should_short_circuit("x:y", "m") for _ in range(50)}
    assert seen == {Policy.LEARNING}


def test_pin_overrides_shadow(tmp_path):
    """``policy_override="force_short_circuit"`` is operator intent
    expressed explicitly. It must beat random-sampling SHADOW —
    the operator is saying "don't validate this, I know what I'm
    doing", and we honour that without sampling around it."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=1.0)
    _trusted_cell(sc)
    sc.set_policy_override("x:y", "m", "force_short_circuit")
    seen = {sc.should_short_circuit("x:y", "m") for _ in range(50)}
    assert seen == {Policy.SHORT_CIRCUIT}


def test_shadow_rate_distribution(tmp_path):
    """A deterministic RNG that yields a known sequence verifies
    we're calling rng()< rate exactly once per query and trusting
    its result. Counts must match ceiling/floor of the expected
    distribution exactly — not within a stat-noise tolerance —
    because the sequence is fixed."""
    # RNG yields 0.0, 0.1, 0.2, ..., 0.9, 0.0, 0.1 ... — a
    # round-robin over 10 values. With shadow_rate=0.5, exactly
    # half (the values < 0.5) trigger SHADOW.
    state = {"i": 0}
    seq = [i / 10 for i in range(10)]
    def rng():
        v = seq[state["i"] % len(seq)]
        state["i"] += 1
        return v

    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.5, rng=rng)
    _trusted_cell(sc)
    outcomes = [
        sc.should_short_circuit("x:y", "m") for _ in range(20)
    ]
    n_shadow = outcomes.count(Policy.SHADOW)
    n_short = outcomes.count(Policy.SHORT_CIRCUIT)
    assert n_shadow == 10
    assert n_short == 10


def test_shadow_rate_invalid_value_rejected(tmp_path):
    """Defensive: silently clamping a typo (e.g. 5 instead of 0.05)
    would mean every trusted call shadows — defeats the cost win.
    Refuse out-of-range values explicitly."""
    with pytest.raises(ValueError, match="shadow_rate"):
        ModelScorecard(tmp_path / "sc.json", shadow_rate=5.0)
    with pytest.raises(ValueError, match="shadow_rate"):
        ModelScorecard(tmp_path / "sc.json", shadow_rate=-0.1)


# ---------------------------------------------------------------------------
# Auto-GC retention
# ---------------------------------------------------------------------------


def _backdate_cell(sc, model: str, decision_class: str,
                   *, days_ago: int) -> None:
    """Helper: rewrite a cell's last_seen_at to be ``days_ago`` days
    in the past. Lets tests stage stale data without having to wait
    or stub time.time() for the read path. Acquires the same write
    lock the public API uses, so the rewrite is consistent with the
    persistence layer.

    Note: this helper's own write counts as a GC trigger when the
    scorecard's auto_gc_interval_seconds is 0. To stage MULTIPLE
    stale cells before letting GC run, call ``_arm_gc(sc)`` after
    all backdates and then perform a single write — that ensures
    GC sees the full set in one pass rather than firing per call.
    """
    from datetime import datetime, timezone
    target = datetime.fromtimestamp(
        time.time() - days_ago * 86400, tz=timezone.utc,
    ).replace(microsecond=0).isoformat()
    with sc._with_lock() as data:
        data["models"][model][decision_class]["last_seen_at"] = target


def _arm_gc(sc) -> None:
    """Helper: clear ``last_gc_at`` so the next write triggers an
    auto-GC pass. Use after staging multiple stale cells via
    ``_backdate_cell`` to fire GC in one batch rather than per-cell."""
    with sc._with_lock() as data:
        data.pop("last_gc_at", None)


class TestAutoGc:
    def test_disabled_when_auto_gc_after_days_none(self, tmp_path):
        # Default would be 90 days; pass None to opt out.
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=None,
        )
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "m", "x:y", days_ago=400)
        # Trigger another write; opt-out means no GC happens.
        sc.record_event(
            "x:y", "m2", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        assert sc.get_stat("x:y", "m") is not None

    def test_disabled_when_auto_gc_after_days_zero(self, tmp_path):
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=0,
        )
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "m", "x:y", days_ago=400)
        sc.record_event(
            "x:y", "m2", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        assert sc.get_stat("x:y", "m") is not None

    def test_drops_stale_cell(self, tmp_path):
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )
        sc.record_event(
            "x:y", "old-model", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "old-model", "x:y", days_ago=120)
        # Next write triggers GC; ``old-model`` is past the cutoff
        # and not in keep_models, so its cell should be dropped.
        sc.record_event(
            "x:y", "fresh", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        assert sc.get_stat("x:y", "old-model") is None
        assert sc.get_stat("x:y", "fresh") is not None

    def test_preserves_fresh_cell(self, tmp_path):
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )
        sc.record_event(
            "x:y", "recent", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "recent", "x:y", days_ago=30)  # well within
        sc.record_event(
            "x:y", "another", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        # Fresh-ish cell survives — it's only 30d old.
        assert sc.get_stat("x:y", "recent") is not None

    def test_keep_models_protects_stale_cell(self, tmp_path):
        # Operator configured ``in-use`` 4 months ago but is back
        # scanning today. The cell would otherwise be GC'd; the
        # ``keep_models`` set protects it.
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
            keep_models={"in-use"},
        )
        sc.record_event(
            "x:y", "in-use", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "in-use", "x:y", days_ago=120)
        sc.record_event(
            "x:y", "fresh", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        # Stale but protected — survives. The Wilson-bound calibration
        # data the operator built up over previous quarters is intact.
        assert sc.get_stat("x:y", "in-use") is not None

    def test_keep_models_does_not_protect_unrelated_models(self, tmp_path):
        # Listing one model in keep_models doesn't rescue cells for
        # other deprecated models.
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
            keep_models={"in-use"},
        )
        sc.record_event(
            "x:y", "deprecated", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "deprecated", "x:y", days_ago=120)
        sc.record_event(
            "x:y", "in-use", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        assert sc.get_stat("x:y", "deprecated") is None

    def test_interval_gates_walk(self, tmp_path):
        # Run 1 with interval=0 → GC fires.
        # Run 2 with default interval (24h) immediately after → no walk.
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )
        sc.record_event(
            "x:y", "old", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "old", "x:y", days_ago=120)
        sc.record_event(  # triggers first GC; old dropped
            "x:y", "fresh", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        assert sc.get_stat("x:y", "old") is None

        # New scorecard handle on the same file with the production
        # interval. Stage another stale cell. GC must NOT fire because
        # last_gc_at was just stamped.
        sc2 = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
        )  # default 24h interval
        sc2.record_event(
            "x:y", "old2", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        # Backdate WITHOUT clearing last_gc_at this time so the
        # interval gate is the thing under test.
        from datetime import datetime, timezone
        with sc2._with_lock() as data:
            old_iso = datetime.fromtimestamp(
                time.time() - 200 * 86400, tz=timezone.utc,
            ).replace(microsecond=0).isoformat()
            data["models"]["old2"]["x:y"]["last_seen_at"] = old_iso

        sc2.record_event(
            "x:y", "fresh2", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        # Should still be present — interval gate suppressed the walk.
        assert sc2.get_stat("x:y", "old2") is not None

    def test_logs_summary_on_drop(self, tmp_path, caplog):
        # Stage two stale cells under auto_gc_after_days=None so
        # the seeding writes don't fire GC themselves. Then
        # construct a fresh handle with the production retention
        # to trigger the single GC pass we care about logging.
        seed = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=None,
        )
        seed.record_event(
            "x:y", "deprecated-a", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        seed.record_event(
            "x:y", "deprecated-b", EventType.CHEAP_SHORT_CIRCUIT, "incorrect",
        )
        _backdate_cell(seed, "deprecated-a", "x:y", days_ago=200)
        _backdate_cell(seed, "deprecated-b", "x:y", days_ago=200)

        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )

        # RaptorLogger uses a "raptor" logger with propagate=False,
        # so caplog (which hooks root by default) doesn't see its
        # records. Attach a captor handler directly to the "raptor"
        # logger for the duration of the test.
        import logging
        captured: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record):  # noqa: D401
                captured.append(record)

        raptor_logger = logging.getLogger("raptor")
        captor = _Capture(level=logging.INFO)
        raptor_logger.addHandler(captor)
        try:
            sc.record_event(
                "x:y", "fresh", EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        finally:
            raptor_logger.removeHandler(captor)

        # Summary line carries the per-model breakdown + outcome
        # tallies. Operators wanting historical data grep this line.
        summary = next(
            (r.getMessage() for r in captured
             if "auto-GC" in r.getMessage()), None,
        )
        assert summary is not None, [r.getMessage() for r in captured]
        assert "deprecated-a: 1" in summary
        assert "deprecated-b: 1" in summary
        # Outcomes summed across both deprecated cells: 1 correct + 1 incorrect.
        assert "1 correct" in summary
        assert "1 incorrect" in summary

    def test_no_log_when_nothing_dropped(self, tmp_path):
        # Interval has elapsed but no cells are stale → walk runs
        # silently (no INFO line). Operators don't get spammed when
        # the scorecard is healthy.
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )
        sc.record_event(
            "x:y", "fresh", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )

        # Same handler-attachment dance as test_logs_summary_on_drop
        # — caplog can't see records on the propagate=False raptor
        # logger.
        import logging
        captured: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record):  # noqa: D401
                captured.append(record)

        raptor_logger = logging.getLogger("raptor")
        captor = _Capture(level=logging.INFO)
        raptor_logger.addHandler(captor)
        try:
            sc.record_event(
                "x:y", "fresh-2", EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        finally:
            raptor_logger.removeHandler(captor)
        assert not any(
            "auto-GC" in r.getMessage() for r in captured
        )

    def test_removes_empty_model_dict(self, tmp_path):
        # When all of a model's cells are GC'd, the model entry
        # itself goes too — keeps the JSON tidy.
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )
        sc.record_event(
            "x:y", "deprecated", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        _backdate_cell(sc, "deprecated", "x:y", days_ago=200)
        sc.record_event(
            "x:y", "fresh", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        with sc._with_lock(write=False) as data:
            assert "deprecated" not in (data.get("models") or {})

    def test_last_gc_at_persists(self, tmp_path):
        sc = ModelScorecard(
            tmp_path / "sc.json", shadow_rate=0.0,
            auto_gc_after_days=90,
            auto_gc_interval_seconds=0.0,
        )
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
        with sc._with_lock(write=False) as data:
            assert data.get("last_gc_at"), (
                "last_gc_at must be stamped after first auto-GC pass"
            )
