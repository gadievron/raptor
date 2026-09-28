"""Mid-audit journal checkpoint — trigger, hysteresis, tiers, guard,
bounded abort, drain interplay, consumer invalidation.

Charter safety requirements pinned here (kill matrix in
``test_journal_checkpoint_killmatrix.py``; executor quiesce plumbing
in ``core/audit/tests/test_journal_quiesce.py``):

1. enforced precondition guard — ``CheckpointBusy`` on inflight
   review work, a busy probe, or a non-empty collector; raised even
   for an under-threshold journal (the guard is unconditional);
2. lock order — the collector is flushed and proven empty strictly
   BEFORE the compactor's first journal ``flock`` (instrumented);
3. foreign appenders blocked across the checkpoint's rename land
   their row in the LIVE journal (integration with the appender's
   post-flock inode re-validation);
5. drain interplay — an abort signal observed before the swap leaves
   the journal byte-identical; one observed after the swap lets the
   completed swap stand (both orderings);
6. consumer invalidation — exactly ONE cold reload of the load cache
   per checkpoint, and a re-checkpoint of an already-slimmed journal
   preserves stub hydration;
7. bounded — exceeding the wall bound aborts cleanly (byte-identical
   journal, loud log, no hysteresis state written).

Plus: trigger math on the largest-shard axis, hysteresis
(ineffective → advisory, regrowth → re-arm, hostile state can only
suppress, aborts never arm), tier policy (dedup+supersede automatic,
slim only under the existing consent — no RAPTOR call site passes
it), and two-direction regression tests for every churn-prone
constant.
"""

from __future__ import annotations

import fcntl as _fcntl_mod
import json
import os
import re
import threading
from itertools import count
from pathlib import Path

import pytest

import core.coverage.journal as journal_mod
import core.coverage.journal_checkpoint as jc
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    load_entries,
    load_entries_checked,
    now_iso,
    require_complete_entries,
)
from core.coverage.journal_checkpoint import (
    CHECKPOINT_STATE_FILENAME,
    CheckpointBusy,
    checkpoint_journal,
    evaluate_trigger,
    max_shard_bytes,
    rearm_bytes,
    trigger_bytes,
)
from core.coverage.journal_sidecar import SIDECAR_FILENAME, hydrate_entry


def _entry(i: int, **over) -> ReviewJournalEntry:
    fields = dict(
        ts=now_iso(),
        run_id="audit-run",
        file=f"src/f{i % 7}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash=f"{i:08x}",
        line_start=1 + i,
        line_end=5 + i,
        strategies=["bounds"],
        model="model-a",
        body="review body " * 20,
    )
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _journal_path(out: Path) -> Path:
    return out / JOURNAL_FILENAME


def _compressible_run(out: Path, n: int = 10, segments: int = 4) -> float:
    """Live $-bearing reviews + per-segment reused re-emissions: the
    shape both automatic tiers shrink hard."""
    spend = 0.0
    for i in range(n):
        cost = 0.25 + i / 100
        spend += cost
        append_entry(out, _entry(i, cost_usd=cost))
    for _seg in range(segments - 1):
        for i in range(n):
            append_entry(out, _entry(
                i, reused=True, reused_from_run="audit-run", cost_usd=0.0,
                body="[reused: verdict imported]",
            ))
    return spend


def _incompressible_run(out: Path, n: int = 24) -> None:
    """Distinct live verdicts only — nothing either automatic tier
    may drop (the 'journal legitimately large' shape)."""
    for i in range(n):
        append_entry(out, _entry(i, cost_usd=0.1))


def _arm_trigger(out: Path, monkeypatch) -> int:
    """Patch the loader budget so the current journal sits over the
    65% trigger (size > 0.65 * budget) while keeping real loader
    headroom (budget = 1.4x size), so loads stay complete and
    cache-serveable around the checkpoint."""
    size = _journal_path(out).stat().st_size
    monkeypatch.setattr(
        journal_mod, "_MAX_JOURNAL_BYTES", int(size * 1.4))
    assert size > trigger_bytes()
    return size


class TestTrigger:
    def test_under_threshold_no_fire(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        d = evaluate_trigger(tmp_path)
        assert not d.fire and not d.advisory
        assert "under threshold" in d.reason

    def test_over_threshold_fires(self, tmp_path: Path, monkeypatch) -> None:
        _incompressible_run(tmp_path, n=8)
        _arm_trigger(tmp_path, monkeypatch)
        d = evaluate_trigger(tmp_path)
        assert d.fire and not d.advisory

    def test_trigger_axis_is_largest_single_shard(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Per-shard budgets bound per-shard sizes: a multi-shard
        # journal whose TOTAL exceeds the trigger but whose largest
        # shard does not must not fire.
        append_entry(tmp_path, _entry(1))
        small = _journal_path(tmp_path).stat().st_size
        shard2 = tmp_path / "review-journal.002.jsonl"
        shard2.write_bytes(_journal_path(tmp_path).read_bytes() * 3)
        assert max_shard_bytes(tmp_path) == shard2.stat().st_size
        # Budget sized so shard2 (the largest) is over the trigger
        # while shard1 alone would not be.
        monkeypatch.setattr(
            journal_mod, "_MAX_JOURNAL_BYTES", shard2.stat().st_size)
        assert evaluate_trigger(tmp_path).fire
        # Largest shard under threshold -> no fire even though the
        # total (small + 3*small) exceeds it.
        monkeypatch.setattr(
            journal_mod, "_MAX_JOURNAL_BYTES", small * 10)
        assert not evaluate_trigger(tmp_path).fire

    def test_missing_journal_never_fires(self, tmp_path: Path) -> None:
        d = evaluate_trigger(tmp_path)
        assert not d.fire and not d.advisory

    def test_trigger_derives_from_budget_at_call_time(
        self, monkeypatch,
    ) -> None:
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 1000)
        assert trigger_bytes() == 650
        assert rearm_bytes() == 100

    def test_exact_threshold_boundary_two_directions(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # The trigger is strictly-over: a largest shard at EXACTLY
        # the threshold must NOT fire (`size <= threshold` is the
        # no-fire arm — the trigger's headroom margin is measured
        # from strictly past it), one byte over must. The evaluation
        # is stat-only, so raw bytes pin the boundary exactly.
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 1000)
        path = _journal_path(tmp_path)
        path.write_bytes(b"x" * trigger_bytes())
        d = evaluate_trigger(tmp_path)
        assert not d.fire and not d.advisory
        assert "under threshold" in d.reason
        path.write_bytes(b"x" * (trigger_bytes() + 1))
        assert evaluate_trigger(tmp_path).fire


class TestConstants:
    """Two-direction regression tests: each bound names the failure
    mode crossing it would reintroduce (see the constants' inline
    rationale comments)."""

    def test_trigger_fraction_bounds(self) -> None:
        # Lower bound: firing full two-pass rewrites on journals with
        # >50% headroom is wasted I/O + needless cold reloads.
        assert jc._CHECKPOINT_TRIGGER_FRACTION >= 0.5
        # Upper bound: must fire BELOW the appender's roll threshold
        # (a rolled shard is sealed — no checkpoint can shrink what a
        # reader must still parse) and the loader's prune-exit margin.
        roll_fraction = (
            journal_mod._JOURNAL_SHARD_ROLL_BYTES
            / journal_mod._MAX_JOURNAL_BYTES
        )
        assert jc._CHECKPOINT_TRIGGER_FRACTION < roll_fraction
        assert jc._CHECKPOINT_TRIGGER_FRACTION < 0.90

    def test_min_freed_fraction_bounds(self) -> None:
        # Lower: 0 would let a no-op checkpoint count as effective and
        # re-fire at every boundary (the thrash the floor stops).
        assert jc._CHECKPOINT_MIN_FREED_FRACTION > 0.0
        # Upper: writing off checkpoints that halved the journal would
        # go advisory on runs the automatic tiers genuinely help.
        assert jc._CHECKPOINT_MIN_FREED_FRACTION <= 0.5

    def test_rearm_fraction_bounds(self) -> None:
        # Lower: 0 re-fires a provably-ineffective rewrite on trivial
        # growth. Upper: past the trigger fraction the journal could
        # roll before the trigger ever re-arms.
        assert 0.0 < jc._CHECKPOINT_REARM_FRACTION
        assert (jc._CHECKPOINT_REARM_FRACTION
                <= jc._CHECKPOINT_TRIGGER_FRACTION)

    def test_wall_bound_bounds(self) -> None:
        # Lower: must outlast a legitimate at-threshold compaction
        # (tens of seconds on slow disks). Upper: the checkpoint runs
        # synchronously in the main loop — every second is paused
        # reviews, so the bound stays well under one review timeout.
        assert 60.0 <= jc._CHECKPOINT_WALL_BOUND_S <= 1800.0


class TestCheckpointFires:
    def test_fires_supersedes_archives_and_records_state(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        spend = _compressible_run(tmp_path)
        before = _arm_trigger(tmp_path, monkeypatch)
        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert outcome.fired and not outcome.advisory
        assert outcome.stats is not None
        after = _journal_path(tmp_path).stat().st_size
        assert after < before
        # Full archive: the original is byte-preserved.
        backup = tmp_path / (JOURNAL_FILENAME + ".pre-supersede")
        assert backup.stat().st_size == before
        # Spend floor preserved through the carriers.
        entries = load_entries(tmp_path)
        assert sum(e.cost_usd or 0.0 for e in entries) == pytest.approx(spend)
        # State record: effective, schema-versioned, in the run dir.
        state = json.loads(
            (tmp_path / CHECKPOINT_STATE_FILENAME).read_text())
        assert state["schema_version"] == 1
        assert state["effective"] is True
        assert state["boundary"] == "test"
        assert state["bytes_after"] == after
        # The journal still passes the resume gate.
        assert require_complete_entries(tmp_path)

    def test_under_threshold_is_a_noop(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        before = _journal_path(tmp_path).read_bytes()
        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert not outcome.fired and not outcome.advisory
        assert _journal_path(tmp_path).read_bytes() == before
        assert not (tmp_path / CHECKPOINT_STATE_FILENAME).exists()

    def test_compactor_refusal_resolves_to_outcome(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        # A live foreign run refuses compaction; the checkpoint
        # resolves that to a refused-marked outcome (pollers arm
        # their retry cooldown on the marker) at WARNING — never an
        # exception.
        from core.run.metadata import RUN_METADATA_FILE
        _incompressible_run(tmp_path, n=8)
        _arm_trigger(tmp_path, monkeypatch)
        (tmp_path / RUN_METADATA_FILE).write_text("{not json")
        before = _journal_path(tmp_path).read_bytes()
        with caplog.at_level(
                "WARNING", logger="core.coverage.journal_checkpoint"):
            outcome = checkpoint_journal(tmp_path, boundary="test")
        assert not outcome.fired and not outcome.aborted
        assert outcome.refused
        assert "cannot be read" in outcome.reason
        assert any(
            "compactor refused" in r.message for r in caplog.records)
        assert _journal_path(tmp_path).read_bytes() == before

    def test_preflight_refusal_two_directions(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Refusal direction: the poll-time preflight reports the same
        # unreadable-metadata refusal the compactor would raise, so
        # callers can skip a doomed quiesce drain.
        from core.run.metadata import RUN_METADATA_FILE
        _incompressible_run(tmp_path, n=8)
        _arm_trigger(tmp_path, monkeypatch)
        (tmp_path / RUN_METADATA_FILE).write_text("{not json")
        reason = jc.preflight_refusal(tmp_path)
        assert reason is not None and "cannot be read" in reason
        # Pass direction: with the metadata gone the preflight passes
        # — and authorizes nothing (the compactor re-asserts the same
        # guard under its own locks).
        (tmp_path / RUN_METADATA_FILE).unlink()
        assert jc.preflight_refusal(tmp_path) is None


class TestTiers:
    def test_automatic_tier_never_slims(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Fat distinct clean rows: slim-eligible content, but the
        # automatic tier must not touch it without the consent.
        for i in range(6):
            append_entry(tmp_path, _entry(
                i, body="prose " * 600, cost_usd=0.1))
        _arm_trigger(tmp_path, monkeypatch)
        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert outcome.fired
        assert not (tmp_path / SIDECAR_FILENAME).exists()
        assert not (tmp_path / (JOURNAL_FILENAME + ".pre-slim")).exists()
        assert all(
            e.body_offload is None for e in load_entries(tmp_path))

    def test_slim_consent_param_engages_the_slim_tier(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        for i in range(6):
            append_entry(tmp_path, _entry(
                i, body="prose " * 600, cost_usd=0.1))
        _arm_trigger(tmp_path, monkeypatch)
        outcome = checkpoint_journal(
            tmp_path, boundary="test", slim_consent=True)
        assert outcome.fired
        assert (tmp_path / SIDECAR_FILENAME).exists()
        assert (tmp_path / (JOURNAL_FILENAME + ".pre-slim")).exists()
        stubs = [e for e in load_entries(tmp_path)
                 if e.body_offload is not None]
        assert stubs
        hydrated = hydrate_entry(tmp_path, stubs[0])
        assert hydrated is not None
        assert hydrated.body.startswith("prose ")

    def test_no_runtime_call_site_passes_slim_consent(self) -> None:
        """The checkpoint never widens the slim tier's consent surface:
        no runtime code passes ``slim_consent=True`` — the only route
        to slimming stays the operator CLI's ``--slim-clean``."""
        repo = Path(__file__).resolve().parents[3]
        offenders = []
        for base in (repo / "core", repo / "libexec"):
            for path in base.rglob("*"):
                if not path.is_file() or "/tests/" in str(path):
                    continue
                if path.suffix not in ("", ".py"):
                    continue
                try:
                    text = path.read_text(errors="ignore")
                except OSError:
                    continue
                if re.search(r"slim_consent\s*=\s*True", text):
                    offenders.append(str(path))
        assert offenders == []


class TestHysteresis:
    def test_ineffective_checkpoint_goes_advisory(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        _incompressible_run(tmp_path)
        _arm_trigger(tmp_path, monkeypatch)
        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert outcome.fired
        assert outcome.freed_fraction < jc._CHECKPOINT_MIN_FREED_FRACTION
        state = json.loads(
            (tmp_path / CHECKPOINT_STATE_FILENAME).read_text())
        assert state["effective"] is False
        # Still over threshold, hysteresis armed: advisory, no re-fire.
        d = evaluate_trigger(tmp_path)
        assert d.advisory and not d.fire
        assert "legitimately large" in d.reason
        with caplog.at_level(
                "WARNING", logger="core.coverage.journal_checkpoint"):
            outcome2 = checkpoint_journal(tmp_path, boundary="test")
        assert outcome2.advisory and not outcome2.fired
        assert any("legitimately large" in r.message
                   for r in caplog.records)
        # No second rewrite: exactly one archive generation exists.
        backups = list(tmp_path.glob(
            JOURNAL_FILENAME + ".pre-supersede*"))
        assert len(backups) == 1

    def test_regrowth_past_rearm_re_fires(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        _incompressible_run(tmp_path)
        _arm_trigger(tmp_path, monkeypatch)
        checkpoint_journal(tmp_path, boundary="test")
        assert evaluate_trigger(tmp_path).advisory
        # Grow past recorded-after + rearm: the trigger re-arms.
        target = max_shard_bytes(tmp_path) + rearm_bytes()
        i = 1000
        while _journal_path(tmp_path).stat().st_size <= target:
            append_entry(tmp_path, _entry(i, cost_usd=0.1))
            i += 1
        d = evaluate_trigger(tmp_path)
        assert d.fire and not d.advisory

    def test_hostile_state_can_only_suppress_never_worse(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # Unparseable / wrong-typed state reads as "no state": the
        # trigger FIRES (the safe direction — wasted I/O, not lost
        # data) and NEVER raises (the record is run-dir content on a
        # bare executor poll path). A forged 'ineffective' record
        # merely suppresses.
        _incompressible_run(tmp_path, n=8)
        _arm_trigger(tmp_path, monkeypatch)
        state_path = tmp_path / CHECKPOINT_STATE_FILENAME
        # freed_fraction feeds a % format in the advisory reason: an
        # otherwise-valid ineffective record with a hostile value
        # there must be rejected wholesale, not crash the format.
        hostile_fractions = (
            None, "evil", True, -0.5, 1.5,
            float("nan"), float("inf"),
        )
        for hostile in (
            "{not json",
            json.dumps({"schema_version": 99}),
            json.dumps({
                "schema_version": 1, "effective": False,
                "max_shard_bytes_after": "big",
                "bytes_before": 1, "bytes_after": 1,
            }),
            json.dumps({
                "schema_version": 1, "effective": "no",
                "max_shard_bytes_after": 1,
                "bytes_before": 1, "bytes_after": 1,
            }),
            *(
                json.dumps({
                    "schema_version": 1, "effective": False,
                    "max_shard_bytes_after": 2**40,
                    "bytes_before": 1, "bytes_after": 1,
                    "freed_fraction": ff,
                })
                for ff in hostile_fractions
            ),
        ):
            state_path.write_text(hostile)
            assert evaluate_trigger(tmp_path).fire, hostile
        state_path.unlink()
        assert evaluate_trigger(tmp_path).fire

    def test_abort_never_arms_hysteresis(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        _incompressible_run(tmp_path)
        before = _journal_path(tmp_path).read_bytes()
        _arm_trigger(tmp_path, monkeypatch)
        with caplog.at_level(
                "WARNING", logger="core.coverage.journal_checkpoint"):
            outcome = checkpoint_journal(
                tmp_path, boundary="test", wall_bound_s=-1.0)
        assert outcome.aborted and not outcome.fired
        # Aborts are not refusals: the refused marker (which cools
        # pollers down) must stay False despite the subclass relation.
        assert not outcome.refused
        assert "wall-clock bound exceeded" in outcome.reason
        assert any("aborted" in r.message for r in caplog.records)
        # Byte-identical journal, no archive, no state record — the
        # next evaluation retries at full strength.
        assert _journal_path(tmp_path).read_bytes() == before
        assert not list(tmp_path.glob(JOURNAL_FILENAME + ".pre-*"))
        assert not (tmp_path / CHECKPOINT_STATE_FILENAME).exists()
        assert evaluate_trigger(tmp_path).fire

    def test_effectiveness_floor_exact_equality_is_effective(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        # The floor is INCLUSIVE (`freed_fraction >=` the constant):
        # a checkpoint freeing exactly the floor fraction counts as
        # effective — the state record must not arm the advisory.
        # (The exclusive direction — strictly under the floor goes
        # advisory — is pinned by
        # test_ineffective_checkpoint_goes_advisory.)
        # Fraction() gives before/freed integers whose float ratio
        # reproduces the floor's double bit-exactly, whatever its
        # value.
        from fractions import Fraction

        from core.coverage.journal_compact import CompactStats

        _incompressible_run(tmp_path, n=8)
        _arm_trigger(tmp_path, monkeypatch)
        floor = Fraction(jc._CHECKPOINT_MIN_FREED_FRACTION)
        before, freed = floor.denominator, floor.numerator
        assert freed / before == jc._CHECKPOINT_MIN_FREED_FRACTION

        def _exact_floor_compact(out_dir, **kwargs):
            return CompactStats(
                journal_path=str(_journal_path(tmp_path)),
                backup_path=str(
                    tmp_path / (JOURNAL_FILENAME + ".pre-supersede")),
                rows_before=10, rows_after=9,
                bytes_before=before, bytes_after=before - freed,
            )

        monkeypatch.setattr(jc, "compact_journal", _exact_floor_compact)
        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert outcome.fired
        assert (outcome.freed_fraction
                == jc._CHECKPOINT_MIN_FREED_FRACTION)
        state = json.loads(
            (tmp_path / CHECKPOINT_STATE_FILENAME).read_text())
        assert state["effective"] is True


class TestGuard:
    def test_inflight_review_work_raises_busy(
        self, tmp_path: Path,
    ) -> None:
        from core.audit import executor as ex
        append_entry(tmp_path, _entry(1))
        before = _journal_path(tmp_path).read_bytes()
        with ex.review_work_active():  # noqa: SIM117 — the guard under test
            with pytest.raises(CheckpointBusy, match="in flight"):
                checkpoint_journal(tmp_path, boundary="test")
        assert _journal_path(tmp_path).read_bytes() == before

    def test_guard_is_unconditional_even_under_threshold(
        self, tmp_path: Path,
    ) -> None:
        # The guard runs BEFORE trigger evaluation: a busy call is a
        # caller bug regardless of journal size.
        from core.audit import executor as ex
        append_entry(tmp_path, _entry(1))
        with ex.review_work_active():  # noqa: SIM117 — the guard under test
            with pytest.raises(CheckpointBusy):
                checkpoint_journal(tmp_path, boundary="test")

    def test_nonempty_collector_after_flush_raises_busy(
        self, tmp_path: Path,
    ) -> None:
        class _StuckCollector:
            def flush(self) -> None:
                pass

            def pending_count(self) -> int:
                return 3

        append_entry(tmp_path, _entry(1))
        with pytest.raises(CheckpointBusy, match="buffered row"):
            checkpoint_journal(
                tmp_path, boundary="test", collector=_StuckCollector())

    def test_busy_probe_raises_busy(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        with pytest.raises(CheckpointBusy, match="mid-batch"):
            checkpoint_journal(
                tmp_path, boundary="test",
                busy_probes=(lambda: "study consumer is mid-batch",))

    def test_lock_order_collector_flush_precedes_first_flock(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """Charter lock-order rule, instrumented: the collector is
        drained provably empty strictly BEFORE the compactor's first
        exclusive journal flock."""
        _compressible_run(tmp_path)
        _arm_trigger(tmp_path, monkeypatch)
        events: list[str] = []

        class _Collector:
            def flush(self) -> None:
                events.append("flush")

            def pending_count(self) -> int:
                events.append("proven-empty")
                return 0

        real_flock = _fcntl_mod.flock

        def _recording_flock(fd, op):
            if op & _fcntl_mod.LOCK_EX:
                events.append("LOCK_EX")
            return real_flock(fd, op)

        monkeypatch.setattr(_fcntl_mod, "flock", _recording_flock)
        outcome = checkpoint_journal(
            tmp_path, boundary="test", collector=_Collector())
        assert outcome.fired
        assert "LOCK_EX" in events
        first_lock = events.index("LOCK_EX")
        assert events.index("flush") < first_lock
        assert events.index("proven-empty") < first_lock


class TestDrainInterplay:
    """Charter safety requirement 5 — SIGTERM (``should_abort``) vs
    the checkpoint, both orderings."""

    def test_abort_before_swap_leaves_journal_byte_identical(
        self, tmp_path: Path, monkeypatch, caplog,
    ) -> None:
        _compressible_run(tmp_path)
        before = _journal_path(tmp_path).read_bytes()
        _arm_trigger(tmp_path, monkeypatch)
        calls = count(1)
        # Call 1 = checkpoint entry, call 2 = shard-loop head, call 3
        # = the pre-swap seam (small file: line polls never fire) —
        # the drain lands mid-transform, before the rename.
        with caplog.at_level(
                "WARNING", logger="core.coverage.journal_checkpoint"):
            outcome = checkpoint_journal(
                tmp_path, boundary="test",
                should_abort=lambda: next(calls) >= 3)
        assert outcome.aborted
        assert "abort requested" in outcome.reason
        assert _journal_path(tmp_path).read_bytes() == before
        assert not list(tmp_path.glob(JOURNAL_FILENAME + ".pre-*"))
        assert require_complete_entries(tmp_path)

    def test_abort_after_swap_lets_the_completed_swap_stand(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        spend = _compressible_run(tmp_path)
        before = _journal_path(tmp_path).stat().st_size
        _arm_trigger(tmp_path, monkeypatch)
        flag = {"set": False}
        real_rename = os.rename

        def _rename_then_signal(src, dst, **kw):
            real_rename(src, dst, **kw)
            flag["set"] = True

        monkeypatch.setattr(os, "rename", _rename_then_signal)
        outcome = checkpoint_journal(
            tmp_path, boundary="test",
            should_abort=lambda: flag["set"])
        # Every pre-swap poll saw False; the swap completed and
        # stands — no corruption, archive intact, spend preserved.
        assert outcome.fired and not outcome.aborted
        assert _journal_path(tmp_path).stat().st_size < before
        backup = tmp_path / (JOURNAL_FILENAME + ".pre-supersede")
        assert backup.stat().st_size == before
        entries = require_complete_entries(tmp_path)
        assert sum(e.cost_usd or 0.0 for e in entries) == pytest.approx(spend)


class TestForeignAppenderAcrossCheckpoint:
    def test_appender_blocked_across_swap_lands_in_live_journal(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """Charter safety requirement 3, integrated: an appender that
        opened the journal BEFORE the checkpoint's rename and flocks
        AFTER it detects the swap (post-flock inode re-validation),
        reopens, and lands its row in the LIVE journal — never the
        archive."""
        _compressible_run(tmp_path)
        _arm_trigger(tmp_path, monkeypatch)
        at_flock = threading.Event()
        release = threading.Event()
        gated = {"done": False}
        real_flock = _fcntl_mod.flock

        def _gating_flock(fd, op):
            if (threading.current_thread().name == "foreign-appender"
                    and op & _fcntl_mod.LOCK_EX and not gated["done"]):
                gated["done"] = True
                at_flock.set()
                assert release.wait(timeout=30.0)
            return real_flock(fd, op)

        monkeypatch.setattr(_fcntl_mod, "flock", _gating_flock)
        errors: list[BaseException] = []

        def _append() -> None:
            try:
                append_entry(tmp_path, _entry(
                    999, function="foreign_row", cost_usd=0.0))
            except BaseException as exc:  # noqa: BLE001 — surfaced below
                errors.append(exc)

        t = threading.Thread(
            target=_append, name="foreign-appender", daemon=True)
        t.start()
        assert at_flock.wait(timeout=30.0)
        # The appender holds an fd on the pre-swap inode, gated before
        # its flock. Checkpoint swaps underneath it.
        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert outcome.fired
        release.set()
        t.join(timeout=30.0)
        assert not t.is_alive() and errors == []
        live = _journal_path(tmp_path).read_bytes()
        backup = (tmp_path / (JOURNAL_FILENAME + ".pre-supersede"))
        assert b"foreign_row" in live
        assert b"foreign_row" not in backup.read_bytes()
        assert any(e.function == "foreign_row"
                   for e in require_complete_entries(tmp_path))


class TestConsumerInvalidation:
    def test_exactly_one_cold_reload_per_checkpoint(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """Charter safety requirement 6: the checkpoint drops the
        process-local load cache once — the next load is cold, the
        one after is cache-served again, and no other invalidation
        fires."""
        _compressible_run(tmp_path)
        _arm_trigger(tmp_path, monkeypatch)
        cold = count()
        cold_total = {"n": 0}
        real_cold = journal_mod._load_shard_cold

        def _counting_cold(path):
            next(cold)
            cold_total["n"] += 1
            return real_cold(path)

        invalidations = {"n": 0}
        real_invalidate = journal_mod.invalidate_load_cache

        def _counting_invalidate(out_dir):
            invalidations["n"] += 1
            return real_invalidate(out_dir)

        monkeypatch.setattr(
            journal_mod, "_load_shard_cold", _counting_cold)
        monkeypatch.setattr(
            journal_mod, "invalidate_load_cache", _counting_invalidate)

        def _age_pin() -> None:
            # Serve requires a non-racy pin: age the shard's mtime
            # past the loader's clock-tick race window (no sleeps).
            st = _journal_path(tmp_path).stat()
            os.utime(_journal_path(tmp_path), ns=(
                st.st_atime_ns, st.st_mtime_ns - 5_000_000_000))

        _age_pin()
        assert load_entries_checked(tmp_path).complete
        assert cold_total["n"] == 1          # warm the cache
        assert load_entries_checked(tmp_path).complete
        assert cold_total["n"] == 1          # served, no cold parse

        outcome = checkpoint_journal(tmp_path, boundary="test")
        assert outcome.fired
        assert invalidations["n"] == 1       # once per swapped shard

        _age_pin()
        assert load_entries_checked(tmp_path).complete
        assert cold_total["n"] == 2          # exactly ONE cold reload
        assert load_entries_checked(tmp_path).complete
        assert cold_total["n"] == 2          # cache-served again

    def test_recheckpoint_of_slimmed_journal_preserves_hydration(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """Regression (charter req 6): re-checkpointing an already-
        slimmed journal must keep every stub's hydration pointer
        resolving — stubs are never re-slimmed and their sidecar
        offsets never move (the sidecar is append-only)."""
        for i in range(6):
            append_entry(tmp_path, _entry(
                i, body=f"unique prose {i} " * 400, cost_usd=0.1))
        _arm_trigger(tmp_path, monkeypatch)
        assert checkpoint_journal(
            tmp_path, boundary="test", slim_consent=True).fired
        stubs = [e for e in load_entries(tmp_path)
                 if e.body_offload is not None]
        assert stubs
        want = {
            s.function: hydrate_entry(tmp_path, s).body for s in stubs
        }
        # Regrow with NEW distinct fat rows (a row with a newer twin
        # would legitimately supersede its stub — not this test's
        # subject) and re-checkpoint with the slim tier again.
        for i in range(10, 16):
            append_entry(tmp_path, _entry(
                i, body=f"unique prose {i} " * 400, cost_usd=0.1))
        _arm_trigger(tmp_path, monkeypatch)
        (tmp_path / CHECKPOINT_STATE_FILENAME).unlink()
        assert checkpoint_journal(
            tmp_path, boundary="test", slim_consent=True).fired
        survivors = [e for e in load_entries(tmp_path)
                     if e.body_offload is not None]
        assert {s.function for s in survivors} >= set(want)
        for s in survivors:
            if s.function not in want:
                continue
            hydrated = hydrate_entry(tmp_path, s)
            assert hydrated is not None
            assert hydrated.body == want[s.function]
