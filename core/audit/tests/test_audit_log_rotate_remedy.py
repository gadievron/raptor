"""The `audit-log rotate` remedy: verbatim re-split of oversized
trails, refuse-live gate, byte preservation, MAC survival.

Rotation exists for trails written before the writer rolled shards
(one file past the read budget → the loader degrades to a bounded
newest-tail read). The remedy re-splits existing bytes VERBATIM at
line boundaries; these tests pin that no byte changes, that the
trail becomes fully loadable, that per-row run-bound integrity
stamps still verify afterwards, and that a live (or unprovably-dead)
run refuses with nothing modified.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.audit import audit_log_rotate as rotate_mod
from core.audit import record
from core.audit.audit_log_rotate import (
    RotateRefused,
    rotate_audit_log,
)


def _shrink_budgets(monkeypatch, *, max_bytes: int = 2048) -> None:
    """Shrink the per-shard budgets consistently in BOTH modules
    (each imported the constants by value)."""
    roll = (max_bytes * 3) // 4
    monkeypatch.setattr(record, "_AUDIT_LOG_MAX_BYTES", max_bytes)
    monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", roll)
    monkeypatch.setattr(rotate_mod, "_AUDIT_LOG_MAX_BYTES", max_bytes)
    monkeypatch.setattr(
        rotate_mod, "_AUDIT_LOG_SHARD_ROLL_BYTES", roll)


def _plant_rows(path: Path, n: int, *, start: int = 0) -> None:
    with path.open("a") as fh:
        for i in range(start, start + n):
            fh.write(json.dumps({
                "action": "orchestrator_review",
                "key": f"a.c:f{i}:1", "status": "clean", "seq": i,
            }) + "\n")


def _trail_bytes(out_dir: Path) -> bytes:
    return b"".join(
        p.read_bytes()
        for p in record.audit_log_paths(out_dir) if p.is_file()
    )


class TestRotateSplits:
    def test_oversize_trail_becomes_fully_loadable(
        self, tmp_path: Path, monkeypatch,
    ):
        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        before = _trail_bytes(tmp_path)
        # Pre-rotation: the loader degrades to a newest tail.
        _, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert not disclosure.complete

        stats = rotate_audit_log(tmp_path)
        assert stats.rotated
        assert stats.shards_before == 1
        assert stats.shards_after > 1
        # Byte preservation: shard concatenation is byte-identical.
        assert _trail_bytes(tmp_path) == before
        # Every shard is at or under the read budget.
        for p in record.audit_log_paths(tmp_path):
            assert p.stat().st_size <= rotate_mod._AUDIT_LOG_MAX_BYTES
        # Post-rotation: complete load, all rows, in order.
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert disclosure.complete
        assert [r["seq"] for r in rows] == list(range(60))
        # Backup preserved with the original bytes.
        backup = tmp_path / (record.AUDIT_LOG_FILENAME + ".pre-rotate")
        assert stats.backups == (backup.name,)
        assert backup.read_bytes() == before

    def test_noop_when_nothing_over_budget(self, tmp_path: Path):
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 5)
        before = _trail_bytes(tmp_path)
        stats = rotate_audit_log(tmp_path)
        assert not stats.rotated
        assert stats.shards_before == stats.shards_after == 1
        assert _trail_bytes(tmp_path) == before
        assert not (
            tmp_path / (record.AUDIT_LOG_FILENAME + ".pre-rotate")
        ).exists()

    def test_second_rotate_is_noop(self, tmp_path: Path, monkeypatch):
        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        assert rotate_audit_log(tmp_path).rotated
        after_first = _trail_bytes(tmp_path)
        stats = rotate_audit_log(tmp_path)
        assert not stats.rotated
        assert _trail_bytes(tmp_path) == after_first

    def test_torn_final_line_preserved_verbatim(
        self, tmp_path: Path, monkeypatch,
    ):
        _shrink_budgets(monkeypatch)
        log = tmp_path / record.AUDIT_LOG_FILENAME
        _plant_rows(log, 60)
        with log.open("a") as fh:
            fh.write('{"action": "orchestrator_review", "tor')  # no \n
        before = _trail_bytes(tmp_path)
        stats = rotate_audit_log(tmp_path)
        assert stats.rotated
        assert _trail_bytes(tmp_path) == before
        last = record.audit_log_paths(tmp_path)[-1]
        assert last.read_bytes().endswith(b'"tor')

    def test_multi_shard_input_rebalanced(
        self, tmp_path: Path, monkeypatch,
    ):
        # A trail that ALREADY has shards, one of them oversized
        # (e.g. the absorb arm at the shard bound), rebalances whole.
        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        _plant_rows(
            tmp_path / ".audit-log.002.jsonl", 5, start=60)
        before = _trail_bytes(tmp_path)
        stats = rotate_audit_log(tmp_path)
        assert stats.rotated
        assert stats.shards_before == 2
        assert _trail_bytes(tmp_path) == before
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert disclosure.complete
        assert [r["seq"] for r in rows] == list(range(65))

    def test_stale_temp_refused_with_actionable_error(
        self, tmp_path: Path, monkeypatch,
    ):
        # A leftover temp from an interrupted rotate hits the O_EXCL
        # open. Fail-safe either way (originals untouched), but the
        # operator must get an actionable refusal naming the stale
        # file — not a raw FileExistsError traceback — and the stale
        # file is left in place for inspection.
        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        stale = tmp_path / ".audit-log-rotate.tmp.001"
        stale.write_text("partial rewrite\n")
        before = _trail_bytes(tmp_path)
        with pytest.raises(RotateRefused, match="stale temp"):
            rotate_audit_log(tmp_path)
        assert _trail_bytes(tmp_path) == before
        assert stale.read_text() == "partial rewrite\n"
        assert not list(tmp_path.glob("*.pre-rotate*"))

    def test_orphan_shard_untouched_and_reported(
        self, tmp_path: Path, monkeypatch,
    ):
        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        orphan = tmp_path / ".audit-log.007.jsonl"
        _plant_rows(orphan, 1, start=999)
        orphan_bytes = orphan.read_bytes()
        stats = rotate_audit_log(tmp_path)
        assert stats.rotated
        assert stats.orphan_shards == (".audit-log.007.jsonl",)
        assert orphan.read_bytes() == orphan_bytes

    def test_shard_bound_final_shard_absorbs(
        self, tmp_path: Path, monkeypatch,
    ):
        # Both directions of the shard-count bound at rotate time:
        # under the bound shards roll; at the bound the final shard
        # absorbs the remainder and the overflow is reported.
        _shrink_budgets(monkeypatch)
        monkeypatch.setattr(rotate_mod, "_AUDIT_LOG_MAX_SHARDS", 2)
        monkeypatch.setattr(record, "_AUDIT_LOG_MAX_SHARDS", 2)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 200)
        before = _trail_bytes(tmp_path)
        stats = rotate_audit_log(tmp_path)
        assert stats.rotated
        assert stats.shards_after == 2
        assert stats.over_budget_shards == (".audit-log.002.jsonl",)
        assert _trail_bytes(tmp_path) == before

    def test_interior_giant_line_shard_reported_over_budget(
        self, tmp_path: Path, monkeypatch,
    ):
        # A single line larger than the read budget pins whichever
        # shard it lands in over the budget — here the FIRST shard,
        # while the final shard stays small. The rewrite cannot split
        # a line, so plain success would misreport a trail that still
        # partially degrades to tail reads (and a re-run would churn
        # without converging). The over-budget report must name the
        # interior shard.
        _shrink_budgets(monkeypatch)
        log = tmp_path / record.AUDIT_LOG_FILENAME
        with log.open("a") as fh:
            fh.write(json.dumps({
                "action": "orchestrator_review",
                "key": "a.c:giant:1",
                "hypothesis": "x" * 4000,
            }) + "\n")
        _plant_rows(log, 10)
        before = _trail_bytes(tmp_path)
        stats = rotate_audit_log(tmp_path)
        assert stats.rotated
        assert stats.shards_after >= 2
        assert record.AUDIT_LOG_FILENAME in stats.over_budget_shards
        last = record.audit_log_paths(tmp_path)[-1]
        assert last.name not in stats.over_budget_shards
        assert _trail_bytes(tmp_path) == before


class TestMacSurvivesRotation:
    def test_verified_load_after_rotate(
        self, tmp_path: Path, monkeypatch,
    ):
        # Stamped rows land in one file; the rotate re-splits them
        # into shards; every stamp must still verify (run-dir-bound,
        # not filename-bound).
        n = 60
        for i in range(n):
            record.append_audit_log(tmp_path, {
                "action": "orchestrator_review",
                "key": f"a.c:f{i}:1", "status": "clean", "seq": i,
            })
        assert len(record.audit_log_paths(tmp_path)) == 1
        _shrink_budgets(monkeypatch)
        stats = rotate_audit_log(tmp_path)
        assert stats.rotated and stats.shards_after > 1
        verified = record.load_verified_audit_log(tmp_path)
        assert [r["seq"] for r in verified] == list(range(n))


class TestRefuseLive:
    def test_live_run_refused_nothing_modified(
        self, tmp_path: Path, monkeypatch,
    ):
        from core.run.metadata import RUN_METADATA_FILE

        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "audit",
            "status": "running",
            "tool_pid": os.getpid(),
            "timestamp": "2026-09-20T00:00:00+00:00",
        }))
        before = _trail_bytes(tmp_path)
        with pytest.raises(RotateRefused, match="in flight") as excinfo:
            rotate_audit_log(tmp_path)
        # The refusal is re-framed for this remedy — no journal-
        # compaction phrasing in an audit-log rotate error.
        assert "compact" not in str(excinfo.value)
        assert "rotate a live run's audit log" in str(excinfo.value)
        assert _trail_bytes(tmp_path) == before
        assert not (
            tmp_path / (record.AUDIT_LOG_FILENAME + ".pre-rotate")
        ).exists()

    def test_corrupt_run_record_refuses_fail_closed(
        self, tmp_path: Path, monkeypatch,
    ):
        from core.run.metadata import RUN_METADATA_FILE

        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        (tmp_path / RUN_METADATA_FILE).write_text("{corrupt")
        with pytest.raises(RotateRefused):
            rotate_audit_log(tmp_path)

    def test_dead_worker_running_status_rotates(
        self, tmp_path: Path, monkeypatch,
    ):
        # A stale 'running' stamp with a proven-dead pid must not
        # wedge the remedy (same contract as journal compaction).
        from core.run.metadata import RUN_METADATA_FILE

        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "audit",
            "status": "running",
            "tool_pid": 2 ** 22 + 12345,  # beyond default pid_max
            "timestamp": "2026-09-20T00:00:00+00:00",
        }))
        assert rotate_audit_log(tmp_path).rotated

    def test_missing_run_record_permissive(
        self, tmp_path: Path, monkeypatch,
    ):
        # Foreign / legacy dirs carry no run record and must stay
        # rotatable — the permissive direction of the gate.
        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        assert rotate_audit_log(tmp_path).rotated


class TestCliSubcommand:
    def _load_cli(self):
        import importlib.util
        from importlib.machinery import SourceFileLoader

        script = (Path(__file__).resolve().parents[3]
                  / "libexec" / "raptor-audit")
        loader = SourceFileLoader("raptor_audit_cli_rotate", str(script))
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_rotate", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def test_rotate_subcommand_rotates(
        self, tmp_path: Path, monkeypatch, capsys,
    ):
        from types import SimpleNamespace

        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        mod = self._load_cli()
        rc = mod.cmd_audit_log(SimpleNamespace(
            audit_log_command="rotate", out_dir=str(tmp_path)))
        assert rc == 0
        out = capsys.readouterr().out
        assert "shards: 1 ->" in out
        assert ".pre-rotate" in out
        _, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert disclosure.complete

    def test_rotate_subcommand_refuses_live(
        self, tmp_path: Path, monkeypatch, capsys,
    ):
        from types import SimpleNamespace

        from core.run.metadata import RUN_METADATA_FILE

        _shrink_budgets(monkeypatch)
        _plant_rows(tmp_path / record.AUDIT_LOG_FILENAME, 60)
        (tmp_path / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "audit",
            "status": "running",
            "tool_pid": os.getpid(),
            "timestamp": "2026-09-20T00:00:00+00:00",
        }))
        mod = self._load_cli()
        rc = mod.cmd_audit_log(SimpleNamespace(
            audit_log_command="rotate", out_dir=str(tmp_path)))
        assert rc == 1
        assert "in flight" in capsys.readouterr().err

    def test_missing_subcommand_usage(self, tmp_path: Path, capsys):
        from types import SimpleNamespace

        mod = self._load_cli()
        rc = mod.cmd_audit_log(SimpleNamespace(
            audit_log_command=None, out_dir=str(tmp_path)))
        assert rc == 1
        assert "usage" in capsys.readouterr().err


class TestHostileShardSet:
    def test_symlink_shard_refused_nothing_read(
        self, tmp_path: Path, monkeypatch,
    ):
        # A regular-file symlink planted at a contiguous shard name
        # would otherwise be streamed through the rewrite — laundering
        # arbitrary operator-readable file content INTO the trail,
        # bypassing the O_NOFOLLOW discipline the appender and loader
        # both enforce on exactly these paths. Rotation must refuse
        # with nothing modified.
        _shrink_budgets(monkeypatch)
        log = tmp_path / record.AUDIT_LOG_FILENAME
        _plant_rows(log, 60)
        before = log.read_bytes()
        victim_dir = tmp_path / "outside"
        victim_dir.mkdir()
        victim = victim_dir / "secret.txt"
        victim.write_text('{"laundered": "content"}\n')
        (tmp_path / ".audit-log.002.jsonl").symlink_to(victim)

        with pytest.raises(RotateRefused, match="not a regular file"):
            rotate_audit_log(tmp_path)
        # Nothing replaced, no temps, no backups; the link target's
        # content never entered the trail.
        assert log.read_bytes() == before
        assert not list(tmp_path.glob(".audit-log-rotate.tmp.*"))
        assert not list(tmp_path.glob("*.pre-rotate*"))
        assert b"laundered" not in log.read_bytes()

    def test_symlink_swapped_in_after_snapshot_refused(
        self, tmp_path: Path, monkeypatch,
    ):
        # TOCTOU arm: the set passes the lstat check, then a shard is
        # swapped for a symlink before its open. O_NOFOLLOW must fail
        # the open (ELOOP → refusal), never follow the link.
        _shrink_budgets(monkeypatch)
        log = tmp_path / record.AUDIT_LOG_FILENAME
        _plant_rows(log, 60)
        shard2 = tmp_path / ".audit-log.002.jsonl"
        _plant_rows(shard2, 5, start=60)
        victim = tmp_path / "outside-secret.txt"
        victim.write_text('{"laundered": "content"}\n')

        real_lstat = os.lstat
        swapped = {"done": False}

        def _swapping_lstat(path, *a, **kw):
            res = real_lstat(path, *a, **kw)
            if (
                not swapped["done"]
                and Path(path).name == shard2.name
            ):
                swapped["done"] = True
                shard2.unlink()
                shard2.symlink_to(victim)
            return res

        monkeypatch.setattr(os, "lstat", _swapping_lstat)
        with pytest.raises(RotateRefused, match="without following"):
            rotate_audit_log(tmp_path)
        monkeypatch.undo()
        assert not list(tmp_path.glob(".audit-log-rotate.tmp.*"))
        assert not list(tmp_path.glob("*.pre-rotate*"))


class TestConcurrentAppendDetection:
    def test_size_change_mid_rewrite_refuses(
        self, tmp_path: Path, monkeypatch,
    ):
        # A writer appending between the size snapshot and the stream
        # copy changes the byte accounting — the rewrite must refuse
        # and replace nothing (the reconciliation backstop behind the
        # refuse-live gate).
        _shrink_budgets(monkeypatch)
        log = tmp_path / record.AUDIT_LOG_FILENAME
        _plant_rows(log, 60)
        before = _trail_bytes(tmp_path)

        real_lstat = os.lstat

        class _InflatedStat:
            """Passes every field through except st_size (+1) — so
            the regularity check keeps working on the wrapped result."""

            def __init__(self, real):
                self._real = real

            def __getattr__(self, name):
                return getattr(self._real, name)

            @property
            def st_size(self):
                return self._real.st_size + 1

        def _lying_lstat(path, *a, **kw):
            res = real_lstat(path, *a, **kw)
            if Path(path).name == record.AUDIT_LOG_FILENAME:
                # Report one byte more than the stream will deliver.
                return _InflatedStat(res)
            return res

        monkeypatch.setattr(os, "lstat", _lying_lstat)
        with pytest.raises(RotateRefused, match="accounting"):
            rotate_audit_log(tmp_path)
        monkeypatch.undo()
        assert _trail_bytes(tmp_path) == before
        # Temp files were cleaned up.
        assert not list(tmp_path.glob(".audit-log-rotate.tmp.*"))

    def test_append_rolling_to_new_shard_mid_rotate_refused(
        self, tmp_path: Path, monkeypatch,
    ):
        # The clobber shape the byte reconciliation CANNOT catch: the
        # trail's shard 1 is over the roll threshold (that is why
        # rotate is running), so a concurrent append resolves to the
        # NEXT shard name — a file the rotate's snapshot never saw.
        # Reconciliation accounts snapshot files only and passes;
        # without the pre-swap recheck, pass 2's rename onto the same
        # name would destroy the appended row — no backup, no
        # warning. The recheck must refuse with the row surviving.
        _shrink_budgets(monkeypatch)
        log = tmp_path / record.AUDIT_LOG_FILENAME
        _plant_rows(log, 60)
        before = log.read_bytes()

        real_fsync = os.fsync
        fired = {"done": False}

        def _racing_fsync(fd: int) -> None:
            # The first fsync happens mid-rewrite (closing the first
            # temp), safely after the snapshot: the racing appender
            # lands its row now.
            if not fired["done"]:
                fired["done"] = True
                record.append_audit_log(tmp_path, {
                    "action": "orchestrator_review",
                    "key": "a.c:racer:1", "status": "clean",
                    "seq": 999,
                })
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", _racing_fsync)
        with pytest.raises(RotateRefused, match="changed during"):
            rotate_audit_log(tmp_path)
        monkeypatch.undo()
        assert fired["done"]
        # The racer's append resolved past the over-threshold shard 1
        # to shard 2 — and it must still be alive after the refusal.
        racer = tmp_path / ".audit-log.002.jsonl"
        assert racer.is_file()
        rows, _ = record.load_audit_log_disclosed(tmp_path)
        assert any(r.get("seq") == 999 for r in rows)
        # Nothing replaced: original shard byte-identical, no
        # backups, temps cleaned.
        assert log.read_bytes() == before
        assert not list(tmp_path.glob("*.pre-rotate*"))
        assert not list(tmp_path.glob(".audit-log-rotate.tmp.*"))
