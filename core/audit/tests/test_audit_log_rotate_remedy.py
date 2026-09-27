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
        assert stats.final_shard_over_budget
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
        with pytest.raises(RotateRefused, match="in flight"):
            rotate_audit_log(tmp_path)
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

        real_stat = Path.stat

        class _InflatedStat:
            """Passes every field through except st_size (+1) — so
            is_file()/exists() keep working on the patched Path."""

            def __init__(self, real):
                self._real = real

            def __getattr__(self, name):
                return getattr(self._real, name)

            @property
            def st_size(self):
                return self._real.st_size + 1

        def _lying_stat(self, **kw):
            res = real_stat(self, **kw)
            if self.name == record.AUDIT_LOG_FILENAME:
                # Report one byte more than the stream will deliver.
                return _InflatedStat(res)
            return res

        monkeypatch.setattr(Path, "stat", _lying_stat)
        with pytest.raises(RotateRefused, match="accounting"):
            rotate_audit_log(tmp_path)
        monkeypatch.undo()
        assert _trail_bytes(tmp_path) == before
        # Temp files were cleaned up.
        assert not list(tmp_path.glob(".audit-log-rotate.tmp.*"))
