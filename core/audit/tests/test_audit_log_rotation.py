"""Audit-log shard rotation: writer roll, loader honesty, MAC lane.

The ``.audit-log.jsonl`` trail historically had a whole-log read
budget whose overflow arm silently returned ``[]`` — a production
multi-segment run crossed it and every consumer (resume suppression,
fail-open deferral, telemetry) read an empty trail for the rest of
the run. The writer now rolls to numbered sibling shards below the
per-shard budget and the loader reads the contiguous set, disclosing
anything the budgets kept out. These tests pin:

- the roll threshold in BOTH directions (below → same shard,
  above → next shard) and the shard-count bound in both directions;
- loader honesty on the legacy oversize single-file shape (newest
  tail, never a silent ``[]``) plus the complete-load direction;
- the per-row run-bound MAC across a rotation boundary — rows are
  bound to the run dir, not the file name, so a verified load must
  return rows from EVERY shard while forged rows anywhere stay
  invisible to authority-bearing readers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit import record


def _plant_raw_rows(path: Path, rows: list[dict]) -> None:
    """Write rows WITHOUT the integrity stamp (legacy / forged
    shape)."""
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _row(i: int) -> dict:
    return {"action": "orchestrator_review", "key": f"a.c:f{i}:1",
            "status": "clean", "seq": i}


class TestWriterRoll:
    def test_below_threshold_stays_in_first_shard(
        self, tmp_path: Path, monkeypatch,
    ):
        # Direction 1 of the roll threshold: under it, no roll.
        monkeypatch.setattr(
            record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 1 << 20)
        for i in range(5):
            record.append_audit_log(tmp_path, _row(i))
        assert (tmp_path / record.AUDIT_LOG_FILENAME).exists()
        assert not (tmp_path / ".audit-log.002.jsonl").exists()
        assert record.audit_log_append_path(tmp_path).name == \
            record.AUDIT_LOG_FILENAME

    def test_over_threshold_rolls_to_numbered_sibling(
        self, tmp_path: Path, monkeypatch,
    ):
        # Direction 2: once the active shard crosses the threshold,
        # the next append lands in the next numbered sibling.
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        for i in range(12):
            record.append_audit_log(tmp_path, _row(i))
        shard2 = tmp_path / ".audit-log.002.jsonl"
        assert shard2.exists() and shard2.stat().st_size > 0

    def test_rows_keep_append_order_across_shards(
        self, tmp_path: Path, monkeypatch,
    ):
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        n = 20
        for i in range(n):
            record.append_audit_log(tmp_path, _row(i))
        assert len(record.audit_log_paths(tmp_path)) >= 3
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert [r["seq"] for r in rows] == list(range(n))
        assert disclosure.complete
        assert disclosure.shards == len(record.audit_log_paths(tmp_path))

    def test_shard_bound_absorbs_into_final_shard(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        # Direction 1 of the shard-count bound: at the bound, appends
        # keep landing in the final shard past its threshold (bounded
        # degradation with a named remedy) — never an unbounded fan
        # of files.
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        monkeypatch.setattr(record, "_AUDIT_LOG_MAX_SHARDS", 2)
        with caplog.at_level("WARNING"):
            for i in range(20):
                record.append_audit_log(tmp_path, _row(i))
        paths = record.audit_log_paths(tmp_path)
        assert [p.name for p in paths] == [
            record.AUDIT_LOG_FILENAME, ".audit-log.002.jsonl"]
        assert not (tmp_path / ".audit-log.003.jsonl").exists()
        assert (tmp_path / ".audit-log.002.jsonl").stat().st_size > 256
        assert "shard bound" in caplog.text
        assert "audit-log rotate" in caplog.text
        # Every row still loads (the final shard is under the read
        # budget here — only the roll threshold was exceeded).
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert [r["seq"] for r in rows] == list(range(20))
        assert disclosure.complete

    def test_below_shard_bound_still_rolls(
        self, tmp_path: Path, monkeypatch,
    ):
        # Direction 2 of the shard-count bound: below it, the roll
        # proceeds normally.
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        monkeypatch.setattr(record, "_AUDIT_LOG_MAX_SHARDS", 3)
        for i in range(20):
            record.append_audit_log(tmp_path, _row(i))
        assert (tmp_path / ".audit-log.003.jsonl").exists()

    def test_planted_high_numbered_file_does_not_extend_set(
        self, tmp_path: Path,
    ):
        record.append_audit_log(tmp_path, _row(0))
        _plant_raw_rows(tmp_path / ".audit-log.005.jsonl", [_row(99)])
        paths = record.audit_log_paths(tmp_path)
        assert [p.name for p in paths] == [record.AUDIT_LOG_FILENAME]


class TestLoaderHonesty:
    def test_legacy_oversize_single_file_loads_newest_tail(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        # The defect shape: one file over the read budget. Before the
        # fix the loader silently returned []; now it must return the
        # NEWEST tail (true last row included) and disclose the loss.
        monkeypatch.setattr(record, "_AUDIT_LOG_MAX_BYTES", 2048)
        n = 60  # ~100 bytes/row -> well over 2048
        _plant_raw_rows(
            tmp_path / record.AUDIT_LOG_FILENAME,
            [_row(i) for i in range(n)],
        )
        with caplog.at_level("WARNING"):
            rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert rows, "over-budget trail must never load as []"
        assert rows[-1]["seq"] == n - 1  # true last row survives
        seqs = [r["seq"] for r in rows]
        assert seqs == sorted(seqs)  # newest contiguous tail, in order
        assert seqs[0] > 0  # oldest rows are the ones dropped
        assert not disclosure.complete
        assert record.AUDIT_LOG_FILENAME in disclosure.tail_read_shards
        assert record.AUDIT_LOG_FILENAME in disclosure.reason
        assert "INCOMPLETE" in caplog.text
        assert "audit-log rotate" in caplog.text
        # The tolerant facade returns the same rows.
        assert record.load_audit_log(tmp_path) == rows

    def test_under_budget_file_loads_complete(
        self, tmp_path: Path, monkeypatch,
    ):
        # Two-direction twin: under the budget nothing degrades.
        monkeypatch.setattr(record, "_AUDIT_LOG_MAX_BYTES", 1 << 20)
        _plant_raw_rows(
            tmp_path / record.AUDIT_LOG_FILENAME,
            [_row(i) for i in range(10)],
        )
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert [r["seq"] for r in rows] == list(range(10))
        assert disclosure.complete
        assert disclosure.reason == ""

    def test_orphan_shard_disclosed_not_read(self, tmp_path: Path):
        # Interior shard deleted (or a plant beyond the set): the
        # survivors must not masquerade as the whole trail.
        _plant_raw_rows(
            tmp_path / record.AUDIT_LOG_FILENAME, [_row(0)])
        _plant_raw_rows(
            tmp_path / ".audit-log.003.jsonl", [_row(99)])
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert [r["seq"] for r in rows] == [0]
        assert not disclosure.complete
        assert disclosure.orphan_shards == (".audit-log.003.jsonl",)

    def test_row_cap_keeps_newest_and_discloses(
        self, tmp_path: Path, monkeypatch,
    ):
        monkeypatch.setattr(
            record, "_AUDIT_LOG_MAX_ROWS_PER_SHARD", 5)
        _plant_raw_rows(
            tmp_path / record.AUDIT_LOG_FILENAME,
            [_row(i) for i in range(10)],
        )
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert [r["seq"] for r in rows] == list(range(5, 10))
        assert not disclosure.complete
        assert disclosure.row_capped_shards == (
            record.AUDIT_LOG_FILENAME,)

    def test_row_count_under_cap_loads_complete(
        self, tmp_path: Path, monkeypatch,
    ):
        # Two-direction twin of the row cap.
        monkeypatch.setattr(
            record, "_AUDIT_LOG_MAX_ROWS_PER_SHARD", 50)
        _plant_raw_rows(
            tmp_path / record.AUDIT_LOG_FILENAME,
            [_row(i) for i in range(10)],
        )
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert len(rows) == 10
        assert disclosure.complete

    def test_missing_log_loads_empty_and_complete(self, tmp_path: Path):
        rows, disclosure = record.load_audit_log_disclosed(tmp_path)
        assert rows == []
        assert disclosure.complete
        assert disclosure.total_bytes == 0


class TestMacAcrossRotation:
    def test_verified_load_across_rotation_boundary(
        self, tmp_path: Path, monkeypatch,
    ):
        # THE rotation-safety proof: the integrity stamp is per-row
        # and run-bound (not filename-bound), so a verified load must
        # return every stamped row whichever shard it landed in.
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        n = 20
        for i in range(n):
            record.append_audit_log(tmp_path, _row(i))
        assert len(record.audit_log_paths(tmp_path)) >= 3
        verified = record.load_verified_audit_log(tmp_path)
        assert [r["seq"] for r in verified] == list(range(n))

    def test_forged_row_in_second_shard_dropped(
        self, tmp_path: Path, monkeypatch,
    ):
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        for i in range(12):
            record.append_audit_log(tmp_path, _row(i))
        shard2 = tmp_path / ".audit-log.002.jsonl"
        assert shard2.exists()
        _plant_raw_rows(shard2, [{"action": "record",
                                  "key": "a.c:evil:1",
                                  "status": "clean", "seq": 999}])
        verified = record.load_verified_audit_log(tmp_path)
        assert all(r["seq"] != 999 for r in verified)
        # ...while the telemetry tier still sees it.
        assert any(
            r.get("seq") == 999 for r in record.load_audit_log(tmp_path))

    def test_cross_run_shard_copy_does_not_verify(
        self, tmp_path: Path, monkeypatch,
    ):
        # Run binding survives sharding: a sibling run's SHARD file
        # copied wholesale never verifies here.
        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        other = tmp_path / "other"
        other.mkdir()
        for i in range(12):
            record.append_audit_log(other, _row(i))
        here = tmp_path / "here"
        here.mkdir()
        record.append_audit_log(here, _row(0))
        (here / ".audit-log.002.jsonl").write_bytes(
            (other / ".audit-log.002.jsonl").read_bytes())
        verified = record.load_verified_audit_log(here)
        assert [r["seq"] for r in verified] == [0]


class TestCollectorFlushRolls:
    def test_flush_crossing_threshold_creates_shards(
        self, tmp_path: Path, monkeypatch,
    ):
        # The collector drains per row through append_audit_log, so a
        # single large flush must respect the roll threshold too (a
        # batch write to one pre-resolved path would overshoot).
        from core.audit.collector import Collector

        monkeypatch.setattr(record, "_AUDIT_LOG_SHARD_ROLL_BYTES", 256)
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        collector = Collector(out_dir=out, target_path=target)
        n = 20
        collector._log_entries.extend(_row(i) for i in range(n))
        collector._flush_audit_log()
        assert collector._log_entries == []
        assert len(record.audit_log_paths(out)) >= 3
        rows, disclosure = record.load_audit_log_disclosed(out)
        assert [r["seq"] for r in rows] == list(range(n))
        assert disclosure.complete
        # Collector writes through the stamping appender — the rows
        # carry authority after a rotation-crossing flush.
        assert len(record.load_verified_audit_log(out)) == n

    def test_flush_failure_retains_unwritten_entries(
        self, tmp_path: Path, monkeypatch,
    ):
        from core.audit.collector import Collector

        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        collector = Collector(out_dir=out, target_path=target)
        collector._log_entries.extend(_row(i) for i in range(4))

        calls = {"n": 0}
        real_append = record.append_audit_log

        def _flaky(out_dir: Path, entry: dict) -> None:
            if calls["n"] >= 2:
                raise OSError("disk full")
            calls["n"] += 1
            real_append(out_dir, entry)

        # _flush_audit_log imports append_audit_log at call time, so
        # patching the record module intercepts the drain.
        monkeypatch.setattr(
            "core.audit.record.append_audit_log", _flaky)
        with pytest.raises(OSError):
            collector._flush_audit_log()
        # The two written rows are dropped from the buffer; the
        # unwritten ones are retained for the next flush.
        assert [e["seq"] for e in collector._log_entries] == [2, 3]
