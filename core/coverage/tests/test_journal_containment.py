"""Containment-boundary tests for the journal/index read paths.

The journal and index live inside sandbox-writable run/project dirs,
so every byte of them is attacker-writable. The invariant under test:
ANY failure in per-row read/parse/validate quarantines that row (or,
for whole-file parses, degrades the read / refuses the write) — it
never propagates an exception into a journal consumer.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import core.json.utils as json_utils
from core.coverage.journal import (
    INDEX_FILENAME,
    JOURNAL_FILENAME,
    IndexUnreadable,
    _load_index,
    latest_entries,
    load_entries,
    load_index,
    load_index_full,
    merge_into_index,
    merge_run_into_index,
    now_iso,
    rehome_legacy_keys,
    reviewed_set,
)


def _valid_line(i: int = 0, verdict: str = "clean") -> bytes:
    return json.dumps({
        "ts": now_iso(),
        "run_id": f"run-{i}",
        "file": f"src/f{i}.c",
        "function": f"fn{i}",
        "verdict": verdict,
        "source_hash": "abc123",
        "schema_version": 1,
    }).encode() + b"\n"


def _both_backends():
    backends = [("stdlib", None)]
    if json_utils._orjson is not None:
        backends.append(("orjson", json_utils._orjson))
    return backends


class TestReaderPreParseContainment:
    """Pre-parse shapes (decode failure, nesting bomb) quarantine
    per row on BOTH JSON backends."""

    def test_invalid_utf8_row_quarantined_valid_rows_load(
        self, tmp_path: Path,
    ):
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(_valid_line(0) + b"\x80\n" + _valid_line(1))
        for name, override in _both_backends():
            saved = json_utils._orjson
            try:
                json_utils._orjson = override
                entries = load_entries(tmp_path)
                assert [e.function for e in entries] == ["fn0", "fn1"], name
            finally:
                json_utils._orjson = saved

    def test_nesting_bomb_row_quarantined_both_backends(
        self, tmp_path: Path,
    ):
        # Deep enough to exhaust the stdlib parser's recursion on any
        # supported Python; orjson refuses depth with ValueError.
        bomb = b"[" * 200_000 + b"]" * 200_000
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(_valid_line(0) + bomb + b"\n" + _valid_line(1))
        for name, override in _both_backends():
            saved = json_utils._orjson
            try:
                json_utils._orjson = override
                entries = load_entries(tmp_path)
                assert [e.function for e in entries] == ["fn0", "fn1"], name
            finally:
                json_utils._orjson = saved

    def test_consumers_survive_hostile_rows(self, tmp_path: Path):
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(
            _valid_line(0)
            + b"\x80\xfe\xff\n"
            + b"[" * 100_000 + b"]" * 100_000 + b"\n"
            + b'"just a string"\n'
            + _valid_line(1, verdict="error"),
        )
        assert reviewed_set(tmp_path) == {"src/f0.c:fn0"}
        assert set(latest_entries(tmp_path)) == {
            "src/f0.c:fn0", "src/f1.c:fn1",
        }

    def test_unreadable_journal_degrades_to_empty(self, tmp_path: Path):
        if os.geteuid() == 0:
            pytest.skip("permission bits do not bind root")
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(_valid_line(0))
        journal.chmod(0)
        try:
            assert load_entries(tmp_path) == []
        finally:
            journal.chmod(0o644)

    def _assert_degenerate_journal_memory_bounded(
        self, tmp_path: Path, size: int,
    ) -> None:
        """The byte cap must bound the reader's own MEMORY, not just
        the file: a journal of 2-byte rows amplified ~20x in peak RSS
        when the reader materialised every line eagerly (an at-cap
        file OOM-killed every journal consumer). Streamed reading
        keeps one line alive at a time."""
        if sys.platform != "linux":
            pytest.skip("/proc/self/status VmHWM is Linux-specific")
        journal = tmp_path / JOURNAL_FILENAME
        # b"00\n" rows: unparseable JSON -> the corrupt-row quarantine
        # arm, which must allocate nothing per row beyond the line
        # itself (measured ~20x amplification on the eager split).
        journal.write_bytes(b"00\n" * (size // 3))
        # Peak measurement is VmHWM from the child's own
        # /proc/self/status, NOT getrusage ru_maxrss: ru_maxrss is
        # inherited across fork and never reset by execve, so under a
        # large test-runner parent the child starts with the parent's
        # watermark already exceeding its own real peak — the delta
        # reads 0 whatever the reader allocates, and the bound can
        # never trip. VmHWM resets on exec and tracks only this
        # child's own high-water mark.
        code = (
            "import logging, sys\n"
            "from pathlib import Path\n"
            "logging.disable(logging.CRITICAL)\n"
            "from core.coverage.journal import load_entries\n"
            "def hwm():\n"
            "    with open('/proc/self/status') as f:\n"
            "        for line in f:\n"
            "            if line.startswith('VmHWM:'):\n"
            "                return int(line.split()[1]) * 1024\n"
            "    raise RuntimeError('no VmHWM in /proc/self/status')\n"
            "hwm0 = hwm()\n"
            "entries = load_entries(Path(sys.argv[1]))\n"
            "hwm1 = hwm()\n"
            "print(hwm1 - hwm0)\n"
            "print(len(entries))\n"
        )
        repo_root = Path(__file__).resolve().parents[3]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo_root)
        proc = subprocess.run(
            [sys.executable, "-c", code, str(tmp_path)],
            capture_output=True, text=True, env=env, check=True,
            timeout=120,
        )
        hwm_delta, n_entries = (int(x) for x in proc.stdout.split())
        assert n_entries == 0
        # Bound: a small multiple of the input covers OS page noise and
        # buffered-IO overhead; the eager-split reader measured ~20x —
        # at EITHER size, an eager-split regression (~20x the input)
        # lands far past the 6x bound, so both tiers assert the same
        # memory-bound mechanics on the same code path.
        assert hwm_delta < 6 * size, (
            f"load_entries peak-RSS delta {hwm_delta} bytes for a "
            f"{size}-byte degenerate journal — reader memory is not "
            f"bounded by the byte cap"
        )

    def test_degenerate_journal_memory_bounded_scaled(
        self, tmp_path: Path,
    ):
        """Default tier: a 1 MiB degenerate journal walks the same
        streamed read + per-row quarantine path and asserts the same
        6x peak-RSS bound as the full-size run below, at ~1/8 the
        row count."""
        self._assert_degenerate_journal_memory_bounded(
            tmp_path, 1024 * 1024)

    # Full-size run: genuinely heavy (a ~2.7M-row subprocess load that
    # breached the default tier's per-test budget on contended CI
    # runners), so it runs in the nightly tier. Trade-off, both
    # directions: unmarking it puts a multi-second, contention-sensitive
    # test back in every PR run; marking it WITHOUT the scaled run above
    # would leave the memory bound unasserted until the next nightly.
    # The scaled run exercises the identical code path and bound daily;
    # only size-proportional effects (allocator behaviour near the byte
    # cap) wait for nightly.
    @pytest.mark.slow
    def test_degenerate_journal_memory_bounded(self, tmp_path: Path):
        """Nightly tier: the original full-size (8 MiB) degenerate
        journal, at the scale where the eager-split OOM was observed."""
        self._assert_degenerate_journal_memory_bounded(
            tmp_path, 8 * 1024 * 1024)

    def test_row_quarantine_warnings_rate_limited(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        """Per-row quarantine warnings downgrade to debug past the
        limit — a hostile journal must not flood one warning per
        refused row — while the trailing summary keeps the totals."""
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b'"not a dict"\n' * 500 + _valid_line(0))
        with caplog.at_level("WARNING", logger="core.coverage.journal"):
            entries = load_entries(tmp_path)
        assert [e.function for e in entries] == ["fn0"]
        warnings = [
            r for r in caplog.records if r.levelname == "WARNING"
        ]
        assert len(warnings) <= 25, len(warnings)

    def test_index_nesting_bomb_readers_degrade_writers_refuse(
        self, tmp_path: Path,
    ):
        """A nesting-bomb index file: readers degrade to empty, the
        merge writer refuses and leaves the file byte-identical."""
        project = tmp_path / "project"
        run = tmp_path / "run"
        project.mkdir()
        run.mkdir()
        bomb = '{"schema_version": 1, "entries": {"k": ' \
            + "[" * 200_000 + "]" * 200_000 + "}}"
        index = project / INDEX_FILENAME
        index.write_text(bomb)
        (run / JOURNAL_FILENAME).write_bytes(_valid_line(0))
        for name, override in _both_backends():
            saved = json_utils._orjson
            try:
                json_utils._orjson = override
                assert load_index(project) == {}, name
                assert load_index_full(project) == {}, name
                assert merge_run_into_index(project, run) == 0, name
                assert index.read_text() == bomb, name
                with pytest.raises(IndexUnreadable):
                    _load_index(index, for_write=True)
            finally:
                json_utils._orjson = saved

    def test_hostile_index_row_quarantined_and_never_dropped(
        self, tmp_path: Path,
    ):
        """A planted row that fails entry validation is skipped by
        readers, left in place by the re-home walk, and survives a
        merge byte-for-byte (never-drop)."""
        project = tmp_path / "project"
        run = tmp_path / "run"
        project.mkdir()
        run.mkdir()
        good = json.loads(_valid_line(7))
        hostile = {"ts": 5, "file": ["x"], "verdict": None}
        index = project / INDEX_FILENAME
        index.write_text(json.dumps({
            "schema_version": 1,
            "entries": {"good:key": good, "hostile:key": hostile},
        }))
        loaded = load_index_full(project)
        assert list(loaded) == ["good:key"]

        (run / JOURNAL_FILENAME).write_bytes(_valid_line(8))
        assert merge_run_into_index(project, run) == 1
        persisted = json.loads(index.read_text())["entries"]
        assert persisted["hostile:key"] == hostile

    def test_merge_never_writes_an_over_budget_index(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """A merge must never WRITE an index larger than the read
        budget: the per-run entry cap bounds row count, not bytes
        (indent-2 re-serialization inflates list-heavy rows), so an
        under-cap run journal could push the index past the cap in
        one merge — after which every reader degraded to empty and
        every writer (compaction included) refused: a permanently
        frozen index. The write gate refuses the MERGE instead; the
        index stays readable/writable and the run journal keeps its
        rows."""
        import core.coverage.journal as journal_mod
        # Scaled cap: 8 KiB budget stands in for the 256 MiB default.
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 8 * 1024)
        project = tmp_path / "project"
        run = tmp_path / "run"
        run2 = tmp_path / "run2"
        project.mkdir()
        run.mkdir()
        run2.mkdir()
        # Pre-seed accumulated history that a frozen index would lose.
        (run2 / JOURNAL_FILENAME).write_bytes(_valid_line(0))
        assert merge_run_into_index(project, run2) == 1
        index = project / INDEX_FILENAME
        before = index.read_bytes()
        # An UNDER-cap run journal whose merged index would serialize
        # over the cap.
        rows = b"".join(
            json.dumps({
                "ts": now_iso(), "run_id": "r", "file": f"g{i}.c",
                "function": f"gfn{i}", "verdict": "clean",
                "source_hash": "", "schema_version": 1,
                "body": "x" * 900,
            }).encode() + b"\n"
            for i in range(6)
        )
        assert len(rows) < 8 * 1024
        (run / JOURNAL_FILENAME).write_bytes(rows)
        assert merge_into_index(project, run) == 0
        # Index untouched; readers see the history; writers still work.
        assert index.read_bytes() == before
        assert set(load_index(project)) == {"src/f0.c:fn0"}
        (run2 / JOURNAL_FILENAME).write_bytes(_valid_line(1))
        assert merge_run_into_index(project, run2) == 1
        assert set(load_index(project)) == {"src/f0.c:fn0", "src/f1.c:fn1"}

    def test_rehome_quarantines_rows_outside_the_legacy_tuple(self):
        """Rows whose validation raises classes the old enumerated
        tuple missed must also stay in place, not crash the walk."""
        deep: list = []
        cur = deep
        for _ in range(100_000):
            nxt: list = []
            cur.append(nxt)
            cur = nxt
        good = json.loads(_valid_line(3))
        index = {
            "legacy:key": good,
            "deep:key": {**json.loads(_valid_line(4)), "hypotheses": deep},
            "nondict:key": "scalar",
        }
        moved = rehome_legacy_keys(index)
        assert moved == 1
        assert "deep:key" in index and "nondict:key" in index
        assert good in index.values()

    def test_deep_field_inside_valid_json_row_quarantined(
        self, tmp_path: Path,
    ):
        """A row that PARSES (depth under the parser's limit) but whose
        serializer round-trip validation recurses past the limit must
        quarantine, not crash — the validate leg of the boundary."""
        depth = 100_000
        row = (
            b'{"ts": "t", "run_id": "r", "file": "a.c", "function": "f",'
            b' "verdict": "clean", "source_hash": "", "schema_version": 1,'
            b' "hypotheses": ' + b"[" * depth + b"]" * depth + b"}"
        )
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(_valid_line(0) + row + b"\n")
        for name, override in _both_backends():
            saved = json_utils._orjson
            try:
                json_utils._orjson = override
                entries = load_entries(tmp_path)
                assert [e.function for e in entries] == ["fn0"], name
            finally:
                json_utils._orjson = saved
