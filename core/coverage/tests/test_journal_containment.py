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
    JOURNAL_FILENAME,
    latest_entries,
    load_entries,
    now_iso,
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

    def test_degenerate_journal_memory_bounded(self, tmp_path: Path):
        """The byte cap must bound the reader's own MEMORY, not just
        the file: a journal of 2-byte rows amplified ~20x in peak RSS
        when the reader materialised every line eagerly (an at-cap
        file OOM-killed every journal consumer). Streamed reading
        keeps one line alive at a time."""
        if sys.platform != "linux":
            pytest.skip("ru_maxrss units are platform-specific")
        size = 8 * 1024 * 1024
        journal = tmp_path / JOURNAL_FILENAME
        # b"00\n" rows: unparseable JSON -> the corrupt-row quarantine
        # arm, which must allocate nothing per row beyond the line
        # itself (measured ~20x amplification on the eager split).
        journal.write_bytes(b"00\n" * (size // 3))
        code = (
            "import logging, resource, sys\n"
            "from pathlib import Path\n"
            "logging.disable(logging.CRITICAL)\n"
            "from core.coverage.journal import load_entries\n"
            "rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss\n"
            "entries = load_entries(Path(sys.argv[1]))\n"
            "rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss\n"
            "print((rss1 - rss0) * 1024)\n"
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
        rss_delta, n_entries = (int(x) for x in proc.stdout.split())
        assert n_entries == 0
        # Bound: a small multiple of the input covers OS page noise and
        # buffered-IO overhead; the eager-split reader measured ~20x.
        assert rss_delta < 6 * size, (
            f"load_entries peak-RSS delta {rss_delta} bytes for a "
            f"{size}-byte degenerate journal — reader memory is not "
            f"bounded by the byte cap"
        )

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
