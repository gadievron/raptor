"""Prune-warning disclosure is once per cache generation.

``_finalize_set`` warns when the load pruned duplicate re-emission
rows. The warning's inputs are stable across cache extensions — the
finalize re-aggregates the SAME cached per-shard in-stream counts and
the cross-shard dedup re-run re-finds the SAME historical duplicates
— so a live run's consumer loads re-emitted one byte-identical
warning per extension finalize, scaling with load frequency.

Two-direction contract under test: the signal must never be LOST (a
cold parse — fresh process, invalidated record, uncacheable outcome —
always warns its full count; new prunes beyond the disclosed baseline
warn with delta AND cumulative) and must never REPEAT (extensions
that re-derive the already-disclosed count stay silent). The prune
itself is unchanged either way.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from core.coverage import journal as journal_mod
from core.coverage.journal import (
    invalidate_load_cache,
    journal_shard_paths,
    load_entries,
)


@pytest.fixture(autouse=True)
def _clean_cache() -> Iterator[None]:
    """Each test starts and ends with an empty load cache."""
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.clear()
    yield
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.clear()


# ── helpers ──────────────────────────────────────────────────────────

def _ts(i: int) -> str:
    """Strictly monotone microsecond ISO stamp for row *i*."""
    return f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.{i % 1_000_000:06d}Z"


def _line(i: int, *, key: int | None = None, reused: bool = False) -> bytes:
    """One raw journal line; ``key`` reuses row *key*'s identity
    fields so re-emission twins can be built explicitly."""
    ident = key if key is not None else i
    d: dict[str, Any] = {
        "ts": _ts(i),
        "run_id": "run-x",
        "file": f"src/f{ident}.c",
        "function": f"fn{ident}",
        "verdict": "clean",
        "source_hash": f"hash{ident}",
        "schema_version": 1,
    }
    if reused:
        d["reused"] = True
    return json.dumps(d).encode() + b"\n"


def _age_all(out_dir: Path, seconds: int = 60) -> None:
    """Back-date every shard past the racy window so identity-serves
    and extensions are eligible."""
    for shard in journal_shard_paths(out_dir):
        if shard.is_file():
            st = os.stat(shard)
            ns = st.st_mtime_ns - seconds * 1_000_000_000
            os.utime(shard, ns=(ns, ns))


def _dup_journal(tmp_path: Path) -> Path:
    """Two shards carrying one cross-shard re-emission twin pair:
    every finalize's dedup pass prunes exactly one historical row."""
    run = tmp_path / "run"
    run.mkdir()
    (run / "review-journal.jsonl").write_bytes(b"".join([
        _line(0, reused=True), _line(1),
    ]))
    (run / "review-journal.002.jsonl").write_bytes(b"".join([
        _line(2, key=0, reused=True),      # twin of row 0
        _line(3),
    ]))
    _age_all(run)
    return run


def _append_active(run: Path, data: bytes) -> None:
    """Append raw rows to the active (last) shard, then re-age ONLY
    that shard so the next load takes the extension path: past the
    racy window, without disturbing the sealed shards' exact
    (dev, ino, size, mtime_ns) pins."""
    active = journal_shard_paths(run)[-1]
    with open(active, "ab") as fh:
        fh.write(data)
    st = os.stat(active)
    ns = st.st_mtime_ns - 60 * 1_000_000_000
    os.utime(active, ns=(ns, ns))


def _prune_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage() for r in caplog.records
        if "duplicate re-emission row" in r.getMessage()
    ]


@pytest.fixture(autouse=True)
def _capture(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.WARNING, logger=journal_mod.logger.name)
    return caplog


class TestPruneWarnOncePerGeneration:
    def test_cold_parse_with_dups_warns_exactly_once(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        run = _dup_journal(tmp_path)
        load_entries(run)
        warnings = _prune_warnings(caplog)
        assert len(warnings) == 1
        assert "pruned 1 duplicate re-emission row" in warnings[0]

    def test_extensions_with_no_new_prunes_stay_silent(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        run = _dup_journal(tmp_path)
        load_entries(run)
        assert len(_prune_warnings(caplog)) == 1

        # Identity serves (unchanged journal) and N extension
        # finalizes that re-derive the SAME historical prune count:
        # zero additional warnings — this was the live-run noise
        # (one byte-identical line per consumer load).
        load_entries(run)
        for i in range(3):
            _append_active(run, _line(10 + i))
            loaded = load_entries(run)
            assert f"fn{10 + i}" in {e.function for e in loaded}
        assert len(_prune_warnings(caplog)) == 1

    def test_extension_with_new_prunes_warns_the_delta(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        run = _dup_journal(tmp_path)
        load_entries(run)
        assert len(_prune_warnings(caplog)) == 1

        # A NEW re-emission twin arrives: the extension finalize must
        # disclose it — delta AND cumulative, so a growing duplicate
        # problem stays visible — and then go silent again.
        _append_active(run, _line(10, key=0, reused=True))
        load_entries(run)
        warnings = _prune_warnings(caplog)
        assert len(warnings) == 2
        assert "pruned 1 NEW duplicate re-emission row" in warnings[1]
        assert "2 total this load generation" in warnings[1]

        load_entries(run)                  # no new prunes: silent
        _append_active(run, _line(11))     # non-dup append: silent
        load_entries(run)
        assert len(_prune_warnings(caplog)) == 2

    def test_new_generation_warns_the_full_count_again(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The whole-record drop resets to cold-parse semantics: a
        # fresh process (or an invalidated record — the compaction
        # seam) must not lose the signal, since the on-disk duplicate
        # rows persist until an offline compact.
        run = _dup_journal(tmp_path)
        load_entries(run)
        assert len(_prune_warnings(caplog)) == 1

        invalidate_load_cache(run)
        load_entries(run)
        warnings = _prune_warnings(caplog)
        assert len(warnings) == 2
        assert "pruned 1 duplicate re-emission row" in warnings[1]
        assert "NEW" not in warnings[1]
