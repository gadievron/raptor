"""Compaction keeps the resume spend floor for exact JSON integers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.resume import journal_spend_usd
from core.coverage import journal_compact as compact
from core.coverage.journal import JOURNAL_FILENAME, ReviewJournalEntry, load_entries
from core.json import utils as json_utils
from core.run.resume import _MAX_SPEND_EVIDENCE_USD


def _write_rows(out: Path, cost: int | float) -> Path:
    rows = []
    for ts, amount in (("2026-01-01T00:00:00Z", cost),
                       ("2026-01-02T00:00:00Z", 0.0)):
        rows.append(ReviewJournalEntry(
            ts=ts, run_id="numeric-cost", file="sample.c", function="sample",
            verdict="clean", source_hash="same", strategies=["bounds"],
            cost_usd=amount,
        ).to_dict())
    path = out / JOURNAL_FILENAME
    path.write_text("".join(json.dumps(row, allow_nan=False) + "\n" for row in rows))
    return path


@pytest.mark.parametrize(("cost", "expected"), [
    (10**400, _MAX_SPEND_EVIDENCE_USD),
    (-(10**400), 0.0),
    (1e308, _MAX_SPEND_EVIDENCE_USD),
    (2.5, 2.5),
], ids=["oversized-positive", "oversized-negative", "large-finite", "ordinary-finite"])
def test_compaction_matches_resume_floor(tmp_path, monkeypatch, cost, expected):
    # Exercise the supported exact-integer decoder, not an optional backend's
    # distinct numeric range. Both consumers reach this same loader namespace.
    monkeypatch.setattr(json_utils, "_orjson", None)
    path = _write_rows(tmp_path, cost)
    entries = load_entries(tmp_path, fresh=True)
    assert len(entries) == 2 and entries[0].cost_usd == cost
    assert journal_spend_usd(tmp_path) == expected
    assert compact._file_spend(path) == expected

    stats = compact.compact_journal(tmp_path, supersede=True)

    assert stats.spend_usd_before == expected
    assert stats.spend_usd_after == expected
    assert journal_spend_usd(tmp_path) == expected
    assert stats.dropped_superseded == 1


def test_lost_oversized_cost_refuses_swap(tmp_path, monkeypatch):
    monkeypatch.setattr(json_utils, "_orjson", None)
    path = _write_rows(tmp_path, 10**400)
    before = path.read_bytes()
    original = compact._spend_carrier_line

    def lose_cost(*args, **kwargs):
        line = original(*args, **kwargs)
        assert line is not None
        row = json.loads(line)
        row["cost_usd"] = 0.0
        return (json.dumps(row) + "\n").encode()

    monkeypatch.setattr(compact, "_spend_carrier_line", lose_cost)
    with pytest.raises(compact.CompactRefused, match="spend floor"):
        compact.compact_journal(tmp_path, supersede=True)
    assert path.read_bytes() == before
