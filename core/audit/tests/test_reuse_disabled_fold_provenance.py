"""The reuse-DISABLED per-run fold verifies row provenance.

The review journal is target-writable during runs, and the
reuse-disabled fold (cold-profile ``--no-verdict-reuse`` + interrupt
+ resume, and every mid-run recompute) used to plain-credit every
function-grade row — no MAC tier, no source-hash gate. One planted
unstamped ``clean`` row retired the named function from the review
queue: exactly the forged-clean-row lever the journal MAC doctrine
exists to stop, reachable because this one fold missed the house
pattern the reuse-enabled and project-index folds already apply.

These tests invert that PoC at the SEAM (``compute_gaps`` with
verdict reuse off), not just at the ``_verify_entries_fold`` helper:
reverting the fold body to a plain ``covered.update()`` fails them.
The stamped/planted pair uses IDENTICAL row fields so the only
discriminating input is the MAC stamp itself. Zero LLM calls.
"""

from __future__ import annotations

import json

import pytest

from core.audit.gaps import compute_gaps
from core.audit.strategy import strategies_from_item
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    now_iso,
)
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_ITEM = {
    "name": "check_pw",
    "kind": "function",
    "line_start": 1,
    "line_end": 5,
}


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _write_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [dict(_ITEM)],
        }],
    }


def _row_fields(**over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "auth.c",
        "function": "check_pw",
        "verdict": "clean",
        "source_hash": "",
        "line_start": 1,
        "line_end": 5,
        "model": "model-a",
        "body": "review body",
    }
    fields.update(over)
    return fields


def _plant_raw_row(run_dir, **over):
    """The attack: append a journal row DIRECTLY — no MAC stamp."""
    run_dir.mkdir(exist_ok=True)
    with (run_dir / JOURNAL_FILENAME).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_row_fields(**over)) + "\n")


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestPlantedRows:
    def test_planted_unstamped_clean_row_resurfaces(self, tmp_path):
        """The original PoC: a hand-written hashless clean row must
        NOT retire the function from the review queue."""
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        _plant_raw_row(run_dir)
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_planted_row_with_forged_hash_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        _plant_raw_row(run_dir, source_hash="f" * 12)
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_stamp_is_the_only_discriminator(self, tmp_path):
        """IDENTICAL row fields: the honest writer's row (MAC-stamped
        by append_entry, hashless — historical suppression for a
        verified row) suppresses; the planted copy does not."""
        target = _write_target(tmp_path)
        fields = _row_fields()

        stamped_dir = tmp_path / "run-stamped"
        append_entry(stamped_dir, ReviewJournalEntry(**fields))
        gaps = compute_gaps(_checklist(target), [], out_dir=stamped_dir)
        assert "auth.c:check_pw" not in _gap_keys(gaps)

        planted_dir = tmp_path / "run-planted"
        _plant_raw_row(planted_dir, **fields)
        gaps = compute_gaps(_checklist(target), [], out_dir=planted_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestLegacyTolerance:
    def test_unstamped_exact_hash_row_keeps_credit(self, tmp_path):
        """Pre-MAC journals carry unstamped rows: with an EXACT
        full-length source-hash match the historical suppression
        stands (the doctrine's unstamped tier), so hardening this
        fold does not re-buy every legacy review."""
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        real = hash_span(target / "auth.c", 1, 5)
        _plant_raw_row(run_dir, source_hash=real)
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_unstamped_exact_hash_stale_source_resurfaces(self, tmp_path):
        """...and the same row resurfaces once the source drifts —
        hash-gated credit is bound to the reviewed bytes."""
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        real = hash_span(target / "auth.c", 1, 5)
        _plant_raw_row(run_dir, source_hash=real)
        (target / "auth.c").write_text(
            _SOURCE.replace("strcmp", "memcmp"), encoding="utf-8")
        gaps = compute_gaps(_checklist(target), [], out_dir=run_dir)
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestCollapseScreens:
    def test_echo_after_review_keeps_suppression_own_run_reuse(
            self, tmp_path):
        """Own-run reuse fold: a LATER mechanical echo at the reviewed
        site must not shadow the genuine review out of the per-site
        collapse (the pre-helper collapse kept latest-by-ts across ALL
        rows, so the screened echo masked the credit)."""
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        real = hash_span(target / "auth.c", 1, 5)
        strategies = sorted(strategies_from_item(dict(_ITEM), "auth.c"))
        append_entry(run_dir, ReviewJournalEntry(**_row_fields(
            ts="2026-09-26T10:00:00Z", source_hash=real,
            strategies=strategies)))
        append_entry(run_dir, ReviewJournalEntry(**_row_fields(
            ts="2026-09-26T10:00:01Z", source_hash=real,
            verdict="suspicious", model=None,
            strategies=["post-loop-mechanical"],
            body="[mechanical] pattern match in check_pw")))
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink={}, own_run_reuse=True, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
