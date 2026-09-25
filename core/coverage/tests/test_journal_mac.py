"""Tests for core/coverage/journal_mac.py — key-loader read discipline.

The mint/verify/tier semantics are exercised end-to-end by the journal
and fold suites; these tests pin the key *loader* mechanics that those
paths depend on.
"""

from __future__ import annotations

import itertools
import os
from pathlib import Path

import pytest

from core.coverage import journal_mac
from core.security import mac_key


# ---------------------------------------------------------------------------
# Key loader: short-read tolerance
# ---------------------------------------------------------------------------


def test_chunked_key_read_loads_full_key(tmp_path: Path, monkeypatch) -> None:
    """os.read may legally return fewer bytes than requested; chunked
    delivery must not land a healthy key in the wrong-length refusal
    (which would demote every stamped journal row to the unstamped
    tier)."""
    key_file = tmp_path / "journal-mac.key"
    data = os.urandom(32)
    key_file.write_bytes(data)
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    assert journal_mac._read_existing_key(key_file) == data


def test_truncated_key_file_reads_exact_length(
    tmp_path: Path, monkeypatch,
) -> None:
    # Two-direction guard: the loop reads to EOF, never pads — a torn
    # 10-byte key still fails the caller's length check (fail-closed).
    key_file = tmp_path / "journal-mac.key"
    key_file.write_bytes(os.urandom(10))
    key_file.chmod(0o600)
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
    got = journal_mac._read_existing_key(key_file)
    assert isinstance(got, bytes)
    assert len(got) == 10


# ---------------------------------------------------------------------------
# Key-creation race: the loser must tolerate the winner's write gap
# ---------------------------------------------------------------------------


@pytest.fixture()
def _race_warn_calls(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        journal_mac, "_warn_once_suspect_key",
        lambda *args: calls.append(args),
    )
    return calls


@pytest.fixture()
def _lose_creation_race(monkeypatch, tmp_path):
    """Make the key-create os.open lose the O_EXCL race."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    real_open = os.open

    def fake_open(path, flags, mode=0o777):
        if flags & os.O_EXCL:
            raise FileExistsError(path)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(mac_key.time, "sleep", lambda s: None)


def test_race_loser_retries_through_empty_read(
        monkeypatch, _race_warn_calls, _lose_creation_race) -> None:
    """Between the winner's O_EXCL create and its write the key file
    exists with 0 bytes. The loser must keep polling through that
    transient shape and stamp with the winner's full key — aborting on
    the first short read left the loser's rows unstamped (no verdict
    reuse) and flagged the operator's healthy key as suspect."""
    full_key = b"k" * 32
    reads = iter([None, b"", full_key])
    monkeypatch.setattr(
        journal_mac, "_read_existing_key", lambda path: next(reads),
    )

    assert journal_mac._load_or_create_key() == full_key
    assert _race_warn_calls == []


def test_persistent_wrong_length_warns_after_retries(
        monkeypatch, _race_warn_calls, _lose_creation_race) -> None:
    """A key file that STAYS short is genuinely suspect: the loop runs
    out of retries, warns once, and refuses (None)."""
    reads = itertools.chain([None], itertools.repeat(b"short"))
    monkeypatch.setattr(
        journal_mac, "_read_existing_key", lambda path: next(reads),
    )

    assert journal_mac._load_or_create_key() is None
    assert len(_race_warn_calls) == 1
    assert "wrong length" in _race_warn_calls[0][1]


class TestAdditiveFieldForwardCompat:
    """The measured basis for persisting new facts in EXISTING row
    fields (the mark-context body) instead of additive schema fields:
    this reader's dataclass round-trip drops unknown fields before the
    MAC recompute, so an additive field covered by a newer writer's
    token demotes the whole row here."""

    def _stamped_row(self, tmp_path, monkeypatch):
        import json

        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        run = tmp_path / "run1"
        run.mkdir()
        append_entry(run, ReviewJournalEntry(
            ts=now_iso(), run_id="run1", file="a.c", function="f",
            verdict="clean", source_hash="", line_start=1, line_end=2,
        ))
        return run, json.loads((run / "review-journal.jsonl").read_text())

    def test_covered_additive_field_demotes_to_tampered(
            self, tmp_path, monkeypatch):
        import json

        from core.coverage.journal import load_entries
        run, row = self._stamped_row(tmp_path, monkeypatch)
        row.pop(journal_mac.TOKEN_KEY, None)
        row["future_field"] = {"sid": "inherited"}
        row[journal_mac.TOKEN_KEY] = journal_mac.mint_row(row)
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run)[0]
        assert "future_field" not in entry.to_dict()
        assert journal_mac.entry_provenance(entry) == journal_mac.ROW_TAMPERED

    def test_uncovered_additive_field_is_ignored_and_unauthenticated(
            self, tmp_path, monkeypatch):
        # The complementary fact: an unknown field OUTSIDE the token's
        # coverage does not break verification — the reader ignores
        # unknown JSON keys — which is exactly why authority-bearing
        # facts must ride a COVERED field, never a loose key.
        import json

        from core.coverage.journal import load_entries
        run, row = self._stamped_row(tmp_path, monkeypatch)
        row["future_field"] = "attacker-appended, not MAC-covered"
        (run / "review-journal.jsonl").write_text(json.dumps(row) + "\n")
        entry = load_entries(run)[0]
        assert journal_mac.entry_provenance(entry) == journal_mac.ROW_VERIFIED
        assert "future_field" not in entry.to_dict()

    def test_covered_body_field_round_trips_verified(
            self, tmp_path, monkeypatch):
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            load_entries,
            now_iso,
        )
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        run = tmp_path / "run2"
        run.mkdir()
        note = "[mark-context] tty=stdin sid=inherited envm=none"
        append_entry(run, ReviewJournalEntry(
            ts=now_iso(), run_id="run2", file="a.c", function="f",
            verdict="clean", source_hash="", body=note,
        ))
        entry = load_entries(run)[0]
        assert entry.body == note
        assert journal_mac.entry_provenance(entry) == journal_mac.ROW_VERIFIED
