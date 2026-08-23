"""Provenance + hash gates on the review-journal gap fold.

Review journals are target-writable during runs and restorable by
imports, and the fold used to credit rows with an EMPTY source_hash
without any verification, compare hashes on a bidirectional PREFIX
(a stored 1-char "hash" matched ~1/16 of real hashes), and import
prior verdicts with no row authentication. A forged ``clean`` row
suppressed future review of a function and dropped findings from
reports. These tests invert the original proof-of-concept.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.gaps import _verify_entries_fold
from core.coverage import journal_mac
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    now_iso,
)


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


SOURCE = "int f(void) { return system(cmd); }\n"


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    t = tmp_path / "target"
    t.mkdir()
    (t / "a.c").write_text(SOURCE)
    return t


def _real_hash(target: Path) -> str:
    from core.staleness import hash_spans
    return hash_spans(target / "a.c", [(1, 1)])[0]


def _entry(**kw) -> ReviewJournalEntry:
    base = dict(ts=now_iso(), run_id="run-x", file="a.c", function="f",
                verdict="clean", source_hash="", line_start=1, line_end=1)
    base.update(kw)
    return ReviewJournalEntry(**base)


def _fold(entries, target, reuse_sink=None):
    covered: set = set()
    _verify_entries_fold(
        covered, entries, target_path=target,
        current_spans={"a.c:f": (1, 1)}, reuse_sink=reuse_sink,
        current_strategies_fn=lambda *_: set(), current_model=None,
        source_label="test")
    return covered


# ---------------------------------------------------------------------------
# Forged rows (inverted PoC)
# ---------------------------------------------------------------------------


def test_empty_hash_unstamped_row_does_not_credit(target: Path) -> None:
    assert _fold([_entry(source_hash="")], target) == set()


def test_one_char_prefix_hash_does_not_credit(target: Path) -> None:
    """Every nibble: the old bidirectional prefix compare let one of
    these match; exact compare refuses all sixteen."""
    covered: set = set()
    for c in "0123456789abcdef":
        covered |= _fold([_entry(source_hash=c)], target)
    assert covered == set()


def test_correct_hash_prefix_shorter_than_full_does_not_credit(
    target: Path,
) -> None:
    """Even a CORRECT 6-char prefix of the real hash is not full-length
    evidence."""
    real = _real_hash(target)
    assert _fold([_entry(source_hash=real[:6])], target) == set()


def test_unverifiable_token_row_demotes_to_unstamped_tier(
    tmp_path: Path, target: Path,
) -> None:
    """A row whose token does not verify (edited content — or,
    equivalently, a newer-schema row this reader's round-trip loses
    fields from) gets UNSTAMPED-tier authority: exact-hash-gated
    fold credit, never verdict reuse. Not dropped below unstamped —
    the token is strippable, so a lower tier would punish only
    honest newer-schema rows."""
    out = tmp_path / "run"
    real = _real_hash(target)
    entry = _entry(source_hash=real, verdict="finding")
    append_entry(out, entry)
    loaded = load_entries(out)[0]
    loaded.verdict = "clean"  # content no longer matches the token
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_TAMPERED

    # Exact-hash gate holds → fold credit, but NEVER the $0 reuse an
    # authenticated row earns.
    reuse_sink: dict = {}
    covered = _fold([loaded], target, reuse_sink=reuse_sink)
    assert covered == {"a.c:f"}
    assert reuse_sink == {}

    # Without a matching hash it carries nothing at all.
    loaded.source_hash = "ffffffffffff"
    assert _fold([loaded], target) == set()
    loaded.source_hash = ""
    assert _fold([loaded], target) == set()


def test_unstamped_row_never_enters_reuse_sink(target: Path) -> None:
    """Legacy tolerance: exact-hash unstamped rows keep suppression,
    but a $0 verdict import requires an authenticated row."""
    real = _real_hash(target)
    reuse_sink: dict = {}
    covered = _fold([_entry(source_hash=real)], target,
                    reuse_sink=reuse_sink)
    assert covered == {"a.c:f"}
    assert reuse_sink == {}


# ---------------------------------------------------------------------------
# Honest rows
# ---------------------------------------------------------------------------


def test_appended_row_is_stamped_and_folds_with_reuse(
    tmp_path: Path, target: Path,
) -> None:
    out = tmp_path / "run"
    real = _real_hash(target)
    append_entry(out, _entry(source_hash=real))
    loaded = load_entries(out)[0]
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED

    reuse_sink: dict = {}
    covered = _fold([loaded], target, reuse_sink=reuse_sink)
    assert covered == {"a.c:f"}
    assert "a.c:f" in reuse_sink


def test_verified_row_with_empty_hash_keeps_suppression(
    tmp_path: Path, target: Path,
) -> None:
    """This install's own writer recorded a review whose hash
    computation failed — the historical suppression stands (it is
    authenticated, just not hash-checkable)."""
    out = tmp_path / "run"
    append_entry(out, _entry(source_hash=""))
    loaded = load_entries(out)[0]
    assert _fold([loaded], target) == {"a.c:f"}


def test_verified_stale_row_resurfaces(tmp_path: Path, target: Path) -> None:
    out = tmp_path / "run"
    real = _real_hash(target)
    append_entry(out, _entry(source_hash=real))
    (target / "a.c").write_text("int f(void) { return 0; }\n")
    loaded = load_entries(out)[0]
    assert _fold([loaded], target) == set()
