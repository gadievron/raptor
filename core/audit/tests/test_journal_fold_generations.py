"""Generation-aware provenance on the gap fold — the incident class.

A follow-on audit run folding a prior run's journal demoted 1,490
honest prior rows to the unstamped tier when a version-skewed reader's
dataclass round-trip dropped a MAC-covered field (the slim-clean
``body_offload`` pointer) before the token recompute: exact-hash fold
credit survived, but every $0 verdict reuse was forfeited and the run
re-paid for reviews. These tests reconstruct that shape (structure
only — synthetic rows) and pin the repair: a genuine row whose
projection is lossy verifies via the raw-form ladder rung and RETAINS
verdict-reuse authority, forged rows still demote on every generation,
and the fold log buckets every demotion by reason.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from core.audit.gaps import _verify_entries_fold
from core.coverage import journal, journal_mac
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


#: The incident's field shape: a slim-clean offload stub pointer,
#: MAC-covered on the restamped stub. Structure only.
_OFFLOAD = {"sidecar": "review-journal-bodies.jsonl", "offset": 0,
            "bytes": 10, "sha256": "ab", "fields": ["body"]}


def _skewed_reader(monkeypatch, dropped: str = "body_offload") -> None:
    """A reader whose dataclass round-trip loses *dropped* — the
    version-skew shape behind the mass demotion."""
    real_to_dict = ReviewJournalEntry.to_dict

    def lossy_to_dict(self):
        d = real_to_dict(self)
        d.pop(dropped, None)
        return d

    monkeypatch.setattr(ReviewJournalEntry, "to_dict", lossy_to_dict)
    # raising=False: pre-fix checkouts have no _ENTRY_FIELD_NAMES —
    # this file must run RED there (demotion), not error at setup.
    monkeypatch.setattr(
        journal, "_ENTRY_FIELD_NAMES",
        frozenset(getattr(journal, "_ENTRY_FIELD_NAMES", ()))
        - {dropped},
        raising=False)


def _incident_row(tmp_path: Path, target: Path) -> Path:
    """One genuine stamped stub row, minted over its FULL bytes."""
    run = tmp_path / "prior-run"
    run.mkdir(exist_ok=True)
    append_entry(run, _entry(
        source_hash=_real_hash(target), body_offload=_OFFLOAD))
    return run


class TestIncidentReconstruction:
    def test_genuine_prior_row_retains_verdict_authority_under_skew(
            self, tmp_path: Path, target: Path, monkeypatch) -> None:
        """THE regression: the skewed fold used to read this honest
        row as tampered — hash-gated credit only, $0 reuse forfeited,
        the review re-bought. It must verify (raw form) and keep FULL
        authority: fold credit AND the reuse sink."""
        run = _incident_row(tmp_path, target)
        _skewed_reader(monkeypatch)
        entry = load_entries(run, fresh=True)[0]

        reuse_sink: dict = {}
        covered = _fold([entry], target, reuse_sink=reuse_sink)
        assert covered == {"a.c:f"}
        assert "a.c:f" in reuse_sink  # verdict authority retained

    def test_forged_prior_row_still_demotes_under_skew(
            self, tmp_path: Path, target: Path, monkeypatch) -> None:
        """Fail-closed unweakened: the same skewed reader, but a
        covered byte flipped in the persisted row — no generation and
        no enumerated form verifies, no reuse."""
        import json
        run = _incident_row(tmp_path, target)
        jf = run / "review-journal.jsonl"
        row = json.loads(jf.read_text())
        row["source_hash"] = _real_hash(target)  # keep the hash gate
        row["verdict"] = "clean"
        row["run_id"] = "forged-run"  # covered byte flip
        jf.write_text(json.dumps(row) + "\n")
        _skewed_reader(monkeypatch)
        entry = load_entries(run, fresh=True)[0]
        assert (journal_mac.entry_provenance(entry)
                == journal_mac.ROW_TAMPERED)

        reuse_sink: dict = {}
        covered = _fold([entry], target, reuse_sink=reuse_sink)
        assert covered == {"a.c:f"}  # unstamped tier: exact-hash credit
        assert reuse_sink == {}      # never verdict reuse


class TestFoldTelemetry:
    def test_raw_form_verifications_logged_as_absorbed_drift(
            self, tmp_path: Path, target: Path, monkeypatch,
            caplog) -> None:
        run = _incident_row(tmp_path, target)
        _skewed_reader(monkeypatch)
        entry = load_entries(run, fresh=True)[0]
        with caplog.at_level(logging.INFO, logger="core.audit.gaps"):
            _fold([entry], target, reuse_sink={})
        legacy_lines = [r.message for r in caplog.records
                        if "legacy canonical form" in r.message]
        assert len(legacy_lines) == 1
        assert "raw_form=1" in legacy_lines[0]
        assert "full verdict authority retained" in legacy_lines[0]

    def test_demotions_bucketed_by_reason_in_fold_warning(
            self, tmp_path: Path, target: Path, caplog) -> None:
        import json
        run = tmp_path / "prior-run"
        run.mkdir()
        real = _real_hash(target)
        for i in range(3):
            append_entry(run, _entry(
                function=f"f{i}", source_hash=real))
        jf = run / "review-journal.jsonl"
        rows = [json.loads(line) for line in jf.read_text().splitlines()]
        rows[0]["verdict"] = "clean-forged"          # hash_mismatch
        rows[1][journal_mac.TOKEN_KEY] = "g9:" + "a" * 64   # unknown gen
        rows[2][journal_mac.TOKEN_KEY] = "not-a-token"      # malformed
        jf.write_text("".join(json.dumps(r) + "\n" for r in rows))
        entries = load_entries(run, fresh=True)
        with caplog.at_level(logging.WARNING, logger="core.audit.gaps"):
            _fold(entries, target, reuse_sink={})
        warned = [r.message for r in caplog.records
                  if "verifies under NO known" in r.message]
        assert len(warned) == 1
        assert "3 row(s)" in warned[0]
        assert "hash_mismatch=1" in warned[0]
        assert "unknown_generation=1" in warned[0]
        assert "malformed_token=1" in warned[0]

    def test_quiet_when_everything_verifies_current_form(
            self, tmp_path: Path, target: Path, caplog) -> None:
        run = tmp_path / "prior-run"
        run.mkdir()
        append_entry(run, _entry(source_hash=_real_hash(target)))
        entries = load_entries(run)
        with caplog.at_level(logging.INFO, logger="core.audit.gaps"):
            _fold(entries, target, reuse_sink={})
        assert not [r for r in caplog.records
                    if "legacy canonical form" in r.message]
        assert not [r for r in caplog.records
                    if "verifies under NO known" in r.message]
