"""Claim history survives journal transport without becoming a receipt."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import fields
import json
from pathlib import Path

from core.coverage import journal_mac
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    load_entries,
    load_index_full,
    merge_into_index,
    now_iso,
)
from core.coverage.journal_compact import compact_journal
from core.coverage.journal_sidecar import OFFLOAD_FIELDS


def _history() -> dict:
    # This layer authenticates opaque history; the audit producer owns its
    # bounded codec. Neither references nor source stamps are tool receipts.
    return {
        "version": 1,
        "role": "history",
        "origin": {"pass_id": "review-round", "source_identity": None},
        "claims": [{
            "reference": {"claim_id": "claim-one", "revision_id": "revision-one"},
            "hypothesis": {"mechanism": "offset exceeds allocation", "cwe": "CWE-787"},
        }],
    }


def _entry(**overrides) -> ReviewJournalEntry:
    values = dict(
        ts=now_iso(), run_id="run", file="src/a.c", function="f",
        verdict="clean", source_hash="owned-source", line_start=3,
        line_end=8, model="owned-model", review_claims=_history(),
        body="Prior review reasoning. " * 100,
        hypotheses=[{"mechanism": "offset exceeds allocation"}],
    )
    values.update(overrides)
    return ReviewJournalEntry(**values)


def test_claim_history_round_trips_in_authenticated_journal(tmp_path: Path) -> None:
    expected = _history()
    append_entry(tmp_path, _entry(review_claims=deepcopy(expected)))

    (loaded,) = load_entries(tmp_path)
    assert loaded.review_claims == expected
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED
    assert loaded.evidence_tools == []
    assert loaded.tools_dispatched == []
    assert loaded.to_dict()["review_claims"] == expected


def test_nested_claim_history_tampering_invalidates_mac(tmp_path: Path) -> None:
    append_entry(tmp_path, _entry())
    path = tmp_path / JOURNAL_FILENAME
    row = json.loads(path.read_text())
    row["review_claims"]["claims"][0]["hypothesis"]["mechanism"] = "changed statement"
    path.write_text(json.dumps(row) + "\n")

    (loaded,) = load_entries(tmp_path)
    assert loaded.review_claims["claims"][0]["hypothesis"]["mechanism"] == "changed statement"
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_TAMPERED


def test_rows_without_claim_history_remain_verified(tmp_path: Path) -> None:
    append_entry(tmp_path, _entry(review_claims=None))
    raw = json.loads((tmp_path / JOURNAL_FILENAME).read_text())
    assert "review_claims" not in raw

    (loaded,) = load_entries(tmp_path)
    assert loaded.review_claims is None
    assert "review_claims" not in loaded.to_dict()
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED


def test_claim_history_stays_inline_when_clean_journal_is_slimmed(tmp_path: Path) -> None:
    append_entry(tmp_path, _entry())
    result = compact_journal(tmp_path, slim_clean=True)
    assert result.slimmed_rows == 1

    (loaded,) = load_entries(tmp_path)
    assert loaded.body == ""
    assert loaded.hypotheses == []
    assert loaded.body_offload
    assert loaded.review_claims == _history()
    assert "review_claims" not in loaded.body_offload["fields"]
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED


def test_index_merge_retains_authenticated_inline_claim_history(tmp_path: Path) -> None:
    project = tmp_path / "project"
    run = project / "run"
    run.mkdir(parents=True)
    append_entry(run, _entry())
    assert merge_into_index(project, run) == 1

    (loaded,) = load_index_full(project).values()
    assert loaded.review_claims == _history()
    assert loaded.body == ""
    assert loaded.hypotheses == []
    assert loaded.body_offload["sidecar"] == ""
    assert journal_mac.entry_provenance(loaded) == journal_mac.ROW_VERIFIED
    assert loaded.evidence_tools == []
    assert loaded.tools_dispatched == []


def test_claim_history_is_current_schema_vocabulary_and_not_offloaded() -> None:
    names = {field.name for field in fields(ReviewJournalEntry)}
    vocabulary = journal_mac._GENERATION_VOCABULARY[journal_mac.GENERATION_CURRENT]
    assert "review_claims" in names
    assert names <= vocabulary
    assert vocabulary - names == journal_mac.RETIRED_ROW_FIELDS
    assert "review_claims" not in OFFLOAD_FIELDS
