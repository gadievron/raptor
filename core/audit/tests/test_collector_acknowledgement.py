"""Mandatory journal acknowledgements remain separate from optional collection."""

import pytest

from core.audit import collector as collector_mod
from core.audit.journal import ReviewJournalEntry, load_entries
from core.audit.orchestrator import ReviewOutcome


@pytest.fixture
def owned(tmp_path):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.py").write_text("def unit():\n    return 1\n")
    outcome = ReviewOutcome(
        file="unit.py", function="unit", line=1, status="clean",
        body="Scripted assessment", model="scripted", cost_usd=0.125,
    )
    gap = {"file": "unit.py", "name": "unit", "line_start": 1, "line_end": 2}
    collector = collector_mod.Collector(out_dir=out, target_path=target, run_id=out.name)
    return collector, outcome, gap


def test_submit_returns_exact_acknowledged_journal_entry(owned, monkeypatch):
    collector, outcome, gap = owned
    append = collector_mod.append_entry
    entries = []

    def capture(out_dir, entry):
        append(out_dir, entry)
        entries.append(entry)

    monkeypatch.setattr(collector_mod, "append_entry", capture)
    acknowledgement = collector.submit(outcome, gap)
    assert isinstance(acknowledgement, ReviewJournalEntry)
    assert acknowledgement is entries[0]
    assert acknowledgement.verdict == outcome.status
    assert len(load_entries(collector.out_dir)) == 1
    assert collector.pending_count() == 1


def test_journal_failure_stops_before_optional_collection(owned, monkeypatch):
    collector, outcome, gap = owned

    def fail_append(*args, **kwargs):
        raise OSError("scripted mandatory append failure")

    def forbidden(*args, **kwargs):
        pytest.fail("unacknowledged assessment reached optional collection")

    monkeypatch.setattr(collector_mod, "append_entry", fail_append)
    monkeypatch.setattr(collector, "_record_acknowledged_outcome", forbidden)
    assert collector.submit(outcome, gap) is None
    assert not load_entries(collector.out_dir)
    assert collector.pending_count() == 0


def test_optional_failure_does_not_revoke_successful_ack(owned, monkeypatch):
    collector, outcome, gap = owned

    def optional_failure(*args, **kwargs):
        raise OSError("scripted optional collection failure")

    monkeypatch.setattr(collector, "_record_acknowledged_outcome", optional_failure)
    acknowledgement = collector.submit(outcome, gap)
    assert isinstance(acknowledgement, ReviewJournalEntry)
    assert acknowledgement.verdict == outcome.status
    assert len(load_entries(collector.out_dir)) == 1


def test_non_typed_acknowledgement_has_no_publication_credit(owned, monkeypatch):
    collector, outcome, gap = owned

    def forbidden(*args, **kwargs):
        pytest.fail("non-typed acknowledgement reached optional collection")

    monkeypatch.setattr(collector, "_append_journal_entry", lambda *args: object())
    monkeypatch.setattr(collector, "_record_acknowledged_outcome", forbidden)
    assert collector.submit(outcome, gap) is None
    assert collector.pending_count() == 0
