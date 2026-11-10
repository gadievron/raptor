"""Incomplete captured witness enumeration is distinct from an empty store."""
from types import SimpleNamespace

import pytest

import core.witness
from core.reporting.witnesses import build_witness_summary, render_witness_summary


def test_interrupted_witness_enumeration_discloses_retained_partial_counts(tmp_path, monkeypatch):
    captured = SimpleNamespace(source=core.witness.WitnessSource.FUZZ,
                               observed_outcome=core.witness.WitnessOutcome.EXIT_SIGNAL,
                               outcome_detail={})

    class CapturedStore:
        def __init__(self, path):
            assert path == tmp_path

        def list_witnesses(self):
            yield captured
            raise OSError("owned enumeration refusal")

    monkeypatch.setattr(core.witness, "WitnessStore", CapturedStore)
    summary = build_witness_summary(tmp_path)
    assert summary["total"] == 1 and summary["by_source"] == {"fuzz": 1}
    assert "partial" in render_witness_summary(tmp_path).lower()


@pytest.mark.parametrize("failure", ["open", "iteration"])
def test_unavailable_witness_enumeration_is_not_an_empty_store(tmp_path, monkeypatch, failure):
    class UnavailableStore:
        def __init__(self, path):
            if failure == "open":
                raise OSError("owned open refusal")

        def list_witnesses(self):
            raise OSError("owned iteration refusal")
            yield  # preserve iterator protocol without producing a record

    monkeypatch.setattr(core.witness, "WitnessStore", UnavailableStore)
    summary = build_witness_summary(tmp_path)
    assert summary["total"] == 0 and summary["enumeration_incomplete"] is True
    rendered = render_witness_summary(tmp_path)
    assert "unavailable" in rendered and "totals unknown" in rendered
    assert "owned" not in rendered


def test_complete_captured_enumeration_keeps_existing_view(tmp_path, monkeypatch):
    class EmptyStore:
        def __init__(self, path):
            pass

        def list_witnesses(self):
            return iter(())

    monkeypatch.setattr(core.witness, "WitnessStore", EmptyStore)
    assert render_witness_summary(tmp_path) == ""
    assert "enumeration_incomplete" not in build_witness_summary(tmp_path)
