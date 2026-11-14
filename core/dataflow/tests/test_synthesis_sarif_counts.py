"""Malformed or incomplete SARIF cannot establish synthesis absence."""

import json
from types import SimpleNamespace

import pytest

from core.dataflow.barrier_synth import _count_results_for_target
from core.dataflow import barrier_synth


@pytest.mark.parametrize("target", [None, "a.py"])
@pytest.mark.parametrize("document", [
    [], {}, {"runs": []}, {"runs": None}, {"runs": [None]},
    {"runs": [{"results": False}]}, {"runs": [{"results": None}]},
    {"runs": [{"results": [False]}]},
    {"runs": [{"invocations": [{"executionSuccessful": False}], "results": []}]},
])
def test_invalid_or_incomplete_sarif_refuses_count(tmp_path, target, document):
    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="SARIF"):
        _count_results_for_target(path, target)


@pytest.mark.parametrize("target", [None, "a.py"])
def test_completed_empty_run_retains_zero_count(tmp_path, target):
    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps({"runs": [{"results": []}]}))
    assert _count_results_for_target(path, target) == 0


@pytest.mark.parametrize("locations", [None, [], [False], [{"physicalLocation": False}]])
def test_scoped_counts_refuse_unusable_locations(tmp_path, locations):
    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps({"runs": [{"results": [{"locations": locations}]}]}))
    with pytest.raises(ValueError, match="SARIF"):
        _count_results_for_target(path, "a.py")


def test_malformed_after_output_cannot_produce_synthesis_verdict(tmp_path, monkeypatch):
    calls = []

    def analyze(db_path, queries, output_path, **kwargs):
        calls.append(db_path.name)
        output_path.write_text("[]")
        return SimpleNamespace(sarif_path=output_path)

    monkeypatch.setattr(barrier_synth, "analyze", analyze)
    proposal = barrier_synth.BarrierProposal("cmdi", "owned", "sink(value)", "fixture")
    guard = "predicate proposedGuard(DataFlow::GuardNode g, DataFlow::Node n, boolean b) { none() }"
    diag = {}
    result = barrier_synth.run_synthesis_loop(
        proposal, tmp_path / "after", tmp_path / "before",
        proposer=lambda proposal, prior_error: guard,
        work_dir=tmp_path / "work", diag=diag,
    )
    assert result is None
    assert calls == ["after"]
    assert "SARIF document must be an object" in diag["last_error"]
