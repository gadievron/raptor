"""Malformed diagnostic metadata cannot discard completed synthesis counts."""

import json
from types import SimpleNamespace

import pytest

from core.dataflow import barrier_synth


@pytest.mark.parametrize("document", [
    {"runs": None}, {"runs": [None]},
    {"runs": [{"results": [{"message": {"text": 1}}]}]},
    {"runs": [{"results": [{"codeFlows": {"wrong": []}}]}]},
    {"runs": [{"results": [{"codeFlows": [{"threadFlows": [{"locations": [False]}]}]}]}]},
])
def test_summary_shape_errors_use_empty_fallback(tmp_path, document):
    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps(document))
    assert barrier_synth._summarise_surviving_finding(path) == ""


def test_summary_shape_error_preserves_not_sound_counts(tmp_path, monkeypatch):
    calls = []

    def analyze(db_path, queries, output_path, **kwargs):
        calls.append(db_path.name)
        output_path.write_text(json.dumps({"runs": [{"results": [{
            "ruleId": "owned", "message": {"text": 1},
        }]}]}))
        return SimpleNamespace(sarif_path=output_path)

    monkeypatch.setattr(barrier_synth, "analyze", analyze)
    proposal = barrier_synth.BarrierProposal("cmdi", "owned", "sink(value)", "fixture")
    guard = "predicate proposedGuard(DataFlow::GuardNode g, DataFlow::Node n, boolean b) { none() }"
    result = barrier_synth.run_synthesis_loop(
        proposal, tmp_path / "after", tmp_path / "before",
        proposer=lambda proposal, prior_error: guard, work_dir=tmp_path / "work",
    )
    assert calls == ["after", "before"]
    assert result is not None
    assert result.after_count == result.before_count == 1
    assert result.is_sound is False
