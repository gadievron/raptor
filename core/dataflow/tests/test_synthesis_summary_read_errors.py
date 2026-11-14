"""Diagnostic summary reads cannot discard completed synthesis counts."""

import json
from types import SimpleNamespace

import pytest

from core.dataflow import barrier_synth


@pytest.mark.parametrize("content", [None, "{"])
def test_missing_or_invalid_summary_artifact_uses_empty_fallback(tmp_path, content):
    path = tmp_path / "owned.sarif"
    if content is not None:
        path.write_text(content)
    assert barrier_synth._summarise_surviving_finding(path) == ""
    with pytest.raises((OSError, ValueError)):
        barrier_synth._count_results_for_target(path)


def test_summary_read_failure_retains_completed_not_sound_result(tmp_path, monkeypatch):
    def analyze(db_path, queries, output_path, **kwargs):
        output_path.write_text(json.dumps({"runs": [{"results": [{
            "ruleId": "owned", "message": {"text": "owned finding"},
        }]}]}))
        return SimpleNamespace(sarif_path=output_path)

    real_load = barrier_synth.load_json
    after_reads = 0

    def load(path, **kwargs):
        nonlocal after_reads
        if path.parent.name == "after-1":
            after_reads += 1
            if after_reads == 2:
                raise FileNotFoundError("owned diagnostic read failure")
        return real_load(path, **kwargs)

    monkeypatch.setattr(barrier_synth, "analyze", analyze)
    monkeypatch.setattr(barrier_synth, "load_json", load)
    proposal = barrier_synth.BarrierProposal("cmdi", "owned", "sink(value)", "fixture")
    guard = "predicate proposedGuard(DataFlow::GuardNode g, DataFlow::Node n, boolean b) { none() }"
    result = barrier_synth.run_synthesis_loop(
        proposal, tmp_path / "after", tmp_path / "before",
        proposer=lambda proposal, prior_error: guard, work_dir=tmp_path / "work",
    )
    assert after_reads == 2
    assert result is not None
    assert result.after_count == result.before_count == 1
    assert result.is_sound is False
