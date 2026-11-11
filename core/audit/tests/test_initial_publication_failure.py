"""Initial publication preserves the previous assessment and paid attempt."""

import json

import pytest

from core.audit import collector as collector_mod
from core.audit import orchestrator as orch
from core.audit.journal import load_entries
from core.audit.shared_state import SharedState


@pytest.mark.parametrize("use_collector", [False, True], ids=["standalone", "collector"])
@pytest.mark.parametrize("failure", ["none", "journal", "telemetry", "mismatched_ack"])
def test_replacement_requires_ack_without_losing_prior_or_spend(
    tmp_path, monkeypatch, use_collector, failure,
):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.py").write_text("def unit(value):\n    return value\n")
    gap = {"file": "unit.py", "name": "unit", "kind": "function",
           "line_start": 1, "line_end": 2, "pinned": True, "force_review": True}
    checklist = {"files": [{"path": "unit.py", "items": [dict(gap)]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, prefilter=False,
        max_refinements=0, immediate_verify=False, sweep_validate_findings=False,
        sage_recall=False, propagate_constraints=False)
    prior = orch.ReviewOutcome(file="unit.py", function="unit", line=1,
        status="suspicious", body="Prior assessment", cost_usd=.2)
    prior_ack = collector_mod.append_journal_for_outcome(out_dir=out, target_path=target,
        run_id=out.name, outcome=prior, gap=gap)
    assert prior_ack is not None
    if failure == "mismatched_ack":
        monkeypatch.setattr(collector_mod.Collector, "_append_journal_entry", lambda *args: prior_ack)
        monkeypatch.setattr(orch, "_commit_outcome", lambda *args: prior_ack)
    result = orch.OrchestratorResult()
    orch._tally_outcome(result, prior)
    reviewed = {"unit.py:unit": prior}
    calls = []

    def review(context, cfg):
        calls.append(context["source"])
        return orch.ReviewOutcome(file="unit.py", function="unit", line=1,
            status="clean", body="Fresh unverified proposal", cost_usd=.125, model="scripted")

    def failed_write(*args, **kwargs):
        raise OSError("scripted persistence failure")

    if failure == "journal":
        monkeypatch.setattr(collector_mod, "append_entry", failed_write)
    if failure == "telemetry":
        import core.audit.record as record
        monkeypatch.setattr(record, "append_audit_log", failed_write)
        monkeypatch.setattr(orch, "append_audit_log", failed_write)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    collector = collector_mod.Collector(out_dir=out, target_path=target, run_id=out.name) if use_collector else None
    final = orch.review_one_function(gap, SharedState(checklist=checklist), config,
        review, result, reviewed_outcomes=reviewed, collector=collector)
    if collector is not None:
        collector.flush()
    assert len(calls) == 1
    assert result.total_cost_usd == pytest.approx(.325)
    assert result.reviewed == 1
    entries = load_entries(out)
    if failure in {"journal", "mismatched_ack"}:
        assert final.status == "error" and final.error_class == "publication"
        assert result.outcomes == [prior] and reviewed["unit.py:unit"] is prior
        assert result.suspicious == 1 and result.clean == 0
        assert [entry.verdict for entry in entries] == ["suspicious"]
        assert len(result.publication_failures) == 1
        failure_record = result.publication_failures[0]
        assert failure_record["adjudication"] == "unverified"
        assert failure_record["unpublished_assessment"]["body"] == "Fresh unverified proposal"
    else:
        assert final.status == "clean" and result.outcomes == [final]
        assert reviewed["unit.py:unit"] is final
        assert result.clean == 1 and result.suspicious == 0
        assert [entry.verdict for entry in entries] == ["suspicious", "clean"]
        assert not result.publication_failures
