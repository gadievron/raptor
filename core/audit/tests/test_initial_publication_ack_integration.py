"""Initial assessments require journal acknowledgement before publication."""

import json

import pytest

from core.audit import collector as collector_mod
from core.audit import orchestrator as orch
from core.audit import record
from core.audit.journal import load_entries
from core.audit.shared_state import SharedState
from core.coverage.journal import reviewed_set
from core.sage import hooks as sage_hooks


@pytest.mark.parametrize("failure", ["none", "journal", "telemetry", "journal_same_unit"])
def test_initial_clean_publication_requires_journal_ack(tmp_path, monkeypatch, failure):
    same_unit = failure == "journal_same_unit"
    journal_failure = failure in {"journal", "journal_same_unit"}
    monkeypatch.setattr(sage_hooks, "_ollama_gpu_available", lambda: False)
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text(
        "int f(int n) {\n    return n;\n}\n"
        "int prior(int n) {\n    return n;\n}\n"
    )
    out = tmp_path / "out"
    out.mkdir()
    items = [
        {"name": "f", "kind": "function", "line_start": 1, "line_end": 3},
        {"name": "prior", "kind": "function", "line_start": 4, "line_end": 6},
    ]
    checklist = {"files": [{"path": "a.c", "items": items}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    config = orch.OrchestratorConfig(
        target_path=target, out_dir=out, prefilter=False, max_refinements=0,
        immediate_verify=False, sweep_validate_findings=False, sage_recall=False,
        propagate_constraints=False,
    )
    prior = orch.ReviewOutcome(
        file="a.c", function="f" if same_unit else "prior",
        line=1 if same_unit else 4, status="suspicious", cost_usd=.2,
        body="Previously recorded owned assessment; no tool verification asserted",
    )
    prior_gap = {"file": "a.c", **items[0 if same_unit else 1]}
    acknowledged = collector_mod.append_journal_for_outcome(
        out_dir=out, target_path=target, run_id=out.name,
        outcome=prior, gap=prior_gap,
    )
    assert acknowledged is not None
    prior_entries = load_entries(out)
    assert any(e.function == prior.function and e.verdict == "suspicious" for e in prior_entries)
    coverage_before = reviewed_set(out)
    journal_append = collector_mod.append_entry
    attempts = []
    telemetry_attempts = []

    def append(out_dir, entry):
        attempts.append(entry)
        if journal_failure:
            raise OSError("owned initial journal append failure")
        return journal_append(out_dir, entry)

    def telemetry(*args, **kwargs):
        telemetry_attempts.append(True)
        raise OSError("owned optional telemetry append failure")

    monkeypatch.setattr(collector_mod, "append_entry", append)
    if failure == "telemetry":
        monkeypatch.setattr(record, "append_audit_log", telemetry)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    reviewed = []

    def review(context, cfg):
        reviewed.append(context["source"])
        assert "int f(int n)" in context["source"]
        return orch.ReviewOutcome(
            file="a.c", function="f", line=1, status="clean",
            body="Owned initial clean assessment", model="scripted", cost_usd=.125,
        )

    collector = collector_mod.Collector(out_dir=out, target_path=target, run_id=out.name)
    result = orch.OrchestratorResult()
    reviewed_outcomes = {}
    if same_unit:
        orch._tally_outcome(result, prior)
        reviewed_outcomes["a.c:f"] = prior
    gap = {"file": "a.c", **items[0], "pinned": True, "force_review": True}
    final = orch.review_one_function(
        gap, SharedState(checklist=checklist), config, review, result,
        collector=collector, reviewed_outcomes=reviewed_outcomes,
    )
    collector.flush()
    orch._persist_findings(result, config)
    entries = load_entries(out)
    findings_path = out / "findings.json"
    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []
    rows = findings.get("findings", []) if isinstance(findings, dict) else findings
    trace = {
        "failure": failure, "review_calls": len(reviewed),
        "journal_attempts": len(attempts), "final_status": final.status,
        "local_statuses": [o.status for o in result.outcomes],
        "journal": [{"function": e.function, "verdict": e.verdict} for e in entries],
        "exported_functions": [r.get("function") for r in rows],
        "telemetry_attempts": len(telemetry_attempts),
    }
    (out / "initial-publication-trace.json").write_text(json.dumps(trace, indent=2))
    assert len(reviewed) == 1 and len(attempts) == 1
    assert any(e.function == prior.function and e.verdict == "suspicious" for e in entries)
    assert not rows, "unverified owned assessments cannot become exported findings"
    if journal_failure:
        if not same_unit:
            assert not any(e.function == "f" for e in entries)
        assert not any(e.function == "f" and e.verdict == "clean" for e in entries)
        assert reviewed_set(out) == coverage_before
        assert final.status != "clean", "unknown journal acknowledgement cannot publish a new clean"
        assert final.status == "error" and final.error_class == "publication"
        assert len(result.publication_failures) == 1
        failed = result.publication_failures[0]
        assert failed["reason"] == "initial_journal_acknowledgement_unavailable"
        assert failed["adjudication"] == "unverified"
        assert failed["unpublished_assessment"]["status"] == "clean"
        assert result.clean == 0
        if same_unit:
            assert result.outcomes == [prior] and reviewed_outcomes["a.c:f"] is prior
            assert result.suspicious == 1 and result.reviewed == 1
        assert result.total_cost_usd == pytest.approx(.325 if same_unit else .125)
        assert not any(o.function == "f" and o.status == "clean" for o in result.outcomes)
    else:
        assert any(e.function == "f" and e.verdict == "clean" for e in entries)
        assert final.status == "clean"
        assert not result.publication_failures
        assert result.total_cost_usd == pytest.approx(.125)
        if failure == "telemetry":
            assert telemetry_attempts and collector.pending_count() > 0
