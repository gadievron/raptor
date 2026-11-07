"""Recorded checker outputs survive normal JSON export without verdict authority."""

import json
from pathlib import Path

import pytest

from core.audit import check_trace
from core.audit.findings_export import export_findings, write_graded_findings
from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome, _run_tool_chain
from core.audit.refutation_source import SourceIdentity
from core.audit.sweep import SweepResult
from core.audit.verification_results import ToolChainResult

FIXTURES = json.loads((Path(__file__).parent / "fixtures/check_trace/observations.json").read_text())


def _result(sample):
    return SweepResult(tool="semgrep", file_path="a.c", function_name="f", rule_id="fixture-rule", **sample)


def _record(out, sample, hypothesis="Fixture assertion", line=1):
    results = ToolChainResult(file="a.c", function="f", line_start=line, hypothesis=hypothesis,
                              source_identity=SourceIdentity("a" * 64, (1, 2, 3, 4, 5)))
    check_trace.record_check_observation(out, results, tool="semgrep", verdict=sample["outcome"],
                                       rule_id="fixture-rule", reason=sample["details"]["reason"], result=_result(sample))


@pytest.mark.parametrize("sample", FIXTURES, ids=lambda x: x["outcome"])
def test_saved_results_export_with_claim_source_and_payload(tmp_path, sample):
    _record(tmp_path, sample)
    finding = ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Fixture",
                            hypothesis="Fixture assertion")
    write_graded_findings(export_findings([finding]), tmp_path)
    exported = json.loads((tmp_path / "findings-graded.json").read_text())
    sidecar = json.loads((tmp_path / "verification-checks.json").read_text())
    check = sidecar["checks"][0]
    assert check["outcome"] == sample["outcome"]
    assert check["scope"]["source_identity"]["sha256"] == "a" * 64
    assert check["result"]["data"]["details"] == sample["details"]
    assert check["result"]["data"]["errors"] == sample["errors"]
    link = exported["findings"][0]["verification_trace"]["check_results"]
    assert link == {"artifact": "verification-checks.json", "status": "recorded",
                    "references": [{"id": check["id"], "matches_final_claim": True}]}
    assert sidecar["history_complete"] is False
    assert finding.status == "suspicious"
    assert exported["findings"][0]["discovery"]["confirmed_by"] == []


def test_old_claims_other_locations_and_clean_functions_remain_distinct(tmp_path):
    _record(tmp_path, FIXTURES[0], hypothesis="Earlier assertion")
    _record(tmp_path, FIXTURES[1], line=40)
    finding = ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Fixture",
                            hypothesis="Current assertion")
    write_graded_findings(export_findings([finding]), tmp_path)
    sidecar = json.loads((tmp_path / "verification-checks.json").read_text())
    graded = json.loads((tmp_path / "findings-graded.json").read_text())
    refs = graded["findings"][0]["verification_trace"]["check_results"]["references"]
    assert len(sidecar["checks"]) == 2
    assert refs == [{"id": sidecar["checks"][0]["id"], "matches_final_claim": False}]
    write_graded_findings(export_findings([]), tmp_path)
    assert len(json.loads((tmp_path / "verification-checks.json").read_text())["checks"]) == 2


def test_unsigned_tampered_and_replayed_rows_do_not_become_check_results(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    _record(out, FIXTURES[0])
    path = out / ".audit-log.jsonl"
    signed = json.loads(path.read_text())
    modified = {**signed, "outcome": "refuted"}
    unsigned = {k: v for k, v in signed.items() if k != "integrity"}
    with path.open("a") as stream:
        stream.write(json.dumps(modified) + "\n" + json.dumps(unsigned) + "\n")
    write_graded_findings(export_findings([]), out)
    assert len(json.loads((out / "verification-checks.json").read_text())["checks"]) == 1
    other = tmp_path / "other"
    other.mkdir()
    (other / ".audit-log.jsonl").write_text(json.dumps(signed) + "\n")
    write_graded_findings(export_findings([]), other)
    assert json.loads((other / "verification-checks.json").read_text())["checks"] == []


def test_large_and_invalid_payloads_preserve_effective_outcome(tmp_path):
    for raw in ["x" * (check_trace._PAYLOAD_BYTES + 1), float("nan")]:
        sample = {**FIXTURES[0], "details": {"reason": "fixture", "data": raw}}
        _record(tmp_path, sample)
    write_graded_findings(export_findings([]), tmp_path)
    checks = json.loads((tmp_path / "verification-checks.json").read_text())["checks"]
    assert [c["outcome"] for c in checks] == ["confirmed", "confirmed"]
    assert all(c["result"]["complete"] is False for c in checks)
    assert checks[0]["result"]["reason"] == "payload_size_limit"
    assert len(checks[0]["result"]["preview"]) <= check_trace._PREVIEW_CHARS
    assert checks[1]["result"]["reason"].startswith("payload_serialization:")


def test_failed_sidecar_write_does_not_publish_stale_links_or_block_findings(tmp_path, monkeypatch):
    _record(tmp_path, FIXTURES[0])
    (tmp_path / "verification-checks.json").write_text('{"checks":["stale"]}')

    def fail(*args, **kwargs):
        raise OSError("fixture write failure")

    monkeypatch.setattr(check_trace, "save_json", fail)
    finding = ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Fixture")
    write_graded_findings(export_findings([finding]), tmp_path)
    trace = json.loads((tmp_path / "findings-graded.json").read_text())["findings"][0]["verification_trace"]
    assert trace["check_results"] == {"artifact": None, "references": [], "status": "export_error"}
    graded = json.loads((tmp_path / "findings-graded.json").read_text())
    summary = graded["verification_summary"]
    assert summary["export_status"] == "export_error"
    assert summary["observations"]["retained"]["records"] == 0
    assert summary["findings"]["without_matching_observations"] == 1


@pytest.mark.parametrize("sample", FIXTURES, ids=lambda x: x["outcome"])
def test_real_chain_records_classification_without_running_a_tool(tmp_path, monkeypatch, sample):
    import core.audit.orchestrator as orch

    (tmp_path / "a.c").write_text("int f(void) { return 0; }\n")
    rule = tmp_path / "r.yml"
    rule.write_text("rules: []\n")
    monkeypatch.setattr(orch, "_memoized_sweep_step", lambda *a, **kw: _result(sample))
    out = tmp_path / "out"
    out.mkdir()
    result = _run_tool_chain(
        [{"type": "semgrep", "config": {"rule": str(rule)}}],
        config=OrchestratorConfig(target_path=tmp_path, out_dir=out),
        file_path="a.c", function_name="f", source="int f(void) { return 0; }\n",
        line_start=1, hypothesis="Fixture assertion",
    )
    write_graded_findings(export_findings([]), out)
    checks = json.loads((out / "verification-checks.json").read_text())["checks"]
    assert checks[0]["outcome"] == result.outcomes[0].verdict == sample["outcome"]
    assert checks[0]["result"]["data"]["request"] == {"rule": str(rule)}
    assert bool(result) is (sample["outcome"] == "confirmed")


def test_reporting_failure_does_not_change_tool_chain_result(tmp_path, monkeypatch):
    import core.audit.orchestrator as orch

    (tmp_path / "a.c").write_text("int f(void) { return 0; }\n")
    rule = tmp_path / "r.yml"
    rule.write_text("rules: []\n")
    monkeypatch.setattr(orch, "_memoized_sweep_step", lambda *a, **kw: _result(FIXTURES[0]))

    def fail(*args, **kwargs):
        raise OSError("fixture telemetry failure")

    monkeypatch.setattr(check_trace, "record_check_observation", fail)
    result = _run_tool_chain(
        [{"type": "semgrep", "config": {"rule": str(rule)}}],
        config=OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"),
        file_path="a.c", function_name="f", source="int f(void) { return 0; }\n",
        line_start=1, hypothesis="Fixture assertion",
    )
    assert result == ["semgrep:fixture-rule"]
    assert result.outcomes[0].verdict == "confirmed"


def test_changed_source_keeps_raw_result_separate_from_effective_outcome(tmp_path, monkeypatch):
    import core.audit.orchestrator as orch

    source = "int f(void) { return 0; }\n"
    (tmp_path / "a.c").write_text(source)
    rule = tmp_path / "r.yml"
    rule.write_text("rules: []\n")
    out = tmp_path / "out"
    out.mkdir()

    def changed(*args, **kwargs):
        (tmp_path / "a.c").write_text("int f(void) { return 1; }\n")
        return _result(FIXTURES[1])

    monkeypatch.setattr(orch, "_memoized_sweep_step", changed)
    result = _run_tool_chain(
        [{"type": "semgrep", "config": {"rule": str(rule)}}],
        config=OrchestratorConfig(target_path=tmp_path, out_dir=out),
        file_path="a.c", function_name="f", source=source, line_start=1, hypothesis="Fixture assertion",
    )
    write_graded_findings(export_findings([]), out)
    check = json.loads((out / "verification-checks.json").read_text())["checks"][0]
    assert result.outcomes[0].verdict == check["outcome"] == "inconclusive"
    assert check["result"]["data"]["outcome"] == "refuted"
    assert "source changed" in check["reason"]


def test_ambiguous_function_location_does_not_link_unrelated_checks(tmp_path):
    _record(tmp_path, FIXTURES[0], line=0)
    findings = [ReviewOutcome(file="a.c", function="f", line=0, status="suspicious", body="Fixture",
                              hypothesis=h) for h in ["First assertion", "Second assertion"]]
    write_graded_findings(export_findings(findings), tmp_path)
    graded = json.loads((tmp_path / "findings-graded.json").read_text())
    for finding in graded["findings"]:
        assert finding["verification_trace"]["check_results"]["references"] == []
        assert finding["verification_trace"]["check_results"]["status"] == "ambiguous_scope"
    assert len(json.loads((tmp_path / "verification-checks.json").read_text())["checks"]) == 1
    assert graded["verification_summary"]["findings"]["trace_statuses"] == {"ambiguous_scope": 2}
    assert graded["verification_summary"]["observations"]["not_linked_to_findings"]["records"] == 1


def test_summary_separates_matching_earlier_and_unlinked_observations(tmp_path):
    _record(tmp_path, FIXTURES[0], hypothesis="Current assertion")
    _record(tmp_path, FIXTURES[1], hypothesis="Earlier assertion")
    _record(tmp_path, FIXTURES[2], hypothesis="Current assertion")
    _record(tmp_path, FIXTURES[3], hypothesis="Earlier assertion", line=40)
    _record(tmp_path, FIXTURES[4], line=90)
    findings = [
        ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Fixture",
                      hypothesis="Current assertion"),
        ReviewOutcome(file="a.c", function="f", line=40, status="suspicious", body="Fixture",
                      hypothesis="Different assertion"),
        ReviewOutcome(file="a.c", function="g", line=10, status="dark", body="Fixture",
                      hypothesis="Unrecorded assertion"),
    ]
    write_graded_findings(export_findings(findings), tmp_path)
    graded = json.loads((tmp_path / "findings-graded.json").read_text())
    summary = graded["verification_summary"]
    assert summary["findings"] == {
        "total": 3, "with_matching_observations": 1, "without_matching_observations": 2,
        "trace_statuses": {"recorded": 2, "unavailable": 1},
    }
    groups = summary["observations"]
    assert groups["retained"]["records"] == 5
    assert groups["matching_final_claim"]["outcomes"] == {"confirmed": 1, "inconclusive": 1}
    assert groups["other_claims"]["outcomes"] == {"refuted": 1, "error": 1}
    assert groups["not_linked_to_findings"]["outcomes"] == {"skipped": 1}
    assert sum(groups[k]["records"] for k in ("matching_final_claim", "other_claims", "not_linked_to_findings")) == 5
    assert groups["retained"]["by_tool"] == {"semgrep": {s["outcome"]: 1 for s in FIXTURES}}
    assert groups["retained"]["checker_assumptions"] == {"reported": 2, "unavailable": 3}
    assert json.loads((tmp_path / "verification-checks.json").read_text())["summary"] == groups["retained"]


def test_marker_without_observations_does_not_inflate_summary(tmp_path):
    finding = ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Fixture",
                            evidence_tool="semgrep:fixture-rule")
    write_graded_findings(export_findings([finding]), tmp_path)
    summary = json.loads((tmp_path / "findings-graded.json").read_text())["verification_summary"]
    assert summary["findings"]["with_matching_observations"] == 0
    assert summary["findings"]["without_matching_observations"] == 1
    assert summary["observations"]["matching_final_claim"]["outcomes"] == {}
    assert summary["observations"]["retained"]["records"] == 0


def test_summary_keeps_conflicting_outcomes_without_adjudicating_them(tmp_path):
    _record(tmp_path, FIXTURES[0])
    _record(tmp_path, FIXTURES[1])
    finding = ReviewOutcome(file="a.c", function="f", line=1, status="suspicious", body="Fixture",
                            hypothesis="Fixture assertion")
    write_graded_findings(export_findings([finding]), tmp_path)
    graded = json.loads((tmp_path / "findings-graded.json").read_text())
    summary = graded["verification_summary"]
    assert summary["observations"]["matching_final_claim"]["outcomes"] == {"confirmed": 1, "refuted": 1}
    assert summary["findings"]["with_matching_observations"] == 1
    assert graded["findings"][0]["status"] == finding.status == "suspicious"
    assert graded["findings"][0]["discovery"]["confirmed_by"] == []


def test_summary_reports_partial_payloads_and_unavailable_source_identity(tmp_path):
    sample = {**FIXTURES[0], "details": {"reason": "fixture", "assumptions": []}}
    results = ToolChainResult(file="a.c", function="f", line_start=1, hypothesis="Fixture assertion")
    check_trace.record_check_observation(tmp_path, results, tool="semgrep", verdict="confirmed",
                                       rule_id="fixture-rule", result=_result(sample))
    large = {**sample, "details": {"reason": "fixture", "data": "x" * (check_trace._PAYLOAD_BYTES + 1)}}
    _record(tmp_path, large)
    write_graded_findings(export_findings([]), tmp_path)
    graded = json.loads((tmp_path / "findings-graded.json").read_text())
    summary = graded["verification_summary"]["observations"]["retained"]
    assert summary["payloads"] == {"complete": 1, "partial": 1, "unavailable": 0}
    assert summary["source_identity"] == {"recorded": 1, "unavailable": 1}
    assert summary["checker_assumptions"] == {"reported": 1, "unavailable": 1}
    assert graded["verification_summary"]["findings"]["total"] == 0
    assert graded["verification_summary"]["observations"]["not_linked_to_findings"]["records"] == 2


@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_each_hypothesis_links_its_own_recorded_observations(tmp_path, status):
    from core.json import load_json

    _record(tmp_path, FIXTURES[1], hypothesis="First claim")
    _record(tmp_path, FIXTURES[0], hypothesis="Independent claim")
    _record(tmp_path, FIXTURES[0], hypothesis="Unrelated claim", line=40)
    outcome = ReviewOutcome(file="a.c", function="f", line=1, status=status, body="Review",
                            hypothesis="First claim", hypotheses=[
                                {"mechanism": "First claim", "confidence": "refuted", "counter": "Caller validates"},
                                {"mechanism": "Independent claim", "confidence": "medium"},
                                {"mechanism": "Missing claim", "confidence": "low"},
                            ])
    write_graded_findings(export_findings([outcome]), tmp_path)
    saved = load_json(tmp_path / "findings-graded.json")
    checks = load_json(tmp_path / "verification-checks.json")["checks"]
    trace = (saved["clean_review_traces"][0] if status == "clean"
             else saved["findings"][0]["verification_trace"])
    reviews = trace["hypothesis_reviews"]
    assert reviews[0]["check_results"]["references"] == [{"id": checks[0]["id"]}]
    assert reviews[1]["check_results"]["references"] == [{"id": checks[1]["id"]}]
    assert reviews[2]["check_results"]["status"] == "unavailable"
    assert reviews[2]["check_results"]["references"] == []
    assert all(review["support_status"] == "not_assessed" for review in reviews)
    assert trace["check_results"]["references"] == [
        {"id": checks[0]["id"], "matches_final_claim": True},
        {"id": checks[1]["id"], "matches_final_claim": False},
    ]
    assert outcome.status == status
    if status == "clean":
        assert saved["findings"] == []
        assert saved["verification_summary"]["clean_reviews"] == {
            "total": 1, "with_matching_observations": 1, "without_matching_observations": 0,
        }
        assert saved["verification_summary"]["findings"]["total"] == 0


@pytest.mark.parametrize("fail_export", [False, True])
def test_clean_hypothesis_links_fail_closed_on_ambiguity_or_export_error(tmp_path, monkeypatch, fail_export):
    from core.json import load_json

    _record(tmp_path, FIXTURES[1], hypothesis="Claim")
    if fail_export:
        def fail(*args, **kwargs):
            raise OSError("fixture export failure")
        monkeypatch.setattr(check_trace, "save_json", fail)
    outcomes = [ReviewOutcome(file="a.c", function="f", line=1, status=status, body="Review",
                              hypothesis="Claim", hypotheses=[{"mechanism": "Claim", "confidence": "refuted"}])
                for status in ["clean", "suspicious"]]
    write_graded_findings(export_findings(outcomes), tmp_path)
    saved = load_json(tmp_path / "findings-graded.json")
    traces = [saved["clean_review_traces"][0], saved["findings"][0]["verification_trace"]]
    for trace in traces:
        for link in [trace["check_results"], trace["hypothesis_reviews"][0]["check_results"]]:
            assert link["references"] == []
            assert link["status"] == ("export_error" if fail_export else "ambiguous_scope")
        assert trace["hypothesis_reviews"][0]["support_status"] == "not_assessed"
