"""Harness receipts record proposals and prerequisites, without executing them."""
import json

import pytest

from packages.binary_analysis import cli


def _spec(run, status):
    generated = {"source": str(run / "candidate.c"), "build_script": str(run / "build.sh")} if status == "generated_candidate" else {}
    return {"id": "owned-plan", "status": status, "family": "exported_api", "target": {"path": str(run / "input.json")},
            "ingress": {"name": "owned", "kind": "exported_api"}, "reason": "native reason", "next_step": "review contract",
            "operator_inputs": {"abi": "buffer-size"} if generated else {}, "unknowns": ["ABI not verified"], "verification_contract": [{"step": "build", "proof": "compile candidate"}],
            "generated": generated,
            "linked_evidence": {"runtime_input_flows": [{"payload": "PRIVATE-RUNTIME-DATA"}]},
            "evidence_policy": "candidate only until validated", "artifacts": {"spec": str(run / "harness-spec.json"),
                "report": str(run / "harness-report.md"), **generated}}


@pytest.mark.parametrize("status", ["needs_abi_contract", "generated_candidate"])
def test_harness_export_preserves_native_plan_status_and_requirement_role(tmp_path, monkeypatch, capsys, status):
    spec = _spec(tmp_path, status)
    source = tmp_path / "candidate.c"
    source.write_text("PRIVATE-SOURCE-CONTENT")
    calls = []
    monkeypatch.setattr(cli, "generate_binary_harness", lambda *a, **kw: calls.append(kw) or spec)
    flags = ["--abi", "buffer-size"] if status == "generated_candidate" else []
    assert cli.main(["harness", str(tmp_path), "--json", "--report-format", "json", *flags]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out) == spec and len(calls) == 1 and calls[0]["llm_rank"] is False
    context_text = (tmp_path / "report-context.json").read_text()
    context = json.loads(context_text)
    data = context["extensions"]["raptor.result"]
    assert data["status"] == status and data["verification_contract"][0]["step"] == "build"
    assert data["linked_evidence_counts"] == {"runtime_input_flows": 1}
    assert "PRIVATE-" not in context_text and source.read_text() == "PRIVATE-SOURCE-CONTENT"
    assert not context["findings"] and context["run_id"] == "unknown"
    assert "requirements, not executed checks" in streams.err


@pytest.mark.parametrize("name", ["input.json", "harness-spec.json", "context-map.json"])
def test_harness_report_cannot_replace_native_binary_spec_or_inputs(tmp_path, monkeypatch, capsys, name):
    spec = _spec(tmp_path, "needs_abi_contract")
    target = tmp_path / name
    target.write_text("owned native")
    monkeypatch.setattr(cli, "generate_binary_harness", lambda *a, **kw: spec)
    assert cli.main(["harness", str(tmp_path), "--json", "--report-format", "json", "--report-output", str(target)]) == 0
    streams = capsys.readouterr()
    assert target.read_text() == "owned native" and json.loads(streams.out) == spec
    assert "Report persistence failed" in streams.err
