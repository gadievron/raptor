"""Reporting keeps sibling leads and their native JSON contract distinct."""
import json

import pytest

from packages.binary_analysis import cli, siblings


def _payload(run):
    return {"binary": "owned", "claim": "structural_lead_only", "clusters": [],
            "asymmetries": [{"property": "check", "disproof_recipe": "Review dominance", "outliers": ["owned"]} for _ in range(101)],
            "hypothesis_seeds_emitted": 7, "honesty": ["consistent clusters are unexamined, not safe"],
            "substrate_notes": ["call graph partial"], "notes": ["native cap warning"],
            "artifacts": {"json": str(run / "sibling-clusters.json"), "report": str(run / "sibling-report.md")}}


def test_siblings_json_export_preserves_lead_semantics_and_native_stdout(tmp_path, monkeypatch, capsys):
    payload = _payload(tmp_path)
    native = tmp_path / "sibling-clusters.json"
    native.write_text(json.dumps(payload))
    before = native.read_bytes()
    calls = []
    monkeypatch.setattr(siblings, "run_siblings", lambda *a, **kw: calls.append(kw) or payload)
    monkeypatch.setattr(cli, "start_run", lambda *a, **kw: pytest.fail("existing run must not acquire new identity"))
    assert cli.main(["siblings", str(tmp_path), "--json", "--report-format", "json"]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out) == payload and len(calls) == 1
    assert native.read_bytes() == before
    context = json.loads((tmp_path / "report-context.json").read_text())
    assert context["findings"] == [] and context["run_id"] == "unknown"
    data = context["extensions"]["raptor.result"]
    assert data["report_omissions"]["asymmetries"] == 1
    assert data["honesty"] == payload["honesty"] and data["substrate_notes"] == payload["substrate_notes"]
    assert data["asymmetries"][0]["disproof_recipe"] == "Review dominance"
    assert context["extensions"]["raptor.metrics"]["Asymmetry review leads"] == 101
    assert "never confirmed findings" in streams.err


@pytest.mark.parametrize("destination", ["sibling-clusters.json", "re-database.json", "binary-hunt-owned.json"])
def test_siblings_report_cannot_replace_native_inputs_or_outputs(tmp_path, monkeypatch, capsys, destination):
    payload = _payload(tmp_path)
    target = tmp_path / destination
    target.write_text("owned native evidence")
    monkeypatch.setattr(siblings, "run_siblings", lambda *a, **kw: payload)
    assert cli.main(["siblings", str(tmp_path), "--json", "--report-format", "json", "--report-output", str(target)]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out) == payload and target.read_text() == "owned native evidence"
    assert "native result retained" in streams.err or "Report persistence failed" in streams.err
