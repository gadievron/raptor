"""Portable hunt views retain scope, native stdout and input protection."""
import json

import pytest

from packages.binary_analysis import cli, hunt


def _views(run):
    binary = str(run / "input.json")
    anchor = {"mode": "anchor", "binary": binary, "families": [{"id": str(i)} for i in range(101)],
              "scan": {"degraded": True, "notes": ["collector unavailable"]}, "claim": "structural_lead_only",
              "truncation_lines": ["native scan cap"], "artifacts": {"json": str(run / "binary-hunt-anchor-owned.json")}}
    calls = {"mode": "calls", "binary": binary, "caller_count": 205, "callers": [{"name": str(i)} for i in range(101)],
             "query": {"resolved_calls": "parse"}, "substrate_notes": ["bounded graph"],
             "residual": {"count": 20, "entries": [], "confidence": "hypothesis", "evidence_note": "absence is inconclusive"},
             "honesty": ["observed edges are syntactic"], "artifacts": {"json": str(run / "binary-hunt-calls-owned.json")}}
    return anchor, calls


def test_hunt_export_preserves_separate_query_populations_and_native_json(tmp_path, monkeypatch, capsys):
    anchor, callers = _views(tmp_path)
    dispatched = []
    monkeypatch.setattr(hunt, "run_anchor_hunt", lambda *a, **kw: dispatched.append("anchor") or anchor)
    monkeypatch.setattr(hunt, "run_calls_hunt", lambda *a, **kw: dispatched.append("calls") or callers)
    monkeypatch.setattr(cli, "start_run", lambda *a, **kw: pytest.fail("existing run must not start new lifecycle"))
    assert cli.main(["hunt", str(tmp_path), "--anchor", "parse", "--calls", "parse", "--json", "--report-format", "json"]) == 0
    streams = capsys.readouterr()
    assert [json.loads(line) for line in streams.out.splitlines()] == [anchor, callers]
    assert dispatched == ["anchor", "calls"]
    context = json.loads((tmp_path / "report-context.json").read_text())
    assert context["state"] == "partial" and context["run_id"] == "unknown" and not context["findings"]
    views = context["extensions"]["raptor.result"]["query_views"]
    assert views[0]["report_list_omissions"]["families"] == 1
    assert views[0]["scan"]["degraded"] is True and views[0]["truncation_lines"] == ["native scan cap"]
    assert views[1]["caller_count"] == 205 and views[1]["residual"]["count"] == 20
    assert views[1]["residual"]["confidence"] == "hypothesis"
    assert "not confirmed findings" in streams.err
    assert (tmp_path / "hunt-review-report.json").is_file()
    assert list(tmp_path.glob("binary-hunt-*.json")) == []  # no portable document masquerades as native hunt input


@pytest.mark.parametrize("name", ["input.json", "binary-hunt-anchor-owned.json", "re-database.json"])
def test_hunt_export_protects_current_binary_and_native_artifacts(tmp_path, monkeypatch, capsys, name):
    anchor, _ = _views(tmp_path)
    target = tmp_path / name
    target.write_text("owned evidence")
    monkeypatch.setattr(hunt, "run_anchor_hunt", lambda *a, **kw: anchor)
    assert cli.main(["hunt", str(tmp_path), "--anchor", "parse", "--json", "--report-format", "json", "--report-output", str(target)]) == 0
    streams = capsys.readouterr()
    assert json.loads(streams.out) == anchor and target.read_text() == "owned evidence"
    assert "Report persistence failed" in streams.err or "native result retained" in streams.err
