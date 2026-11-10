"""Graph query exports keep native JSON and avoid rereading evidence payloads."""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from core.evidence import EvidenceTier, make_evidence
from core.testing.standalone_cli import run_standalone_cli
from core.testing.module_bindings import patch_module_attribute
from packages.binary_analysis import cli
from packages.binary_analysis.graph_store import BinaryGraphStore


def _database(tmp_path):
    db = tmp_path / "store.json"  # SQLite may use any filename; guard by identity, not extension.
    binary = tmp_path / "input.json"
    binary.write_text("owned binary")
    store = BinaryGraphStore(db)
    try:
        sha = "a" * 64
        snapshot = store.begin_snapshot(sha, str(binary), tmp_path)
        evidence = make_evidence(sha, kind="runtime", source="owned", summary="PRIVATE-SUMMARY",
                                 tier=EvidenceTier.OBSERVED_RUNTIME, confidence="candidate", reproducible=False,
                                 tool="owned", data={"payload": "PRIVATE-RUNTIME-DATA"})
        store.add_evidence(snapshot, evidence)
    finally:
        store.close()
    return db


def _query(*args):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return run_standalone_cli([sys.executable, str(Path(__file__).resolve().parents[3] / "libexec" / "raptor-binary-graph-query"), *map(str, args)],
                              env=env, capture_output=True, text=True, timeout=30)


def test_graph_native_evidence_json_survives_metadata_export(tmp_path):
    db = _database(tmp_path)
    result = _query("--db", db, "--evidence", "--report-format", "json")
    assert result.returncode == 0, result.stderr
    native = json.loads(result.stdout)
    assert native["evidence"][0]["summary"] == "PRIVATE-SUMMARY"
    text = (tmp_path / "report-context.json").read_text()
    context = json.loads(text)
    assert "PRIVATE-" not in text
    data = context["extensions"]["raptor.result"]
    assert data["records"][0]["tier"] == "observed_runtime" and data["records"][0]["reproducible"] is False
    assert context["extensions"]["raptor.metrics"]["Records returned by native query"] == 1
    assert not context["findings"] and context["run_id"] == "unknown"


def test_graph_report_cannot_overwrite_database(tmp_path):
    db = _database(tmp_path)
    original = db.read_bytes()
    result = _query("--db", db, "--json", "--report-format", "json", "--report-output", db)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["exists"] is True
    assert db.read_bytes() == original and "Report persistence failed" in result.stderr


def test_graph_missing_database_keeps_native_failure_and_no_fake_zero_population(tmp_path):
    db = tmp_path / "missing.json"
    result = _query("--db", db, "--json", "--report-format", "json")
    assert result.returncode == 1 and result.stdout == "" and not db.exists()
    context = json.loads((tmp_path / "report-context.json").read_text())
    assert context["state"] == "failed" and context["extensions"]["raptor.result"]["result"] is None
    assert "Records returned by native query" not in context["extensions"]["raptor.metrics"]
    assert not any("native JSON retains" in note for note in context["diagnostics"])


@pytest.mark.parametrize("flags", [[], ["--report-format", "json", "--report-output", "relative.json"], ["--no-report"]])
def test_binary_graph_forwards_report_controls_without_extra_child(tmp_path, monkeypatch, flags):
    calls = []
    def child(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=7)
    patch_module_attribute(monkeypatch, cli, "subprocess", "run", child)
    assert cli.main(["graph", str(tmp_path), "--edges", "--kind", "CALLS", *flags]) == 7
    assert len(calls) == 1
    command = calls[0][0]
    assert command[1:6] == ["--run-dir", str(tmp_path), "--edges", "--kind", "CALLS"]
    if "--report-output" in flags:
        assert command[-4:] == ["--report-format", "json", "--report-output", str(Path("relative.json").resolve())]
    elif flags:
        assert command[-1] == "--no-report"
    else:
        assert len(command) == 6


def test_binary_graph_preflight_refuses_conflicting_report_controls(tmp_path, monkeypatch):
    patch_module_attribute(monkeypatch, cli, "subprocess", "run", lambda *a, **kw: pytest.fail("invalid report options reached child"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["graph", str(tmp_path), "--no-report", "--report-format", "json"])
    assert exc.value.code == 2


def test_graph_edge_export_preserves_endpoints_and_omits_properties(tmp_path):
    db = _database(tmp_path)
    store = BinaryGraphStore(db)
    try:
        sha = "b" * 64
        snapshot = store.begin_snapshot(sha, str(tmp_path / "input.json"), tmp_path)
        source = store.add_node(snapshot, sha, "function", "a", name="source")
        target = store.add_node(snapshot, sha, "function", "b", name="target")
        store.add_edge(snapshot, sha, "CALLS", source, target, props={"raw": "PRIVATE-EDGE-PROPERTY"})
    finally:
        store.close()
    result = _query("--db", db, "--edges", "--kind", "CALLS", "--report-format", "json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["edges"][0]["props"]["raw"] == "PRIVATE-EDGE-PROPERTY"
    text = (tmp_path / "report-context.json").read_text()
    data = json.loads(text)["extensions"]["raptor.result"]
    assert data["selection"]["kind"] == "CALLS"
    assert data["records"][0]["source"]["name"] == "source"
    assert data["records"][0]["target"]["name"] == "target"
    assert "PRIVATE-" not in text


@pytest.mark.parametrize("mode,payload,expected", [
    ("summary", None, "No native graph-query payload was captured."),
    ("summary", {"exists": True, "nodes": {}, "edges": {}, "evidence": {}}, "Summary view contains counts"),
    ("edges", {"edges": [{"id": 1, "kind": "CALLS", "source": {}, "target": {}, "props": {"private": "captured"}}]}, "native JSON retains them"),
    ("evidence", {"evidence": [{"id": "captured", "summary": "captured detail"}]}, "native JSON retains them"),
])
def test_captured_graph_retention_notice_matches_view_without_query(tmp_path, mode, payload, expected):
    from core.reporting.options import ReportOptions
    from core.reporting.writer import load_committed_report
    from packages.binary_analysis.graph_reporting import complete_graph_report
    args = SimpleNamespace(run_dir=str(tmp_path), edges=mode == "edges", evidence=mode == "evidence",
                           kind=None, tier=None, report_format=["json"], report_output=None,
                           _report_options=ReportOptions(formats=("json",)))
    result = complete_graph_report(args, payload, tmp_path / "absent.sqlite", 1 if payload is None else 0)
    assert not result.errors and result.publication.committed
    context, _, _ = load_committed_report(tmp_path)
    assert any(expected in note for note in context.diagnostics)
    assert any("do not establish a finding verdict" in note for note in context.diagnostics)
    if payload is None or mode == "summary":
        assert not any("native JSON retains" in note for note in context.diagnostics)
    assert not (tmp_path / "absent.sqlite").exists()
