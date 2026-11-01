"""Regressions from adversarial review of the #810 pipeline integrations."""

import hashlib
import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.json import save_json
from core.understand_graph import (
    agentic_graph_groups, fuzz_targets, ingest_agentic_findings, ingest_run,
    ingest_fuzz_evidence, ingest_sca_evidence, ingest_web_evidence, open_graph, rebuild_graph,
)
from core.understand_graph import evidence
from core.understand_graph.tests.test_pipeline_integration import (
    _findings,
    project as project,
)


def _web(run, findings, outcomes):
    run.mkdir(parents=True, exist_ok=True)
    save_json(run / "web_findings.json", {"findings": findings})
    save_json(run / "verified-outcomes.json", {"outcomes": outcomes})


def _lane_state(graph, run, lane):
    with open_graph(graph) as conn:
        snapshot = conn.execute(
            "SELECT id, props_json FROM snapshots WHERE producer_run=? AND producer=?",
            (str(run.resolve()), lane),
        ).fetchone()
        if snapshot is None:
            return None
        nodes = conn.execute("SELECT kind, stable_key FROM nodes WHERE snapshot_id=? ORDER BY id",
                             (snapshot["id"],)).fetchall()
        edges = conn.execute("SELECT kind, src_id, dst_id FROM edges WHERE snapshot_id=? ORDER BY id",
                             (snapshot["id"],)).fetchall()
        return {"nodes": [tuple(n) for n in nodes], "edges": [tuple(e) for e in edges],
                "ingest": json.loads(snapshot["props_json"]).get("ingest", {})}


def test_duplicate_web_ids_cannot_amplify_into_quadratic_work(project):
    root, target, graph = project
    run = root / "web"
    _web(run, [{"id": "W", "url": "https://example.test/"}] * 10000,
         [{"finding_id": "W", "status": "verified"}] * 10000)
    with patch.object(evidence, "_upsert_node", wraps=evidence._upsert_node) as node_writes:
        ingest_web_evidence(run, str(target))
    state = _lane_state(graph, run, "web")
    assert len(state["nodes"]) == node_writes.call_count == 3
    assert len(state["edges"]) == 2
    assert state["ingest"]["work"] == 4
    assert not state["ingest"]["degraded"]


def test_conflicting_ids_are_retained_without_ambiguous_confirmations(project):
    root, target, graph = project
    run = root / "web"
    _web(run, [{"id": "W", "url": "https://example.test/a"},
               {"id": "W", "url": "https://example.test/b"}],
         [{"finding_id": "W", "status": "verified"}])
    ingest_web_evidence(run, str(target))
    state = _lane_state(graph, run, "web")
    assert sum(kind == "finding" for kind, _ in state["nodes"]) == 2
    assert not any(edge[0] == "CONFIRMED_BY" for edge in state["edges"])
    assert "ambiguous_finding_id" in state["ingest"]["reasons"]


@pytest.mark.parametrize("budget,value,reason", [
    ("_MAX_NODES", 4, "node_limit"),
    ("_MAX_EDGES", 2, "edge_limit"),
    ("_MAX_WORK", 3, "work_limit"),
    ("_MAX_RECORDS", 2, "record_limit"),
])
def test_total_ingest_budgets_are_enforced_and_reported(project, monkeypatch, caplog, budget, value, reason):
    root, target, graph = project
    run = root / "web"
    _web(run, [{"id": f"W{i}", "url": f"https://example.test/{i}"} for i in range(6)],
         [{"finding_id": f"W{i}", "status": "verified"} for i in range(6)])
    monkeypatch.setattr(evidence, budget, value)
    ingest_web_evidence(run, str(target))
    state = _lane_state(graph, run, "web")
    assert state["ingest"]["degraded"]
    assert reason in state["ingest"]["reasons"]
    assert reason in caplog.text
    assert len(state["nodes"]) <= evidence._MAX_NODES
    assert len(state["edges"]) <= evidence._MAX_EDGES
    assert state["ingest"]["work"] <= evidence._MAX_WORK


def test_fuzz_witnesses_share_one_actual_byte_budget(project, monkeypatch):
    root, target, graph = project
    run = root / "fuzz"
    manifests = run / "witnesses" / "manifests"
    manifests.mkdir(parents=True)
    for name in ("a", "b"):
        save_json(manifests / f"{name}.json", {"name": name, "padding": "x" * 70})
    first_size = (manifests / "a.json").stat().st_size
    monkeypatch.setattr(evidence, "RUN_ARTIFACT_MAX_BYTES", first_size + 5)
    save_json(run / "fuzzing-result.json", {"crashes": 2})
    with patch.object(evidence, "_artifact_digest", wraps=evidence._artifact_digest) as digests:
        ingest_fuzz_evidence(run, str(target))
    state = _lane_state(graph, run, "fuzz")
    assert sum(kind == "verified_outcome" for kind, _ in state["nodes"]) == 1
    assert "manifest_read_refused" in state["ingest"]["reasons"]
    # Witness hashes must be pinned to read bytes, not a second unbudgeted read.
    assert [call.args[0].name for call in digests.call_args_list] == ["fuzzing-result.json"]


def test_fuzz_manifest_enumeration_stops_before_sorting(project, monkeypatch):
    from contextlib import contextmanager
    root, target, graph = project
    run = root / "fuzz"
    run.mkdir()
    read_entries = []

    def entries():
        for i in range(1000000):
            read_entries.append(i)
            yield SimpleNamespace(name=f"{i}.txt", path=str(run / f"{i}.txt"))

    @contextmanager
    def directory(*args):
        yield entries()

    monkeypatch.setattr(evidence, "_MAX_RECORDS", 2)
    monkeypatch.setattr(evidence, "os", SimpleNamespace(scandir=directory))
    ingest_fuzz_evidence(run, str(target), result={"crashes": 0})
    assert len(read_entries) == 3  # budget plus one sentinel, never the full directory
    assert "manifest_entry_limit" in _lane_state(graph, run, "fuzz")["ingest"]["reasons"]


def test_agentic_groups_only_the_requested_snapshot_with_reused_ids(project):
    root, target, graph = project
    run = root / "agentic"
    assert agentic_graph_groups(run, str(target), _findings())
    changed = _findings()
    for finding in changed:
        finding.update(file_path="different.py", function="different")
    assert agentic_graph_groups(run, str(target), changed) == []
    # Preserve historical memory rather than deleting it to hide the bug.
    with open_graph(graph) as conn:
        assert conn.execute("SELECT count(*) FROM snapshots WHERE producer='scan' AND producer_run=?",
                            (str(run.resolve()),)).fetchone()[0] == 2
    # Replaying the original request must still query its exact snapshot.
    assert agentic_graph_groups(run, str(target), _findings())


@pytest.mark.parametrize("lane", ["web", "sca"])
def test_authoritative_empty_clears_only_that_run_lane(project, lane):
    root, target, graph = project
    runs = [root / f"{lane}-{i}" for i in range(2)]
    ingest = ingest_web_evidence if lane == "web" else ingest_sca_evidence
    for run in runs:
        run.mkdir()
        if lane == "web":
            _web(run, [{"id": "W", "url": "https://example.test/"}], [{"finding_id": "W"}])
        else:
            save_json(run / "findings.json", [{"id": "S", "sca": {
                "name": "dep", "version": "1", "reachability": {"verdict": "imported"}}}])
        ingest(run, str(target))
    other = _lane_state(graph, runs[1], lane)
    assert _lane_state(graph, runs[0], lane)["nodes"]
    if lane == "web":
        _web(runs[0], [], [])
    else:
        save_json(runs[0] / "findings.json", [])
    assert ingest(runs[0], str(target)) == graph
    emptied = _lane_state(graph, runs[0], lane)
    assert emptied["nodes"] == emptied["edges"] == []
    assert not emptied["ingest"]["degraded"]
    assert _lane_state(graph, runs[1], lane) == other


@pytest.mark.parametrize("lane", ["web", "sca"])
@pytest.mark.parametrize("bad", [None, "invalid json", {}, [None, 7]])
def test_unavailable_or_malformed_reports_do_not_erase_prior_evidence(project, lane, bad):
    root, target, graph = project
    run = root / lane
    run.mkdir()
    if lane == "web":
        _web(run, [{"id": "W"}], [{"finding_id": "W"}])
        path = run / "verified-outcomes.json"
        ingest = ingest_web_evidence
    else:
        path = run / "findings.json"
        save_json(path, [{"id": "S", "sca": {"name": "dep"}}])
        ingest = ingest_sca_evidence
    ingest(run, str(target))
    previous = _lane_state(graph, run, lane)
    if bad is None:
        path.unlink()
    elif isinstance(bad, str):
        path.write_text(bad)
    else:
        save_json(path, bad)
    assert ingest(run, str(target)) is None
    assert _lane_state(graph, run, lane) == previous


def test_empty_replacement_rolls_back_if_artifact_write_fails(project, monkeypatch):
    root, target, graph = project
    run = root / "web"
    _web(run, [{"id": "W"}], [{"finding_id": "W"}])
    ingest_web_evidence(run, str(target))
    previous = _lane_state(graph, run, "web")
    _web(run, [], [])

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("forced write failure")

    monkeypatch.setattr(evidence, "_artifact", fail)
    assert ingest_web_evidence(run, str(target)) is None
    assert _lane_state(graph, run, "web") == previous


@pytest.mark.parametrize("skip_dedup", [True, False])
@pytest.mark.parametrize("file_uri", [True, False])
def test_rebuild_uses_the_live_agentic_adapter(project, skip_dedup, file_uri):
    root, target, graph = project
    run = root / "agentic"
    run.mkdir()
    save_json(run / ".raptor-run.json", {"command": "agentic", "target_path": str(target)})
    save_json(run / "scanner.sarif", {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": []}}, "results": [{
            "ruleId": "test.injection", "level": "warning", "message": {"text": "candidate"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                           "uri": (target / "server.py").as_uri() if file_uri else "server.py"},
                           "region": {"startLine": 2}},
                           "logicalLocations": [{"kind": "function", "name": "parse"}]}],
        }],
    }]})
    if not skip_dedup:
        (run / "validation").mkdir()
        save_json(run / "validation" / "findings.json", {"findings": _findings()})
    ingest_agentic_findings(run, str(target))
    before = _lane_state(graph, run, "scan")
    assert before["nodes"] and before["edges"]
    assert rebuild_graph(root) == graph
    after = _lane_state(graph, run, "scan")
    assert after == before
    assert _lane_state(graph, run, "codeql") is None


def test_empty_generic_scan_does_not_manufacture_an_sca_rebuild(project):
    root, target, graph = project
    # Only old graph memory remains; an empty generic scanner report is not
    # an SCA report and must not turn "nothing to rebuild" into replacement.
    (root / "understand" / "checklist.json").unlink()
    (root / "understand" / "context-map.json").unlink()
    run = root / "scan"
    run.mkdir()
    save_json(run / ".raptor-run.json", {"command": "scan", "target_path": str(target)})
    save_json(run / "findings.json", [])
    with open_graph(graph) as conn:
        before = conn.execute("SELECT count(*) FROM nodes").fetchone()[0]
    assert rebuild_graph(root) is None
    with open_graph(graph) as conn:
        assert conn.execute("SELECT count(*) FROM nodes").fetchone()[0] == before


def test_stale_fuzz_candidates_do_not_consume_the_limit(project):
    root, target, graph = project
    run = root / "understand-ranked"
    run.mkdir()
    files, entries, sinks, flows = [], [], [], []
    # More stale top-ranked entries than the default limit, followed by a
    # fresh lower-ranked candidate. Hashes/paths are real source fixtures.
    for i in range(12):
        path = target / f"parser{i}.py"
        path.write_text(f"def parse{i}(data: bytes):\n    return eval(data)\n")
        files.append({"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "items": [{"name": f"parse{i}", "line_start": 1, "line_end": 2}]})
        entries.append({"id": f"E{i}", "name": f"parse{i}", "file": path.name, "line": 1})
        sinks.append({"id": f"S{i}", "name": "eval", "file": path.name, "line": 2})
        flows.append({"entry_point": f"E{i}", "sink": f"S{i}",
                      "confidence": "high" if i < 11 else "medium"})
    save_json(run / "checklist.json", {"target_path": str(target), "files": files})
    save_json(run / "context-map.json", {"meta": {"target": str(target)},
              "entry_points": entries, "sink_details": sinks, "unchecked_flows": flows})
    ingest_run(run, str(target))
    for i in range(11):
        (target / f"parser{i}.py").write_text("# changed\n")
    assert [row["function"] for row in fuzz_targets(graph, str(target), limit=1)] == ["parse11"]
    assert [row["function"] for row in fuzz_targets(graph, str(target))] == ["parse11"]


@pytest.mark.parametrize("suffix", [
    "parse = 7\n",
    "def parse(data, extra):\n    return data\n",
    "async def parse(data: bytes):\n    return data\n",
    "class parse:\n    pass\n",
    "import other as parse\n",
    "from other import parse\n",
    "from other import *\n",
    "del parse\n",
    "if False:\n    parse = 7\n",
    "for parse in []:\n    pass\n",
    "try:\n    pass\nexcept Exception as parse:\n    pass\n",
    "match 7:\n    case parse:\n        pass\n",
    "parse.__code__ = other.__code__\n",
    "module.parse = 7\n",
    "globals()['parse'] = 7\n",
    "def overwrite():\n    global parse\n    parse = 7\noverwrite()\n",
    "def other(x=overwrite()):\n    pass\n",
    "@decorator\ndef other():\n    pass\n",
])
def test_automatic_python_selection_rejects_rebound_or_dynamic_names(tmp_path, suffix):
    from packages.fuzzing.orchestrator import FuzzingOrchestrator
    (tmp_path / "module.py").write_text("def parse(data: bytes):\n    return data\n" + suffix)
    plan = SimpleNamespace(target=SimpleNamespace(path=tmp_path),
                           graph_targets=[{"file": "module.py", "function": "parse"}])
    assert FuzzingOrchestrator._graph_python_entry(plan) is None


def test_local_bindings_do_not_make_a_clean_module_ambiguous(tmp_path):
    from packages.fuzzing.orchestrator import FuzzingOrchestrator
    (tmp_path / "module.py").write_text(
        "import json\n"
        "def helper():\n    parse = 7\n    return parse\n"
        "def parse(data: bytes):\n    return json.loads(data)\n")
    plan = SimpleNamespace(target=SimpleNamespace(path=tmp_path),
                           graph_targets=[{"file": "module.py", "function": "parse"}])
    assert FuzzingOrchestrator._graph_python_entry(plan) == ("module:parse", "bytes")
