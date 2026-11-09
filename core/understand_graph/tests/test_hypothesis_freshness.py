"""Hypothesis hints must refer to the current inventoried source."""

import hashlib
import json

import pytest

from core.understand_graph import hypothesis_seeds, ingest_run
from core.understand_graph.store import graph_write_txn
from core.understand_graph.tests.test_expansion import _write_understand_run


@pytest.mark.parametrize("target_supplied", [True, False], ids=["explicit", "inferred"])
@pytest.mark.parametrize("change", ["replaced", "deleted"])
def test_changed_source_is_not_a_hypothesis_hint(tmp_path, target_supplied, change):
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_understand_run(run, target)
    query_target = str(target) if target_supplied else None
    assert hypothesis_seeds(graph, query_target)[0]["function"] == "handle_request"
    source = target / "server.c"
    if change == "replaced":
        source.write_text("/* replaced source */\n")
    else:
        source.unlink()
    assert hypothesis_seeds(graph, query_target) == []


@pytest.mark.parametrize("kind", ["entry_point", "sink"])
def test_stale_endpoint_nodes_do_not_supply_hypothesis_hints(tmp_path, kind):
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_understand_run(run, target)
    assert hypothesis_seeds(graph, str(target))
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE nodes SET stale=1 WHERE kind=?", (kind,))
    assert hypothesis_seeds(graph, str(target)) == []


def test_stale_higher_ranked_function_does_not_consume_limit(tmp_path):
    target, run = tmp_path / "target", tmp_path / "run"
    _write_understand_run(run, target)
    source = target / "fresh.c"
    source.write_text("void fresh_request(void) {}\n")
    checklist = json.loads((run / "checklist.json").read_text())
    checklist["files"].append({
        "path": "fresh.c", "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "items": [{"kind": "function", "name": "fresh_request", "line_start": 1}],
    })
    checklist["total_files"] = 2
    checklist["total_items"] = 3
    (run / "checklist.json").write_text(json.dumps(checklist))
    context = json.loads((run / "context-map.json").read_text())
    context["entry_points"].append({
        "id": "EP-FRESH", "name": "fresh_request", "file": "fresh.c", "line": 1,
    })
    context["sink_details"].append({
        "id": "SINK-FRESH", "name": "copy", "file": "fresh.c", "line": 1,
    })
    context["unchecked_flows"].append({
        "entry_point": "EP-FRESH", "sink": "SINK-FRESH", "confidence": "high",
    })
    (run / "context-map.json").write_text(json.dumps(context))
    graph = ingest_run(run, str(target), graph_path=tmp_path / "combined.sqlite")
    assert hypothesis_seeds(graph, str(target), limit=1)[0]["function"] == "handle_request"
    (target / "server.c").write_text("/* changed highest ranked source */\n")
    rows = hypothesis_seeds(graph, str(target), limit=1)
    assert [row["function"] for row in rows] == ["fresh_request"]


def test_stale_sink_file_does_not_hide_remaining_fresh_flow(tmp_path):
    target, run = tmp_path / "target", tmp_path / "run"
    _write_understand_run(run, target)
    sink_source = target / "helper.c"
    sink_source.write_text("void copy(void) {}\n")
    checklist = json.loads((run / "checklist.json").read_text())
    checklist["files"].append({
        "path": "helper.c", "sha256": hashlib.sha256(sink_source.read_bytes()).hexdigest(),
        "items": [],
    })
    (run / "checklist.json").write_text(json.dumps(checklist))
    context = json.loads((run / "context-map.json").read_text())
    context["sink_details"][1]["file"] = "helper.c"
    (run / "context-map.json").write_text(json.dumps(context))
    graph = ingest_run(run, str(target), graph_path=tmp_path / "cross-file.sqlite")
    assert hypothesis_seeds(graph, str(target))[0]["flow_count"] == 2
    sink_source.write_text("/* changed sink source */\n")
    rows = hypothesis_seeds(graph, str(target))
    assert len(rows) == 1
    assert rows[0]["flow_count"] == 1
    assert rows[0]["nearby_sinks"] == ["system"]


def test_edge_from_other_snapshot_does_not_supply_hint(tmp_path):
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_understand_run(run, target)
    assert hypothesis_seeds(graph, str(target))
    with graph_write_txn(graph) as conn:
        conn.execute("INSERT INTO snapshots (id,target_path) VALUES ('other','other-target')")
        conn.execute("UPDATE edges SET snapshot_id='other' WHERE kind='REACHES'")
    assert hypothesis_seeds(graph, str(target)) == []
