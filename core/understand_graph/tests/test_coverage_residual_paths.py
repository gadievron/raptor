"""Validation of one path must not hide another path to the same sink."""

import hashlib
import json

import pytest

from core.json import save_json
from core.understand_graph import attack_paths, coverage_residual, ingest_run, ingest_validation_outcomes
from core.understand_graph.store import graph_write_txn
from core.understand_graph.tests.test_validates_join import _write_two_flow_run


from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        yield


@pytest.fixture
def monkeypatch(_user_state_in_tmp):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def _shared_sink_graph(tmp_path, section="entry_points"):
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    source = target / "server.c"
    source.write_text("void handle_request(){system(cmd);}\nvoid other_request(){system(cmd);}\n")
    checklist = json.loads((run / "checklist.json").read_text())
    checklist["files"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    checklist["files"][0]["items"].append({"name": "other_request", "line_start": 2})
    checklist["total_items"] = 2
    save_json(run / "checklist.json", checklist)
    context = json.loads((run / "context-map.json").read_text())
    context["entry_points"].append({
        "id": "EP-2", "name": "other_request", "file": "server.c", "line": 2,
    })
    if section == "sources":
        context["sources"] = context.pop("entry_points")
    context["unchecked_flows"][1].update({"entry_point": "EP-2", "sink": "SINK-1"})
    save_json(run / "context-map.json", context)
    ingest_run(run, str(target), graph_path=graph)
    assert {(p["entry"]["id"], p["sink"]["id"]) for p in attack_paths(graph, str(target))} == {
        ("EP-1", "SINK-1"), ("EP-2", "SINK-1"),
    }
    return graph, target, run


@pytest.mark.parametrize("section", ["entry_points", "sources"])
def test_validating_one_entry_does_not_hide_another_entry_to_the_same_sink(tmp_path, section):
    graph, target, run = _shared_sink_graph(tmp_path, section)
    save_json(run / "validation-outcomes.json", [{"finding_id": "FLOW-1", "status": "exploitable"}])
    ingest_validation_outcomes(run, str(target), graph_path=graph)
    remaining = coverage_residual(graph, str(target))
    assert [(p["entry"]["id"], p["sink"]["id"]) for p in remaining] == [("EP-2", "SINK-1")]
    save_json(run / "validation-outcomes.json", [
        {"finding_id": "FLOW-1", "status": "exploitable"},
        {"finding_id": "FLOW-2", "status": "exploitable"},
    ])
    ingest_validation_outcomes(run, str(target), graph_path=graph)
    assert coverage_residual(graph, str(target)) == []


def test_sink_link_without_source_link_does_not_validate_a_path(tmp_path):
    graph, target, run = _shared_sink_graph(tmp_path)
    save_json(run / "validation-outcomes.json", [{"finding_id": "FLOW-1", "status": "exploitable"}])
    ingest_validation_outcomes(run, str(target), graph_path=graph)
    with graph_write_txn(graph) as conn:
        conn.execute("DELETE FROM edges WHERE kind='HAS_SOURCE' AND src_id IN "
                     "(SELECT dst_id FROM edges WHERE kind='VALIDATES')")
    assert {(p["entry"]["id"], p["sink"]["id"]) for p in coverage_residual(graph, str(target))} == {
        ("EP-1", "SINK-1"), ("EP-2", "SINK-1"),
    }
