"""The residual output cap applies after removing validated paths."""

import hashlib
import json

import pytest

from core.json import save_json
from core.understand_graph import attack_paths, coverage_residual, ingest_run, ingest_validation_outcomes
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


@pytest.mark.parametrize("validated_count", [0, 50, 51])
def test_residual_limit_does_not_hide_unvalidated_paths(tmp_path, validated_count):
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    source = target / "server.c"
    source.write_text("void handle_request(){\n" + "system(cmd);\n" * 51 + "}\n")
    checklist = json.loads((run / "checklist.json").read_text())
    checklist["files"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    save_json(run / "checklist.json", checklist)
    context = json.loads((run / "context-map.json").read_text())
    context["sinks"] = [
        {"id": f"SINK-{i:03d}", "name": "system", "file": "server.c", "line": i + 2}
        for i in range(51)
    ]
    context["unchecked_flows"] = [
        {"id": f"FLOW-{i:03d}", "entry_point": "EP-1", "sink": f"SINK-{i:03d}",
         "confidence": "high", "missing_boundary": "no check"}
        for i in range(51)
    ]
    save_json(run / "context-map.json", context)
    ingest_run(run, str(target), graph_path=graph)
    assert len(attack_paths(graph, str(target))) == 50
    assert len(attack_paths(graph, str(target), limit=1)) == 1
    if validated_count:
        save_json(run / "validation-outcomes.json", [
            {"finding_id": f"FLOW-{i:03d}", "status": "exploitable"}
            for i in range(validated_count)
        ])
        ingest_validation_outcomes(run, str(target), graph_path=graph)
    remaining = coverage_residual(graph, str(target))
    assert [p["sink"]["id"] for p in remaining] == [
        f"SINK-{i:03d}" for i in range(validated_count, min(51, validated_count + 50))
    ]
