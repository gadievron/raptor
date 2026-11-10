"""Imported graph history must not become locally earned execution evidence."""

from pathlib import Path

import pytest

from core.json import save_json
from core.project.export import export_project, import_project
from core.project.project import Project
from core.testing.scratch_state import isolated_scratch_keepalive
from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph import ingest_run, ingest_validation_outcomes, rebuild_graph
from core.understand_graph.store import GRAPH_FILENAME, open_graph
from core.understand_graph.tests.test_validates_join import _write_two_flow_run


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        with isolated_scratch_keepalive():
            yield


@pytest.fixture
def monkeypatch(_user_state_in_tmp):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def _roundtrip(tmp_path, source):
    metadata = tmp_path / "project.json"
    save_json(metadata, Project(name="fixture", target=str(tmp_path / "target"),
                                output_dir=str(source)).to_dict())
    archive = export_project(source, tmp_path / "project.zip", project_json_path=metadata)
    restored = import_project(Path(archive["path"]), tmp_path / "user" / "projects",
                              output_base=tmp_path / "restored")
    return Path(restored["output_dir"])


@pytest.mark.parametrize("name", [
    GRAPH_FILENAME, GRAPH_FILENAME + "-wal", GRAPH_FILENAME + "-shm",
    GRAPH_FILENAME + "-journal", "validation-outcomes.json",
])
def test_import_retains_graph_history_outside_canonical_paths(tmp_path, name):
    source = tmp_path / "source"
    relative = Path("run") / ("graph" if name.startswith(GRAPH_FILENAME) else "") / name
    artifact = source / relative
    artifact.parent.mkdir(parents=True)
    payload = b"[]" if name.endswith(".json") else b"opaque historical data"
    artifact.write_bytes(payload)
    (source / "run" / "context-map.json").write_text("{}")
    (source / "run" / "operator-data.sqlite").write_bytes(b"ordinary opaque artifact")
    restored = _roundtrip(tmp_path, source)
    assert not (restored / relative).exists()
    assert (restored / "_imported-quarantine" / relative).read_bytes() == payload
    assert (restored / "run" / "context-map.json").read_text() == "{}"
    assert (restored / "run" / "operator-data.sqlite").read_bytes() == b"ordinary opaque artifact"


def test_graph_rebuild_uses_run_json_without_replaying_quarantined_outcomes(tmp_path, monkeypatch):
    source, target = tmp_path / "source", tmp_path / "target"
    run = source / "understand-run"
    run_graph = _write_two_flow_run(run, target)
    project_graph = source / "graph" / GRAPH_FILENAME
    assert ingest_run(run, str(target), graph_path=project_graph) == project_graph
    # Ordinary producer output, not a fabricated graph or execution claim.
    save_json(run / "validation-outcomes.json", [{"status": "inconclusive"}])
    assert ingest_validation_outcomes(run, str(target), graph_path=project_graph) == project_graph
    save_json(source / "validation-outcomes.json", [{"status": "inconclusive"}])
    graph_bytes = {path.relative_to(source): path.read_bytes() for path in (run_graph, project_graph)}
    restored = _roundtrip(tmp_path, source)
    for relative, content in graph_bytes.items():
        assert not (restored / relative).exists()
        assert (restored / "_imported-quarantine" / relative).read_bytes() == content
    assert (restored / "understand-run" / "context-map.json").exists()

    import core.understand_graph.ingest as ingesters

    original = ingesters.ingest_validation_outcomes
    replayed_outcomes = []

    def record_replay(directory, *args, **kwargs):
        replayed_outcomes.append(Path(directory))
        return original(directory, *args, **kwargs)

    monkeypatch.setattr(ingesters, "ingest_validation_outcomes", record_replay)
    rebuilt = rebuild_graph(restored)
    assert rebuilt is not None
    assert replayed_outcomes == []
    with open_graph(rebuilt) as conn:
        assert conn.execute("SELECT count(*) FROM nodes WHERE kind='entry_point'").fetchone()[0] > 0
        assert conn.execute("SELECT count(*) FROM nodes WHERE kind='verified_outcome'").fetchone()[0] == 0


def test_local_validation_inputs_remain_rebuildable(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    run = source / "understand-run"
    _write_two_flow_run(run, target)
    save_json(run / "validation-outcomes.json", [{"status": "inconclusive"}])
    rebuilt = rebuild_graph(source)
    assert rebuilt is not None
    with open_graph(rebuilt) as conn:
        assert conn.execute("SELECT count(*) FROM nodes WHERE kind='verified_outcome'").fetchone()[0] == 1
