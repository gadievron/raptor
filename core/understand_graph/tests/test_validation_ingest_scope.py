"""Validation references belong to one target and its current producer snapshot."""

import pytest

from core.json import save_json
from core.understand_graph import (
    ingest_codeql_sarif,
    ingest_run,
    ingest_scan_findings,
    ingest_validation_outcomes,
)
from core.understand_graph.store import graph_write_txn, open_graph
from core.understand_graph.tests.test_expansion import _write_sarif
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


def _validate(run, target, graph):
    save_json(run / "validation-outcomes.json", [
        {"finding_id": "FLOW-1", "status": "exploitable"},
    ])
    ingest_validation_outcomes(run, str(target), graph_path=graph)


def test_reused_ids_bind_only_the_outcomes_target(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first_run, second_run = tmp_path / "run-first", tmp_path / "run-second"
    graph = _write_two_flow_run(first_run, first)
    _write_two_flow_run(second_run, second)
    ingest_run(second_run, str(second), graph_path=graph)
    # Both targets must work: whichever row an unscoped LIMIT 1 picks,
    # it cannot be correct for both references to the same display id.
    _validate(first_run, first, graph)
    _validate(second_run, second, graph)
    with open_graph(graph) as conn:
        rows = conn.execute(
            "SELECT vs.target_path AS outcome_target, fs.target_path AS finding_target "
            "FROM edges v JOIN nodes n ON n.id=v.dst_id "
            "JOIN snapshots vs ON vs.id=v.snapshot_id "
            "JOIN snapshots fs ON fs.id=n.snapshot_id WHERE v.kind='VALIDATES'"
        ).fetchall()
    assert len(rows) == 2
    assert all(row["outcome_target"] == row["finding_target"] for row in rows)


@pytest.mark.parametrize("reused_id", [True, False], ids=["reused", "absent"])
def test_validation_uses_latest_snapshot_without_historical_fallback(tmp_path, reused_id):
    target, old_run, new_run = tmp_path / "target", tmp_path / "old", tmp_path / "new"
    graph = _write_two_flow_run(old_run, target)
    _write_two_flow_run(new_run, target,
                        flow_ids=("FLOW-1" if reused_id else "NEW-FLOW", "FLOW-2"))
    ingest_run(new_run, str(target), graph_path=graph)
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE snapshots SET created_at='2000-01-01' WHERE producer='understand'")
        conn.execute("UPDATE snapshots SET created_at='2001-01-01' WHERE producer_run=?",
                     (str(new_run.resolve()),))
    _validate(new_run, target, graph)
    with open_graph(graph) as conn:
        rows = conn.execute(
            "SELECT s.producer_run FROM edges v JOIN nodes n ON n.id=v.dst_id "
            "JOIN snapshots s ON s.id=n.snapshot_id WHERE v.kind='VALIDATES'"
        ).fetchall()
    assert [row["producer_run"] for row in rows] == ([str(new_run.resolve())] if reused_id else [])


@pytest.mark.parametrize("kind", ["scan_finding", "codeql_result"])
def test_non_understand_producer_identity_still_joins(tmp_path, kind):
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    if kind == "scan_finding":
        save_json(run / "findings.json", [
            {"id": "SCAN-1", "rule_id": "r1", "file": "server.c", "message": "review"},
        ])
        ingest_scan_findings(run, str(target), graph_path=graph)
    else:
        _write_sarif(run)
        ingest_codeql_sarif(run, str(target), graph_path=graph)
    with open_graph(graph) as conn:
        node = conn.execute("SELECT id, stable_key FROM nodes WHERE kind=?", (kind,)).fetchone()
        assert node is not None
        node_id, ref = node["id"], node["stable_key"].split("://", 1)[1]
    save_json(run / "validation-outcomes.json", [{"finding_id": ref, "status": "exploitable"}])
    ingest_validation_outcomes(run, str(target), graph_path=graph)
    with open_graph(graph) as conn:
        assert [row["dst_id"] for row in conn.execute(
            "SELECT dst_id FROM edges WHERE kind='VALIDATES'",
        )] == [node_id]
