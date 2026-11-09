"""Historical or stale validation must not suppress current unresolved paths."""

import pytest

from core.json import save_json
from core.understand_graph import coverage_residual, ingest_run, ingest_validation_outcomes
from core.understand_graph.store import graph_write_txn
from core.understand_graph.tests.test_validates_join import _write_two_flow_run


def _validated_graph(tmp_path):
    target, run = tmp_path / "target", tmp_path / "old"
    graph = _write_two_flow_run(run, target)
    save_json(run / "validation-outcomes.json", [
        {"finding_id": "FLOW-1", "status": "exploitable"},
    ])
    ingest_validation_outcomes(run, str(target), graph_path=graph)
    assert {p["sink"]["id"] for p in coverage_residual(graph, str(target))} == {"SINK-2"}
    return graph, target


@pytest.mark.parametrize("target_supplied", [True, False], ids=["explicit", "inferred"])
def test_old_validation_does_not_suppress_new_snapshot(tmp_path, target_supplied):
    graph, target = _validated_graph(tmp_path)
    new_run = tmp_path / "new"
    _write_two_flow_run(new_run, target)
    ingest_run(new_run, str(target), graph_path=graph)
    # Deterministic ordering, independent of the host clock resolution.
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE snapshots SET created_at='2000-01-01' WHERE producer='understand'")
        conn.execute("UPDATE snapshots SET created_at='2001-01-01' WHERE producer_run=?",
                     (str(new_run.resolve()),))
    query_target = str(target) if target_supplied else None
    paths = coverage_residual(graph, query_target)
    assert {p["sink"]["id"] for p in paths} == {"SINK-1", "SINK-2"}


def test_stale_validation_outcome_does_not_suppress_path(tmp_path):
    graph, target = _validated_graph(tmp_path)
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE nodes SET stale=1 WHERE kind='verified_outcome'")
    paths = coverage_residual(graph, str(target))
    assert {p["sink"]["id"] for p in paths} == {"SINK-1", "SINK-2"}


@pytest.mark.parametrize("outcome_target", ["other", ""])
def test_persisted_validation_from_another_target_does_not_suppress_path(tmp_path, outcome_target):
    graph, target = _validated_graph(tmp_path)
    with graph_write_txn(graph) as conn:
        # Model a VALIDATES edge minted by the former unscoped ingestion:
        # its destination is current, but its outcome belongs elsewhere.
        conn.execute("UPDATE snapshots SET target_path=? WHERE producer='validate'",
                     (str(tmp_path / outcome_target) if outcome_target else "",))
    assert {p["sink"]["id"] for p in coverage_residual(graph, str(target))} == {"SINK-1", "SINK-2"}
