"""Default diff endpoints stay with the selected target in shared stores."""

import pytest

from core.understand_graph import graph_diff, ingest_run
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


def _interleaved_targets(tmp_path):
    graph = None
    snapshots = {}
    for i, (target_name, run_name) in enumerate([
        ("a", "a-old"), ("b", "b-old"), ("a", "a-new"), ("b", "b-new"),
    ]):
        target, run = tmp_path / target_name, tmp_path / run_name
        seeded = _write_two_flow_run(run, target)
        graph = graph or seeded
        if seeded != graph:
            ingest_run(run, str(target), graph_path=graph)
        with graph_write_txn(graph) as conn:
            conn.execute("UPDATE snapshots SET created_at=? WHERE producer_run=?",
                         (f"200{i}-01-01", str(run.resolve())))
            snapshots[run_name] = conn.execute(
                "SELECT id FROM snapshots WHERE producer_run=?", (str(run.resolve()),),
            ).fetchone()["id"]
    return graph, snapshots


@pytest.mark.parametrize("anchor", ["head", "base", "latest"])
def test_default_diff_endpoint_stays_in_anchored_target(tmp_path, anchor):
    graph, snapshots = _interleaved_targets(tmp_path)
    kwargs = {}
    if anchor == "head":
        kwargs["head_snapshot"] = snapshots["a-new"]
    elif anchor == "base":
        kwargs["base_snapshot"] = snapshots["a-old"]
    diff = graph_diff(graph, **kwargs)
    expected = ("b-old", "b-new") if anchor == "latest" else ("a-old", "a-new")
    assert diff["is_diffable"]
    assert diff["base_snapshot"]["id"] == snapshots[expected[0]]
    assert diff["head_snapshot"]["id"] == snapshots[expected[1]]


def test_explicit_cross_target_pair_remains_supported(tmp_path):
    graph, snapshots = _interleaved_targets(tmp_path)
    diff = graph_diff(graph, base_snapshot=snapshots["a-old"], head_snapshot=snapshots["b-new"])
    assert diff["is_diffable"]
    assert diff["base_snapshot"]["id"] == snapshots["a-old"]
    assert diff["head_snapshot"]["id"] == snapshots["b-new"]


def test_unknown_target_does_not_borrow_an_automatic_diff_endpoint(tmp_path):
    graph, snapshots = _interleaved_targets(tmp_path)
    with graph_write_txn(graph) as conn:
        conn.execute("UPDATE snapshots SET target_path='' WHERE id=?", (snapshots["a-new"],))
    assert not graph_diff(graph, head_snapshot=snapshots["a-new"])["is_diffable"]
