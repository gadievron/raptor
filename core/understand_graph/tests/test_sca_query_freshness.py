"""Omitting a query target must still verify current snapshot source."""

import pytest

from core.understand_graph import attack_paths, build_context_map, sca_reachability, sca_reachability_batch
from core.understand_graph.tests.test_pipeline_integration import _seed


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


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
@pytest.mark.parametrize("change", ["replaced", "deleted"])
def test_inferred_sca_target_excludes_changed_source(tmp_path, batch, change):
    target = tmp_path / "target"
    graph = _seed(tmp_path / "run", target)

    def query(query_target=None):
        if batch:
            return sca_reachability_batch(graph, ["example-dep", "unknown", "example-dep"], query_target)
        return sca_reachability(graph, "example-dep", query_target)

    fresh = query(str(target))
    assert fresh
    assert query() == fresh
    source = target / "server.py"
    if change == "replaced":
        source.write_text("# changed since the snapshot\n")
    else:
        source.unlink()
    assert query(str(target)) == ({} if batch else [])
    assert query() == ({} if batch else [])


@pytest.mark.parametrize("change", ["replaced", "deleted"])
def test_inferred_context_target_excludes_changed_source(tmp_path, change):
    target = tmp_path / "target"
    graph = _seed(tmp_path / "run", target)
    context, stale = build_context_map(graph)
    assert context["entry_points"] and context["sink_details"]
    assert not stale
    assert attack_paths(graph)
    source = target / "server.py"
    if change == "replaced":
        source.write_text("# changed since the snapshot\n")
    else:
        source.unlink()
    context, stale = build_context_map(graph)
    assert stale == {"server.py"}
    assert not context.get("entry_points") and not context.get("sink_details")
    assert attack_paths(graph) == []
