"""Path-query zero quotas do not return over-budget positive evidence."""

import pytest

from core.analysis import package_callgraph as calls


@pytest.fixture
def owned_graph(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("hand-built graph query entered package assembly/resolution")

    for name in ("build_package_callgraph", "_collect_file", "_find_method"):
        monkeypatch.setattr(calls, name, forbidden)
    nodes = tuple(
        calls.CallGraphNode(name, "function", "owned.py", name, "owned", line)
        for line, name in enumerate(("source", "target"), 1)
    )
    return calls.PackageCallGraph(
        nodes=nodes,
        edges=(calls.CallGraphEdge("source", "target", calls.TIER_RESOLVED_STATIC, calls.KIND_CALL),),
    )


@pytest.mark.parametrize("destination", ["source", "target"])
def test_zero_path_quota_returns_no_paths(owned_graph, destination):
    result = owned_graph.paths_found("source", destination, max_paths=0)
    assert result.paths == ()
    assert result.budget_exhausted


def test_zero_depth_excludes_direct_edge(owned_graph):
    result = owned_graph.paths_found("source", "target", max_depth=0)
    assert result.paths == ()
    assert result.budget_exhausted


def test_zero_depth_and_expansions_allow_zero_edge_self_path(owned_graph):
    result = owned_graph.paths_found("source", "source", max_depth=0, max_expansions=0)
    assert result.paths == (("source",),)
    assert not result.budget_exhausted


def test_zero_expansion_quota_excludes_direct_edge(owned_graph):
    result = owned_graph.paths_found("source", "target", max_expansions=0)
    assert result.paths == ()
    assert result.budget_exhausted


def test_positive_quotas_keep_direct_path(owned_graph):
    result = owned_graph.paths_found("source", "target", max_paths=1, max_depth=1, max_expansions=1)
    assert result.paths == (("source", "target"),)
    assert result.budget_exhausted


def test_unknown_node_handling_precedes_zero_quotas(owned_graph):
    result = owned_graph.paths_found("missing", "missing", max_paths=0, max_depth=0, max_expansions=0)
    assert result.paths == ()
    assert not result.budget_exhausted
