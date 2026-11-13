"""Oversized weighted balls are rejected without changing retained clusters."""
from dataclasses import asdict

import pytest

from core.analysis import rank_clusters as cluster


def _blob_inputs():
    # Same rejected blob and retained trio as the existing ranking fixture.
    spokes = [f"s{i}" for i in range(30)]
    chains = [{"functions": spokes, "rank": 3, "iterations": 3},
              {"functions": ["h1", "h2", "h3"], "rank": 1, "iterations": 3}]
    edges = [("hub", name) for name in spokes] + [("h1", "h2"), ("h2", "h3")]
    return chains, edges


def _run(monkeypatch, chains, edges, *, unbounded=False, **kwargs):
    original_adjacency = cluster._adjacency
    original_ball = cluster._ball
    visits = []

    class ObservedNeighbours(set):
        def __iter__(self):
            for value in super().__iter__():
                visits.append(value)
                yield value

    def adjacency(values):
        return {key: ObservedNeighbours(value)
                for key, value in original_adjacency(values).items()}

    def full_ball(seed, adj, radius, **ignored):
        # Exercise the original full traversal through the helper's defaults.
        return original_ball(seed, adj, radius)

    with monkeypatch.context() as owned:
        owned.setattr(cluster, "_adjacency", adjacency)
        if unbounded:
            owned.setattr(cluster, "_ball", full_ball)
        result = cluster.rank_clusters(chains, edges, **kwargs)
    return asdict(result), len(visits)


def test_rejected_existing_blob_visits_fewer_neighbours(monkeypatch):
    chains, edges = _blob_inputs()
    full, full_visits = _run(monkeypatch, chains, edges, unbounded=True)
    actual, visits = _run(monkeypatch, chains, edges)
    assert actual == full
    assert full_visits == 974
    assert visits < full_visits
    assert all(len(row["members"]) <= 16 for row in actual["clusters"])
    assert actual["clusters"][0]["members"] == ("h1", "h2", "h3")


@pytest.mark.parametrize("cap", [-1, 0, 1, 2, 3, 16, 30, 16.5, True, False])
def test_member_cap_preserves_complete_report(monkeypatch, cap):
    chains, edges = _blob_inputs()
    full, _ = _run(monkeypatch, chains, edges, unbounded=True, max_members=cap)
    actual, _ = _run(monkeypatch, chains, edges, max_members=cap)
    assert actual == full


def test_unweighted_connectors_do_not_consume_member_cap(monkeypatch):
    chains = [{"functions": ["a", "b", "c"], "rank": 1, "iterations": 2}]
    edges = [("a", "mid1"), ("mid1", "mid2"), ("mid2", "b")]
    full, _ = _run(monkeypatch, chains, edges, unbounded=True,
                   radii=(3,), max_members=2)
    actual, _ = _run(monkeypatch, chains, edges, radii=(3,), max_members=2)
    assert actual == full
    assert actual["clusters"][0]["members"] == ("a", "b")


def test_rejection_does_not_cross_the_requested_radius(monkeypatch):
    chains = [{"functions": ["a", "b", "c"], "rank": 1, "iterations": 2}]
    edges = [("a", "b"), ("b", "c")]
    full, _ = _run(monkeypatch, chains, edges, unbounded=True,
                   radii=(1, 2), max_members=2)
    actual, _ = _run(monkeypatch, chains, edges, radii=(1, 2), max_members=2)
    assert actual == full
    assert {row["members"] for row in actual["clusters"]} == {("a", "b"), ("b", "c")}
    assert all(row["radius"] == 1 for row in actual["clusters"])


def test_nonliteral_caps_keep_complete_traversal(monkeypatch):
    class IntCap(int):
        pass

    class ComparedCap:
        def __lt__(self, members):
            return 16 < members

    chains, edges = _blob_inputs()
    for cap in (IntCap(16), ComparedCap(), 16.5, True, False):
        full, full_visits = _run(monkeypatch, chains, edges, unbounded=True,
                                 max_members=cap)
        actual, visits = _run(monkeypatch, chains, edges, max_members=cap)
        assert actual == full
        assert visits == full_visits == 974


def test_direct_ball_keeps_full_neighbourhood():
    adj = cluster._adjacency([("a", "mid"), ("mid", "b")])
    assert cluster._ball("a", adj, 2) == {"a", "mid", "b"}
