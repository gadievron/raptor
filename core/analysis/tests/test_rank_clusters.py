"""Tests for call-graph cluster analysis over ranking output."""

from __future__ import annotations

import pytest

from core.analysis.rank_clusters import (
    rank_clusters,
    weight_functions,
)


def _chain(functions, rank, iterations=1):
    return {"functions": functions, "rank": rank, "iterations": iterations}


def test_weight_is_best_rank_and_max_iterations_across_chains():
    weights = weight_functions([
        _chain(["a", "b"], rank=4, iterations=2),
        _chain(["a"], rank=2, iterations=1),
        _chain(["b", "c"], rank=8, iterations=5),
    ])
    # a: best rank 2, max iterations 2 -> 1.0
    assert weights["a"].weight == pytest.approx(1.0)
    assert weights["a"].best_rank == 2
    assert weights["a"].iterations == 2
    # b: best rank 4, max iterations 5 -> 1.25
    assert weights["b"].weight == pytest.approx(1.25)
    # c: 5/8
    assert weights["c"].weight == pytest.approx(0.625)


def test_malformed_chains_are_skipped():
    weights = weight_functions([
        "not a dict",
        {"functions": ["x"]},  # no rank
        {"functions": ["x"], "rank": 0},  # invalid rank
        {"functions": ["x"], "rank": "nope"},
        _chain(["ok"], rank=1),
    ])
    assert set(weights) == {"ok"}


def test_ball_distance_conducts_through_unweighted_nodes():
    # a -- mid -- b where mid never appeared in a ranked chain: at
    # radius 2, a's cluster reaches b through mid, but mid itself is
    # not a member.
    chains = [_chain(["a"], 1, 2), _chain(["b"], 2, 2)]
    edges = [("a", "mid"), ("mid", "b")]
    report = rank_clusters(chains, edges, radii=(2,))
    top = report.clusters[0]
    assert top.members == ("a", "b")
    assert "mid" not in top.members


def test_score_is_mass_times_density():
    chains = [_chain(["a"], 1, 2), _chain(["b"], 2, 2)]
    edges = [("a", "b")]
    report = rank_clusters(chains, edges, radii=(1,))
    top = report.clusters[0]
    # weights: a = 2/1 = 2.0, b = 2/2 = 1.0; mass 3.0, density 1.5.
    assert top.mass == pytest.approx(3.0)
    assert top.density == pytest.approx(1.5)
    assert top.score == pytest.approx(4.5)


def test_concentrated_cluster_beats_isolated_heavy_node():
    # The paper's payoff: a connected neighbourhood of solid weights
    # outranks a lone heavyweight (mass x density rewards both).
    chains = [
        _chain(["log"], rank=1, iterations=5),          # w = 5.0, isolated
        _chain(["auth1"], rank=1, iterations=5),        # w = 5.0
        _chain(["auth2"], rank=1, iterations=5),        # w = 5.0
        _chain(["auth3"], rank=2, iterations=5),        # w = 2.5
    ]
    edges = [("auth1", "auth2"), ("auth2", "auth3")]
    report = rank_clusters(chains, edges, radii=(1, 2, 3))
    top = report.clusters[0]
    assert set(top.members) == {"auth1", "auth2", "auth3"}
    # (12.5)^2 / 3 ~ 52.1 > lone log's 25.0
    assert top.score == pytest.approx(12.5 ** 2 / 3)
    assert any(c.members == ("log",) for c in report.clusters)


def test_duplicate_member_sets_deduplicated_keeping_smallest_radius():
    chains = [_chain(["a"], 1, 2), _chain(["b"], 2, 2)]
    edges = [("a", "b")]
    report = rank_clusters(chains, edges, radii=(1, 2, 3))
    pairs = [c for c in report.clusters if c.members == ("a", "b")]
    assert len(pairs) == 1
    assert pairs[0].radius == 1


def test_flat_weight_blob_is_skipped_not_ranked_first():
    # 30 flat-weight functions around one unweighted hub would score
    # 30.0 as a single radius-2 ball and bury a tight heavy trio
    # (score 27.0); the max_members guard keeps the blob out.
    spokes = [f"s{i}" for i in range(30)]
    chains = [_chain(spokes, rank=3, iterations=3)]  # w = 1.0 each
    chains += [_chain(["h1", "h2", "h3"], rank=1, iterations=3)]  # w = 3.0
    edges = [("hub", s) for s in spokes] + [("h1", "h2"), ("h2", "h3")]
    report = rank_clusters(chains, edges, radii=(1, 2))
    assert set(report.clusters[0].members) == {"h1", "h2", "h3"}
    assert all(len(c.members) <= 16 for c in report.clusters)


def test_string_functions_field_is_skipped():
    assert weight_functions([{"functions": "abc", "rank": 1}]) == {}


def test_null_iterations_defaults_to_one():
    weights = weight_functions(
        [{"functions": ["x"], "rank": 2, "iterations": None}],
    )
    assert weights["x"].weight == pytest.approx(0.5)


def test_empty_inputs():
    report = rank_clusters([], [])
    assert report.weights == {}
    assert report.clusters == []
    report = rank_clusters([_chain(["a"], 1)], [])
    assert [c.members for c in report.clusters] == [("a",)]


def test_deterministic_ordering_on_ties():
    chains = [_chain(["a"], 2, 2), _chain(["z"], 2, 2)]
    report = rank_clusters(chains, [], radii=(1,))
    # Equal scores: tie broken by seed name.
    assert [c.seed for c in report.clusters] == ["a", "z"]
