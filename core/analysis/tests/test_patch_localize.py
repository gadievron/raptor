"""Tests for the patch-localization pipeline (rank → chains → cluster)."""

from __future__ import annotations

import re

import pytest

from core.analysis.patch_localize import (
    build_chains,
    localize,
    normalize_edges,
)

_DOC_RE = re.compile(
    r"id: (\w+)\nBEGIN_DOC_\w+\n(.*?)\nEND_DOC_\w+", re.S,
)
_VALUE_RE = re.compile(r"value=(-?\d+)")


class _Response:
    def __init__(self, result):
        self.result = result
        self.cost = 0.001


class FakeRankClient:
    """Ranks chains by the max ``value=N`` across the chain's
    function texts, descending (higher = more advisory-relevant)."""

    def generate_structured(self, prompt, schema, **kwargs):
        docs = _DOC_RE.findall(prompt)
        scored = sorted(
            ((max(int(v) for v in _VALUE_RE.findall(text) or ["0"]), bid)
             for bid, text in docs),
            reverse=True,
        )
        return _Response({"ranked_ids": [bid for _v, bid in scored]})


def _cand(name, value):
    return {"function": name, "text": f"{name} does things value={value}"}


def test_build_chains_singles_and_candidate_pairs_only():
    candidates = [_cand("a", 1), _cand("b", 2), _cand("c", 3)]
    edges = [("a", "b"), ("b", "x"), ("x", "c"), ("a", "a"), ("a", "b")]
    chains = build_chains(candidates, edges)
    singles = [c["functions"] for c in chains if len(c["functions"]) == 1]
    pairs = [c["functions"] for c in chains if len(c["functions"]) == 2]
    assert sorted(f[0] for f in singles) == ["a", "b", "c"]
    # Only a->b qualifies: b->x and x->c cross out of the candidate
    # set, self-edges and duplicates are dropped.
    assert pairs == [["a", "b"]]


def test_build_chains_tolerates_malformed_candidates():
    chains = build_chains(
        ["junk", {"text": "no name"}, _cand("ok", 1), _cand("ok", 1)],
        [],
    )
    assert [c["functions"] for c in chains] == [["ok"]]


def test_localize_end_to_end_surfaces_the_hot_neighbourhood():
    # auth trio carries the advisory signal; the rest is noise.
    candidates = (
        [_cand(f"noise{i}", i) for i in range(1, 9)]
        + [_cand("auth_check", 900),
           _cand("session_get", 800),
           _cand("cookie_parse", 700)]
    )
    edges = [
        ("auth_check", "session_get"),
        ("session_get", "cookie_parse"),
        ("noise1", "noise2"),
    ]
    report = localize(
        candidates, edges, "authentication bypass via session cookies",
        client=FakeRankClient(), seed=7, max_workers=1,
    )
    # Ranked chains: permutation of singles + candidate pairs.
    functions_seen = {f for c in report["chains"] for f in c["functions"]}
    assert functions_seen == {c["function"] for c in candidates}
    assert report["chains"][0]["rank"] == 1
    # The top cluster is the auth neighbourhood.
    top = report["clusters"][0]
    assert set(top["members"]) >= {"auth_check", "session_get"}
    assert "noise5" not in top["members"]
    assert report["stats"]["llm_calls"] > 0
    assert report["stats"]["cost_usd"] > 0


def test_localize_survivor_fallback_when_no_refinement():
    # Small corpus converges by order stability in one iteration —
    # nothing has iterations > 1, so everything survives to
    # clustering rather than nothing.
    candidates = [_cand("a", 3), _cand("b", 2), _cand("c", 1)]
    report = localize(
        candidates, [("a", "b")], "advisory",
        client=FakeRankClient(), seed=1, max_workers=1,
    )
    assert report["survivors"] == report["stats"]["chains_total"]
    assert report["clusters"]


def test_localize_rejects_empty_candidates():
    with pytest.raises(ValueError):
        localize([], [], "advisory", client=FakeRankClient())


def test_normalize_edges_rejects_dict_string_and_arity():
    assert normalize_edges([["a", "b"], ("c", 4)]) == [
        ("a", "b"), ("c", "4"),
    ]
    for bad in ([{"caller": "f", "callee": "g"}], ["ab"], [["a"]],
                [["a", "b", "c"]], "not a list"):
        with pytest.raises(ValueError):
            normalize_edges(bad)


def test_chain_cap_keeps_singles_and_reports_truncation():
    candidates = [_cand(f"f{i}", i) for i in range(6)]
    # Dense graph: 6 singles + up to 30 pairs; cap at 10 keeps all
    # singles plus the first 4 pairs and reports the drop.
    edges = [(f"f{i}", f"f{j}") for i in range(6) for j in range(6)
             if i != j]
    report = localize(
        candidates, edges, "advisory", client=FakeRankClient(),
        max_chains=10, seed=1, max_workers=1,
    )
    assert report["stats"]["chains_total"] == 10
    assert report["stats"]["chains_truncated"] == 26
    singles = [c for c in report["chains"] if len(c["functions"]) == 1]
    assert len(singles) == 6  # every candidate stays represented


def test_render_caps_untrusted_function_names():
    huge_name = "n" * 100_000
    candidates = [
        {"function": huge_name, "text": "value=9"},
        _cand("small", 1), _cand("tiny", 2),
    ]
    client = FakeRankClient()
    captured = {}
    original = client.generate_structured

    def spy(prompt, schema, **kwargs):
        captured["len"] = max(captured.get("len", 0), len(prompt))
        return original(prompt, schema, **kwargs)

    client.generate_structured = spy
    localize(candidates, [], "advisory", client=client, seed=1,
             max_workers=1)
    assert captured["len"] < 10_000


def test_duplicate_candidate_names_first_occurrence_wins():
    candidates = [
        {"function": "f", "text": "FIRST value=5"},
        {"function": "f", "text": "SECOND value=1"},
        _cand("g", 2), _cand("h", 3),
    ]
    client = FakeRankClient()
    captured = []
    original = client.generate_structured

    def spy(prompt, schema, **kwargs):
        captured.append(prompt)
        return original(prompt, schema, **kwargs)

    client.generate_structured = spy
    localize(candidates, [], "advisory", client=client, seed=1,
             max_workers=1)
    joined = "\n".join(captured)
    assert "FIRST" in joined
    assert "SECOND" not in joined


def test_localize_caps_candidate_text():
    big = {"function": "big", "text": "value=9 " + "x" * 50_000}
    client = FakeRankClient()
    captured = {}

    original = client.generate_structured

    def spy(prompt, schema, **kwargs):
        captured["len"] = len(prompt)
        return original(prompt, schema, **kwargs)

    client.generate_structured = spy
    localize(
        [big, _cand("small", 1), _cand("tiny", 2)], [], "advisory",
        client=client, seed=1, max_workers=1,
    )
    assert captured["len"] < 10_000  # cap applied, prompt stays small
