"""Membership indexing must retain the original scan's order and multiplicity."""

import random
from types import SimpleNamespace

from core.audit.gap_index import select_peer_gaps


def original(gaps, siblings):
    return [g for g in gaps if any(
        s.function == g.get("name") and s.file == g.get("file") for s in siblings)]


def test_duplicates_missing_values_and_identity():
    one = {"name": "f", "file": "a.c"}
    gaps = [one, {}, {"name": "", "file": ""}, one, {"name": "f", "file": "b.c"}]
    siblings = [SimpleNamespace(function="f", file="a.c"),
                SimpleNamespace(function=None, file=None),
                SimpleNamespace(function="f", file="a.c")]
    actual = select_peer_gaps(gaps, siblings)
    expected = original(gaps, siblings)
    assert actual == expected
    assert all(a is b for a, b in zip(actual, expected))
    assert actual[0] is actual[2] is one


def test_randomized_differential():
    rng = random.Random(125)
    identities = (None, "", "f", "g", "a.c", "b.c")
    for _ in range(200):
        gaps = [{"name": rng.choice(identities), "file": rng.choice(identities)}
                for _ in range(100)]
        siblings = [SimpleNamespace(function=rng.choice(identities), file=rng.choice(identities))
                    for _ in range(rng.randrange(20))]
        actual = select_peer_gaps(gaps, siblings)
        expected = original(gaps, siblings)
        assert len(actual) == len(expected)
        assert all(a is b for a, b in zip(actual, expected))


def test_nonhashable_producer_values_fall_back():
    gaps = [{"name": ["f"], "file": "a.c"}, {"name": "f", "file": {"path": "a.c"}}]
    for siblings in ([SimpleNamespace(function=["f"], file="a.c")],
                     [SimpleNamespace(function="f", file="a.c")]):
        assert select_peer_gaps(gaps, siblings) == original(gaps, siblings)


def test_empty_siblings_and_generator_semantics():
    assert select_peer_gaps([None], []) == []
    gaps = [{"name": "f", "file": "a.c"}] * 2
    make_siblings = lambda: iter([SimpleNamespace(function="f", file="a.c")])
    assert select_peer_gaps(gaps, make_siblings()) == original(gaps, make_siblings())
