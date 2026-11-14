"""Malformed function collections do not discard healthy chain neighbors."""
from collections import UserDict
from copy import deepcopy

import pytest

from core.analysis import rank_clusters as mod


@pytest.fixture(autouse=True)
def no_graph_or_localization(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("weight-only test entered graph clustering")
    for name in ("rank_clusters", "_ball", "_adjacency"):
        monkeypatch.setattr(mod, name, forbidden)


@pytest.mark.parametrize("functions", [7, True, 1.5, {"owned-fake": 1}, UserDict({"owned-fake": 1}), "owned-fake", b"owned-fake"],
                         ids=["integer", "boolean", "float", "object", "mapping", "text", "bytes"])
def test_malformed_function_collection_keeps_healthy_neighbor(functions):
    malformed = {"functions": functions, "rank": 1, "iterations": 1}
    healthy = {"functions": ["owned-healthy"], "rank": 2, "iterations": 2}
    before = deepcopy([malformed, healthy])
    weights = mod.weight_functions([malformed, healthy])
    assert set(weights) == {"owned-healthy"}
    assert weights["owned-healthy"].weight == 1.0
    assert [malformed, healthy] == before


class GetitemSequence:
    def __getitem__(self, index):
        return ["owned-first", "owned-second"][index]


@pytest.mark.parametrize("mode", ["list", "tuple", "generator", "sequence"],
                         ids=["list", "tuple", "generator", "sequence"])
def test_existing_function_iterables_are_preserved(mode):
    values = ["owned-first", "owned-second"]
    functions = {"list": values, "tuple": tuple(values), "generator": iter(values),
                 "sequence": GetitemSequence()}[mode]
    weights = mod.weight_functions([{"functions": functions, "rank": 2, "iterations": 2}])
    assert set(weights) == set(values)
    assert all(item.weight == 1.0 for item in weights.values())


class AcquireFailure:
    def __iter__(self):
        raise TypeError("owned iterator acquisition failure")


def test_iterator_acquisition_typeerror_skips_only_malformed_chain():
    weights = mod.weight_functions([
        {"functions": AcquireFailure(), "rank": 1},
        {"functions": ["owned-healthy"], "rank": 2},
    ])
    assert set(weights) == {"owned-healthy"}


@pytest.mark.parametrize("error", [TypeError, KeyboardInterrupt, SystemExit], ids=["body-typeerror", "interrupt", "exit"])
def test_iterator_body_error_keeps_identity(error):
    primary = error("owned iterator body failure")

    def values():
        yield "owned-first"
        raise primary

    with pytest.raises(error) as exc:
        mod.weight_functions([{"functions": values(), "rank": 1}])
    assert exc.value is primary
