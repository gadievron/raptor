"""Malformed numeric counts must not discard healthy ranked chains."""
import pytest

from core.analysis import rank_clusters as mod


@pytest.fixture(autouse=True)
def no_graph_work(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("weight-only test attempted graph work")
    for name in ("rank_clusters", "_ball", "_adjacency"):
        monkeypatch.setattr(mod, name, forbidden)


@pytest.mark.parametrize("field", ["rank", "iterations"])
@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")],
                         ids=["positive-infinity", "negative-infinity", "nan"])
def test_nonfinite_count_keeps_healthy_neighbor(field, value):
    bad = {"functions": ["owned-bad"], "rank": 1, "iterations": 1}
    bad[field] = value
    good = {"functions": ["owned-good"], "rank": 2, "iterations": 3}
    result = mod.weight_functions([bad, good])
    assert set(result) == {"owned-good"}
    assert result["owned-good"].weight == 1.5
    assert result["owned-good"].best_rank == 2
    assert result["owned-good"].iterations == 3


def test_existing_numeric_text_coercion_remains():
    result = mod.weight_functions([{"functions": ["owned"], "rank": "2", "iterations": "3"}])
    assert result["owned"].weight == 1.5
