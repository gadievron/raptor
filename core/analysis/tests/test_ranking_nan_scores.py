"""NaN refusal is bounded without running an unbounded metric loop."""

import pytest

from core.analysis import ranking_metrics
from core.testing.module_views import module_function_view


@pytest.fixture
def bounded_auc():
    calls = 0

    def bounded_len(value):
        nonlocal calls
        calls += 1
        if calls > 128:
            pytest.fail("AUC did not advance on a two-record NaN input")
        return len(value)

    # Run unchanged production code with private globals; do not patch
    # process builtins, share a runaway thread or launch a child process.
    return module_function_view(ranking_metrics, bindings={"len": bounded_len}).auc


@pytest.mark.parametrize("scored", [
    [(float("nan"), True), (0.0, False)],
    [(0.0, False), (float("nan"), True)],
    [(float("nan"), False), (0.0, True)],
    [(0.0, True), (float("nan"), False)],
])
def test_nan_cannot_be_ranked(bounded_auc, scored):
    with pytest.raises(ValueError, match="NaN"):
        bounded_auc(scored)


@pytest.mark.parametrize("scored, expected", [
    ([(float("inf"), True), (0.0, False)], 1.0),
    ([(float("-inf"), True), (0.0, False)], 0.0),
    ([(float("inf"), True), (float("inf"), False)], 0.5),
    ([(10 ** 1000, True), (0, False)], 1.0),
])
def test_ordered_numeric_scores_remain_valid(bounded_auc, scored, expected):
    assert bounded_auc(scored) == expected


@pytest.mark.parametrize("label", [True, False])
def test_missing_class_remains_undefined(bounded_auc, label):
    assert bounded_auc([(float("nan"), label)]) is None
