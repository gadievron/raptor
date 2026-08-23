"""Unit tests for ``core.llm.ranking`` (listwise LLM ranking).

No real LLM: a fake client parses the batch prompt and orders items
by a numeric value embedded in each rendered document, optionally
with deterministic noise. All runs are seeded and serialized
(``max_workers=1``) so outcomes are reproducible.
"""

from __future__ import annotations

import re
from random import Random

import pytest

from core.llm.ranking import (
    RankingResult,
    _batch_ids,
    _parse_ranked_ids,
    _values_stable,
    find_inflection,
    rank_items,
)

_DOC_RE = re.compile(
    r"id: (\w+)\nBEGIN_DOC_\w+\n(.*?)\nEND_DOC_\w+", re.S,
)
_VALUE_RE = re.compile(r"value=(-?\d+)")


class _Response:
    def __init__(self, result, cost=0.001):
        self.result = result
        self.cost = cost


class FakeRankClient:
    """Orders batch documents by embedded ``value=N`` descending
    (higher value = more relevant). ``noise`` jitters small-valued
    items only, deterministically, to keep the tail unstable while
    the head stays put."""

    def __init__(self, noise: int = 0, noise_below: int = 500):
        self.calls: list[list[str]] = []  # texts per batch, in order
        self.noise = noise
        self.noise_below = noise_below
        self._rng = Random(1234)

    def generate_structured(self, prompt, schema, **kwargs):
        docs = _DOC_RE.findall(prompt)
        self.calls.append([text for _bid, text in docs])
        scored = []
        for bid, text in docs:
            value = int(_VALUE_RE.search(text).group(1))
            if self.noise and value < self.noise_below:
                value += self._rng.randint(-self.noise, self.noise)
            scored.append((value, bid))
        scored.sort(reverse=True)
        return _Response({"ranked_ids": [bid for _v, bid in scored]})


class RetryOnceClient(FakeRankClient):
    """First call per batch returns a truncated id list; the retry
    succeeds. Exercises the retry-then-succeed path."""

    def __init__(self):
        super().__init__()
        self._bad_next = True

    def generate_structured(self, prompt, schema, **kwargs):
        response = super().generate_structured(prompt, schema, **kwargs)
        if self._bad_next:
            self._bad_next = False
            return _Response({"ranked_ids": response.result["ranked_ids"][:-1]})
        self._bad_next = True
        return response


class AlwaysBadClient:
    def __init__(self):
        self.calls = 0

    def generate_structured(self, prompt, schema, **kwargs):
        self.calls += 1
        return _Response({"ranked_ids": []})


class PoisonBatchClient(FakeRankClient):
    """Drops (returns malformed output for) any batch containing the
    poison marker; ranks other batches normally."""

    def __init__(self, poison: str):
        super().__init__()
        self.poison = poison

    def generate_structured(self, prompt, schema, **kwargs):
        response = super().generate_structured(prompt, schema, **kwargs)
        if any(self.poison in text for text in self.calls[-1]):
            return _Response({"ranked_ids": []})
        return response


class FailFirstTrialClient(FakeRankClient):
    """Fails the first two calls (one batch's attempt + retry), then
    behaves normally — exercises the failed-trial counter reset."""

    def __init__(self):
        super().__init__()
        self._count = 0

    def generate_structured(self, prompt, schema, **kwargs):
        response = super().generate_structured(prompt, schema, **kwargs)
        self._count += 1
        if self._count <= 2:
            return _Response({"ranked_ids": []})
        return response


class ScriptedOrderClient:
    """Returns pre-scripted item orderings (by item text), echoing
    the presentation order once the script is exhausted."""

    def __init__(self, scripts: list[list[str]]):
        self.scripts = list(scripts)

    def generate_structured(self, prompt, schema, **kwargs):
        docs = _DOC_RE.findall(prompt)
        by_text = {text: bid for bid, text in docs}
        if self.scripts:
            script = self.scripts.pop(0)
            ranked = [by_text[text] for text in script]
        else:
            ranked = [bid for bid, _text in docs]
        return _Response({"ranked_ids": ranked})


class RaisingClient:
    def generate_structured(self, prompt, schema, **kwargs):
        raise RuntimeError("budget exceeded")


def _items(values):
    return [f"item value={v}" for v in values]


def _ranked_values(result: RankingResult):
    return [int(_VALUE_RE.search(r.item).group(1)) for r in result.ranked]


# ---------------------------------------------------------------------------
# Pure-function tests.
# ---------------------------------------------------------------------------

def test_find_inflection_rejects_short_and_flat():
    assert find_inflection([]) == -1
    assert find_inflection([1.0, 2.0, 3.0]) == -1
    assert find_inflection([2.0] * 20) == -1


def test_find_inflection_locates_knee():
    # Steep head (3 tightly-ranked items) then a flat tail: the point
    # of maximum curvature must sit near the transition, not in the
    # head or deep in the tail.
    scores = [1.0, 1.2, 1.4] + [8.0 + i * 0.05 for i in range(27)]
    knee = find_inflection(scores)
    assert 1 <= knee <= 8


def test_values_stable_window_and_sentinel():
    assert _values_stable([5, 5, 5], window=3, tolerance=0)
    assert _values_stable([4, 5, 6], window=3, tolerance=2)
    assert not _values_stable([4, 5, 6], window=3, tolerance=1)
    assert not _values_stable([5, 5], window=3, tolerance=1)
    assert not _values_stable([5, -1, 5], window=3, tolerance=5)


def test_batch_ids_unique_and_spreadsheet_style():
    ids = _batch_ids(30)
    assert len(set(ids)) == 30
    assert ids[0] == "A"
    assert ids[25] == "Z"
    assert ids[26] == "AA"


def test_parse_ranked_ids_cleanup_and_rejection():
    ids = ["A", "B", "C"]
    ok = _parse_ranked_ids({"ranked_ids": ["`b`", " C ", "a"]}, ids)
    assert ok == [1, 2, 0]
    assert _parse_ranked_ids({"ranked_ids": ["A", "B"]}, ids) is None
    assert _parse_ranked_ids({"ranked_ids": ["A", "A", "B"]}, ids) is None
    assert _parse_ranked_ids({"ranked_ids": ["A", "B", "X"]}, ids) is None
    assert _parse_ranked_ids({"ranked_ids": "A,B,C"}, ids) is None
    assert _parse_ranked_ids("not a dict", ids) is None


# ---------------------------------------------------------------------------
# End-to-end algorithm tests (fake client, seeded, serial).
# ---------------------------------------------------------------------------

def test_empty_and_single_item():
    empty = rank_items([], "q", client=FakeRankClient(), max_workers=1)
    assert empty.ranked == []

    single = rank_items(["item value=1"], "q", client=FakeRankClient(),
                        max_workers=1)
    assert len(single.ranked) == 1
    assert single.ranked[0].rank == 1
    assert single.stats.converged
    assert single.stats.llm_calls == 0


def test_single_batch_corpus_exact_order():
    # Corpus fits one batch: every trial sees the full ordering, a
    # perfect comparator repeats it, and the run converges by order
    # stability after exactly min_trials trials with no refinement.
    values = [30, 5, 90, 12, 77, 41]
    result = rank_items(_items(values), "most relevant first",
                        client=FakeRankClient(), seed=7, max_workers=1,
                        min_trials=3, stable_window=3)
    assert _ranked_values(result) == sorted(values, reverse=True)
    assert result.stats.converged
    assert result.stats.trials == 3
    assert result.stats.iterations == 1
    assert result.stats.llm_calls == 3


def test_multi_batch_corpus_finds_head():
    # 30 items, 3 dominant: the head must surface regardless of which
    # batches it landed in, and the output must be a permutation.
    values = [1000, 900, 800] + list(range(1, 28))
    result = rank_items(_items(values), "largest value", seed=11,
                        client=FakeRankClient(), max_workers=1)
    ranked = _ranked_values(result)
    assert sorted(ranked) == sorted(values)  # permutation, nothing lost
    assert ranked[0] == 1000
    assert set(ranked[:8]) >= {1000, 900, 800}
    top3 = [r for r in result.ranked if r.rank <= 3]
    assert all(r.iterations >= 1 for r in top3)


def test_two_and_three_item_corpora():
    two = rank_items(_items([5, 9]), "largest", client=FakeRankClient(),
                     seed=1, max_workers=1, min_trials=2, stable_window=2)
    assert _ranked_values(two) == [9, 5]
    three = rank_items(_items([3, 9, 6]), "largest",
                       client=FakeRankClient(), seed=1, max_workers=1,
                       min_trials=2, stable_window=2)
    assert _ranked_values(three) == [9, 6, 3]


def test_identical_items_no_refinement_no_crash():
    # Indistinguishable items: flat score curve, no measurable
    # inflection, no refinement — output is still a permutation.
    result = rank_items(_items([42] * 8), "largest",
                        client=FakeRankClient(), seed=2, max_workers=1,
                        max_trials=6, min_trials=2, stable_window=2)
    assert sorted(_ranked_values(result)) == [42] * 8
    assert result.stats.iterations == 1


def test_exhaustion_refines_with_fallback_tau():
    # stable_window > max_trials makes convergence impossible: every
    # iteration exhausts its trials and refines at the median of the
    # recent measurable inflections (paper: t* = T -> refinement).
    values = [1000, 980, 960, 940, 920] + list(range(1, 36))
    result = rank_items(_items(values), "largest",
                        client=FakeRankClient(noise=40), seed=3,
                        max_workers=1, max_trials=3, min_trials=2,
                        stable_window=5)
    assert sorted(_ranked_values(result)) == sorted(values)
    assert not result.stats.converged
    assert result.stats.iterations >= 2
    assert set(_ranked_values(result)[:5]) == {1000, 980, 960, 940, 920}


def test_partial_failure_appends_unranked_item_last(caplog):
    # One item's batch always fails; every other batch ranks fine.
    # The unobserved item must be appended (never silently dropped)
    # and land at the very back of the final order.
    values = list(range(1, 21))
    client = PoisonBatchClient(poison="value=13")
    with caplog.at_level("WARNING", logger="core.llm.ranking"):
        result = rank_items(_items(values), "largest", client=client,
                            seed=6, max_workers=1, max_trials=3,
                            min_trials=2, stable_window=99)
    ranked = _ranked_values(result)
    assert sorted(ranked) == values
    assert ranked[-1] == 13
    assert "no successful batch" in caplog.text


def test_failed_trial_then_recovery_converges():
    values = [30, 5, 90, 12, 77, 41]
    client = FailFirstTrialClient()
    result = rank_items(_items(values), "largest", client=client,
                        seed=7, max_workers=1, min_trials=2,
                        stable_window=2)
    assert _ranked_values(result) == sorted(values, reverse=True)
    assert result.stats.converged
    assert result.stats.dropped_batches == 1


def test_median_and_mean_aggregates_disagree():
    # Scripted positions: A gets [1, 1, 4], B gets [2, 2, 1] ->
    # mean ranks B first (1.67 < 2.0), median ranks A first (1 < 2).
    items = ["A value=0", "B value=0", "C value=0", "D value=0"]
    scripts = [
        ["A value=0", "B value=0", "C value=0", "D value=0"],
        ["A value=0", "B value=0", "C value=0", "D value=0"],
        ["B value=0", "C value=0", "D value=0", "A value=0"],
    ]
    common = {"max_workers": 1, "max_trials": 3, "min_trials": 2,
              "stable_window": 5, "max_iterations": 1, "seed": 9}
    by_mean = rank_items(items, "q", client=ScriptedOrderClient(scripts),
                         **common)
    by_median = rank_items(items, "q",
                           client=ScriptedOrderClient(list(scripts)),
                           use_median=True, **common)
    assert by_mean.ranked[0].item.startswith("B")
    assert by_median.ranked[0].item.startswith("A")


def test_noisy_tail_triggers_refinement_and_reassembly():
    # A stable 5-item head over a jittering 35-item tail: full-order
    # stability cannot happen, so the run must refine at the
    # inflection and reassemble frozen segments without losing items.
    values = [1000, 980, 960, 940, 920] + list(range(1, 36))
    client = FakeRankClient(noise=40)
    result = rank_items(_items(values), "largest value", client=client,
                        seed=3, max_workers=1, max_trials=12)
    ranked = _ranked_values(result)
    assert sorted(ranked) == sorted(values)
    assert set(ranked[:5]) == {1000, 980, 960, 940, 920}
    assert result.stats.iterations >= 2
    # Frozen-tail items carry the iteration they were frozen at.
    by_value = {int(_VALUE_RE.search(r.item).group(1)): r
                for r in result.ranked}
    assert by_value[1000].iterations >= by_value[1].iterations
    # Reassembly is R_K, F_{K-1}, ..., F_1: iteration counts must be
    # non-increasing along the final order (a frozen-segment ordering
    # bug would violate this).
    iters = [r.iterations for r in result.ranked]
    assert iters == sorted(iters, reverse=True)


def test_trial_one_remainder_joins_trial_two():
    # 12 items, batch 10: trial 1 floors to one batch and leaves 2
    # remainder items; the spec requires them in trial 2's batches.
    client = FakeRankClient()
    rank_items(_items(range(1, 13)), "largest", client=client, seed=5,
               max_workers=1, min_trials=2, stable_window=2)
    trial1_seen = set(client.calls[0])
    trial2_seen = set(client.calls[1])
    all_texts = {f"item value={v}" for v in range(1, 13)}
    remainders = all_texts - trial1_seen
    assert len(remainders) == 2
    assert remainders <= trial2_seen


def test_bad_response_retries_then_succeeds():
    values = [30, 5, 90, 12, 77, 41]
    client = RetryOnceClient()
    result = rank_items(_items(values), "largest", client=client, seed=7,
                        max_workers=1, min_trials=2, stable_window=2)
    assert _ranked_values(result) == sorted(values, reverse=True)
    assert result.stats.dropped_batches == 0
    # Every batch cost two calls (bad + retry).
    assert result.stats.llm_calls == 2 * result.stats.trials


def test_all_batches_bad_returns_input_order_without_raising():
    values = list(range(1, 13))
    client = AlwaysBadClient()
    result = rank_items(_items(values), "largest", client=client, seed=1,
                        max_workers=1)
    assert _ranked_values(result) == values
    assert not result.stats.converged
    assert result.stats.dropped_batches > 0


def test_client_exceptions_are_absorbed():
    values = list(range(1, 13))
    result = rank_items(_items(values), "largest", client=RaisingClient(),
                        seed=1, max_workers=1)
    assert _ranked_values(result) == values
    assert not result.stats.converged


def test_median_aggregation_flag():
    values = [30, 5, 90, 12, 77, 41]
    result = rank_items(_items(values), "largest", client=FakeRankClient(),
                        seed=7, max_workers=1, use_median=True,
                        min_trials=2, stable_window=2)
    assert _ranked_values(result) == sorted(values, reverse=True)


def test_seed_determinism():
    values = [1000, 900, 800] + list(range(1, 28))
    first = rank_items(_items(values), "largest", client=FakeRankClient(),
                       seed=42, max_workers=1)
    second = rank_items(_items(values), "largest", client=FakeRankClient(),
                        seed=42, max_workers=1)
    assert _ranked_values(first) == _ranked_values(second)
    assert first.stats.llm_calls == second.stats.llm_calls


def test_threaded_batches_match_serial_result():
    # Worker count must not change the outcome: batch composition
    # comes from the main-thread rng, each batch result embeds its
    # own corpus indices, and aggregation happens on the main thread.
    # Pins: workers never consume the shuffle rng, no batch result is
    # lost or duplicated under concurrency, stats counters are
    # lock-consistent.
    values = [1000, 900, 800] + list(range(1, 28))
    serial = rank_items(_items(values), "largest",
                        client=FakeRankClient(), seed=42, max_workers=1)
    threaded = rank_items(_items(values), "largest",
                          client=FakeRankClient(), seed=42, max_workers=4)
    assert _ranked_values(threaded) == _ranked_values(serial)
    assert threaded.stats.llm_calls == serial.stats.llm_calls
    assert threaded.stats.cost == pytest.approx(serial.stats.cost)


def test_custom_render_and_cost_accumulation():
    items = [{"name": "a", "weight": 3}, {"name": "b", "weight": 9},
             {"name": "c", "weight": 1}, {"name": "d", "weight": 7}]
    result = rank_items(
        items, "heaviest first", client=FakeRankClient(), seed=2,
        max_workers=1, min_trials=2, stable_window=2,
        render=lambda it: f"{it['name']} value={it['weight']}",
    )
    assert [r.item["name"] for r in result.ranked] == ["b", "d", "a", "c"]
    assert result.stats.cost == pytest.approx(
        0.001 * result.stats.llm_calls)
