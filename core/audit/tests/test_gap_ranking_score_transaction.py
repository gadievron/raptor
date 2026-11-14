"""Score stamping commits only after all within-tier refinement succeeds."""
from copy import deepcopy

import pytest

from core.audit import gap_ranking as mod
from core.llm import ranking


def owned_gaps(scores=True):
    rows = [{"name": f"owned-{tier}-{index}", "file": "owned.c", "priority": tier,
             "priority_score": float(30 - index * 10)} for tier in (0, 1) for index in range(3)]
    if not scores:
        for row in rows:
            del row["priority_score"]
    return rows


def ranked(items, signal=True):
    return ranking.RankingResult(
        ranked=[ranking.RankedItem(rank=index + 1, index=index, item=item, score=float(index), iterations=1)
                for index, item in enumerate(reversed(items))],
        stats=ranking.RankingStats(ranked_batches=int(signal), llm_calls=1, cost=0.0),
    )


@pytest.fixture(autouse=True)
def no_actual_ranking(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("owned result-injection test entered real ranking")
    monkeypatch.setattr(ranking, "rank_items", forbidden)
    monkeypatch.setattr(ranking, "_Ranker", forbidden)


@pytest.mark.parametrize("stamp", [True, False], ids=["stamp", "no-stamp"])
def test_later_tier_failure_keeps_mechanical_scores(monkeypatch, stamp):
    gaps = owned_gaps()
    before = deepcopy(gaps)
    calls = []

    def result(items, *args, **kwargs):
        calls.append(items)
        if len(calls) == 2:
            raise RuntimeError("owned later tier failure")
        return ranked(items)

    monkeypatch.setattr(ranking, "rank_items", result)
    out, note = mod.rank_gap_queue(gaps, client=object(), stamp_scores=stamp)
    assert len(calls) == 2
    assert out is gaps
    assert gaps == before
    assert "owned later tier failure" in note and "mechanical order kept" in note


def test_later_score_conversion_failure_leaves_all_input_scores(monkeypatch):
    gaps = owned_gaps()
    gaps[-1]["priority_score"] = "owned invalid score"
    before = deepcopy(gaps)
    monkeypatch.setattr(ranking, "rank_items", lambda items, *args, **kwargs: ranked(items))
    out, note = mod.rank_gap_queue(gaps, client=object(), stamp_scores=True)
    assert out is gaps
    assert gaps == before
    assert "failed" in note and "mechanical order kept" in note


def test_success_commits_scores_without_replacing_gap_objects(monkeypatch):
    gaps = owned_gaps()
    before = deepcopy(gaps)
    identities = {id(gap) for gap in gaps}
    observed = []

    def result(items, *args, **kwargs):
        observed.append(deepcopy(gaps))
        return ranked(items)

    monkeypatch.setattr(ranking, "rank_items", result)
    out, note = mod.rank_gap_queue(gaps, client=object(), stamp_scores=True)
    assert observed == [before, before]
    assert [row["priority"] for row in out] == [0, 0, 0, 1, 1, 1]
    assert [row["name"] for row in out] == ["owned-0-2", "owned-0-1", "owned-0-0", "owned-1-2", "owned-1-1", "owned-1-0"]
    assert [row["priority_score"] for row in out] == [30.0, 20.0, 10.0] * 2
    assert {id(row) for row in out} == identities
    assert [row["priority_score"] for row in gaps] == [10.0, 20.0, 30.0] * 2
    assert "ranked 6/6" in note


def test_missing_scores_are_not_added(monkeypatch):
    gaps = owned_gaps(scores=False)
    before = deepcopy(gaps)
    monkeypatch.setattr(ranking, "rank_items", lambda items, *args, **kwargs: ranked(items))
    out, _ = mod.rank_gap_queue(gaps, client=object(), stamp_scores=True)
    assert gaps == before
    assert all("priority_score" not in row for row in out)


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit], ids=["interrupt", "exit"])
def test_later_cancellation_propagates_without_partial_stamps(monkeypatch, error):
    gaps = owned_gaps()
    before = deepcopy(gaps)
    primary = error("owned cancellation")
    calls = []

    def result(items, *args, **kwargs):
        calls.append(items)
        if len(calls) == 2:
            raise primary
        return ranked(items)

    monkeypatch.setattr(ranking, "rank_items", result)
    with pytest.raises(error) as exc:
        mod.rank_gap_queue(gaps, client=object(), stamp_scores=True)
    assert exc.value is primary
    assert gaps == before


def test_later_no_signal_preserves_its_scores_and_commits_success(monkeypatch):
    gaps = owned_gaps()
    calls = []

    def result(items, *args, **kwargs):
        calls.append(items)
        return ranked(items, signal=len(calls) == 1)

    monkeypatch.setattr(ranking, "rank_items", result)
    out, note = mod.rank_gap_queue(gaps, client=object(), stamp_scores=True)
    assert [row["name"] for row in out[:3]] == ["owned-0-2", "owned-0-1", "owned-0-0"]
    assert [row["name"] for row in out[3:]] == ["owned-1-0", "owned-1-1", "owned-1-2"]
    assert [row["priority_score"] for row in gaps[:3]] == [10.0, 20.0, 30.0]
    assert [row["priority_score"] for row in gaps[3:]] == [30.0, 20.0, 10.0]
    assert "ranked 3/6" in note


def test_direct_restamp_helper_keeps_existing_in_place_contract():
    rows = [{"priority_score": 1}, {"priority_score": 3}, {}, {"priority_score": None}]
    assert mod._restamp_scores(rows) is None
    assert rows == [{"priority_score": 3.0}, {"priority_score": 1.0}, {}, {"priority_score": None}]
