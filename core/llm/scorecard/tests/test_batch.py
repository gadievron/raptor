"""Tests for ``core.llm.scorecard._batch.record_event_batch``.

The producers hand their whole run to ONE ``record_events`` cycle
(each ``record_event`` call is a full flock + load + verify +
atomic-rewrite); per-event writes remain only as the failure-isolation
fallback when the batch is rejected.
"""

from __future__ import annotations

import logging

import pytest

from core.llm.scorecard._batch import record_event_batch
from core.llm.scorecard.consensus import record_consensus_outcomes
from core.llm.scorecard.scorecard import ModelScorecard

logger = logging.getLogger(__name__)


def _events(n: int) -> list[dict]:
    return [
        {"decision_class": f"agentic:rule-{i}", "model": "m",
         "event_type": "multi_model_consensus", "outcome": "correct"}
        for i in range(n)
    ]


class _CountingScorecard:
    def __init__(self, *, batch_fails: bool = False) -> None:
        self.batch_calls = 0
        self.single_calls = 0
        self.batch_fails = batch_fails

    def record_events(self, events: list[dict]) -> None:
        self.batch_calls += 1
        if self.batch_fails:
            raise RuntimeError("batch rejected")

    def record_event(self, *args, **kwargs) -> None:
        self.single_calls += 1


def test_happy_path_is_one_batch_call():
    sc = _CountingScorecard()
    n = record_event_batch(sc, _events(5), log=logger, producer="t")
    assert n == 5
    assert sc.batch_calls == 1
    assert sc.single_calls == 0


def test_empty_batch_makes_no_calls():
    sc = _CountingScorecard()
    assert record_event_batch(sc, [], log=logger, producer="t") == 0
    assert sc.batch_calls == 0
    assert sc.single_calls == 0


def test_batch_failure_degrades_to_per_event(caplog):
    sc = _CountingScorecard(batch_fails=True)
    with caplog.at_level(logging.WARNING, logger=__name__):
        n = record_event_batch(sc, _events(3), log=logger, producer="t")
    assert n == 3
    assert sc.batch_calls == 1
    assert sc.single_calls == 3
    assert any("retrying per event" in r.getMessage()
               for r in caplog.records)


def test_consensus_producer_writes_one_batch(tmp_path, monkeypatch):
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    calls: list[int] = []
    real = sc.record_events

    def _spy(events: list[dict]) -> None:
        calls.append(len(events))
        real(events)

    monkeypatch.setattr(sc, "record_events", _spy)
    n = record_consensus_outcomes(
        sc,
        correlation={
            "agreement_matrix": {"f1": {
                "pro": {"is_exploitable": True},
                "opus": {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            }},
            "confidence_signals": {"f1": "disputed"},
        },
        results_by_id={"f1": {"rule_id": "py/x"}},
    )
    assert n == 3
    assert calls == [3]
    # The events really landed.
    stat = sc.get_stat("agentic:py/x", "flash")
    assert stat is not None
    assert stat.events["multi_model_consensus"].incorrect == 1


@pytest.mark.parametrize("producer_mod,func_name", [
    ("self_consistency", "record_self_consistency_outcomes"),
    ("dataflow_validation", "record_dataflow_validation_outcomes"),
])
def test_sibling_producers_route_through_batch(
    producer_mod, func_name, tmp_path, monkeypatch,
):
    import importlib
    mod = importlib.import_module(f"core.llm.scorecard.{producer_mod}")
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    calls: list[int] = []
    real = sc.record_events

    def _spy(events: list[dict]) -> None:
        calls.append(len(events))
        real(events)

    monkeypatch.setattr(sc, "record_events", _spy)
    kwargs = {"results_by_id": {
        "f1": {"rule_id": "py/x", "analysed_by": "m",
               "retried": True, "is_exploitable": True,
               "dataflow_validation": {"verdict": "confirmed"}},
    }}
    if producer_mod == "self_consistency":
        kwargs["verdicts_pre_retry"] = {"f1": True}
    n = getattr(mod, func_name)(sc, **kwargs)
    assert n == 1
    assert calls == [1]
