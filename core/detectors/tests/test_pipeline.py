"""Execution semantics shared by tool and pure-Python detectors."""
from __future__ import annotations

import pytest

from core.detectors.pipeline import Detector, Stage, StageResult, run_detector


def test_python_stages_exchange_artifacts_once_in_order():
    calls = []

    def extract(state):
        calls.append("extract")
        state["sizes"] = [4, 8]
        return StageResult()

    def analyze(state):
        calls.append("analyze")
        state["total"] = sum(state["sizes"])
        return StageResult()

    definition = Detector("sizes", "1", (Stage("extract", extract), Stage("analyze", analyze)))
    result = run_detector(definition, {})
    assert calls == ["extract", "analyze"]
    assert result.value["total"] == 12
    assert result.status == "complete"
    assert (result.identifier, result.version) == ("sizes", "1")
    assert [record.name for record in result.stages] == calls
    assert all(record.elapsed_seconds >= 0 for record in result.stages)


@pytest.mark.parametrize("status", ["skipped", "error"])
def test_failed_prerequisite_never_runs_downstream_analysis(status):
    def unavailable(state):
        state.append("attempted")
        return StageResult(status, "missing input")

    def forbidden(state):
        pytest.fail("analysis ran without its prerequisite")

    result = run_detector(Detector("check", "1", (
        Stage("extract", unavailable), Stage("analyze", forbidden),
    )), [])
    assert result.status == status
    assert result.reason == "missing input"
    assert result.value == ["attempted"]
    assert len(result.stages) == 1


def test_later_complete_stage_does_not_erase_partial_execution():
    def partial(state):
        state.append("retained candidate")
        return StageResult("partial", "one input failed")

    def analyze(state):
        state.append("analyzed")
        return StageResult()

    result = run_detector(Detector("check", "2", (
        Stage("extract", partial), Stage("analyze", analyze),
    )), [])
    assert result.status == "partial"
    assert result.reason == "one input failed"
    assert result.value == ["retained candidate", "analyzed"]


def test_unexpected_analysis_exception_keeps_callers_error_policy():
    def broken(state):
        raise RuntimeError("analysis bug")

    with pytest.raises(RuntimeError, match="analysis bug"):
        run_detector(Detector("check", "1", (Stage("analyze", broken),)), {})


def test_invalid_handler_return_cannot_look_complete():
    with pytest.raises(TypeError, match="StageResult"):
        run_detector(Detector("check", "1", (Stage("broken", lambda state: None),)), {})


def test_repeated_runs_do_not_share_results_or_records():
    def count(state):
        state.append(len(state))
        return StageResult()

    definition = Detector("check", "1", (Stage("count", count),))
    first, second = run_detector(definition, []), run_detector(definition, [])
    assert first.value == second.value == [0]
    assert first.value is not second.value
    assert first.stages is not second.stages


def test_duplicate_stage_names_are_rejected():
    stage = Stage("same", lambda state: StageResult())
    with pytest.raises(ValueError, match="unique"):
        Detector("check", "1", (stage, stage))


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError, match="status"):
        StageResult("clean")
