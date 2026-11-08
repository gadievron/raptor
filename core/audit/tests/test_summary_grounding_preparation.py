"""Preparation preserves grounding decisions and adapter ordering."""

import sys

import pytest

from core.analysis.summaries import FunctionSummary, Precondition
from core.audit.llm_summaries import _ground_summary


def test_empty_native_paths_do_not_split_source():
    if sys.getprofile() is not None:
        pytest.skip("profiler already owned")
    source = "int helper(int value) { return value; }\n" * 4000
    summary = FunctionSummary(function="helper", file="a.c")
    original_paths = summary.error_paths
    splits = []

    def profile(frame, event, arg):
        if (event == "c_call" and getattr(arg, "__name__", None) == "split"
                and getattr(arg, "__self__", None) is source):
            splits.append(arg)

    sys.setprofile(profile)
    try:
        result = _ground_summary(summary, source)
    finally:
        sys.setprofile(None)
    assert result is summary
    assert result.error_paths == []
    assert result.error_paths is not original_paths
    assert splits == []


def test_condition_adapter_can_add_paths_before_filtering():
    summary = FunctionSummary(function="helper", file="a.c")

    class Condition:
        def __str__(self):
            summary.error_paths[:] = ["return value;", "invented"]
            return "non-negative"

    summary.preconditions = [Precondition("value", 0, [Condition()])]
    result = _ground_summary(summary, "int helper(int value) { return value; }")
    assert result.error_paths == ["return value;"]
    assert result.preconditions[0].conditions == ["non-negative"]


def test_source_adapter_split_keeps_original_timing():
    events = []

    class Source(str):
        def split(self, *args, **kwargs):
            events.append("source")
            return super().split(*args, **kwargs)

    class Condition:
        def __str__(self):
            events.append("condition")
            return "non-negative"

    summary = FunctionSummary(function="helper", file="a.c")
    summary.preconditions = [Precondition("value", 0, [Condition()])]
    result = _ground_summary(summary, Source("int helper(int value) {}"))
    assert events == ["source", "condition", "condition"]
    assert result.error_paths == []


def test_foreign_empty_paths_can_yield_during_iteration():
    class Paths(list):
        def __iter__(self):
            yield "return value;"
            yield "invented"

    summary = FunctionSummary(function="helper", file="a.c", error_paths=Paths())
    result = _ground_summary(summary, "int helper(int value) { return value; }")
    assert result.error_paths == ["return value;"]


def test_nonempty_paths_preserve_whitespace_grounding_and_objects():
    path = "return\n value;"
    summary = FunctionSummary(function="helper", file="a.c", error_paths=[path, "missing"])
    result = _ground_summary(summary, "int helper(int value) { return\tvalue; }")
    assert result.error_paths == [path]
    assert result.error_paths[0] is path
