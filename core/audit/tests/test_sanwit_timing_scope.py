"""Diagnostic ownership controls; timing limits remain unchanged."""

from __future__ import annotations

import gc

import pytest

from core.audit.tests import test_sanwit_extract_linear as subject


@pytest.mark.parametrize("raises", [False, True])
def test_timing_retires_only_its_collection_callback(raises):
    before = list(gc.callbacks)
    marker = RuntimeError("measured failure")

    def measured():
        assert gc.callbacks[:-1] == before
        gc.collect(0)
        if raises:
            raise marker
        return marker

    if raises:
        with pytest.raises(RuntimeError) as caught:
            subject._timed(measured)
        assert caught.value is marker
    else:
        result, elapsed = subject._timed(measured)
        assert result is marker
        assert elapsed >= 0
    assert gc.callbacks == before


def test_overrun_reports_costs_without_discounting_them(monkeypatch, capsys):
    ticks = iter([10.0, 11.0, 12.0, 14.0])
    monkeypatch.setattr(subject.time, "process_time", lambda: next(ticks))
    monkeypatch.setattr(subject.time, "thread_time", lambda: 5.0)
    before = list(gc.callbacks)

    def measured():
        callback = gc.callbacks[-1]
        callback("start", {"generation": 2})
        callback("stop", {"generation": 2})
        return "refusal"

    result, elapsed = subject._timed(measured)
    assert result == "refusal"
    assert elapsed == 4.0  # Includes the recorded collector CPU.
    assert elapsed > subject._CPU_BOUND_S
    output = capsys.readouterr().out
    assert "process_cpu=4.000000s" in output
    assert "thread_cpu=0.000000s" in output
    assert "gc_cpu=1.000000s" in output
    assert gc.callbacks == before
