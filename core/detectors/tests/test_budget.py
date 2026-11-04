"""A shared deadline must bound dispatch without dropping completed work."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import subprocess

import pytest

from core.detectors import budget as module


@pytest.mark.parametrize('value', [0, -1, 'nan', 'inf', '-inf'])
def test_budget_rejects_nonpositive_or_nonfinite_values(value):
    with pytest.raises(ValueError):
        module.WorkBudget(value)


def test_runner_recomputes_remaining_budget_and_preserves_tool_timeout(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module, 'monotonic', lambda: now[0])
    budget = module.WorkBudget(10)
    observed = []
    run = budget.runner(lambda cmd, **kw: observed.append(kw['timeout']))
    run(['tool'], timeout=3)
    now[0] = 8
    run(['tool'], timeout=5)
    now[0] = 10
    with pytest.raises(subprocess.TimeoutExpired):
        run(['tool'], timeout=5)
    assert observed == [3, 2] and budget.exhausted


def test_short_per_tool_timeout_is_not_stage_exhaustion(monkeypatch):
    monkeypatch.setattr(module, 'monotonic', lambda: 0)
    budget = module.WorkBudget(10)
    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw['timeout'])
    with pytest.raises(subprocess.TimeoutExpired):
        budget.runner(timeout)(['tool'], timeout=2)
    assert not budget.exhausted
    with pytest.raises(subprocess.TimeoutExpired):
        budget.runner(timeout)(['tool'], timeout=20)
    assert budget.exhausted


def test_dispatch_does_not_eagerly_consume_inputs_or_start_after_expiry(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module, 'monotonic', lambda: now[0])
    budget = module.WorkBudget(5)
    started, release = Event(), Event()
    consumed = []
    def items():
        for value in range(1000):
            consumed.append(value)
            yield value
    def work(value):
        started.set()
        assert release.wait(8)
        return value
    def collect():
        return [(item, future.result()) for item, future in
                module.bounded_futures(items(), work, workers=1, budget=budget)]
    with ThreadPoolExecutor(max_workers=1) as parent:
        pending = parent.submit(collect)
        try:
            assert started.wait(5)
            assert consumed == [0]
            now[0] = 5
        finally:
            release.set()
        assert pending.result(timeout=5) == [(0, 0)]
    assert consumed == [0, 1]  # one lookahead detects unfinished coverage
    assert budget.exhausted
