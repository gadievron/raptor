"""The logical retry-clock control keeps its native rail and owns its binding."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import time
from types import ModuleType

import pytest

from core.taint.tests import test_engine_hostile as owner


@contextmanager
def _time_binding(borrowed):
    with pytest.MonkeyPatch.context() as scope:
        if borrowed:
            view = ModuleType(time.__name__)
            vars(view).update(vars(time))
            view.borrowed_marker = object()
            scope.setattr(owner, "time", view)
        yield owner.time


def _assert_private_clock(before, shared_namespace, borrowed_namespace):
    assert owner.time is not before
    assert owner.time.process_time is not before.process_time
    assert owner.time.monotonic is before.monotonic
    assert vars(time) == shared_namespace
    assert vars(before) == borrowed_namespace


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("attempts", [3, 4])
def test_retry_control_keeps_interleaved_sizes_and_rejects_extra_attempt(attempts, borrowed):
    packs = owner.load_packs(owner.HAND_COMPUTED_PACKS)
    original_rail = owner._rail_verdict
    sizes, observed_ratios = [], []
    shared_namespace = dict(vars(time))
    with _time_binding(borrowed) as before:
        borrowed_namespace = dict(vars(before))

        def observe(packs, *, run):
            _assert_private_clock(before, shared_namespace, borrowed_namespace)

            def counted(texts, graph, routes, packs):
                sizes.append(len(graph.nodes))
                return run(texts, graph, routes, packs)

            ok, ratios = original_rail(packs, run=counted)
            observed_ratios.extend(ratios)
            return ok, ratios

        with pytest.MonkeyPatch.context() as scope:
            scope.setattr(owner, "_RAIL_ATTEMPTS", attempts)
            scope.setattr(owner, "_rail_verdict", observe)
            expected = (nullcontext() if attempts == 3 else
                        pytest.raises(AssertionError, match="retry budget ran past"))
            with expected:
                owner.test_growth_ratio_rail_retry_budget_is_bounded(packs, scope)
        assert owner.time is before
        assert vars(before) == borrowed_namespace
        assert vars(time) == shared_namespace
    assert sizes == [600, 1200] * (3 * attempts)
    assert observed_ratios == pytest.approx([4.0] * 3 + ([2.0] if attempts == 4 else []))


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_retry_control_restores_the_clock_after_body_failure(borrowed, error):
    packs = owner.load_packs(owner.HAND_COMPUTED_PACKS)
    shared_namespace = dict(vars(time))
    with _time_binding(borrowed) as before:
        borrowed_namespace = dict(vars(before))

        def fail(packs, *, run):
            _assert_private_clock(before, shared_namespace, borrowed_namespace)
            raise error("retry control interrupted")

        with pytest.raises(error, match="retry control interrupted"):
            with pytest.MonkeyPatch.context() as scope:
                scope.setattr(owner, "_rail_verdict", fail)
                owner.test_growth_ratio_rail_retry_budget_is_bounded(packs, scope)
        assert owner.time is before
        assert vars(before) == borrowed_namespace
        assert vars(time) == shared_namespace
