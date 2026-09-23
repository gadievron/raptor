"""The caller's timeout_ms reaches every solver a feasibility call builds.

check_path_feasibility documents a per-call budget, but the
per-condition tautology solver was constructed before the override
and kept the 5 s substrate default regardless — up to one full
default-budget check() per condition per call — and the WP redundancy
pass ran its (up to 32) tests on a fixed 2 s solver. Pin the
plumbing: with a caller budget set, the tautology solver is built on
that budget and the WP solver's per-test timeout is capped by it
(never raised above the WP default).
"""

import pytest

pytest.importorskip("z3")

import core.smt_solver.path_feasibility as pf  # noqa: E402
from core.smt_solver.path_feasibility import (  # noqa: E402
    WP_TIMEOUT_MS,
    PathCondition,
    check_path_feasibility,
)


def _record_solver_builds(monkeypatch):
    calls: list[int | None] = []
    real = pf._new_solver

    def _recording(timeout_ms=None):
        calls.append(timeout_ms)
        return real(timeout_ms) if timeout_ms is not None else real()

    monkeypatch.setattr(pf, "_new_solver", _recording)
    return calls


def test_tautology_solver_gets_caller_budget(monkeypatch):
    calls = _record_solver_builds(monkeypatch)
    conditions = [
        PathCondition(text="size < 1024", step_index=0),
        PathCondition(text="size > 16", step_index=1),
    ]
    result = check_path_feasibility(conditions, timeout_ms=123)
    assert result.feasible is True
    # Every solver built for this call carries the caller's budget
    # (the WP pass caps by it below the WP default).
    assert calls, "no solver was built"
    assert all(c == 123 for c in calls), calls


def test_wp_solver_capped_never_raised(monkeypatch):
    calls = _record_solver_builds(monkeypatch)
    conditions = [PathCondition(text="size < 1024", step_index=0)]
    generous = WP_TIMEOUT_MS * 10
    check_path_feasibility(conditions, timeout_ms=generous)
    # The final/tautology solvers take the generous budget; the WP
    # pass keeps its own (smaller) default rather than inflating.
    assert generous in calls
    assert WP_TIMEOUT_MS in calls


def test_default_budget_unchanged(monkeypatch):
    calls = _record_solver_builds(monkeypatch)
    conditions = [PathCondition(text="size < 1024", step_index=0)]
    result = check_path_feasibility(conditions)
    assert result.feasible is True
    # No caller budget: substrate defaults (None) for the main
    # solvers, the WP default for the WP pass.
    assert set(calls) <= {None, WP_TIMEOUT_MS}
