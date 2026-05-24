"""CI gate for the selection eval.

Every labeled positive must route to its strategy, no labeled negative
may over-fire, and every bundled strategy must have at least one positive
case so the eval can't silently stop covering one.
"""

from __future__ import annotations

from packages.strategy_eval.selection import (
    load_cases,
    run_selection_eval,
    uncovered_strategies,
)


def test_all_selection_cases_route_correctly():
    outcomes = run_selection_eval()
    failures = [o for o in outcomes if not o.passed]
    detail = "\n".join(
        f"  {o.case.name}: missing={list(o.missing)} "
        f"overfired={list(o.overfired)} picked={list(o.picked)}"
        for o in failures
    )
    assert not failures, f"selection routing regressions:\n{detail}"


def test_every_strategy_has_a_positive_case():
    outcomes = run_selection_eval()
    missing = uncovered_strategies(outcomes)
    assert not missing, (
        f"strategies with no positive selection case (eval would stop "
        f"covering them): {missing}"
    )


def test_cases_load():
    cases = load_cases()
    assert cases, "no selection cases loaded"
    # Every case must carry a file_path (picker requires it).
    for c in cases:
        assert "file_path" in c.signals, f"{c.name}: missing file_path signal"
