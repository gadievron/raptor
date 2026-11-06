"""Unsat-core helpers: name which constraints contradict.

When a solver returns ``unsat`` after asserting a batch of constraints,
Z3's ``unsat_core()`` tells us which tracked assertions it used to
derive the contradiction — a subset (not always minimal) that is itself
unsatisfiable. That turns "some of these conflict" into "specifically X
contradicts Y", which is stronger evidence for Stage-E chain_breaks than
a generic "mutually exclusive" note.

Usage::

    rev = track(solver, [(name, expr), ...])
    if solver.check() == z3.unsat:
        print(core_names(solver, rev))
"""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .availability import z3

if TYPE_CHECKING:
    from collections.abc import Sequence


def _boolean_names(expressions) -> set[str]:
    """Visit a formula DAG once; bound variables cannot alias free labels."""
    names, seen, pending = set(), set(), list(expressions)
    while pending:
        expr = pending.pop()
        identity = expr.get_id()
        if identity in seen:
            continue
        seen.add(identity)
        if z3.is_const(expr) and z3.is_bool(expr):
            names.add(str(expr.decl().name()))
        pending.extend(expr.children())
    return names


def track(
        solver: Any,
        labeled: Sequence[tuple[str, Any]],
        rev: dict[str, str] | None = None,
) -> dict[str, str]:
    """Track a complete batch without changing its formula's meaning.

    Labels use the solver's context and are disjoint from Boolean names
    in existing assertions, incoming expressions, and the reverse map.
    Native fresh symbols alone are insufficient: an explicit declaration
    can already have the name the native fresh-name counter will choose.
    Invalid expression sorts or contexts decline before any assertion is
    added. Later batches may not use active tracking labels as formula
    variables. Pass an existing reverse map to retain display names.
    The reverse map preserves assertion order: each input appends one fresh
    marker, even when display names repeat. Existing entries retain order.
    """
    if rev is None:
        rev = {}
    batch = []
    for name, expr in labeled:
        if type(expr) is bool:
            expr = z3.BoolVal(expr, ctx=solver.ctx)
        if not z3.is_bool(expr) or expr.ctx != solver.ctx:
            raise ValueError("tracked expressions must be Boolean formulas in the solver context")
        batch.append((name, expr))
    existing = _boolean_names(solver.assertions())
    incoming = _boolean_names(expr for _, expr in batch)
    # Retain only labels still present after pop/reset, bounding registry
    # lifetime to the solver's live assertions. A later source expression
    # cannot reuse an active marker: those markers are assumed true by Z3.
    active_labels = getattr(solver, "_raptor_track_labels", set(rev)) & existing
    if incoming & active_labels:
        raise ValueError("tracked expressions reference an active tracking label")
    solver._raptor_track_labels = active_labels
    reserved = existing | incoming | set(rev)
    for name, expr in batch:
        label = z3.FreshBool("_raptor_track", ctx=solver.ctx)
        while str(label.decl().name()) in reserved:
            label = z3.FreshBool("_raptor_track", ctx=solver.ctx)
        reserved.add(str(label.decl().name()))
        active_labels.add(str(label.decl().name()))
        solver.assert_and_track(expr, label)
        rev[str(label)] = name
    return rev


def core_names(solver: Any, rev: dict[str, str]) -> list[str]:
    """Return human-readable names of assertions in the unsat core.

    Call after ``solver.check()`` returns ``z3.unsat``. Labels added by
    other callers (not present in ``rev``) are silently omitted.

    Guards against bad solver state. Z3's ``unsat_core()`` raises
    ``z3.Z3Exception`` when:

    * `check()` was never called on the solver
    * `check()` was called but returned `sat` or `unknown` (the unsat
      core is only defined for `unsat`)
    * `check()` was called with no tracked assertions present
    * The solver was constructed without `set_param("unsat_core", True)`
      (some Z3 builds), or with a tactic that doesn't produce cores

    Pre-fix any of these leaked a `Z3Exception` out of `core_names`,
    crashing Stage-E `chain_breaks` reporting. Treat all of them as
    "no nameable core available" — return an empty list, which the
    caller already handles (no constraints to display). The caller
    is responsible for verifying `solver.check() == z3.unsat` before
    expecting a populated list.
    """
    names: list[str] = []
    try:
        core = solver.unsat_core()
    except (z3.Z3Exception, AttributeError):
        return names
    for label in core:
        name = rev.get(str(label))
        if name is not None:
            names.append(name)
    return names
