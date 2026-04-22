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

from typing import Any, Dict, List, Sequence, Tuple

from .availability import z3


def track(solver: Any, labeled: Sequence[Tuple[str, Any]]) -> Dict[str, str]:
    """Assert each labelled expression via ``assert_and_track``.

    Returns a mapping from the generated Z3 label identifier back to the
    caller's human-readable name, used by ``core_names`` to translate
    ``solver.unsat_core()`` output.  Existing (non-tracked) assertions on
    the solver are unaffected and will not appear in the unsat core.

    One-shot per solver: labels are generated as ``_c0``, ``_c1``, ... so
    calling ``track`` twice on the same solver will collide.  If you need
    to probe multiple batches, use a fresh solver (or merge the batches
    into one call).
    """
    rev: Dict[str, str] = {}
    for i, (name, expr) in enumerate(labeled):
        label = z3.Bool(f"_c{i}")
        solver.assert_and_track(expr, label)
        rev[str(label)] = name
    return rev


def core_names(solver: Any, rev: Dict[str, str]) -> List[str]:
    """Return human-readable names of assertions in the unsat core.

    Call after ``solver.check()`` returns ``z3.unsat``. Labels added by
    other callers (not present in ``rev``) are silently omitted.
    """
    names: List[str] = []
    for label in solver.unsat_core():
        name = rev.get(str(label))
        if name is not None:
            names.append(name)
    return names
