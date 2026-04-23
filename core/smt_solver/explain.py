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

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .availability import z3


def track(
        solver: Any, 
        labeled: Sequence[Tuple[str, Any]],
        rev: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Assert each labelled expression via ``assert_and_track``.

    Returns a mapping from the generated Z3 label identifier back to the
    caller's human-readable name, used by ``core_names`` to translate
    ``solver.unsat_core()`` output.  Existing (non-tracked) assertions on
    the solver are unaffected and will not appear in the unsat core.

    Pass an existing ``rev`` dict to chain multiple batches on 
    the same solver safely — the label counter is derived from 
    ``len(rev)`` so new labels never collide with previously 
    tracked ones.  When ``rev`` is ``None`` (default) a fresh
    dict is created, matching the original single-call behaviour.
    """

    if rev is None:
        rev = {}
    offset = len(rev)
    for i, (name, expr) in enumerate(labeled):
        label = z3.Bool(f"_c{offset+i}")
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
