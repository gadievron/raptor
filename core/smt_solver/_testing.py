"""Shared test helpers for ``core.smt_solver`` consumers.

Centralises the two helpers every SMT-adjacent test file needs:
- evaluating a closed z3 boolean expression to ``True``/``False``
- reading the raw-bits value of a closed z3 bitvec expression

Placed alongside the module (with a leading underscore) rather than in a
``conftest.py`` because tests live in several trees (``core/smt_solver/tests/``,
``packages/codeql/tests/``, ``packages/exploit_feasibility/tests/``) and
pytest's per-tree ``conftest.py`` discovery doesn't cross those boundaries.

Each test file still defines its own ``_requires_z3`` marker inline — the
marker is just a one-liner and keeps pytest out of this module's import path.
"""
from __future__ import annotations

from typing import Any


def eval_predicate(pred: Any) -> bool:
    """Return ``True`` iff ``pred`` is satisfiable.

    Wrap in ``z3.Not(...)`` to check tautology (``eval_predicate(z3.Not(p))
    == False`` iff ``p`` is valid).
    """
    from core.smt_solver import new_solver, z3
    s = new_solver()
    s.add(pred)
    return s.check() == z3.sat


def eval_bv(expr: Any, width: int) -> int:
    """Return the raw-bits integer value of a closed z3 bitvec expression.

    Always unsigned bit pattern — callers that want the signed
    interpretation should apply their own two's-complement reinterpretation.
    """
    from core.smt_solver import new_solver, z3
    s = new_solver()
    probe = z3.BitVec("_probe", width)
    s.add(probe == expr)
    assert s.check() == z3.sat
    return s.model()[probe].as_long()


__all__ = ["eval_predicate", "eval_bv"]
