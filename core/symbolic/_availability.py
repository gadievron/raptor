"""Availability probes for the heavy dependencies core.symbolic uses.

Every primitive in this package that needs angr / claripy
should call the relevant ``*_available()`` at entry and return a
descriptive :class:`SymbolicResult` when the dep is missing, rather
than raising ImportError. Callers (the LLM tool wrappers) can then
present a clean "capability unavailable" signal instead of a
Python traceback.

Cheap by design — each probe is one import attempt, cached per
process. Import errors are logged once at debug level; subsequent
calls return the cached bool without re-attempting.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.symbolic._types import SymbolicResult

log = logging.getLogger(__name__)

_cache: dict[str, bool] = {}


def _probe(name: str, module: str) -> bool:
    if name in _cache:
        return _cache[name]
    if module == "angr":
        # Pre-set the noisy import-time logger: angr logs an ERROR
        # when optional acceleration (unicornlib) is missing —
        # operator noise, not a result channel. Must happen before
        # the first angr import anywhere, and this probe is the
        # substrate's earliest chokepoint.
        import logging as _logging
        _logging.getLogger(
            "angr.state_plugins.unicorn_engine").setLevel(
            _logging.CRITICAL)
    try:
        __import__(module)
        _cache[name] = True
    except Exception as exc:  # noqa: BLE001
        log.debug("core.symbolic dep %s unavailable: %s", name, exc)
        _cache[name] = False
    return _cache[name]


def angr_available() -> bool:
    """True when angr can be imported. Angr is the heaviest optional
    dep — CFG / symex / claripy. Primitives that need angr must
    check this first."""
    return _probe("angr", "angr")


def z3_available() -> bool:
    """True when Z3 (via claripy or direct) can be imported. Some
    primitives can degrade to Z3-only paths when angr is absent —
    e.g. constraint solving over a caller-supplied SMT formula
    doesn't need binary execution.

    Note: angr always pulls z3 via claripy, so ``z3_available()``
    should return True whenever ``angr_available()`` does. It can
    also return True when angr is missing but the standalone
    ``z3-solver`` package is installed for :mod:`core.smt_solver`.
    """
    return _probe("z3", "z3") or _probe("claripy", "claripy")




def clear_probe_cache() -> None:
    """Reset the availability cache. Test-only helper — production
    code should never need this."""
    _cache.clear()


def unavailable_result(dep: str, primitive: str) -> "SymbolicResult":
    """Uniform SymbolicResult for a primitive that can't run because
    its underlying dep isn't installed. Keeps the LLM tool surface
    consistent: same tool always registered; a clean 'unavailable'
    result on invocation rather than a Python traceback.
    """
    from core.symbolic._types import SymbolicResult
    return SymbolicResult(
        succeeded=False,
        reason=(
            f"{primitive} requires {dep}; not available on this "
            "install. Install the dep (e.g. `pip install "
            f"{dep}`) or use an alternate primitive."
        ),
        wall_seconds=0.0,
        metadata={"unavailable_dep": dep, "primitive": primitive},
    )
