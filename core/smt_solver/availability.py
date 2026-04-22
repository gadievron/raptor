"""Z3 availability gate for RAPTOR's SMT harness.

Z3 is an optional soft dependency. When the ``z3-solver`` package is not
installed, the ``z3`` module attribute exported from here is ``None`` and
``z3_available()`` returns ``False``. 

"""
from __future__ import annotations
from core.logging import get_logger

import os

try:
    import z3  # type: ignore
    _Z3_AVAILABLE = True
except ImportError as i:
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False
    get_logger().debug(f"An import error occurred: {i}")
except Exception as e:
    z3 = None
    _Z3_AVAILABLE = False
    get_logger().debug(f"An Exception occurred: {e}")


def z3_available() -> bool:
    """True when the ``z3-solver`` package imported successfully."""
    return _Z3_AVAILABLE
