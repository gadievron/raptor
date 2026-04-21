"""Z3 availability gate for RAPTOR's SMT harness.

Z3 is an optional soft dependency. When the ``z3-solver`` package is not
installed, the ``z3`` module attribute exported from here is ``None`` and
``z3_available()`` / ``smt_enabled()`` both return ``False``. Domain
encoders must check ``smt_enabled()`` before touching any solver API.

Environment:
    RAPTOR_SMT_ENABLED  - ``1`` to enable SMT passes (disabled by default)
"""
from __future__ import annotations

import os

try:
    import z3  # type: ignore
    _Z3_AVAILABLE = True
except ImportError:
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False


def z3_available() -> bool:
    """True when the ``z3-solver`` package imported successfully."""
    return _Z3_AVAILABLE


def smt_enabled() -> bool:
    """True when z3 is available AND ``RAPTOR_SMT_ENABLED=1``."""
    return _Z3_AVAILABLE and os.environ.get("RAPTOR_SMT_ENABLED", "0") == "1"
