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
    # Soft-dependency missing — expected, log at debug.
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False
    get_logger().debug(f"z3-solver not installed: {i}")
except Exception as e:
    # Anything OTHER than ImportError indicates the package
    # IS installed but failed to load. Pre-fix this branch
    # logged at debug — same level as the expected
    # not-installed case — so the operator never saw a hint
    # that Z3 is broken in their environment. Symptoms in
    # the wild:
    #
    #   * `OSError: libz3.so.4 cannot open shared object file`
    #     (system Z3 library mismatched against the wheel
    #     bundled with z3-solver — common after distro
    #     upgrades).
    #   * `RuntimeError` from Z3's C++ ctor on architectures
    #     where the wheel's prebuilt binary is incompatible
    #     (musl/Alpine vs the manylinux wheel).
    #   * `ImportError` re-raised from a transitive deep dep
    #     (caught by the outer `Exception` arm only on
    #     unusual stack-walks; normally caught above).
    #
    # In every case, SMT-dependent features (CodeQL dataflow
    # path-feasibility, exploit_feasibility one-gadget SMT)
    # silently degrade to "skipped" with no operator-visible
    # warning — the user thinks they're getting SMT
    # validation when they aren't.
    #
    # Log at WARNING so it lands in the operator's terminal
    # and `out/<run>/raptor.log`. The `exc_info=True` keeps
    # the original traceback for diagnosis (a wheel/lib
    # mismatch's stacktrace is the actionable bit).
    z3 = None
    _Z3_AVAILABLE = False
    get_logger().warning(
        "z3-solver is installed but failed to import — SMT-dependent "
        "features (CodeQL dataflow path-feasibility, exploit_feasibility "
        "one-gadget SMT) will be SKIPPED. Original error: %s",
        e, exc_info=True,
    )


def z3_available() -> bool:
    """True when the ``z3-solver`` package imported successfully."""
    return _Z3_AVAILABLE
