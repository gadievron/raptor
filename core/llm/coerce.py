"""Defensive numeric coercion — a shared home for the ``_safe_int`` /
``_safe_float`` helpers that pre-uplift each subsystem carried its own
copy of.

Rationale for a shared module rather than absorbing into
:mod:`core.cost`:

  * ``core.cost`` already owns the domain-specific clamping rule for
    LLM cost accumulators (NaN / +inf / negative → 0.0). Extending
    it to be a general-purpose numeric coerecer would blur its
    contract.
  * ``providers.py`` (LLM SDK subprocess envelope) and
    ``scorecard.py`` (persisted-cell numeric fields) both want
    "coerce with a caller-supplied default, log the failure so a
    real upstream regression is visible, never raise mid-hot-path".
    Same semantics, no domain overlap — the right home is a
    general-purpose module.

Callers:

  * ``core/llm/providers.py`` — CC subprocess envelope's cost / token
    coercion.
  * ``core/llm/scorecard/scorecard.py`` — cell-field coercion under
    the write lock.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

_default_log = logging.getLogger(__name__).debug


def to_int_safe(
    value: Any,
    *,
    default: int = 0,
    on_error: Optional[Callable[[Any, int], None]] = None,
) -> int:
    """Coerce ``value`` to ``int``; return ``default`` on failure.

    Handles ``None`` and empty string as "no value → default" without
    entering the try block (avoids logging a benign miss).

    ``on_error(value, default)`` is called when the coercion raises
    ``TypeError`` or ``ValueError``. Callers pass their own logger
    (typically ``.debug``) so a real upstream regression is visible
    without crashing the run. Default is a package-level DEBUG log.
    """
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        (on_error or _default_log)(value, default)
        return default


def to_float_safe(
    value: Any,
    *,
    default: float = 0.0,
    on_error: Optional[Callable[[Any, float], None]] = None,
) -> float:
    """Float counterpart to :func:`to_int_safe`. Same semantics."""
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        (on_error or _default_log)(value, default)
        return default


__all__ = ["to_int_safe", "to_float_safe"]
