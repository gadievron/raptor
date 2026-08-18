"""Defensive coercion of LLM-call surfaces — numeric values,
structured-response unwrapping, and fenced-code extraction.

Numeric half: a shared home for the ``_safe_int`` / ``_safe_float``
helpers that pre-uplift each subsystem carried its own copy of.

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

Response half: :func:`structured_result` replaces the
``response.result if hasattr(response, "result") else response[0]``
unwrap idiom copied across a dozen ``generate_structured`` consumers,
and :func:`extract_fenced_code` replaces the hand-rolled FIRST-block
markdown-fence strippers used on freeform code replies (QL predicates,
generated snippets). JSON consumers wanting the injection-hardened
LAST-block selection keep using
:func:`core.llm.cc_adapter.strip_json_fences` — the two selection
policies are deliberately distinct functions, not a flag.

Callers (numeric):

  * ``core/llm/providers.py`` — CC subprocess envelope's cost / token
    coercion.
  * ``core/llm/scorecard/scorecard.py`` — cell-field coercion under
    the write lock.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

_logger = logging.getLogger(__name__)

_MISSING = object()

_LEADING_LANG_TAG_RE = re.compile(r"^[A-Za-z]+\s*")


def _default_log(value: object, default: object) -> None:
    _logger.debug("coerce fallback: %r → %r", value, default)


def to_int_safe(
    value: Any,
    *,
    default: int = 0,
    on_error: Callable[[Any, int], None] | None = None,
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
    on_error: Callable[[Any, float], None] | None = None,
) -> float:
    """Float counterpart to :func:`to_int_safe`. Same semantics."""
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        (on_error or _default_log)(value, default)
        return default


def structured_result(response: Any, *, default: Any = None) -> Any:
    """Unwrap the result payload from a ``generate_structured`` return.

    The canonical return is :class:`core.llm.providers.
    StructuredResponse` (``.result`` + 2-tuple unpack compatibility),
    but a decade of call sites also tolerate bare ``(result, raw)``
    tuples from stubs, already-unwrapped dicts, and ``None``. This is
    the one spelling of that tolerance:

    * ``None`` → *default*
    * object with ``.result`` → ``response.result``
    * ``dict`` → returned as-is (already unwrapped)
    * indexable (tuple/list) → ``response[0]``
    * anything else → *default*

    Never raises — the hand-rolled copies sat inside broad ``try``
    blocks and an unwrap failure must stay non-fatal.
    """
    if response is None:
        return default
    result = getattr(response, "result", _MISSING)
    if result is not _MISSING:
        return result
    if isinstance(response, dict):
        return response
    try:
        return response[0]
    except (TypeError, IndexError, KeyError):
        return default


def extract_fenced_code(text: str) -> str:
    """Extract the FIRST markdown-fenced block's body from a freeform
    code reply (QL predicates, generated snippets), tolerating fences
    the prompt forbade. Without a fence the stripped text is returned
    unchanged.

    The fence line's language tag is dropped (first line of a
    multi-line block; leading alphabetic tag of a single-line block),
    and stray trailing backticks are stripped — the union of the
    consolidated copies' behaviours.

    NOT for JSON: schema-shaped replies must go through
    :func:`core.llm.cc_adapter.strip_json_fences`, whose LAST-block
    preference defeats prepend-prefix injection.
    """
    text = (text or "").strip()
    if "```" not in text:
        return text
    block = text.split("```", 2)[1]
    if "\n" in block:
        # Drop the fence line (optional language tag).
        block = block.split("\n", 1)[1]
    else:
        # Single-line block — strip a leading language tag.
        block = _LEADING_LANG_TAG_RE.sub("", block)
    return block.strip().rstrip("`").strip()


__all__ = [
    "extract_fenced_code",
    "structured_result",
    "to_float_safe",
    "to_int_safe",
]
