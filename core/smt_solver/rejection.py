"""Structured rejection reasons for SMT encoder parsers.

When a domain encoder (``smt_path_validator``, ``smt_onegadget``) can't
turn a constraint string into a Z3 expression, the failure is recorded
as a :class:`Rejection` rather than just a textual entry in an
``unknown`` list.  The :class:`RejectionKind` tells callers — and the
LLM that produced the text — *why* the parse failed, so the long tail
of unparseable inputs can be retried with a rephrasing or fed back as
schema feedback rather than disappearing into a bag of strings.

Each domain encoder result keeps its existing ``unknown: List[str]``
field for backwards compatibility and adds a parallel
``unknown_reasons: List[Rejection]`` carrying the structured form.

This module also hosts the small set of helpers every encoder needs to
*build* and *route* rejections so future encoders pick them up for free
instead of cloning the logic:

- :func:`propagate` — re-anchor a sub-expression's rejection on its
  parent's full input text.
- :func:`parse_literal_value` — validate a hex/decimal literal against
  the active :class:`BVProfile`, returning the int or a structured
  :class:`Rejection` (out-of-range, leading-zero ambiguity, or
  unrecognised shape).
- :func:`classify_solver_unknown` — translate Z3's ``reason_unknown()``
  string into ``SOLVER_TIMEOUT`` vs ``SOLVER_UNKNOWN``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Union

from .config import BVProfile


class RejectionKind(str, Enum):
    """Why the parser refused to encode a constraint."""

    LEX_EMPTY = "lex_empty"
    """Tokeniser produced no tokens — input was empty or pure whitespace."""

    UNRECOGNIZED_FORM = "unrecognized_form"
    """Top-level structure didn't match any accepted condition pattern."""

    UNRECOGNIZED_OPERAND = "unrecognized_operand"
    """A token in operand position isn't a register, identifier, literal,
    NULL, or memory reference accepted by the encoder."""

    UNSUPPORTED_OPERATOR = "unsupported_operator"
    """An operator outside the accepted set appeared in the expression."""

    PARENS_NOT_SUPPORTED = "parens_not_supported"
    """Input contained ``(`` or ``)`` — function calls and grouping
    aren't supported by the current grammar."""

    MIXED_PRECEDENCE = "mixed_precedence"
    """Expression mixed additive and multiplicative/bitwise operators.
    The parser is strictly left-to-right with no precedence, so it
    rejects mixed forms rather than risk silent mis-encoding."""

    TRAILING_TOKENS = "trailing_tokens"
    """Tokens were left unconsumed after parsing (e.g. ``a b``)."""

    LITERAL_OUT_OF_RANGE = "literal_out_of_range"
    """Integer literal doesn't fit in the active profile width;
    accepting it would silently wrap inside ``z3.BitVecVal``."""

    LITERAL_AMBIGUOUS = "literal_ambiguous"
    """Decimal literal had a leading zero — ambiguous with C octal."""

    UNKNOWN_REGISTER = "unknown_register"
    """Token looked register-shaped but isn't in the active
    architecture's register set."""

    SOLVER_TIMEOUT = "solver_timeout"
    """Z3 returned ``unknown`` and reported the per-solver timeout was hit."""

    SOLVER_UNKNOWN = "solver_unknown"
    """Z3 returned ``unknown`` for some other reason (incomplete tactic,
    construct outside the decidable bitvector fragment)."""


@dataclass(frozen=True)
class Rejection:
    """Why a single constraint/condition couldn't participate in SMT analysis.

    ``text`` is the original input verbatim so callers can match it back
    to a source location.  ``kind`` is the machine-readable category;
    ``detail`` carries free-form context (e.g. the offending token);
    ``hint`` (when non-empty) names a concrete rephrasing that would let
    a retry succeed.
    """
    text: str
    kind: RejectionKind
    detail: str = ""
    hint: str = ""


# ---------------------------------------------------------------------------
# Shared encoder helpers
# ---------------------------------------------------------------------------

# Anchored via .fullmatch() at the call site, so the patterns themselves
# are intentionally unanchored — they accept the whole token or nothing.
_HEX_LITERAL_RE = re.compile(r'0x[0-9a-f]+', re.IGNORECASE)
_DEC_LITERAL_RE = re.compile(r'\d+')


def propagate(text: str, sub: Rejection) -> Rejection:
    """Re-anchor a sub-expression rejection on the full input text.

    Sub-parsers see only their own slice of input, so ``sub.text``
    starts out as that slice.  When bubbling up to the caller we
    replace it with ``text`` (the parent's full input) so consumers
    can match the rejection back to the original source.
    """
    return Rejection(text, sub.kind, sub.detail, sub.hint)


def parse_literal_value(tok: str, profile: BVProfile) -> Union[int, Rejection]:
    """Validate and convert a literal token, or return a structured rejection.

    Centralised so atom-position literals and bitmask-form literals
    across all encoders reject the same things:

    - Out-of-range for ``profile.width`` (would silently wrap inside
      ``z3.BitVecVal``, e.g. ``0x100`` at uint8 → 0, producing a
      misleading verdict) → :data:`RejectionKind.LITERAL_OUT_OF_RANGE`.
    - Leading-zero decimals (octal in C, ambiguous if interpreted as
      base-10) → :data:`RejectionKind.LITERAL_AMBIGUOUS`.
    - Anything that isn't a clean hex or decimal literal
      → :data:`RejectionKind.UNRECOGNIZED_OPERAND`.
    """
    if _HEX_LITERAL_RE.fullmatch(tok):
        v = int(tok, 16)
    elif _DEC_LITERAL_RE.fullmatch(tok):
        if len(tok) > 1 and tok[0] == "0":
            return Rejection(
                tok, RejectionKind.LITERAL_AMBIGUOUS,
                "leading-zero decimal is ambiguous with C octal",
                hint="rewrite as hex (0x...) or strip the leading zero",
            )
        v = int(tok)
    else:
        return Rejection(
            tok, RejectionKind.UNRECOGNIZED_OPERAND,
            f"token {tok!r} is not a hex or decimal literal",
        )
    if v >= (1 << profile.width):
        return Rejection(
            tok, RejectionKind.LITERAL_OUT_OF_RANGE,
            f"value {v:#x} exceeds {profile.width}-bit profile range",
        )
    return v


def classify_solver_unknown(solver: Any) -> RejectionKind:
    """Map Z3's ``reason_unknown()`` string to a :class:`RejectionKind`.

    Z3 reports ``"timeout"`` (or, on some builds, ``"canceled"``) when
    the per-solver timeout fires; anything else is grouped under
    :data:`RejectionKind.SOLVER_UNKNOWN` (incomplete tactic, undecidable
    fragment, ...).
    """
    try:
        reason = (solver.reason_unknown() or "").lower()
    except Exception:
        return RejectionKind.SOLVER_UNKNOWN
    if "timeout" in reason or "canceled" in reason or "cancelled" in reason:
        return RejectionKind.SOLVER_TIMEOUT
    return RejectionKind.SOLVER_UNKNOWN
