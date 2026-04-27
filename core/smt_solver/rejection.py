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
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


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
