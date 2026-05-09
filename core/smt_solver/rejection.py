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
from typing import Any, Optional, Union

from .availability import z3
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
    """Deprecated — kept for backward compatibility with downstream
    consumers that match on this value.  No encoder emits it any more:
    the path validator's expression parser now supports grouping
    parentheses via precedence climbing, and unbalanced cases emit
    :data:`UNBALANCED_PARENS` instead."""

    UNBALANCED_PARENS = "unbalanced_parens"
    """Input had ``(`` without a matching ``)`` (or vice versa).  Fired
    by the path validator's expression parser when the bracket structure
    of a grouping subexpression doesn't close cleanly, or by the
    condition-level balance check before dispatch."""

    MIXED_PRECEDENCE = "mixed_precedence"
    """Deprecated — kept for backward compatibility with downstream
    consumers that match on this value.  No encoder emits it any more:
    the path validator's expression parser now uses C operator precedence
    (``*`` > ``+ -`` > ``<< >>`` > ``|``) and accepts mixed-operator
    expressions directly.  Use parentheses to override precedence."""

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


# RejectionKinds that no encoder emits any more but that we've kept in
# the enum for back-compat with downstream consumers that match on the
# string value. Constructing a `Rejection(kind=...)` with one of these
# is almost certainly a mistake — a freshly-written encoder rule that
# accidentally targets a stale category, or a refactor that moved
# semantics from PARENS_NOT_SUPPORTED → UNBALANCED_PARENS but missed a
# call site. Emit a DeprecationWarning at construction time so the
# misuse surfaces in tests / dev runs without breaking external
# consumers that only consume the string value via API output.
_DEPRECATED_KINDS = frozenset({
    RejectionKind.PARENS_NOT_SUPPORTED,
    RejectionKind.MIXED_PRECEDENCE,
})


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

    def __post_init__(self) -> None:
        if self.kind in _DEPRECATED_KINDS:
            import warnings
            warnings.warn(
                f"Rejection(kind={self.kind.name}) is deprecated; "
                f"the parser no longer emits this category. "
                f"Use UNBALANCED_PARENS (for unbalanced groups) or "
                f"omit the rejection entirely (for precedence-mixed "
                f"expressions, which the parser now accepts).",
                DeprecationWarning,
                stacklevel=2,
            )


# ---------------------------------------------------------------------------
# Shared encoder helpers
# ---------------------------------------------------------------------------

# Anchored via .fullmatch() at the call site, so the patterns themselves
# are intentionally unanchored — they accept the whole token or nothing.
_HEX_LITERAL_RE = re.compile(r'0x[0-9a-f]+', re.IGNORECASE)
# Decimal literals may carry a leading `-` so source-form expressions
# like ``x > -10`` or ``errno == -EAGAIN`` (when the C macro expands
# to a literal) are parseable. Hex literals stay positive-only —
# `-0xff` isn't real source-form input; bit-pattern literals are
# always written as their unsigned representation.
_DEC_LITERAL_RE = re.compile(r'-?\d+')


def propagate(text: str, sub: Rejection) -> Rejection:
    """Re-anchor a sub-expression rejection on the full input text.

    Sub-parsers see only their own slice of input, so ``sub.text``
    starts out as that slice.  When bubbling up to the caller we
    replace it with ``text`` (the parent's full input) so consumers
    can match the rejection back to the original source.

    Carry the inner cause through the detail so chained propagations
    don't lose the cause location. Pre-fix the propagate sequence
    overwrote text at each hop without preserving the inner slice's
    text in the visible output:

        outer "(a + b) > 10"
          inner "a + b" → Rejection(text="a + b", detail="bad token")
          propagate("(a + b) > 10", sub) →
              Rejection(text="(a + b) > 10", detail="bad token")

    The operator saw "(a + b) > 10" with detail "bad token" and had
    no signal that the failure originated in the inner `a + b` slice
    — they had to re-parse the outer text to localise the cause.
    Three levels of propagation lost the inner context twice over.

    Append the inner slice to the detail when it differs from the
    new outer text, so the cause-chain stays visible:

        Rejection(text="(a + b) > 10",
                  detail="bad token (in: 'a + b')")

    Idempotent: if the sub.text already matches the new outer text
    (caller propagates a same-level rejection), no annotation is
    added — keeps the message clean for non-chained cases.
    """
    detail = sub.detail
    if sub.text and sub.text != text and "(in:" not in detail:
        # Truncate inner-text rendering at 80 chars so a deeply
        # nested expression doesn't blow up the rejection message.
        inner = sub.text if len(sub.text) <= 80 else sub.text[:77] + "..."
        suffix = f" (in: {inner!r})" if not detail else f" (in: {inner!r})"
        detail = f"{detail}{suffix}" if detail else f"(in: {inner!r})"
    return Rejection(text, sub.kind, detail, sub.hint)


def parse_literal_value(
    tok: str,
    profile: BVProfile,
    *,
    outer_text: Optional[str] = None,
) -> Union[int, Rejection]:
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

    Text-anchoring contract: by default the returned ``Rejection.text``
    is the per-token slice (``tok``), and the caller is expected to
    call :func:`propagate` to re-anchor on the parent expression's
    text. Pre-fix every caller that forgot the propagate step
    surfaced rejections to consumers with `text=tok` only — useful
    for the LITERAL_AMBIGUOUS / OUT_OF_RANGE messages but unhelpful
    for source-location lookup since the operator can't grep for a
    bare token like `0x100` in a 5000-line constraint set. Pass
    ``outer_text=<parent expression>`` to self-anchor: the function
    stores ``outer_text`` in ``Rejection.text`` and folds the token
    into the detail message, removing the propagate dependency.
    """
    # Text anchor: prefer caller-supplied outer expression when
    # provided, otherwise the bare token. Detail uniformly mentions
    # the token via `{tok!r}` so the operator-facing message is the
    # same regardless of anchoring choice.
    text = outer_text if outer_text is not None else tok
    is_hex = bool(_HEX_LITERAL_RE.fullmatch(tok))
    if is_hex:
        v = int(tok, 16)
    elif _DEC_LITERAL_RE.fullmatch(tok):
        # Leading-zero check applies only to the magnitude — `-01234`
        # has the same C-octal ambiguity as `01234`. Skip the sign
        # before checking.
        magnitude = tok.lstrip("-")
        if len(magnitude) > 1 and magnitude[0] == "0":
            return Rejection(
                text, RejectionKind.LITERAL_AMBIGUOUS,
                f"leading-zero decimal is ambiguous with C octal (token {tok!r})",
                hint="rewrite as hex (0x...) or strip the leading zero",
            )
        v = int(tok)
    else:
        return Rejection(
            text, RejectionKind.UNRECOGNIZED_OPERAND,
            f"token {tok!r} is not a hex or decimal literal",
        )
    # Range check, with hex vs decimal distinction:
    #
    # * Hex literals are BIT PATTERNS. `0x80000000` at int32
    #   profile represents the underlying bit pattern of -2^31,
    #   which IS representable as signed int32 (just at the
    #   negative end of two's complement). Allow up to 2^width
    #   regardless of signedness — width caps what the bit
    #   pattern can encode, signedness only changes how Z3
    #   *interprets* the value during model rendering.
    #
    # * Decimal literals are NUMERICAL values. `200` at int8
    #   profile (signed, range -128..127) doesn't fit even though
    #   the bit pattern (0xC8) does — Z3 would silently
    #   reinterpret it as -56, producing a verdict that didn't
    #   match the source intent. Cap decimal literals at
    #   2^(width-1) for signed profiles. (The regex rejects
    #   leading '-', so we only see positive decimals here.)
    #
    # Pre-batch-210 the check used `v >= (1 << profile.width)`
    # uniformly, which over-accepted decimal literals (the `200`
    # at int8 case). Batch 210 over-corrected by tightening BOTH
    # paths, which over-rejected hex literals like `0x80000000`
    # at int32. This split restores hex support while keeping the
    # decimal sign-discipline.
    if is_hex or not profile.signed:
        upper_exclusive = 1 << profile.width
        lower_inclusive = 0  # hex + unsigned reject negatives
    else:
        upper_exclusive = 1 << (profile.width - 1)
        # Signed two's-complement range is asymmetric: ``int8`` covers
        # ``-128..127`` (lower bound is ``-2^(width-1)``, upper is
        # ``2^(width-1) - 1``). A decimal `-128` at int8 must be
        # accepted; `-129` rejected.
        lower_inclusive = -(1 << (profile.width - 1))
    if v >= upper_exclusive or v < lower_inclusive:
        if is_hex:
            range_desc = f"{profile.width}-bit range"
        else:
            range_desc = f"{profile.describe()} range"
        return Rejection(
            text, RejectionKind.LITERAL_OUT_OF_RANGE,
            f"value {v:#x} (from token {tok!r}) outside {range_desc} "
            f"({lower_inclusive:#x}..{upper_exclusive - 1:#x})",
        )
    return v


def classify_solver_unknown(solver: Any) -> RejectionKind:
    """Map Z3's ``reason_unknown()`` string to a :class:`RejectionKind`.

    Z3 reports ``"timeout"`` (or, on some builds, ``"canceled"``) when
    the per-solver timeout fires; anything else is grouped under
    :data:`RejectionKind.SOLVER_UNKNOWN` (incomplete tactic, undecidable
    fragment, ...).
    """
    # Catch the specific failure modes Z3 may exhibit — bare
    # `except Exception` swallowed programming bugs introduced by
    # future maintainers (AttributeError if `solver` is the wrong
    # type, NameError, etc.) and silently mis-classified them as
    # SOLVER_UNKNOWN. Z3's `reason_unknown` may legitimately raise
    # `z3.Z3Exception` (no model available — solver hasn't been
    # called yet; called after add() during reset; etc.) or
    # `RuntimeError` from the wrapping in some Z3 builds. Also
    # tolerate AttributeError specifically — caller passing None or
    # a stub object is explicit-enough that we shouldn't crash, but
    # narrower TypeError-level mismatches should propagate.
    try:
        reason = (solver.reason_unknown() or "").lower()
    except (AttributeError,) + (
        (z3.Z3Exception,) if hasattr(z3, "Z3Exception") else ()
    ) + (RuntimeError,):
        return RejectionKind.SOLVER_UNKNOWN
    if "timeout" in reason or "canceled" in reason or "cancelled" in reason:
        return RejectionKind.SOLVER_TIMEOUT
    return RejectionKind.SOLVER_UNKNOWN
