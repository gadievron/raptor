#!/usr/bin/env python3
"""
SMT-based path condition feasibility checker for CodeQL dataflow findings.

The LLM extracts branch conditions from a dataflow path as structured
constraint strings; this module encodes them into Z3 bitvector expressions
and checks whether they are jointly satisfiable.

- sat   → path is reachable; model gives concrete variable values for PoC
- unsat → path conditions are mutually exclusive (likely false positive);
          unsat core names the specific conflicting conditions
- None  → Z3 unavailable or all conditions unparseable; fall back to LLM

Accepted condition forms (case-insensitive):
  size > 0
  size < 1024
  offset + length <= buffer_size
  count * 16 < max_alloc       (bitvector mul — wraps at the chosen width)
  n >> 1 < limit               (arithmetic right shift when the profile is
                               signed; logical right shift when unsigned)
  n << 3 == buf_size           (left shift)
  flags | 0x1 != 0             (bitwise OR)
  ptr != NULL  /  ptr == NULL
  index >= 0
  flags & 0x80000000 == 0
  value == 42

Width and signedness are carried by a ``BVProfile`` (from
``core.smt_solver``).  Default is ``BV_C_UINT64`` — 64-bit unsigned,
matching sizes / offsets / counts which dominate dataflow path
conditions.  Pass ``BV_C_UINT32`` to detect 32-bit unsigned wraparound
(CWE-190); pass ``BV_C_INT32`` for signed-integer path conditions.
Pre-made profiles are importable from ``core.smt_solver``.

Conditions rejected to the ``unknown`` bucket (rather than silently
mis-encoded):

  - **Operators outside the supported set.**  Accepted: ``+ - * |``,
    relational ``< <= > >= == !=``, shifts ``<< >>``, bitmask
    ``&`` (only in the ``flags & MASK == VAL`` form).  Rejected:
    unary NOT (``~``), XOR (``^``), division (``/``), modulo (``%``),
    ternary (``? :``), single-equals assignment, chained relational
    (``0 < x < 100``).  Anything else goes to ``unknown`` via the
    full-input-consumed sanity check.
  - **C-syntax constructs.**  Function calls (``strlen(input)``),
    type casts (``(uint32_t)x``), struct/pointer access (``obj.field``,
    ``s->len``), array indexing (``arr[0]``), pointer dereference
    (``*p``), ``sizeof``.  Any token containing ``(``, ``)``, ``.``,
    ``->``, ``[``, ``]`` triggers rejection.
  - **Negative integer literals** (e.g. ``!= -1``) — write the
    bit-pattern in hex instead (``!= 0xFFFFFFFF`` at uint32).
  - **Leading-zero decimals** (e.g. ``01234``) — ambiguous with C
    octal; use hex or remove the leading zero.
  - **Literals outside the profile's width range** — ``0x100`` at
    uint8 would silently wrap to 0 in z3; we reject so the caller
    knows the profile was wrong for this literal.

Other limitations (verdict still trustworthy, but with caveats):

  - **No operator precedence** — expressions are evaluated strictly
    left-to-right.  Mixed-operator expressions (e.g. ``a + b * c``)
    are rejected to avoid mis-encoding; full precedence support is
    planned for a follow-up.  ``a * b * c`` and ``a + b + c`` are
    fine (associativity preserves correctness).
  - **Bitmask form** requires both ``MASK`` and ``VAL`` to be integer
    literals; variables on either side go to ``unknown``.
  - **Profile-level signedness conflates** two concerns: comparison
    signedness (``<``/``<=``/``>``/``>=`` routed through ``lt``/``le``)
    AND ``>>`` arithmetic-vs-logical shift.  In real C these can
    decouple (``(int)x >> 1`` is always arithmetic regardless of the
    comparison's signedness).  Single-profile-per-path is the
    first-cut design; per-variable typing is the next step when a
    real case demands it.
  - **Z3 picks the smallest satisfying witness by default**, which is
    often the trivial assignment (``x = 0``).  To find an *exploit*
    witness, add a lower-bound condition that forces the dangerous
    range (e.g. ``count > 0x10000000`` for CWE-190 wraparound at
    uint32).  Will be addressed by Z3 Optimize integration in a
    follow-up.

Integration: packages/codeql/dataflow_validator.py :: DataflowValidator
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.logging import get_logger as _get_logger
from core.smt_solver import (
    BV_C_UINT64,
    BVProfile,
    DEFAULT_TIMEOUT_MS as _DEFAULT_TIMEOUT_MS,
    core_names as _core_names,
    mk_val as _mk_val,
    mk_var as _mk_var,
    new_solver as _new_solver,
    scoped as _scoped,
    track as _track,
    z3,
    z3_available as _z3_available,
)
from core.smt_solver.bitvec import ge, gt, le, lt
from core.smt_solver.csem import ashr as _ashr, lshr as _lshr
from core.smt_solver.witness import format_witness as _format_witness


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class PathCondition:
    """A single guard/branch condition extracted from a dataflow step."""
    text: str
    step_index: int
    negated: bool = False


@dataclass
class PathSMTResult:
    """Result of SMT feasibility check over a set of path conditions."""
    feasible: Optional[bool]
    satisfied: List[str]
    unsatisfied: List[str]
    unknown: List[str]
    model: Dict[str, int]
    smt_available: bool
    reasoning: str


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r'^0x[0-9a-f]+$', re.IGNORECASE)
_INT_RE = re.compile(r'^\d+$')
_IDENT_RE = re.compile(r'^[a-z_][a-z0-9_]*$', re.IGNORECASE)
_NULL_RE = re.compile(r'^NULL$', re.IGNORECASE)

# Tokenise: identifiers, hex literals, decimal literals, operators.
# '>>' and '<<' appear before '[<>&|]' so they are matched as two-char tokens
# rather than as two separate single-char tokens.
_TOKEN_RE = re.compile(
    r'(0x[0-9a-f]+|\d+|[a-z_][a-z0-9_]*|[+\-*]|<=|>=|!=|==|>>|<<|[<>&|])',
    re.IGNORECASE,
)


def _parse_literal_value(tok: str, profile: BVProfile) -> Optional[int]:
    """Validate and convert a literal token to int, or None if invalid.

    Centralised so atom-position literals and bitmask-form literals both
    reject the same things:

    - Out-of-range for profile width (would silently wrap in z3.BitVecVal).
    - Leading-zero decimals (octal in C, ambiguous if interpreted as base-10).
    - Anything that isn't a clean hex or decimal literal.
    """
    if _HEX_RE.match(tok):
        v = int(tok, 16)
    elif _INT_RE.match(tok):
        if len(tok) > 1 and tok[0] == "0":
            return None  # ambiguous with C octal
        v = int(tok)
    else:
        return None
    if v >= (1 << profile.width):
        return None
    return v


def _parse_expr(text: str, vars_: Dict[str, Any], *, profile: BVProfile) -> Optional[Any]:
    """Parse an arithmetic expression into a Z3 bitvector at the given profile.

    Handles: identifier, NULL, hex literal, decimal literal, and binary
    +/-/* /|/shifts between those terms (left-to-right, no precedence).
    Right-shift is routed through ``csem.ashr`` / ``csem.lshr`` by
    signedness so the same ``>>`` source form encodes differently for
    signed vs unsigned path conditions.

    Returns None — rather than a partial result — when an unsupported
    token is encountered mid-expression, so the whole condition falls
    through to the unknown list rather than being silently mis-encoded.
    """
    tokens = [t for t in _TOKEN_RE.findall(text.strip()) if t not in ('(', ')')]
    if not tokens:
        return None

    # Reject if any non-whitespace character was silently dropped by the
    # tokeniser — characters like '~' (NOT), '^' (XOR), '/', '%' aren't in
    # the token regex and would otherwise vanish, producing wrong answers
    # (e.g. "~mask == 0xFF" mis-encoded as "mask == 0xFF").
    if "".join(tokens) != re.sub(r"\s+", "", text):
        return None

    # Reject mixed-operator expressions to avoid silent mis-encoding due to
    # the lack of operator precedence (currently strictly left-to-right).
    if {'+', '-'} & set(tokens[1::2]) and {'*', '>>', '<<', '|'} & set(tokens[1::2]):
        return None

    def atom(tok: str) -> Optional[Any]:
        if _NULL_RE.match(tok):
            return _mk_val(0, profile.width)
        if _HEX_RE.match(tok) or _INT_RE.match(tok):
            v = _parse_literal_value(tok, profile)
            return None if v is None else _mk_val(v, profile.width)
        if _IDENT_RE.match(tok):
            if tok.lower() not in vars_:
                vars_[tok.lower()] = _mk_var(tok.lower(), profile.width)
            return vars_[tok.lower()]
        return None

    # Left-to-right accumulation of arithmetic and bitwise operators.
    # Any unsupported operator causes an immediate None return.
    result = atom(tokens[0])
    if result is None:
        return None
    i = 1
    while i < len(tokens) - 1:
        op = tokens[i]
        if op not in ('+', '-', '*', '|', '>>', '<<'):
            return None  # unsupported op — reject cleanly
        right = atom(tokens[i + 1])
        if right is None:
            return None
        if op == '+':
            result = result + right
        elif op == '-':
            result = result - right
        elif op == '*':
            result = result * right
        elif op == '|':
            result = result | right
        elif op == '>>':
            # Route right-shift through csem so signedness picks the
            # correct arithmetic vs logical variant.
            result = _ashr(result, right) if profile.signed else _lshr(result, right)
        else:  # '<<'
            result = result << right
        i += 2

    # Reject orphaned trailing tokens.
    if i != len(tokens):
        return None

    return result


def _parse_condition(text: str, vars_: Dict[str, Any], *, profile: BVProfile) -> Optional[Any]:
    """Parse a single condition string into a Z3 boolean expression.

    Recognised forms:
      lhs == rhs / lhs != rhs
      lhs < rhs  / lhs <= rhs / lhs > rhs / lhs >= rhs
      lhs & mask == val  (bitmask alignment)
      lhs & mask != val

    Conditions containing function-call syntax (parentheses) are rejected
    and return None — they go to the unknown list.
    """
    t = text.strip()

    if '(' in t or ')' in t:
        return None

    # Bitmask: lhs & mask (==|!=) val
    m = re.fullmatch(
        r'(.+?)\s*&\s*(0x[0-9a-f]+|\d+)\s*(==|!=)\s*(0x[0-9a-f]+|\d+)',
        t, re.IGNORECASE,
    )
    if m:
        lhs = _parse_expr(m.group(1).strip(), vars_, profile=profile)
        if lhs is None:
            return None
        # Mask and rhs literals go through the same validation as atom-level
        # literals — width range and leading-zero ambiguity must be rejected
        # the same way, otherwise the bitmask path silently wraps or trips
        # ValueError on octal-style tokens.
        mask_val = _parse_literal_value(m.group(2), profile)
        rhs_val = _parse_literal_value(m.group(4), profile)
        if mask_val is None or rhs_val is None:
            return None
        masked = lhs & _mk_val(mask_val, profile.width)
        rhs = _mk_val(rhs_val, profile.width)
        return (masked == rhs) if m.group(3) == '==' else (masked != rhs)

    # Relational: lhs OP rhs
    # The LHS pattern consumes '>>' and '<<' as atomic units so the regex
    # doesn't split inside a shift operator.
    m = re.fullmatch(
        r'((?:>>|<<|[^<>]|(?<![<>])[<>](?![<>]))+?)'
        r'\s*(<=|>=|!=|==|<(?!<)|>(?!>))\s*(.+)',
        t,
    )
    if m:
        lhs = _parse_expr(m.group(1).strip(), vars_, profile=profile)
        rhs = _parse_expr(m.group(3).strip(), vars_, profile=profile)
        if lhs is None or rhs is None:
            return None
        op = m.group(2)
        if op == '==':
            return lhs == rhs
        if op == '!=':
            return lhs != rhs
        if op == '<':
            return lt(lhs, rhs, signed=profile.signed)
        if op == '<=':
            return le(lhs, rhs, signed=profile.signed)
        if op == '>':
            return gt(lhs, rhs, signed=profile.signed)
        if op == '>=':
            return ge(lhs, rhs, signed=profile.signed)

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_path_feasibility(
    conditions: List[PathCondition],
    *,
    profile: BVProfile = BV_C_UINT64,
) -> PathSMTResult:
    """
    Check whether a set of path conditions are jointly satisfiable.

    Args:
        conditions: Conditions extracted from a dataflow path.  Each has
                    a ``text`` field (e.g. ``"size < 1024"``) and an
                    optional ``negated`` flag for conditions that must
                    be *false* for the path to proceed.
        profile:    BVProfile setting bitvector width, relational-operator
                    signedness, right-shift semantics, and witness
                    rendering.  Defaults to BV_C_UINT64 (64-bit unsigned).
                    Use BV_C_UINT32 for CWE-190 32-bit wraparound paths;
                    BV_C_INT32 for signed-integer path conditions; etc.

    Returns:
        PathSMTResult.  feasible=None when Z3 is unavailable or every
        condition was unparseable.
    """
    mode = profile.describe()

    if not _z3_available():
        return PathSMTResult(
            feasible=None,
            satisfied=[], unsatisfied=[],
            unknown=[c.text for c in conditions],
            model={}, smt_available=False,
            reasoning="z3 not available — install z3-solver for path feasibility analysis",
        )

    if not conditions:
        return PathSMTResult(
            feasible=True,
            satisfied=[], unsatisfied=[], unknown=[],
            model={}, smt_available=True,
            reasoning=f"no conditions ({mode}) — path is unconditionally reachable",
        )

    vars_: Dict[str, Any] = {}
    solver = _new_solver()

    satisfied: List[str] = []
    unknown: List[str] = []
    pending: List[Tuple[str, Any]] = []

    for cond in conditions:
        expr = _parse_condition(cond.text, vars_, profile=profile)
        if expr is None:
            _get_logger().debug(f"smt_path_validator: unparseable condition: {cond.text!r}")
            unknown.append(cond.text)
            continue

        final_expr = z3.Not(expr) if cond.negated else expr
        # Display form reflects what was actually asserted — without this,
        # an unsat-core listing for a negated condition shows the un-negated
        # text and confuses readers ("ptr != NULL ⊥ ptr > 0" looks
        # consistent until you realise we asserted ptr == 0 not ptr != NULL).
        display = f"NOT ({cond.text})" if cond.negated else cond.text

        # Quick individual check: is this condition alone satisfiable?
        with _scoped(solver):
            solver.add(z3.Not(final_expr))
            if solver.check() == z3.unsat:
                # Condition is a tautology — trivially satisfied
                satisfied.append(display)
                continue

        pending.append((display, final_expr))

    if not pending:
        if unknown:
            return PathSMTResult(
                feasible=None,
                satisfied=satisfied, unsatisfied=[], unknown=unknown,
                model={}, smt_available=True,
                reasoning=(
                    f"indeterminate ({mode}): {len(satisfied)} trivially satisfied, "
                    f"{len(unknown)} unparseable — LLM analysis required"
                ),
            )
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=[],
            model={}, smt_available=True,
            reasoning=f"all {len(satisfied)} condition(s) trivially satisfied ({mode})",
        )

    label_map = _track(solver, pending)
    result = solver.check()

    if result == z3.sat:
        model_dict = _format_witness(solver.model(), signed=profile.signed)
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=unknown,
            model=model_dict, smt_available=True,
            reasoning=(
                f"feasible ({mode}): {len(pending)} condition(s) are jointly satisfiable"
                + (f"; {len(satisfied)} trivially satisfied" if satisfied else "")
                + (f"; {len(unknown)} unparsed" if unknown else "")
            ),
        )

    if result == z3.unsat:
        conflicts = _core_names(solver, label_map)
        conflict_set = conflicts if conflicts else [t for t, _ in pending]
        reasoning = f"infeasible ({mode}): path conditions are mutually exclusive"
        if conflicts:
            reasoning += f"; conflict: {' ⊥ '.join(conflicts[:3])}"
        return PathSMTResult(
            feasible=False,
            satisfied=satisfied, unsatisfied=conflict_set, unknown=unknown,
            model={}, smt_available=True,
            reasoning=reasoning,
        )

    # z3.unknown — timeout or outside decidable fragment
    return PathSMTResult(
        feasible=None,
        satisfied=satisfied, unsatisfied=[],
        unknown=unknown + [t for t, _ in pending],
        model={}, smt_available=True,
        reasoning=(
            f"Z3 returned unknown ({mode}) — likely the {_DEFAULT_TIMEOUT_MS}ms timeout "
            f"or conditions outside the bitvector fragment"
        ),
    )
