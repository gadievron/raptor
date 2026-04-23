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
  count * 16 < max_alloc       (bitvector mul — wraparound at 2^64, not 2^32)
  n >> 1 < limit               (logical right shift)
  n << 3 == buf_size           (left shift)
  flags | 0x1 != 0             (bitwise OR)
  ptr != NULL  /  ptr == NULL
  index >= 0
  flags & 0x80000000 == 0
  value == 42

Variables are created as 64-bit bitvectors.  Unsigned comparisons are used
by default (e.g. 0 <= index < size is encoded as index >= 0 and index < size) since
most dataflow-relevant variables are sizes, offsets, counts, and bitmasks.

Limitations:
  - Negative integer literals (e.g. != -1) go to the unknown list.
  - Bitvector width is 64 bits.  Multiplication overflow wraps at 2^64, not
    at the C type width (32-bit unsigned int overflows are invisible unless
    the LLM separates the already-computed result as a distinct variable).
  - Unary NOT (~) is not supported; conditions using it fall through to unknown.
  - Bitmask form (flags & MASK == val) requires both MASK and val to be
    integer literals.

Integration: packages/codeql/dataflow_validator.py :: DataflowValidator
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.logging import get_logger as _get_logger
from core.smt_solver import (
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
from core.smt_solver.witness import format_witness as _format_witness

_WIDTH = 64
_SIGNED = False

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


def _parse_expr(text: str, vars_: Dict[str, Any]) -> Optional[Any]:
    """Parse an arithmetic expression into a Z3 bitvector.

    Handles: identifier, NULL, hex literal, decimal literal,
    and binary +/- /* between those terms (left-to-right, no precedence).

    Returns None — rather than a partial result — when an unsupported token
    is encountered mid-expression.  This prevents conditions like
    ``count * 16 < MAX`` from being silently mis-encoded as ``count < MAX``.
    """
    tokens = [t for t in _TOKEN_RE.findall(text.strip()) if t not in ('(', ')')]
    if not tokens:
        return None

    def atom(tok: str) -> Optional[Any]:
        if _NULL_RE.match(tok):
            return _mk_val(0, width=_WIDTH)
        if _HEX_RE.match(tok):
            return _mk_val(int(tok, 16), width=_WIDTH)
        if _INT_RE.match(tok):
            return _mk_val(int(tok), width=_WIDTH)
        if _IDENT_RE.match(tok):
            if tok.lower() not in vars_:
                vars_[tok.lower()] = _mk_var(tok.lower(), width=_WIDTH)
            return vars_[tok.lower()]
        return None

    # Left-to-right accumulation of arithmetic and bitwise operators.
    # Any unsupported operator causes an immediate None return so the
    # condition falls through to the unknown list rather than encoding
    # a silently truncated (and incorrect) expression.
    #
    # '>>' is logical right shift (z3.LShR) — correct for unsigned values.
    # '<<' is left shift; '*' and '+'/'-' are standard bitvector arithmetic.
    # '|' is bitwise OR.
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
            result = z3.LShR(result, right)  # logical (unsigned) right shift
        else:  # '<<'
            result = result << right
        i += 2

    # Reject orphaned trailing tokens (e.g. 'flags' when '| 0x1' was silently
    # dropped by the tokeniser before this fix).
    if i != len(tokens):
        return None

    return result


def _parse_condition(text: str, vars_: Dict[str, Any]) -> Optional[Any]:
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
        lhs = _parse_expr(m.group(1).strip(), vars_)
        if lhs is None:
            return None
        masked = lhs & _mk_val(int(m.group(2), 0), width=_WIDTH)
        rhs = _mk_val(int(m.group(4), 0), width=_WIDTH)
        return (masked == rhs) if m.group(3) == '==' else (masked != rhs)

    # Relational: lhs OP rhs
    # The LHS pattern consumes '>>' and '<<' as atomic units so the regex
    # doesn't split inside a shift operator (e.g. 'n >> 1 < limit' must
    # not split as lhs='n', op='>', rhs='> 1 < limit').
    m = re.fullmatch(
        r'((?:>>|<<|[^<>]|(?<![<>])[<>](?![<>]))+?)'
        r'\s*(<=|>=|!=|==|<(?!<)|>(?!>))\s*(.+)',
        t,
    )
    if m:
        lhs = _parse_expr(m.group(1).strip(), vars_)
        rhs = _parse_expr(m.group(3).strip(), vars_)
        if lhs is None or rhs is None:
            return None
        op = m.group(2)
        if op == '==':
            return lhs == rhs
        if op == '!=':
            return lhs != rhs
        if op == '<':
            return lt(lhs, rhs, signed=_SIGNED)
        if op == '<=':
            return le(lhs, rhs, signed=_SIGNED)
        if op == '>':
            return gt(lhs, rhs, signed=_SIGNED)
        if op == '>=':
            return ge(lhs, rhs, signed=_SIGNED)

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_path_feasibility(
    conditions: List[PathCondition],
) -> PathSMTResult:
    """
    Check whether a set of path conditions are jointly satisfiable.

    Args:
        conditions: Conditions extracted from a dataflow path.  Each has a
                    ``text`` field (e.g. ``"size < 1024"``) and an optional
                    ``negated`` flag for conditions that must be *false* for
                    the path to proceed.

    Returns:
        PathSMTResult.  feasible=None when Z3 is unavailable or every
        condition was unparseable.
    """
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
            reasoning="no conditions — path is unconditionally reachable",
        )

    vars_: Dict[str, Any] = {}
    solver = _new_solver()

    satisfied: List[str] = []
    unknown: List[str] = []
    pending: List[Tuple[str, Any]] = []

    for cond in conditions:
        expr = _parse_condition(cond.text, vars_)
        if expr is None:
            _get_logger().debug(f"smt_path_validator: unparseable condition: {cond.text!r}")
            unknown.append(cond.text)
            continue

        final_expr = z3.Not(expr) if cond.negated else expr

        # Quick individual check: is this condition alone satisfiable?
        with _scoped(solver):
            solver.add(z3.Not(final_expr))
            if solver.check() == z3.unsat:
                # Condition is a tautology — trivially satisfied
                satisfied.append(cond.text)
                continue

        pending.append((cond.text, final_expr))

    if not pending:
        if unknown:
            return PathSMTResult(
                feasible=None,
                satisfied=satisfied, unsatisfied=[], unknown=unknown,
                model={}, smt_available=True,
                reasoning=(
                    f"indeterminate: {len(satisfied)} trivially satisfied, "
                    f"{len(unknown)} unparseable — LLM analysis required"
                ),
            )
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=[],
            model={}, smt_available=True,
            reasoning=f"all {len(satisfied)} condition(s) trivially satisfied",
        )

    label_map = _track(solver, pending)
    result = solver.check()

    if result == z3.sat:
        model_dict = _format_witness(solver.model(), signed=_SIGNED)
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=unknown,
            model=model_dict, smt_available=True,
            reasoning=(
                f"feasible: {len(pending)} condition(s) are jointly satisfiable"
                + (f"; {len(satisfied)} trivially satisfied" if satisfied else "")
                + (f"; {len(unknown)} unparsed" if unknown else "")
            ),
        )

    if result == z3.unsat:
        conflicts = _core_names(solver, label_map)
        conflict_set = conflicts if conflicts else [t for t, _ in pending]
        reasoning = f"infeasible: path conditions are mutually exclusive"
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
            f"Z3 returned unknown — likely the {_DEFAULT_TIMEOUT_MS}ms timeout "
            f"or conditions outside the bitvector fragment"
        ),
    )
