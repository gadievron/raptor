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
    ``&`` (only in the ``flags & MASK == VAL`` form), and grouping
    parentheses ``( )``.  Rejected: unary NOT (``~``), XOR (``^``),
    division (``/``), modulo (``%``), ternary (``? :``), single-equals
    assignment, chained relational (``0 < x < 100``).  Anything else
    goes to ``unknown`` via the full-input-consumed sanity check.
  - **C-syntax constructs (other than function calls and grouping).**
    Type casts (``(uint32_t)x``), struct/pointer access (``obj.field``,
    ``s->len``), array indexing (``arr[0]``), pointer dereference
    (``*p``), ``sizeof``.  Any token containing ``.``, ``->``, ``[``,
    ``]`` still triggers rejection.  Function calls are an exception —
    see the free-variable fallback below.
  - **Negative integer literals** (e.g. ``!= -1``) — write the
    bit-pattern in hex instead (``!= 0xFFFFFFFF`` at uint32).
  - **Leading-zero decimals** (e.g. ``01234``) — ambiguous with C
    octal; use hex or remove the leading zero.
  - **Literals outside the profile's width range** — ``0x100`` at
    uint8 would silently wrap to 0 in z3; we reject so the caller
    knows the profile was wrong for this literal.
  - **Unbalanced parentheses** — extra ``(`` or ``)``, mismatched
    nesting (``)(``), or a paren count that doesn't return to zero.

Function-call subterms (``strlen(input)``, ``getpid()``, ...) are
recovered through a free-variable fallback: each balanced
``<ident>(...)`` subterm is replaced with a fresh ``_anon_N`` Z3
variable before parsing, so the rest of the condition can still
contribute to feasibility analysis.  Two textually-identical calls
(``strlen(s) == strlen(s)``) are deliberately treated as *independent*
free variables — the parser doesn't know which calls are pure, so it
chooses the conservative semantics (no false claims of infeasibility).

Other limitations (verdict still trustworthy, but with caveats):

  - **C operator precedence**, not arithmetic-textbook precedence.
    Within an expression, ``*`` binds tightest, then ``+ -``, then
    ``<< >>``, then ``|`` (lowest).  All left-associative.  The
    notable surprise is that shifts bind *less* tightly than additive
    operators in C — ``a + b << 2`` parses as ``(a + b) << 2``, not
    ``a + (b << 2)``.  Use parentheses to make the grouping explicit
    when the C reading isn't what was meant.
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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from core.logging import get_logger as _get_logger
from core.smt_solver import (
    BV_C_UINT64,
    BVProfile,
    DEFAULT_TIMEOUT_MS as _DEFAULT_TIMEOUT_MS,
    Rejection,
    RejectionKind,
    canonicalise as _canonicalise,
    classify_solver_unknown as _classify_solver_unknown,
    core_names as _core_names,
    mk_val as _mk_val,
    mk_var as _mk_var,
    new_solver as _new_solver,
    parse_literal_value as _parse_literal_value,
    propagate as _propagate,
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
    """Result of SMT feasibility check over a set of path conditions.

    ``unknown`` keeps the original list-of-strings form for callers that
    only care which texts were dropped.  ``unknown_reasons`` carries the
    same set in :class:`Rejection` form, naming *why* each was dropped
    (parser failure kind, solver timeout, ...) so consumers can retry,
    rephrase, or surface diagnostics.

    ``anon_var_map`` records the mapping from each ``_anon_N``
    placeholder allocated by ``_substitute_calls`` to the original
    function-call subexpression it replaced (e.g.
    ``{"_anon_0": "strlen(argv[1])"}``).  Downstream consumers
    (``/exploit``'s witness PoC seed, report renderers) use this to
    render meaningful labels — without it the witness model shows
    only the opaque ``_anon_N`` names and the LLM can't connect the
    concrete value back to anything actionable.
    """
    feasible: Optional[bool]
    satisfied: List[str]
    unsatisfied: List[str]
    unknown: List[str]
    model: Dict[str, int]
    smt_available: bool
    reasoning: str
    unknown_reasons: List[Rejection] = field(default_factory=list)
    anon_var_map: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r'^0x[0-9a-f]+$', re.IGNORECASE)
_INT_RE = re.compile(r'^\d+$')
_IDENT_RE = re.compile(r'^[a-z_][a-z0-9_]*$', re.IGNORECASE)
_NULL_RE = re.compile(r'^NULL$', re.IGNORECASE)

# Tokenise: identifiers, hex literals, decimal literals, operators, parens.
# '>>' and '<<' appear before '[<>&|]' so they are matched as two-char tokens
# rather than as two separate single-char tokens.
_TOKEN_RE = re.compile(
    r'(0x[0-9a-f]+|\d+|[a-z_][a-z0-9_]*|[+\-*()]|<=|>=|!=|==|>>|<<|[<>&|])',
    re.IGNORECASE,
)

# Operator precedence for the arithmetic/bitwise sub-expression.  C-derived:
#   *               > +-              > << >>            > |
# All left-associative.  The relational and bitmask layers run in
# ``_parse_condition`` above this; ``&`` therefore doesn't appear in this
# table — it's only accepted in the dedicated bitmask form.
_PRECEDENCE: Dict[str, int] = {
    '|':  1,
    '<<': 2, '>>': 2,
    '+':  3, '-':  3,
    '*':  4,
}

# Maximum nesting depth for parenthesised subexpressions.  The parser
# recurses once per nesting level (_atom -> _climb -> _atom), so untrusted
# input with deep nesting can blow the Python call stack.  64 levels is
# far more than any real C condition would ever need.
_MAX_PAREN_DEPTH = 64

# Operator-shaped tokens we recognise but don't accept as binary operators
# inside ``_parse_expr`` — they belong to the relational or bitmask layer
# and reaching ``_parse_expr`` with one in operand-trailing position is a
# user error rather than a malformed expression.  Named
# ``_CONDITION_LEVEL_OPS`` (not ``_RELATIONAL_TOKENS``) because the set
# includes ``&`` (bitwise AND in bitmask form), which is not relational.
_CONDITION_LEVEL_OPS = frozenset({'<=', '>=', '!=', '==', '<', '>', '&'})


def _parse_expr(
    text: str, vars_: Dict[str, Any], *, profile: BVProfile,
) -> Union[Any, Rejection]:
    """Parse an arithmetic expression into a Z3 bitvector at the given profile.

    Handles: identifier, NULL, hex literal, decimal literal, parenthesised
    grouping, and binary ``+ - * | << >>`` between those terms.  Operators
    bind by C precedence (``*`` > ``+ -`` > ``<< >>`` > ``|``), all
    left-associative.  Right-shift is routed through ``csem.ashr`` /
    ``csem.lshr`` by signedness so the same ``>>`` source form encodes
    differently for signed vs unsigned path conditions.

    Returns a :class:`Rejection` — rather than a partial Z3 expression —
    when something can't be encoded, so the whole condition falls through
    to the unknown list with a structured reason rather than being
    silently mis-encoded.

    Implementation: precedence climbing over a flat token list, with a
    mutable cursor (``pos``) shared by closures.  Atoms include
    parenthesised subexpressions, which recursively re-enter the climb
    with ``min_prec=0`` and consume the matching ``)``.
    """
    tokens = _TOKEN_RE.findall(text.strip())
    if not tokens:
        return Rejection(text, RejectionKind.LEX_EMPTY, "no tokens after tokenisation")

    # Reject if any non-whitespace character was silently dropped by the
    # tokeniser — characters like '~' (NOT), '^' (XOR), '/', '%' aren't in
    # the token regex and would otherwise vanish, producing wrong answers
    # (e.g. "~mask == 0xFF" mis-encoded as "mask == 0xFF").
    if "".join(tokens) != re.sub(r"\s+", "", text):
        return Rejection(
            text, RejectionKind.UNRECOGNIZED_OPERAND,
            "non-tokenisable character was silently dropped by the tokeniser",
            hint="remove or rephrase unsupported operators (e.g. ~, ^, /, %)",
        )

    pos = [0]
    paren_depth = [0]

    def _atom() -> Union[Any, Rejection]:
        if pos[0] >= len(tokens):
            return Rejection(
                text, RejectionKind.UNRECOGNIZED_OPERAND,
                "unexpected end of expression — operand expected",
            )
        tok = tokens[pos[0]]
        if tok == '(':
            paren_depth[0] += 1
            if paren_depth[0] > _MAX_PAREN_DEPTH:
                return Rejection(
                    text, RejectionKind.UNRECOGNIZED_FORM,
                    "parenthesis nesting exceeds depth limit",
                )
            pos[0] += 1
            inner = _climb(0)
            if isinstance(inner, Rejection):
                paren_depth[0] -= 1
                return inner
            if pos[0] >= len(tokens) or tokens[pos[0]] != ')':
                paren_depth[0] -= 1
                # Check for a relational/bitmask operator that shouldn't
                # appear inside a parenthesised arithmetic subexpression
                # (e.g. ``(a == b) + 1``).  Without this, the user gets
                # UNBALANCED_PARENS which misidentifies the problem.
                if pos[0] < len(tokens) and tokens[pos[0]] in _CONDITION_LEVEL_OPS:
                    return Rejection(
                        text, RejectionKind.UNSUPPORTED_OPERATOR,
                        f"relational operator {tokens[pos[0]]!r} cannot appear "
                        f"inside a parenthesised arithmetic subexpression",
                    )
                return Rejection(
                    text, RejectionKind.UNBALANCED_PARENS,
                    "expected ')' to close subexpression",
                )
            paren_depth[0] -= 1
            pos[0] += 1
            return inner
        if tok == ')':
            return Rejection(
                text, RejectionKind.UNBALANCED_PARENS,
                "expected operand, got ')'",
            )
        if _NULL_RE.match(tok):
            pos[0] += 1
            return _mk_val(0, profile.width)
        if _HEX_RE.match(tok) or _INT_RE.match(tok):
            v = _parse_literal_value(tok, profile)
            if isinstance(v, Rejection):
                # Re-anchor the literal-specific rejection (LITERAL_AMBIGUOUS
                # / LITERAL_OUT_OF_RANGE) on the full input text so callers
                # can match it back to the original condition.
                return _propagate(text, v)
            pos[0] += 1
            return _mk_val(v, profile.width)
        if _IDENT_RE.match(tok):
            key = tok.lower()
            if key not in vars_:
                vars_[key] = _mk_var(key, profile.width)
            pos[0] += 1
            return vars_[key]
        return Rejection(
            text, RejectionKind.UNRECOGNIZED_OPERAND,
            f"token {tok!r} is not an identifier, NULL, or numeric literal",
        )

    def _apply(op: str, lhs: Any, rhs: Any) -> Any:
        if op == '+':  return lhs + rhs
        if op == '-':  return lhs - rhs
        if op == '*':  return lhs * rhs
        if op == '|':  return lhs | rhs
        if op == '<<': return lhs << rhs
        if op == '>>':
            # Route right-shift through csem so signedness picks the
            # correct arithmetic vs logical variant.
            return _ashr(lhs, rhs) if profile.signed else _lshr(lhs, rhs)
        # _PRECEDENCE keys are exhaustive; reaching here is a bug, not user
        # input.  Raise so the invariant survives under ``python -O``.
        raise RuntimeError(f"unhandled operator {op!r}")

    def _climb(min_prec: int) -> Union[Any, Rejection]:
        lhs = _atom()
        if isinstance(lhs, Rejection):
            return lhs
        while pos[0] < len(tokens):
            tok = tokens[pos[0]]
            if tok not in _PRECEDENCE:
                # Anything else — ``)``, a relational op, an extra atom —
                # ends this climb level.  The outer dispatcher classifies
                # the leftover (paren imbalance, unsupported operator, or
                # plain trailing token).
                break
            prec = _PRECEDENCE[tok]
            if prec < min_prec:
                break
            pos[0] += 1
            rhs = _climb(prec + 1)  # left-associative
            if isinstance(rhs, Rejection):
                return rhs
            lhs = _apply(tok, lhs, rhs)
        return lhs

    result = _climb(0)
    if isinstance(result, Rejection):
        return result

    if pos[0] != len(tokens):
        leftover = tokens[pos[0]]
        if leftover in ('(', ')'):
            return Rejection(
                text, RejectionKind.UNBALANCED_PARENS,
                f"unexpected {leftover!r} in expression",
            )
        if leftover in _CONDITION_LEVEL_OPS:
            return Rejection(
                text, RejectionKind.UNSUPPORTED_OPERATOR,
                f"operator {leftover!r} not in {{+, -, *, |, >>, <<}}",
            )
        return Rejection(
            text, RejectionKind.TRAILING_TOKENS,
            f"unconsumed token {leftover!r}",
        )

    return result


_CALL_HEAD_RE = re.compile(r'[a-z_][a-z0-9_]*', re.IGNORECASE)


def _next_anon_index(vars_: Dict[str, Any]) -> int:
    """Return the next free ``_anon_<N>`` index for ``vars_``.

    Seeds from ``max(existing index) + 1`` rather than ``len(existing)``
    so names stay unique even if a caller has deleted entries from
    ``vars_`` (a sparse range would otherwise collide with a live anon
    name).  Defensive against ``_anon_<non-int>`` keys: ignored.

    Shared between :func:`_substitute_calls` (parser-side) and
    :func:`make_anon_call_var` (verb-side) so both paths allocate from
    the same counter.
    """
    existing_indices: List[int] = []
    for k in vars_:
        if k.startswith('_anon_'):
            try:
                existing_indices.append(int(k[len('_anon_'):]))
            except ValueError:
                pass
    return max(existing_indices, default=-1) + 1


def is_balanced_call(text: str) -> bool:
    """Match a complete balanced ``<ident>(...)`` form, end-to-end.

    Returns ``True`` only if ``text`` is *entirely* a single function-
    call-shaped expression.  Used by domain encoders building operand
    BVs to detect whether a single-operand string is a function call
    that should be substituted with a free variable, vs an arithmetic
    expression that should be rejected as compound.
    """
    m = _CALL_HEAD_RE.match(text)
    if not m or m.end() >= len(text) or text[m.end()] != '(':
        return False
    depth = 1
    j = m.end() + 1
    while j < len(text) and depth > 0:
        if text[j] == '(':
            depth += 1
        elif text[j] == ')':
            depth -= 1
        j += 1
    return depth == 0 and j == len(text)


def make_anon_call_var(vars_: Dict[str, Any], *, profile: BVProfile) -> Any:
    """Allocate a fresh ``_anon_N`` Z3 BV for a function-call operand.

    Two textually-identical calls (``strlen(s) == strlen(s)``) produce
    *distinct* anon vars — the parser doesn't assume calls are pure.
    Callers wanting same-call equality should use a helper variable in
    a guard instead.

    Shares the ``_anon_*`` namespace with the parser-side substitution
    in :func:`_substitute_calls`, so a verb can build an operand and
    then a guard that references the same call without index collision.
    """
    counter = _next_anon_index(vars_)
    name = f"_anon_{counter}"
    vars_[name] = _mk_var(name, profile.width)
    return vars_[name]


def _substitute_calls(
    text: str, vars_: Dict[str, Any], *, profile: BVProfile,
    anon_map: Optional[Dict[str, str]] = None,
) -> str:
    """Replace balanced ``<ident>(...)`` subterms with fresh free variables.

    Each function-call-shaped subterm is swapped for a unique
    ``_anon_N`` placeholder and registered as a free Z3 bitvector in
    ``vars_``.  Lets conditions like ``strlen(input) < 1024`` parse
    instead of being rejected wholesale on the parens check, while
    preserving correctness: the placeholder is unconstrained, so the
    solver can never claim infeasibility based on the elided subterm.

    Nested calls collapse to a single placeholder
    (``f(g(x))`` → ``_anon_0``), since the outer call drives the
    balanced-paren walk.  Two textually-identical calls produce
    *distinct* placeholders — calls aren't assumed pure.

    Unbalanced parens (``strlen(x``) are left in place; the caller's
    parens-check still rejects them.

    When ``anon_map`` is supplied, each new ``_anon_N`` allocated
    here is recorded with the original substring it replaced
    (``anon_map["_anon_0"] = "strlen(argv[1])"``).  Threaded through
    ``_parse_condition`` and ``_classify_text_condition`` from
    ``check_path_feasibility`` so the final ``PathSMTResult`` can
    surface meaningful labels for the witness model.  None / omitted
    preserves backwards compatibility — callers that don't care
    (verb path, tests pre-dating this) still work unchanged.
    """
    counter = _next_anon_index(vars_)
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        m = _CALL_HEAD_RE.match(text, i)
        if m and m.end() < n and text[m.end()] == '(':
            depth = 1
            j = m.end() + 1
            while j < n and depth > 0:
                if text[j] == '(':
                    depth += 1
                elif text[j] == ')':
                    depth -= 1
                j += 1
            if depth == 0:
                placeholder = f'_anon_{counter}'
                counter += 1
                vars_[placeholder] = _mk_var(placeholder, profile.width)
                if anon_map is not None:
                    anon_map[placeholder] = text[i:j]
                out.append(placeholder)
                i = j
                continue
            # Unbalanced: fall through and copy the head char-by-char so
            # the parens-check can flag it.
        out.append(text[i])
        i += 1
    return ''.join(out)


def _parse_condition(
    text: str, vars_: Dict[str, Any], *, profile: BVProfile,
    anon_map: Optional[Dict[str, str]] = None,
) -> Union[Any, Rejection]:
    """Parse a single condition string into a Z3 boolean expression.

    Recognised forms:
      lhs == rhs / lhs != rhs
      lhs < rhs  / lhs <= rhs / lhs > rhs / lhs >= rhs
      lhs & mask == val  (bitmask alignment)
      lhs & mask != val

    English operator phrases ("is greater than", "equals", ...) are
    rewritten to symbolic operators by :func:`canonicalise` first, so
    callers can use natural-language conditions.  Then function-call-
    shaped subterms (``ident(...)``) are replaced with fresh ``_anon_N``
    free variables by :func:`_substitute_calls`, so conditions like
    ``strlen(input) < 1024`` can still drive feasibility analysis.  Any
    parentheses left behind after that pass are non-call grouping
    (``(a + b) * c``) and are now supported via precedence climbing in
    :func:`_parse_expr` — the early balance check below only catches
    the structurally-broken cases (extra ``)`` or unmatched ``(``)
    before they fall through to a less specific rejection further down.
    ``text`` (the original) is preserved for rejection messages so
    callers can match failures back to their input.
    """
    t = _substitute_calls(
        _canonicalise(text), vars_, profile=profile, anon_map=anon_map,
    )

    # Early paren-balance scan.  ``_parse_expr`` would catch most imbalances
    # itself, but only conditions whose top-level matches the relational or
    # bitmask regex below ever reach it.  Cases like ``strlen(x`` or
    # ``f(g(x)`` (no relational op) would otherwise fall through to a
    # generic UNRECOGNIZED_FORM rejection — this loop pre-empts that with
    # a more specific UNBALANCED_PARENS.
    depth = 0
    for ch in t:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth < 0:
                return Rejection(
                    text, RejectionKind.UNBALANCED_PARENS,
                    "')' has no matching '('",
                )
    if depth != 0:
        return Rejection(
            text, RejectionKind.UNBALANCED_PARENS,
            f"{depth} unmatched '(' at end of input",
        )

    # Bitmask: lhs & mask (==|!=) val
    m = re.fullmatch(
        r'(.+?)\s*&\s*(0x[0-9a-f]+|\d+)\s*(==|!=)\s*(0x[0-9a-f]+|\d+)',
        t, re.IGNORECASE,
    )
    if m:
        lhs = _parse_expr(m.group(1).strip(), vars_, profile=profile)
        if isinstance(lhs, Rejection):
            return _propagate(text, lhs)
        # Mask and rhs literals go through the same validation as atom-level
        # literals — width range and leading-zero ambiguity must be rejected
        # the same way, otherwise the bitmask path silently wraps or trips
        # ValueError on octal-style tokens.  Specific Rejection reasons
        # (LITERAL_AMBIGUOUS / LITERAL_OUT_OF_RANGE) are preserved here.
        mask_val = _parse_literal_value(m.group(2), profile)
        if isinstance(mask_val, Rejection):
            return _propagate(text, mask_val)
        rhs_val = _parse_literal_value(m.group(4), profile)
        if isinstance(rhs_val, Rejection):
            return _propagate(text, rhs_val)
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
        if isinstance(lhs, Rejection):
            return _propagate(text, lhs)
        rhs = _parse_expr(m.group(3).strip(), vars_, profile=profile)
        if isinstance(rhs, Rejection):
            return _propagate(text, rhs)
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

    return Rejection(
        text, RejectionKind.UNRECOGNIZED_FORM,
        "no relational or bitmask pattern matched",
        hint="use 'lhs OP rhs' with OP in {==, !=, <, <=, >, >=}, "
             "or 'lhs & MASK (==|!=) VAL' for bitmask alignment",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _classify_text_condition(
    cond: PathCondition,
    vars_: Dict[str, Any],
    solver: Any,
    *,
    profile: BVProfile,
    anon_map: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[str], Optional[Tuple[str, Any]], Optional[Rejection]]:
    """Parse one text condition and classify it.

    Returns one of:
      - ``(satisfied_display, None, None)`` — tautology, no further work
      - ``(None, (display, expr), None)`` — pending, must be solved
      - ``(None, None, rejection)`` — unparseable, accumulate into unknown

    Factored out so :func:`check_path_feasibility` and
    :func:`check_verb_feasibility` share the same parse-and-classify
    semantics.
    """
    expr = _parse_condition(cond.text, vars_, profile=profile, anon_map=anon_map)
    if isinstance(expr, Rejection):
        _get_logger().debug(
            f"smt_path_validator: rejected {cond.text!r} ({expr.kind.value}: {expr.detail})"
        )
        return None, None, expr

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
            return display, None, None  # tautology

    return None, (display, final_expr), None


def _solve_pending(
    pending: List[Tuple[str, Any]],
    solver: Any,
    satisfied: List[str],
    unknown: List[str],
    unknown_reasons: List[Rejection],
    *,
    profile: BVProfile,
    anon_map: Optional[Dict[str, str]] = None,
) -> PathSMTResult:
    """Run the solver over pending predicates and produce a verdict.

    Shared between :func:`check_path_feasibility` and
    :func:`check_verb_feasibility`.  Caller has already classified
    each input as tautology/pending/unknown; this function turns the
    pending list into a sat/unsat/unknown verdict and packages the
    result.
    """
    mode = profile.describe()

    # Default to empty dict so the field is always present on the
    # PathSMTResult — downstream consumers never need to None-check.
    _anon_map = anon_map or {}

    if not pending:
        if unknown:
            return PathSMTResult(
                feasible=None,
                satisfied=satisfied, unsatisfied=[], unknown=unknown,
                unknown_reasons=unknown_reasons,
                model={}, smt_available=True,
                reasoning=(
                    f"indeterminate ({mode}): {len(satisfied)} trivially satisfied, "
                    f"{len(unknown)} unparseable — LLM analysis required"
                ),
                anon_var_map=_anon_map,
            )
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=[],
            unknown_reasons=[],
            model={}, smt_available=True,
            reasoning=f"all {len(satisfied)} condition(s) trivially satisfied ({mode})",
            anon_var_map=_anon_map,
        )

    label_map = _track(solver, pending)
    result = solver.check()

    if result == z3.sat:
        model_dict = _format_witness(solver.model(), signed=profile.signed)
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=unknown,
            unknown_reasons=unknown_reasons,
            model=model_dict, smt_available=True,
            reasoning=(
                f"feasible ({mode}): {len(pending)} condition(s) are jointly satisfiable"
                + (f"; {len(satisfied)} trivially satisfied" if satisfied else "")
                + (f"; {len(unknown)} unparsed" if unknown else "")
            ),
            anon_var_map=_anon_map,
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
            unknown_reasons=unknown_reasons,
            model={}, smt_available=True,
            reasoning=reasoning,
            anon_var_map=_anon_map,
        )

    # z3.unknown — timeout or outside decidable fragment.
    solver_reason = _classify_solver_unknown(solver)
    pending_texts = [t for t, _ in pending]
    pending_reasons = [
        Rejection(
            t, solver_reason,
            f"Z3 reason_unknown: {solver.reason_unknown()}"
            if hasattr(solver, "reason_unknown") else "",
        )
        for t in pending_texts
    ]
    detail = (
        f"likely the {_DEFAULT_TIMEOUT_MS}ms timeout"
        if solver_reason is RejectionKind.SOLVER_TIMEOUT
        else "conditions outside the decidable bitvector fragment"
    )
    return PathSMTResult(
        feasible=None,
        satisfied=satisfied, unsatisfied=[],
        unknown=unknown + pending_texts,
        unknown_reasons=unknown_reasons + pending_reasons,
        model={}, smt_available=True,
        reasoning=f"Z3 returned unknown ({mode}) — {detail}",
        anon_var_map=_anon_map,
    )


def make_var(name: str, vars_: Dict[str, Any], *, profile: BVProfile) -> Any:
    """Get-or-create a Z3 bitvector variable, sharing ``vars_`` with the parser.

    Domain encoders (``smt_verbs``) building Z3 predicates directly via
    csem need their operand BVs to share names with parser-built BVs so
    that, e.g., a verb's overflow predicate over ``count`` and a guard
    ``count < MAX`` constrain the *same* Z3 variable.

    Names are lowercased to match the parser's convention.
    """
    key = name.lower()
    if key not in vars_:
        vars_[key] = _mk_var(key, profile.width)
    return vars_[key]


def make_val(literal: str, *, profile: BVProfile) -> Any:
    """Resolve a literal token (``"16"``, ``"0xff"``) to a Z3 BitVecVal.

    Goes through the same width / leading-zero validation as atom-position
    literals in the parser, so callers get consistent rejection.
    Raises ``ValueError`` on invalid literal — verbs catch and surface
    as a verb-layer error.
    """
    from core.smt_solver import parse_literal_value
    v = parse_literal_value(literal, profile)
    if isinstance(v, Rejection):
        raise ValueError(
            f"literal {literal!r} rejected: {v.kind.value} ({v.detail})"
        )
    return _mk_val(v, profile.width)


def check_verb_feasibility(
    intrinsic: List[Tuple[str, Any]],
    text_guards: List[PathCondition],
    vars_: Dict[str, Any],
    *,
    profile: BVProfile = BV_C_UINT64,
) -> PathSMTResult:
    """Feasibility analysis for a named SMT verb.

    Verbs build their intrinsic Z3 predicate directly (typically via
    ``core.smt_solver.csem``) and pass it as ``intrinsic`` — a list of
    ``(display_text, z3_expr)`` tuples.  ``display_text`` appears in
    unsat-core conflict listings, so callers should pick a form that
    reads as the verb's intent (e.g. ``"unsigned mul wraps: count * 16"``).

    ``text_guards`` are caller-supplied path conditions, parsed via the
    same path as :func:`check_path_feasibility`.  Verbs and the parser
    share ``vars_`` so identifier-named operands resolve to the same
    Z3 BV regardless of which path created them.

    Always called with Z3 available; verbs short-circuit the
    ``smt_available=False`` case before calling this helper.
    """
    mode = profile.describe()
    solver = _new_solver()

    satisfied: List[str] = []
    unknown: List[str] = []
    unknown_reasons: List[Rejection] = []
    pending: List[Tuple[str, Any]] = list(intrinsic)  # intrinsic always solved

    for cond in text_guards:
        sat_display, pending_pair, rejection = _classify_text_condition(
            cond, vars_, solver, profile=profile,
        )
        if sat_display is not None:
            satisfied.append(sat_display)
        elif rejection is not None:
            unknown.append(cond.text)
            unknown_reasons.append(rejection)
        else:
            assert pending_pair is not None
            pending.append(pending_pair)

    if not intrinsic and not pending and not unknown and not satisfied:
        # Defensive: a verb with no intrinsic and no guards is a usage
        # error but we still return something coherent rather than
        # divide-by-zero in the verdict logic.
        return PathSMTResult(
            feasible=True,
            satisfied=[], unsatisfied=[], unknown=[],
            unknown_reasons=[],
            model={}, smt_available=True,
            reasoning=f"no predicates ({mode}) — vacuously satisfiable",
        )

    return _solve_pending(
        pending, solver, satisfied, unknown, unknown_reasons, profile=profile,
    )


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
            unknown_reasons=[],
            model={}, smt_available=False,
            reasoning="z3 not available — install z3-solver for path feasibility analysis",
        )

    if not conditions:
        return PathSMTResult(
            feasible=True,
            satisfied=[], unsatisfied=[], unknown=[],
            unknown_reasons=[],
            model={}, smt_available=True,
            reasoning=f"no conditions ({mode}) — path is unconditionally reachable",
        )

    vars_: Dict[str, Any] = {}
    solver = _new_solver()
    # Per-check anon-var mapping. Populated by `_substitute_calls`
    # as it allocates `_anon_N` placeholders for function-call
    # subterms; threaded into the PathSMTResult so downstream
    # consumers (witness PoC seed renderer) can show meaningful
    # labels like `_anon_0 (= strlen(argv[1])) = 32` instead of
    # bare `_anon_0 = 32`.
    anon_map: Dict[str, str] = {}

    satisfied: List[str] = []
    unknown: List[str] = []
    unknown_reasons: List[Rejection] = []
    pending: List[Tuple[str, Any]] = []

    for cond in conditions:
        sat_display, pending_pair, rejection = _classify_text_condition(
            cond, vars_, solver, profile=profile, anon_map=anon_map,
        )
        if sat_display is not None:
            satisfied.append(sat_display)
        elif rejection is not None:
            unknown.append(cond.text)
            unknown_reasons.append(rejection)
        else:
            assert pending_pair is not None
            pending.append(pending_pair)

    return _solve_pending(
        pending, solver, satisfied, unknown, unknown_reasons,
        profile=profile, anon_map=anon_map,
    )
