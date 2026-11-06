#!/usr/bin/env python3
"""
SMT-based path condition feasibility checker.

Shared module: consumed by packages/codeql (dataflow validation),
core/audit (post-deepen mechanical gates), and future SMT consumers.

Callers extract branch/guard conditions as structured constraint strings;
this module encodes them into Z3 bitvector expressions and checks whether
they are jointly satisfiable.

- sat   → the encoded conjunction is satisfiable under its model assumptions
- unsat → the encoded conditions are mutually exclusive under those assumptions;
          unsat core names the specific conflicting conditions
- None  → Z3 unavailable or all conditions unparseable; fall back to LLM

Accepted condition forms (case-sensitive identifiers; case-insensitive English aliases):
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
  - **Negative literals outside a signed profile's range**, or negative
    values at unsigned profiles. Signed decimal atoms such as ``-1``
    are supported; arbitrary unary negation remains unsupported.
  - **Leading-zero decimals** (e.g. ``01234``) — ambiguous with C
    octal; use hex or remove the leading zero.
  - **Literals outside the profile's width range** — ``0x100`` at
    uint8 would silently wrap to 0 in z3; we reject so the caller
    knows the profile was wrong for this literal.
  - **Unbalanced parentheses** — extra ``(`` or ``)``, mismatched
    nesting (``)(``), or a paren count that doesn't return to zero.

Function-call subterms (``strlen(input)``, ``getpid()``, ...) are
recovered through a free-variable fallback: each balanced
``<ident>(...)`` subterm is replaced with an ``_anon_N`` Z3 variable
before parsing, so the rest of the condition can still contribute to
feasibility analysis. Each syntactic call occurrence receives a distinct
result, even when its text matches another occurrence in the same guard.
Text equality, scalar SSA names, and unchanged pointer arguments do not
establish referential transparency or unchanged memory. When conditions
refer to the same evaluation, the caller must name its result explicitly
(e.g. ``Result > 100`` and ``Result < 50``).
A conservative set of libc/POSIX calls additionally gets a *summary
axiom* asserted on its placeholder (``strlen(...) >= 0`` at signed
profiles, ``sizeof(...) != 0``, ``abs``-family with the INT_MIN corner,
``min``/``max`` as ITE definitions, and literal ``strnlen`` bounds) — see ``_CALL_SUMMARIES``; applied
axioms are reported in ``PathSMTResult.summary_axioms``. Consumers that
cannot bind these callee models may set ``use_call_summaries=False``;
calls then remain opaque results and no name-based axiom is constructed.

Deterministic definition summaries can relate separate results through the
same modeled arguments, without assuming identity from text. Range-only
summaries leave occurrences independent. These callee models remain
explicit assumptions, not source signatures or effect proofs.

Named scalar values still require an SSA view. Assignment-shaped input is
rejected as a program effect and marks a new value-flow segment. An UNSAT
core crossing that unmodeled mutation cannot refute the path; independent
contradictions wholly within one segment may still do so.

Other limitations of the uniform-profile model:

  - **C operator precedence**, not arithmetic-textbook precedence.
    Within an expression, ``*`` binds tightest, then ``+ -``, then
    ``<< >>``, then ``|`` (lowest).  All left-associative.  The
    notable surprise is that shifts bind *less* tightly than additive
    operators in C — ``a + b << 2`` parses as ``(a + b) << 2``, not
    ``a + (b << 2)``.  Use parentheses to make the grouping explicit
    when the C reading isn't what was meant.
  - **Bitmask form** requires both ``MASK`` and ``VAL`` to be integer
    literals; variables on either side go to ``unknown``.
  - **Variables still share one profile.** High-bit hex literals carry
    unsigned expression type through arithmetic, comparisons, and shifts.
    Shift results preserve the left operand's type. This is not general C
    typing: per-variable types, ranks, casts, and target ABI conversions
    remain outside this path model.
  - **Z3 picks the smallest satisfying witness by default**, which is
    often the trivial assignment (``x = 0``).  To drive the witness
    into the dangerous range, pass ``prefer_witness=("count", "max")``
    (or the shim's ``--prefer-witness max:count``) and the encoder
    swaps in a ``z3.Optimize`` backend with the corresponding
    ``maximize`` objective.  Manual lower-bound hints (e.g.
    ``count > 0x10000000``) still work and remain useful when the
    caller wants to constrain the search to a specific subrange
    rather than push to the extreme.

Integration: packages/codeql/dataflow_validator.py :: DataflowValidator
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Sequence

from core.smt_solver.condition_syntax import MAX_CONDITION_CHARS as _MAX_CONDITION_CHARS
from core.smt_solver.witness_preferences import parse_witness_preference
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
    new_optimizer as _new_optimizer,
    new_solver as _new_solver,
    parse_literal_value as _parse_literal_value,
    propagate as _propagate,
    scoped as _scoped,
    z3,
    z3_available as _z3_available,
)
from core.smt_solver.bitvec import ge, gt, le, lt
from core.smt_solver.assertion_frames import track_frames
from core.smt_solver.call_arguments import find_call_end, split_call_arguments
from core.smt_solver.csem import ashr as _ashr, lshr as _lshr
from core.smt_solver._validation import require_bool
from core.smt_solver.witness import format_witness as _format_witness


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class PathCondition:
    """A guard with Boolean branch polarity; malformed flags raise ValueError."""
    text: str
    step_index: int
    negated: bool = False

    def __post_init__(self):
        require_bool(self.negated, argument="negated")


# --- Phase 8: weakest-precondition extraction ------------------------------
# Cap on solver calls in the WP deletion pass.  Each kept-conjunct
# redundancy test is one ``check()``; real paths carry 1-10 conjuncts and
# ``_MAX_CONDITIONS_PER_CALL`` caps the input at 64, so 32 covers typical
# paths fully while bounding worst-case cost on adversarial inputs.
WP_MAX_SOLVER_CALLS = 32

# Per-check timeout for the WP deletion pass.  Each redundancy test is
# a simple implication query (conjunction of kept conjuncts vs negation
# of one candidate) — far cheaper than the initial sat check that
# evaluates the full path.  2s is generous for these queries; a timeout
# means "keep the conjunct" (same conservative stance as ``unknown``).
WP_TIMEOUT_MS = 2000

# The deletion pass visits conjuncts in lexicographic order of their
# canonicalised text (ties broken by original index).  Recorded on the
# result so re-runs reproduce the same minimal subset: different visit
# orders can yield different (equally valid) minimal subsets when
# conjuncts pairwise imply one another.
WP_ORDERING = "canonical-text-lexicographic"


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
    feasible: bool | None
    satisfied: list[str]
    unsatisfied: list[str]
    unknown: list[str]
    model: dict[str, int]
    smt_available: bool
    reasoning: str
    unknown_reasons: list[Rejection] = field(default_factory=list)
    anon_var_map: dict[str, str] = field(default_factory=dict)

    # Human-readable labels of the libc/POSIX call-summary axioms that
    # were asserted alongside the path conditions (see
    # ``_summarise_call``).  Empty when no recognised call appeared or
    # every candidate axiom was vacuous under the active profile.
    # Consumers treat these as the assumptions the verdict is
    # conditional on; an axiom label can also appear in ``unsatisfied``
    # when it participates in an unsat core.
    summary_axioms: list[str] = field(default_factory=list)

    # --- Phase 8: weakest-precondition predicate (additive) ---
    # Legacy WP fields describe an implication-reduced constraint summary,
    # not a program weakest precondition or source reachability proof.
    # Equivalence is conditional on the supplied background axioms.
    wp_predicate: str | None = None
    # Retained conjuncts remain diagnostic if serialization is unavailable.
    wp_conjuncts: list[str] = field(default_factory=list)
    # For a present summary, False also covers undecided redundancy checks
    # and original inputs that could not be encoded.
    wp_complete: bool = True
    # Deterministic reduction order, retained for wire compatibility.
    wp_ordering: str = WP_ORDERING
    # Native core dependency, not a source type or reachability proof.
    # False: every core assertion is a parsed guard without call terms.
    # True: at least one core assertion uses a call term or call axiom.
    # None: unavailable core or unclassified intrinsic assertion.
    refutation_uses_call_terms: bool | None = None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r'^0x[0-9a-f]+$', re.IGNORECASE)


def _hex_literal_forces_unsigned(tok: str, profile: "BVProfile") -> bool:
    """True when *tok* is a bare hex literal whose value exceeds the
    profile's signed max — in C such a literal has UNSIGNED type and
    contributes unsigned type at its expression leaf. The parser carries
    that type through arithmetic conversions and left-operand shift rules.
    This remains a uniform-width convention, not a target ABI type resolver."""
    if not profile.signed or not _HEX_RE.fullmatch(tok):
        return False
    return int(tok, 16) >= (1 << (profile.width - 1))
_INT_RE = re.compile(r'^\d+$')
_IDENT_RE = re.compile(r'^[a-z_][a-z0-9_]*$', re.IGNORECASE)
# Source identifiers are case-sensitive; English aliases canonicalise to NULL.
_NULL_RE = re.compile(r'^NULL$')

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
_PRECEDENCE: dict[str, int] = {
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

# Maximum number of conditions accepted in a single ``check_path_feasibility``
# call.  Real findings carry 1-10 conditions; tens of thousands signals
# malformed upstream extraction or amplification.  When exceeded the call
# degrades to ``feasible=None`` so partial answers can't be misread as
# authoritative.
_MAX_CONDITIONS_PER_CALL = 64

# Operator-shaped tokens we recognise but don't accept as binary operators
# inside ``_parse_expr`` — they belong to the relational or bitmask layer
# and reaching ``_parse_expr`` with one in operand-trailing position is a
# user error rather than a malformed expression.  Named
# ``_CONDITION_LEVEL_OPS`` (not ``_RELATIONAL_TOKENS``) because the set
# includes ``&`` (bitwise AND in bitmask form), which is not relational.
_CONDITION_LEVEL_OPS = frozenset({'<=', '>=', '!=', '==', '<', '>', '&'})


@dataclass(frozen=True)
class _TypedExpression:
    """An expression's bits and signedness within the selected uniform width."""

    value: Any
    signed: bool


def _parse_expr(text: str, vars_: dict[str, Any], *, profile: BVProfile) -> Any | Rejection:
    """Compatibility view returning only bits; typed consumers keep metadata."""
    result = _parse_typed_expr(text, vars_, profile=profile)
    return result if isinstance(result, Rejection) else result.value


def _parse_typed_expr(
    text: str, vars_: dict[str, Any], *, profile: BVProfile,
) -> _TypedExpression | Rejection:
    """Parse an arithmetic expression into a Z3 bitvector at the given profile.

    Handles: identifier, NULL, hex literal, decimal literal, parenthesised
    grouping, and binary ``+ - * | << >>`` between those terms.  Operators
    bind by C precedence (``*`` > ``+ -`` > ``<< >>`` > ``|``), all
    left-associative.  Right-shift is routed through ``csem.ashr`` /
    ``csem.lshr`` by signedness so the same ``>>`` source form encodes
    differently for signed vs unsigned expression operands. High-bit hex
    literals contribute unsigned type through arithmetic; shifts preserve
    the left operand's type regardless of the shift count's signedness.

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

    def _atom() -> _TypedExpression | Rejection:
        if pos[0] >= len(tokens):
            return Rejection(
                text, RejectionKind.UNRECOGNIZED_OPERAND,
                "unexpected end of expression — operand expected",
            )
        tok = tokens[pos[0]]
        if tok == '-' and pos[0] + 1 < len(tokens) and _INT_RE.fullmatch(tokens[pos[0] + 1]):
            literal = '-' + tokens[pos[0] + 1]
            value = _parse_literal_value(literal, profile)
            if isinstance(value, Rejection):
                return _propagate(text, value)
            pos[0] += 2
            return _TypedExpression(_mk_val(value, profile.width), profile.signed)
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
            return _TypedExpression(_mk_val(0, profile.width), profile.signed)
        if _HEX_RE.match(tok) or _INT_RE.match(tok):
            v = _parse_literal_value(tok, profile)
            if isinstance(v, Rejection):
                # Re-anchor the literal-specific rejection (LITERAL_AMBIGUOUS
                # / LITERAL_OUT_OF_RANGE) on the full input text so callers
                # can match it back to the original condition.
                return _propagate(text, v)
            pos[0] += 1
            return _TypedExpression(_mk_val(v, profile.width),
                                    profile.signed and not _hex_literal_forces_unsigned(tok, profile))
        if _IDENT_RE.match(tok):
            pos[0] += 1
            return _TypedExpression(make_var(tok, vars_, profile=profile), profile.signed)
        return Rejection(
            text, RejectionKind.UNRECOGNIZED_OPERAND,
            f"token {tok!r} is not an identifier, NULL, or numeric literal",
        )

    def _apply(op: str, lhs: _TypedExpression, rhs: _TypedExpression) -> _TypedExpression:
        a, b = lhs.value, rhs.value
        signed = lhs.signed and rhs.signed
        if op == '+':
            value = a + b
        elif op == '-':
            value = a - b
        elif op == '*':
            value = a * b
        elif op == '|':
            value = a | b
        elif op == '<<':
            value, signed = a << b, lhs.signed
        elif op == '>>':
            value = _ashr(a, b) if lhs.signed else _lshr(a, b)
            signed = lhs.signed
        else:
            # Keep the operator-table invariant effective under python -O.
            raise RuntimeError(f"unhandled operator {op!r}")
        return _TypedExpression(value, signed)

    # Recursion depth bound for `_climb`. Pre-fix the recursive
    # precedence-climber unwound through Python's call stack one
    # frame per nested operator. A long flat chain like
    # `a+a+a+a+...+a` (1000+ ops) crossed Python's default
    # recursion limit (~1000) and raised RecursionError, which
    # bypassed every Rejection-shaped error path the parser
    # relied on. Bound depth explicitly + return a Rejection
    # rather than crashing. 256 is well above any realistic
    # human-or-LLM-emitted condition (deeply-nested constraints
    # in real RAPTOR runs top out at <20 ops).
    _MAX_CLIMB_DEPTH = 256
    _climb_depth = [0]

    def _climb(min_prec: int) -> _TypedExpression | Rejection:
        if _climb_depth[0] >= _MAX_CLIMB_DEPTH:
            return Rejection(
                ' '.join(tokens),
                RejectionKind.UNRECOGNIZED_FORM,
                f"expression nesting exceeded depth {_MAX_CLIMB_DEPTH}; "
                f"refusing to recurse further",
            )
        _climb_depth[0] += 1
        try:
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
        finally:
            _climb_depth[0] -= 1
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
_ANON_SOURCE_RE = re.compile(r'(?<![A-Za-z0-9_])_anon_[0-9]+(?![A-Za-z0-9_])')


def reserve_anon_names(texts: list[str], vars_: dict[str, Any]) -> None:
    """Reserve source spellings before allocating generated call symbols.

    None is a lazy reservation, not a Z3 value. Only make_var materializes
    a source variable, so unused reservations cannot become objectives or
    witness values. Oversized guards will be rejected before parsing.
    """
    for text in texts:
        if len(text) <= _MAX_CONDITION_CHARS:
            for match in _ANON_SOURCE_RE.finditer(text):
                vars_.setdefault(match.group(), None)


def _next_anon_index(vars_: dict[str, Any]) -> int:
    """Lowest unused index; sparse or huge source suffixes cannot inflate it."""
    index = 0
    while f'_anon_{index}' in vars_:
        index += 1
    return index


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
    return find_call_end(text, m.end()) == len(text)


def make_anon_call_var(vars_: dict[str, Any], *, profile: BVProfile) -> Any:
    """Allocate a fresh internal Z3 BV for a function-call operand.

    Every allocation represents a separate call occurrence. Textual
    repetition does not establish execution identity with another operand
    or guard. Optional summaries can constrain a result without merging
    its variable with another occurrence.

    The native name contains ``!`` and cannot be a parsed source identifier.
    It stays separate from parser aliases and from source names introduced
    later, even when a low-level caller has not pre-reserved its guards.
    """
    variable = z3.FreshConst(z3.BitVecSort(profile.width), prefix="_anon_operand")
    vars_[str(variable.decl().name())] = variable
    return variable


# Detects program-statement shapes that aren't valid Boolean path-
# conditions. Matches route to RejectionKind.ASSIGNMENT_SHAPED so
# check_path_feasibility can mark a new value-flow segment and refuse
# scalar contradictions that cross an unmodeled state update.
#
# Coverage is a mix of *designed* matches (operators we explicitly
# enumerate in the regex) and *incidental* matches (operators that
# fire via substring overlap with a designed alternation). Both
# directions are intentional — the incidental side gives us
# best-effort coverage of language operators we never thought
# about — but the dependency is fragile: dropping e.g. ``*`` from
# ``[+\-*/%&|^]`` would silently regress ``**=`` along with the
# obvious ``*=``. Pinning tests in TestAssignmentShapeCoverage
# (see test_smt_path_validator.py) make every entry below load-
# bearing so a future "simplify this regex" refactor fails loudly.
#
#  operator       matched?  how
#  -------------  --------  ---------------------------------------
#  =              yes       designed (bare-`=` alternation, with
#                            `(?<![=<>!])` / `(?!=)` guards
#                            excluding `==`/`<=`/`>=`/`!=`)
#  += -= *= /=    yes       designed (`[+\-*/%&|^]=` alternation)
#  %= &= |= ^=    yes       designed (same alternation)
#  <<= >>=        yes       designed (`<<=|>>=` alternation)
#  ++ --          yes       designed (`\+\+|--` alternation)
#
#  :=  (Python walrus)               yes  INCIDENTAL — `:` not in
#                                          the bare-`=` lookbehind
#                                          exclusion, so the bare-`=`
#                                          alternation fires.
#  **= (Python pow-assign)           yes  INCIDENTAL — trailing
#                                          `*=` matches the compound-
#                                          assignment alternation.
#  //= (Python floordiv-assign)      yes  INCIDENTAL — trailing
#                                          `/=` matches the compound-
#                                          assignment alternation.
#  >>>= (Java unsigned-rshift-assign) yes  INCIDENTAL — trailing
#                                          `>>=` matches the shift-
#                                          compound alternation.
#  @=  (Python PEP 465 matmul-assign) yes  INCIDENTAL — `@` not in
#                                          the bare-`=` lookbehind
#                                          exclusion, so the bare-`=`
#                                          alternation fires.
#
# Known exotic false positives (flagged for completeness, NOT tested
# as wanted-behaviour):
#  --x  (numeric double-negation in a condition): matches via the
#       `--` decrement alternation. Effectively never seen in real
#       path-condition input — C rejects `--literal` at compile
#       time, and LLM-emitted conditions don't write it this way.
#       If it ever appears, the operator gets ASSIGNMENT_SHAPED on a
#       valid Boolean predicate; rephrasing as `x != 0` or `0 - x`
#       in the condition string sidesteps it.
_ASSIGNMENT_SHAPED_RE = re.compile(
    r'(?<![=<>!])=(?!=)'         # bare `=` not in `==`/`<=`/`>=`/`!=`
    r'|[+\-*/%&|^]='             # compound assignment ops `+= -= *= /= %= &= |= ^=`
    r'|<<=|>>='                  # shift compound assignment
    r'|\+\+|--'                  # post/pre-increment, decrement
)


# ---------------------------------------------------------------------------
# Call summaries — axioms for recognised libc/POSIX calls
# ---------------------------------------------------------------------------
#
# When _substitute_calls recovers ``strlen(input)`` as a free ``_anon_N``
# variable, the fact that strlen can never be negative is lost, and paths
# like ``strlen(x) < 0`` read as feasible.  For a small, conservative set
# of libc/POSIX functions we assert a summary axiom on the placeholder.
#
# Doctrine note: libc/POSIX names are fine to hardcode here.  Summaries
# for PROJECT APIs must come from learned vocabulary (study/IRIS), never
# from this table.
#
# Signedness honesty: each builder decides per-profile whether its axiom
# is meaningful.
#   * ``result >= 0`` is vacuous at an unsigned profile — skipped, never
#     asserted as junk.
#   * ``abs``-family axioms model the two's-complement INT_MIN corner
#     (``abs(INT_MIN) == INT_MIN`` at the same width) as a disjunct
#     instead of pretending ``abs`` is always non-negative.
#   * ``sizeof`` is modelled as ``!= 0`` (C guarantees sizeof >= 1); the
#     form is signedness-neutral so it is asserted at every profile.
# Axioms are explicit callee-model assumptions, surfaced to consumers via
# ``PathSMTResult.summary_axioms``. They do not establish call purity or
# unchanged memory; each occurrence receives its own result and axiom.

_MAX_SUMMARY_ARGS_CHARS = 200


def _nonneg_summary(var: Any, _args_text: str, _vars: dict[str, Any],
                    profile: BVProfile) -> Any | None:
    """``result >= 0`` — meaningful only at signed profiles."""
    if not profile.signed:
        return None
    return ge(var, _mk_val(0, profile.width), signed=True)


def _abs_summary(var: Any, args_text: str, vars_: dict[str, Any],
                 profile: BVProfile) -> Any | None:
    """Signed absolute value, preserving the conservative INT_MIN corner.

    The prior model retains INT_MIN as a possible result bit pattern.
    This is conservative handling of C undefined behavior, not proof of
    a defined C execution at INT_MIN.
    """
    if not profile.signed:
        return None
    argument = _parse_expr(args_text.strip(), vars_, profile=profile)
    if not isinstance(argument, Rejection):
        return var == z3.If(ge(argument, _mk_val(0, profile.width), signed=True), argument, -argument)
    # Unsupported argument expressions retain the prior conservative range.
    int_min = _mk_val(1 << (profile.width - 1), profile.width)
    return z3.Or(ge(var, _mk_val(0, profile.width), signed=True),
                 var == int_min)


def _sizeof_summary(var: Any, _args_text: str, _vars: dict[str, Any],
                    profile: BVProfile) -> Any | None:
    """``sizeof(...) != 0`` — signedness-neutral, always meaningful."""
    return var != _mk_val(0, profile.width)


def _strnlen_summary(var: Any, args_text: str, _vars: dict[str, Any],
                     profile: BVProfile) -> Any | None:
    """A literal bound constrains raw result bits even under a signed frame.

    Bounds outside the frame, negative values, and symbolic bounds do not
    establish a range. In particular, do not invent signed nonnegativity
    when a representable result can set the sign bit.
    """
    parts = split_call_arguments(args_text)
    if parts is None or len(parts) != 2:
        return None
    bound = _parse_literal_value(parts[1], BVProfile(width=profile.width, signed=False))
    if isinstance(bound, Rejection):
        return None
    return le(var, _mk_val(bound, profile.width), signed=False)


def _minmax_summary(pick_smaller: bool):
    """Build a min/max summary: ``var == ITE(a <= b, a, b)`` (or the
    max mirror), applied only when BOTH arguments parse as plain
    arithmetic expressions (nested calls or unsupported syntax mean no
    axiom — the placeholder stays free, today's behaviour)."""
    def _builder(var: Any, args_text: str, vars_: dict[str, Any],
                 profile: BVProfile) -> Any | None:
        parts = split_call_arguments(args_text)
        if parts is None or len(parts) != 2:
            return None
        a = _parse_expr(parts[0].strip(), vars_, profile=profile)
        if isinstance(a, Rejection):
            return None
        b = _parse_expr(parts[1].strip(), vars_, profile=profile)
        if isinstance(b, Rejection):
            return None
        cond = le(a, b, signed=profile.signed)
        return var == z3.If(cond, a, b) if pick_smaller \
            else var == z3.If(cond, b, a)
    return _builder


# Callee name (case-sensitive, matching C) → (arity, axiom builder). A builder
# returns a Z3 expression or None (axiom not meaningful for this
# profile / arguments) — None keeps today's free-variable behaviour.
_CALL_SUMMARIES: dict[str, tuple[int, Any]] = {
    "strlen": (1, _nonneg_summary),
    "strnlen": (2, _strnlen_summary),
    "wcslen": (1, _nonneg_summary),
    "abs": (1, _abs_summary),
    "labs": (1, _abs_summary),
    "llabs": (1, _abs_summary),
    "sizeof": (1, _sizeof_summary),
    "min": (2, _minmax_summary(pick_smaller=True)),
    "max": (2, _minmax_summary(pick_smaller=False)),
    "MIN": (2, _minmax_summary(pick_smaller=True)),
    "MAX": (2, _minmax_summary(pick_smaller=False)),
}


def _summarise_call(
    callee: str, args_text: str, call_text: str, var: Any,
    vars_: dict[str, Any], *, profile: BVProfile,
) -> tuple[str, Any] | None:
    """Return ``(label, axiom_expr)`` for a recognised call, else None."""
    summary = _CALL_SUMMARIES.get(callee)
    if summary is None or len(args_text) > _MAX_SUMMARY_ARGS_CHARS:
        return None
    arity, builder = summary
    arguments = split_call_arguments(args_text)
    if arguments is None or len(arguments) != arity:
        return None
    expr = builder(var, args_text, vars_, profile)
    if expr is None:
        return None
    return f"summary: {call_text}", expr


def _substitute_calls(
    text: str, vars_: dict[str, Any], *, profile: BVProfile,
    anon_map: dict[str, str] | None = None,
    axiom_sink: list[tuple[str, Any]] | None = None,
) -> str:
    """Replace balanced ``<ident>(...)`` subterms with free Z3 variables.

    Each function-call-shaped subterm is swapped for an ``_anon_N``
    placeholder registered as a free Z3 bitvector in ``vars_``.  Lets
    conditions like ``strlen(input) < 1024`` parse instead of being
    rejected wholesale on the parens check.

    Nested calls collapse to a single placeholder
    (``f(g(x))`` → ``_anon_0``), since the outer call drives the
    balanced-paren walk.

    Each syntactic occurrence gets a fresh result. Repeated text is not
    proof of the same evaluation, call purity, or unchanged memory. The
    optional anon_map records occurrence labels only; it is never an alias
    oracle. Definition summaries may independently equate results through
    their modeled arguments, while range summaries leave them independent.

    Unbalanced parentheses are left for the condition parser to reject.
    """
    reserve_anon_names([text], vars_)
    counter = _next_anon_index(vars_)
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        m = _CALL_HEAD_RE.match(text, i)
        if m and m.end() < n and text[m.end()] == '(':
            j = find_call_end(text, m.end())
            if j is not None:
                call_text = text[i:j]
                while f'_anon_{counter}' in vars_:
                    counter += 1
                placeholder = f'_anon_{counter}'
                counter += 1
                vars_[placeholder] = _mk_var(placeholder, profile.width)
                if anon_map is not None:
                    anon_map[placeholder] = call_text
                # Report the assumption separately for every occurrence.
                if axiom_sink is not None:
                    summary = _summarise_call(
                        text[i:m.end()],
                        text[m.end() + 1:j - 1],
                        call_text,
                        vars_[placeholder],
                        vars_,
                        profile=profile,
                    )
                    if summary is not None:
                        axiom_sink.append(summary)
                out.append(placeholder)
                i = j
                continue
            # Unbalanced: fall through and copy the head char-by-char so
            # the parens-check can flag it.
        # Pre-fix the no-match path always did `i += 1`, even when
        # `_CALL_HEAD_RE.match` returned an identifier-shaped match
        # that just wasn't followed by `(`. That meant for an
        # identifier-heavy input (100k chars of `foo bar baz qux ...`
        # / large macro-expanded condition text), each character
        # position re-scanned the identifier from scratch — O(N) per
        # position × N positions = O(N²) wallclock.
        # When we matched an identifier but it wasn't a call, jump
        # past the identifier in one step instead of one char at a
        # time. Append the matched substring as-is. Reduces O(N²)
        # to O(N) for identifier-heavy text.
        if m:
            out.append(text[i:m.end()])
            i = m.end()
            continue
        out.append(text[i])
        i += 1
    return ''.join(out)


def _parse_condition(
    text: str, vars_: dict[str, Any], *, profile: BVProfile,
    anon_map: dict[str, str] | None = None,
    axiom_sink: list[tuple[str, Any]] | None = None,
) -> Any | Rejection:
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
    # Hard cap on input size before any parsing work runs.  Defends the
    # parser combinator against pathological inputs whose total length is
    # unboundedly large.  See ``_MAX_CONDITION_CHARS`` for the rationale
    # and tuning guidance.
    if len(text) > _MAX_CONDITION_CHARS:
        return Rejection(
            text, RejectionKind.INPUT_TOO_LONG,
            f"condition length {len(text)} exceeds limit {_MAX_CONDITION_CHARS}",
            hint=(
                f"shorten or split the predicate so each condition is at "
                f"most {_MAX_CONDITION_CHARS} characters"
            ),
        )
    canonicalised = _canonicalise(text)
    # Reject program-statement shapes (assignment, compound assignment,
    # increment/decrement) BEFORE call substitution — they aren't
    # Boolean guards and routing them to ASSIGNMENT_SHAPED lets
    # check_path_feasibility mark a new scalar value-flow segment rather
    # than proving a contradiction across an unmodeled mutation.
    # The detection is purely textual; the regex
    # carefully excludes the `==` / `<=` / `>=` / `!=` relational ops.
    if _ASSIGNMENT_SHAPED_RE.search(canonicalised):
        return Rejection(
            text, RejectionKind.ASSIGNMENT_SHAPED,
            "condition is assignment-shaped (program statement, not a "
            "Boolean guard)",
            hint=(
                "path conditions are Boolean guards on the path; emit the "
                "guard predicates only, not the statements between them. "
                "If a variable mutates between guards, SSA-rename it so "
                "later references denote the post-mutation value "
                "(e.g. `strlen(input_pre)` then `strlen(input_post)`)"
            ),
        )
    t = _substitute_calls(
        canonicalised, vars_, profile=profile,
        anon_map=anon_map,
        axiom_sink=axiom_sink,
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

    # Bitmask: lhs & mask (==|!=) val.
    #
    # The lhs group is a negated class (no `&`) ending in
    # non-whitespace, with a single-`\s` branch for the
    # all-whitespace-lhs corner the previous spelling matched. The
    # naive `([^&]+?)\s*&` overlapped the lazy lhs and the following
    # whitespace span on whitespace: a condition whose lhs ends in a
    # long whitespace run with no `&` made the engine try every
    # split of the run between them — quadratic in the condition
    # length. Match set and the stripped lhs capture are unchanged.
    # (`[^&]` rather than `.` so a non-bitmask input still fails at
    # the first `&`-less stretch instead of rescanning, the earlier
    # hardening this pattern shares with `_parse_atom`.)
    m = re.fullmatch(
        r'([^&]*?[^&\s]|\s)\s*&\s*(0x[0-9a-f]+|\d+)\s*(==|!=)\s*(0x[0-9a-f]+|\d+)',
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
    # The lhs ends in a non-whitespace atom (or is a single char):
    # the naive lazy lhs overlapped the following whitespace span —
    # quadratic on a condition whose lhs ends in a whitespace run
    # with no operator. The stripped capture is unchanged.
    m = re.fullmatch(
        r'((?:>>|<<|[^<>]|(?<![<>])[<>](?![<>]))*?'
        r'(?:>>|<<|[^<>\s]|(?<![<>])[<>](?![<>]))|\s)'
        r'\s*(<=|>=|!=|==|<(?!<)|>(?!>))\s*(.+)',
        t,
    )
    if m:
        lhs = _parse_typed_expr(m.group(1).strip(), vars_, profile=profile)
        if isinstance(lhs, Rejection):
            return _propagate(text, lhs)
        rhs = _parse_typed_expr(m.group(3).strip(), vars_, profile=profile)
        if isinstance(rhs, Rejection):
            return _propagate(text, rhs)
        op = m.group(2)
        signed_cmp = lhs.signed and rhs.signed
        lhs, rhs = lhs.value, rhs.value
        if op == '==':
            return lhs == rhs
        if op == '!=':
            return lhs != rhs
        if op == '<':
            return lt(lhs, rhs, signed=signed_cmp)
        if op == '<=':
            return le(lhs, rhs, signed=signed_cmp)
        if op == '>':
            return gt(lhs, rhs, signed=signed_cmp)
        if op == '>=':
            return ge(lhs, rhs, signed=signed_cmp)

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
    vars_: dict[str, Any],
    solver: Any,
    *,
    profile: BVProfile,
    anon_map: dict[str, str] | None = None,
    axiom_sink: list[tuple[str, Any]] | None = None,
) -> tuple[str | None, tuple[str, Any] | None, Rejection | None]:
    """Parse one text condition and classify it.

    Returns one of:
      - ``(satisfied_display, None, None)`` — tautology, no further work
      - ``(None, (display, expr), None)`` — pending, must be solved
      - ``(None, None, rejection)`` — unparseable, accumulate into unknown

    Factored out so :func:`check_path_feasibility` and
    :func:`check_verb_feasibility` share the same parse-and-classify
    semantics.

    With ``solver=None``, parse and retain every supported condition without
    an optional tautology query. All call-summary and rejection handling stays
    active.

    """
    expr = _parse_condition(
        cond.text, vars_, profile=profile,
        anon_map=anon_map,
        axiom_sink=axiom_sink,
    )
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

    # Optional classification: is this condition a tautology?
    if solver is not None:
        with _scoped(solver):
            solver.add(z3.Not(final_expr))
            if solver.check() == z3.unsat:
                return display, None, None  # tautology

    return None, (display, final_expr), None


@dataclass
class _ConditionBatch:
    """One parsed guard frame shared by path and intrinsic queries."""

    pending: list[tuple[str, Any]] = field(default_factory=list)
    satisfied: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)
    anon_map: dict[str, str] = field(default_factory=dict)
    axioms: list[tuple[str, Any]] = field(default_factory=list)
    pending_call_terms: list[bool] = field(default_factory=list)
    pending_epochs: list[int] = field(default_factory=list)
    axiom_epochs: list[int] = field(default_factory=list)


def _classify_conditions(
    conditions: list[PathCondition], vars_: dict[str, Any], solver: Any,
    *, profile: BVProfile, use_call_summaries: bool = True,
) -> _ConditionBatch:
    """Parse a complete guard frame without dropping its background theory.

    Reserve source names before allocating fresh call occurrences. An
    assignment-shaped rejection advances the scalar value-flow segment
    without erasing labels or axioms. Every rejection remains visible.
    Each predicate and axiom retains its mutation-free segment so a native
    unsat core can establish an independent contradiction. A None solver
    disables only optional tautology queries. Disabling call summaries
    prevents constructing callee axioms, while retaining opaque results.
    """
    require_bool(use_call_summaries, argument="use_call_summaries")
    reserve_anon_names([cond.text for cond in conditions], vars_)
    batch = _ConditionBatch()
    epoch = 0
    for cond in conditions:
        previous_calls = len(batch.anon_map)
        previous_axioms = len(batch.axioms)
        sat_display, pending_pair, rejection = _classify_text_condition(
            cond, vars_, solver, profile=profile,
            anon_map=batch.anon_map,
            axiom_sink=batch.axioms if use_call_summaries else None,
        )
        batch.axiom_epochs.extend([epoch] * (len(batch.axioms) - previous_axioms))
        if sat_display is not None:
            batch.satisfied.append(sat_display)
        elif rejection is not None:
            batch.unknown.append(cond.text)
            batch.rejections.append(rejection)
            if rejection.kind is RejectionKind.ASSIGNMENT_SHAPED:
                epoch += 1
        else:
            assert pending_pair is not None
            batch.pending.append(pending_pair)
            batch.pending_epochs.append(epoch)
            batch.pending_call_terms.append(len(batch.anon_map) > previous_calls)
    return batch


def _extract_wp(
    pending: list[tuple[str, Any]],
    *,
    cap: int = WP_MAX_SOLVER_CALLS,
    axioms: list[tuple[str, Any]] | None = None,
    timeout_ms: int | None = None,
) -> tuple[str | None, list[str], bool]:
    """Reduce a satisfiable conjunction by proved implication only.

    Return its SMTLIB predicate, retained conjunct texts, and completeness.
    Deleting an implied conjunct preserves the encoded solution set modulo
    the supplied background axioms. This is not a program weakest
    precondition and does not prove source execution or reachability.

    Visit conjuncts deterministically. Keep a conjunct when redundancy is
    undecided; the result remains equivalent, but minimality is incomplete.
    Limits, unavailable solvers, and serialization failures also prevent a
    complete summary. Background axioms are not themselves deleted.
    """
    n = len(pending)
    if n == 0:
        return None, [], True
    if not _z3_available():
        return None, [text for text, _ in pending], False

    _axioms = axioms or []

    order = sorted(range(n), key=lambda i: (_canonicalise(pending[i][0]), i))
    kept = [True] * n
    calls = 0
    complete = True
    # The caller's per-call budget CAPS the per-redundancy-test
    # timeout: WP is a best-effort refinement (up to 32 solver
    # calls), so a caller who asked for a tight overall budget must
    # not pay the fixed default per test. It never RAISES it — WP
    # cost stays bounded even under a generous caller budget.
    effective_ms = WP_TIMEOUT_MS
    if timeout_ms is not None:
        effective_ms = min(WP_TIMEOUT_MS, timeout_ms)
    solver = _new_solver(effective_ms)
    for idx in order:
        if calls >= cap:
            complete = False
            break
        with _scoped(solver):
            for _, axiom_expr in _axioms:
                solver.add(axiom_expr)
            for j in range(n):
                if kept[j] and j != idx:
                    solver.add(pending[j][1])
            solver.add(z3.Not(pending[idx][1]))
            calls += 1
            verdict = solver.check()
        if verdict == z3.unsat:
            kept[idx] = False  # implied by the rest → redundant, drop it
        elif verdict != z3.sat:
            complete = False  # an undecided test cannot certify minimality

    # Serialise + list the kept conjuncts in the deterministic visit order
    # so the predicate and the conjunct list line up across re-runs.
    kept_in_order = [i for i in order if kept[i]]
    kept_exprs = [pending[i][1] for i in kept_in_order]
    wp_conjuncts = [pending[i][0] for i in kept_in_order]

    if not kept_exprs:
        # Degenerate — cannot occur for a sat, tautology-filtered pending
        # set, but stay total rather than index into an empty list.
        return "true", wp_conjuncts, complete

    expr = kept_exprs[0] if len(kept_exprs) == 1 else z3.And(*kept_exprs)
    try:
        wp_predicate = expr.sexpr()
    except (z3.Z3Exception, AttributeError):
        wp_predicate = None
        complete = False
    return wp_predicate, wp_conjuncts, complete


def _solve_pending(
    pending: list[tuple[str, Any]],
    solver: Any,
    satisfied: list[str],
    unknown: list[str],
    unknown_reasons: list[Rejection],
    *,
    profile: BVProfile,
    anon_map: dict[str, str] | None = None,
    prefer_witness: str | tuple[str, str] | None = None,
    vars_: dict[str, Any] | None = None,
    axioms: list[tuple[str, Any]] | None = None,
    wp_timeout_ms: int | None = None,
    reduce_constraints: bool = True,
    pending_call_terms: Sequence[bool | None] | None = None,
    pending_epochs: Sequence[int | None] | None = None,
    axiom_epochs: Sequence[int | None] | None = None,
) -> PathSMTResult:
    """Run the solver over pending predicates and produce a verdict.

    Shared between :func:`check_path_feasibility` and
    :func:`check_verb_feasibility`.  Caller has already classified
    each input as tautology/pending/unknown; this function turns the
    pending list into a sat/unsat/unknown verdict and packages the
    result. Optional epoch metadata records each assertion's ownership for
    mutation-aware core checks; unowned predicates cannot establish an
    independent contradiction across rejected scalar updates. Call flags
    describe parsed guards; unclassified intrinsics retain None provenance.

    When ``prefer_witness`` is set, ``solver`` is expected to be a
    ``z3.Optimize`` instance (the caller is responsible for the
    backend swap).  This function then adds the appropriate
    ``maximize`` or ``minimize`` objective for the named variable.
    ``vars_`` carries the parser's interned BitVec table so the
    objective lookup uses the same variable instance the predicates
    were built against — name collisions in z3's hash-cons would
    otherwise produce an objective on a freshly-minted variable
    decoupled from the path.
    """
    prefer_witness = parse_witness_preference(prefer_witness)
    require_bool(reduce_constraints, argument="reduce_constraints")
    call_flags = tuple(pending_call_terms) if pending_call_terms is not None else (None,) * len(pending)
    if len(call_flags) != len(pending):
        raise ValueError("call dependency count must match pending constraints")
    if any(flag is not None and type(flag) is not bool for flag in call_flags):
        raise ValueError("call dependencies must be booleans or None")
    mode = profile.describe()

    # Apply the witness-direction objective before solving.  Silently
    # skip if the named variable doesn't appear in the parsed
    # conditions — the caller can spot this by inspecting `model` to
    # confirm the variable is present, and the unsat-core /
    # smallest-model behaviour still produces a valid (just not
    # extremal) witness.
    objective_active = False
    if (prefer_witness is not None and vars_ is not None
            and not (unknown and not pending and not axioms)):
        var_name, direction = prefer_witness
        target = vars_.get(var_name)
        if target is not None:
            # Optimize orders bitvectors as unsigned. Flipping the sign
            # bit maps signed order monotonically into unsigned order.
            objective = target ^ z3.BitVecVal(1 << (target.size() - 1), target.size(), ctx=target.ctx) if profile.signed else target
            if direction == "max":
                solver.maximize(objective)
            elif direction == "min":
                solver.minimize(objective)
            objective_active = True

    # Default to empty dict so the field is always present on the
    # PathSMTResult — downstream consumers never need to None-check.
    _anon_map = anon_map or {}
    _axioms = axioms or []
    _axiom_labels = [label for label, _ in _axioms]

    if not pending and not _axioms and not objective_active:
        if unknown:
            return PathSMTResult(
                wp_complete=reduce_constraints,
                feasible=None,
                satisfied=satisfied, unsatisfied=[], unknown=unknown,
                unknown_reasons=unknown_reasons,
                model={}, smt_available=True,
                reasoning=(
                    f"indeterminate ({mode}): {len(satisfied)} trivially satisfied, "
                    f"{len(unknown)} unparseable — LLM analysis required"
                ),
                anon_var_map=_anon_map,
                summary_axioms=_axiom_labels,
            )
        return PathSMTResult(
            wp_complete=reduce_constraints,
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=[],
            unknown_reasons=[],
            model={}, smt_available=True,
            reasoning=f"all {len(satisfied)} condition(s) trivially satisfied ({mode})",
            anon_var_map=_anon_map,
            summary_axioms=_axiom_labels,
        )

    tracked = track_frames(solver, ((pending, pending_epochs), (_axioms, axiom_epochs)))
    result = tracked.check()

    if result == z3.sat:
        model_dict = _format_witness(solver.model(), signed=profile.signed)
        # Optional implication-reduced constraint summary. Its fresh solver
        # cannot change the primary verdict, but still consumes worker time.
        wp_predicate, wp_conjuncts, wp_complete = None, [], False
        if reduce_constraints:
            try:
                wp_predicate, wp_conjuncts, wp_complete = _extract_wp(
                    pending, axioms=_axioms, timeout_ms=wp_timeout_ms,
                )
            except Exception:
                # Reduction owns a separate solver; preserve the primary
                # verdict and its model if optional diagnostics fail.
                _get_logger().debug("SMT conjunct reduction unavailable", exc_info=True)
                wp_predicate, wp_conjuncts, wp_complete = None, [text for text, _ in pending], False
            wp_complete = wp_complete and not unknown
        return PathSMTResult(
            feasible=True,
            satisfied=satisfied, unsatisfied=[], unknown=unknown,
            unknown_reasons=unknown_reasons,
            model=model_dict, smt_available=True,
            reasoning=(
                f"feasible ({mode}): {len(pending)} condition(s) are jointly satisfiable"
                + (f"; {len(satisfied)} trivially satisfied" if satisfied else "")
                + (f"; {len(unknown)} unparsed" if unknown else "")
                + (f"; {len(_axioms)} call summar"
                   f"{'y' if len(_axioms) == 1 else 'ies'} applied"
                   if _axioms else "")
            ),
            anon_var_map=_anon_map,
            summary_axioms=_axiom_labels,
            wp_predicate=wp_predicate,
            wp_conjuncts=wp_conjuncts,
            wp_complete=wp_complete,
        )

    if result == z3.unsat:
        indices = tracked.core_indices(solver)
        flags = call_flags + (True,) * len(_axioms)
        core_flags = tuple(flags[index] for index in indices) if indices is not None else ()
        uses_calls = (
            True if any(flag is True for flag in core_flags)
            else False if core_flags and all(flag is False for flag in core_flags)
            else None
        )
        conflicts = _core_names(solver, tracked.labels)
        conflict_set = conflicts or [t for t, _ in pending]
        # Rejecting a mutation does not make scalar identities SSA-correct.
        # A contradiction may compare pre- and post-assignment values as one
        # symbol. Only a native core owned by one mutation-free segment can
        # establish a refutation independently of the unmodeled transition.
        has_mutation = any(
            reason.kind == RejectionKind.ASSIGNMENT_SHAPED
            for reason in unknown_reasons
        )
        core_epoch = tracked.single_core_origin(solver) if has_mutation else None
        unmodeled_mutation = has_mutation and core_epoch is None
        if unmodeled_mutation:
            reasoning = (
                f"indeterminate ({mode}): encoded constraints are unsatisfiable, "
                "but assignment-shaped input has unmodeled scalar value flow; "
                "refusing the refutation"
            )
        else:
            reasoning = f"infeasible ({mode}): path conditions are mutually exclusive"
            if has_mutation:
                reasoning += f"; native core confined to mutation-free segment {core_epoch}"
        if conflicts:
            label = "encoded conflict" if unmodeled_mutation else "conflict"
            reasoning += f"; {label}: {' ⊥ '.join(conflicts[:3])}"
        return PathSMTResult(
            wp_complete=reduce_constraints and not has_mutation,
            refutation_uses_call_terms=uses_calls,
            feasible=None if unmodeled_mutation else False,
            satisfied=satisfied, unsatisfied=conflict_set, unknown=unknown,
            unknown_reasons=unknown_reasons,
            model={}, smt_available=True,
            reasoning=reasoning,
            anon_var_map=_anon_map,
            summary_axioms=_axiom_labels,
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
        wp_complete=reduce_constraints,
        feasible=None,
        satisfied=satisfied, unsatisfied=[],
        unknown=unknown + pending_texts,
        unknown_reasons=unknown_reasons + pending_reasons,
        model={}, smt_available=True,
        reasoning=f"Z3 returned unknown ({mode}) — {detail}",
        anon_var_map=_anon_map,
        summary_axioms=_axiom_labels,
    )


@dataclass
class CallOperandModel:
    """Independent call occurrences and their optional background theory."""

    anon_var_map: dict[str, str] = field(default_factory=dict)
    axioms: list[tuple[str, Any]] = field(default_factory=list)


def make_call_operand(
    text: str, vars_: dict[str, Any], *, profile: BVProfile,
    model: CallOperandModel,
) -> Any:
    """Allocate one independent occurrence, retaining its labels and theory.

    Matching operand or guard text never establishes execution identity.
    The same optional summaries used by guards constrain only this fresh
    result. Argument variables retain the shared uniform-profile model.
    """
    text = text.strip()
    if len(text) > _MAX_CONDITION_CHARS:
        raise ValueError("call operand exceeds the condition character limit")
    if not is_balanced_call(text):
        raise ValueError("call operand must be one balanced function call")
    head = _CALL_HEAD_RE.match(text)
    assert head is not None
    variable = make_anon_call_var(vars_, profile=profile)
    summary = _summarise_call(head.group(), text[head.end() + 1:-1], text, variable, vars_, profile=profile)
    model.anon_var_map[str(variable.decl().name())] = text
    if summary is not None:
        model.axioms.append(summary)
    return variable


def is_literal_identifier(name: str) -> bool:
    """Whether the condition grammar treats an identifier token as a literal."""
    return bool(_NULL_RE.fullmatch(name))


def make_var(name: str, vars_: dict[str, Any], *, profile: BVProfile) -> Any:
    """Get-or-create a Z3 bitvector variable, sharing ``vars_`` with the parser.

    Domain encoders (``smt_verbs``) building Z3 predicates directly via
    csem need their operand BVs to share names with parser-built BVs so
    that, e.g., a verb's overflow predicate over ``count`` and a guard
    ``count < MAX`` constrain the *same* Z3 variable.

    Names retain case, matching the parser and source identifier identity.
    The reserved NULL literal cannot denote a source variable.
    """
    if is_literal_identifier(name):
        raise ValueError("NULL is a reserved zero literal, not a source variable")
    key = name
    if vars_.get(key) is None:
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
        msg = f"literal {literal!r} rejected: {v.kind.value} ({v.detail})"
        raise ValueError(msg)
    return _mk_val(v, profile.width)


def check_verb_feasibility(
    intrinsic: list[tuple[str, Any]],
    text_guards: list[PathCondition],
    vars_: dict[str, Any],
    *,
    profile: BVProfile = BV_C_UINT64,
    reduce_constraints: bool = True,
    operand_model: CallOperandModel | None = None,
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
    Z3 BV regardless of which path created them. ``operand_model`` carries
    independent call occurrences and their optional theory; matching call
    text does not merge operand and guard executions.

    ``reduce_constraints=False`` skips optional tautology and constraint-summary
    queries. The full parsed obligation is still asserted; summary fields are
    None/empty with ``wp_complete=False``.

    Always called with Z3 available; verbs short-circuit the
    ``smt_available=False`` case before calling this helper.
    """
    require_bool(reduce_constraints, argument="reduce_constraints")
    for condition in text_guards:
        require_bool(condition.negated, argument="negated")
    mode = profile.describe()
    count = len(intrinsic) + len(text_guards)
    if count > _MAX_CONDITIONS_PER_CALL:
        reason = Rejection(
            text="", kind=RejectionKind.TOO_MANY_CONDITIONS,
            detail=f"{count} verb conditions exceeds per-call cap {_MAX_CONDITIONS_PER_CALL}",
            hint="reduce the complete obligation; do not discard constraints to obtain a verdict",
        )
        return PathSMTResult(
            wp_complete=reduce_constraints,
            feasible=None, satisfied=[], unsatisfied=[],
            unknown=[text for text, _ in intrinsic] + [cond.text for cond in text_guards],
            unknown_reasons=[reason], model={}, smt_available=True,
            reasoning=f"refused: {reason.detail} ({mode})",
        )
    tautology_solver = _new_solver() if reduce_constraints else None
    solver = _new_solver()
    batch = _classify_conditions(text_guards, vars_, tautology_solver, profile=profile)
    # Operand calls remain independent occurrences. Their theory has no
    # established scalar segment across rejected mutations.
    operand_model = operand_model if operand_model is not None else CallOperandModel()
    operand_axioms = list(operand_model.axioms)
    return _solve_pending(
        list(intrinsic) + batch.pending, solver,
        batch.satisfied, batch.unknown, batch.rejections,
        profile=profile, anon_map={**operand_model.anon_var_map, **batch.anon_map},
        axioms=operand_axioms + batch.axioms,
        pending_call_terms=[None] * len(intrinsic) + batch.pending_call_terms,
        pending_epochs=[None] * len(intrinsic) + batch.pending_epochs,
        axiom_epochs=[None] * len(operand_axioms) + batch.axiom_epochs,
        reduce_constraints=reduce_constraints,
    )


def check_path_feasibility(
    conditions: list[PathCondition],
    *,
    profile: BVProfile = BV_C_UINT64,
    timeout_ms: int | None = None,
    prefer_witness: str | tuple[str, str] | None = None,
    reduce_constraints: bool = True,
    use_call_summaries: bool = True,
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
        timeout_ms: Z3 solver timeout in milliseconds, applied to
                    every solver this call builds: the final joint
                    solve, the per-condition tautology checks, and
                    (as a cap, never a raise) the per-test timeout of
                    the WP redundancy pass. When None (default) the
                    solvers use the substrate's ``DEFAULT_TIMEOUT_MS``
                    (5000 ms; WP tests use ``WP_TIMEOUT_MS``). Note
                    the bound is per SOLVER CALL — a call with many
                    conditions can still spend
                    ``O(len(conditions)) x timeout_ms`` overall.
        prefer_witness: Accepts ``"max:name"`` / ``"min:name"`` strings
                    or tuples. When set to ``(var_name, "max")`` or
                    ``(var_name, "min")``, drive the satisfying witness
                    toward an extreme value of ``var_name`` instead of
                    Z3's default (smallest model).  Useful for CWE-190
                    wraparound and similar bug classes where the
                    *exploit* witness lives at the high end of a
                    variable's domain — without ``prefer_witness`` Z3
                    typically returns the trivial ``var=0`` model that
                    technically satisfies the path but isn't a useful
                    PoC seed.  When the named variable is absent from
                    the parsed conditions (e.g. caller mistake or
                    rejected via parser fall-through) the objective is
                    silently skipped and the witness reverts to the
                    default smallest-model behaviour.

        reduce_constraints: Defaults to True. False skips individual tautology
                    checks and post-SAT conjunct reduction, retaining the full
                    parsed conjunction and background axioms. Witnesses and
                    conflicts remain available; summary fields are None/empty
                    and wp_complete=False. This is not a whole-call time limit.

        use_call_summaries: Defaults to True for explicit conditional models.
                    False leaves each call occurrence opaque and constructs no
                    name-based callee axioms. Use False when source identities,
                    signatures, and callee effects have not been established.
                    Plain guard contradictions remain available for refutation.

    Returns:
        PathSMTResult.  feasible=None when Z3 is unavailable or every
        condition was unparseable.
    """
    prefer_witness = parse_witness_preference(prefer_witness)
    require_bool(reduce_constraints, argument="reduce_constraints")
    require_bool(use_call_summaries, argument="use_call_summaries")
    for condition in conditions:
        require_bool(condition.negated, argument="negated")
    mode = profile.describe()

    if not _z3_available():
        return PathSMTResult(
            wp_complete=reduce_constraints,
            feasible=None,
            satisfied=[], unsatisfied=[],
            unknown=[c.text for c in conditions],
            unknown_reasons=[],
            model={}, smt_available=False,
            reasoning="z3 not available — install z3-solver for path feasibility analysis",
        )

    # Hard cap on number of conditions per call.  Caller mistakes
    # (malformed upstream extraction, accidental amplification) can
    # flood the parser with tens of thousands of items.  Refuse the
    # whole call cleanly so partial parser progress isn't misread as
    # an authoritative feasibility verdict.
    if len(conditions) > _MAX_CONDITIONS_PER_CALL:
        cap_reason = Rejection(
            text="",
            kind=RejectionKind.TOO_MANY_CONDITIONS,
            detail=(
                f"{len(conditions)} conditions exceeds per-call cap "
                f"{_MAX_CONDITIONS_PER_CALL}"
            ),
            hint=(
                "split the path into smaller condition batches or "
                "deduplicate before calling check_path_feasibility"
            ),
        )
        return PathSMTResult(
            wp_complete=reduce_constraints,
            feasible=None,
            satisfied=[], unsatisfied=[],
            unknown=[c.text for c in conditions],
            unknown_reasons=[cap_reason],
            model={}, smt_available=True,
            reasoning=(
                f"refused: {len(conditions)} conditions exceeds the per-call "
                f"cap of {_MAX_CONDITIONS_PER_CALL} — caller should split or "
                f"deduplicate before retrying"
            ),
        )

    if not conditions:
        return PathSMTResult(
            wp_complete=reduce_constraints,
            feasible=True,
            satisfied=[], unsatisfied=[], unknown=[],
            unknown_reasons=[],
            model={}, smt_available=True,
            reasoning=f"no conditions ({mode}) — path is unconditionally reachable",
        )

    vars_: dict[str, Any] = {}
    # Tautology checks (push/add(Not(expr))/check/pop) run on a
    # throwaway solver so residual push/pop state cannot leak into
    # the final solve.  Z3 4.15.4.0 has been observed to return
    # models that violate tracked assertions after repeated
    # push/pop cycles on the same solver instance.
    # The caller's budget reaches EVERY solver this call builds —
    # the final solve below, and this tautology solver, which runs
    # one full check() per condition (up to the per-call cap) and
    # previously kept the 5 s default regardless of timeout_ms,
    # making the documented per-call budget a fiction for the
    # per-condition lane.
    tautology_solver = None
    if reduce_constraints:
        tautology_solver = _new_solver(timeout_ms) if timeout_ms is not None else _new_solver()
    # Per-call timeout override. Default to the substrate's
    # DEFAULT_TIMEOUT_MS (5s). Callers that know their CWE-class
    # solving-cost profile (CWE-190 wraparound is fast; CWE-787
    # OOB with complex array indexing may need longer) can pass
    # a tuned value via _tier4_smt_refine or the libexec shims.
    #
    # When prefer_witness is set, swap z3.Solver for z3.Optimize so
    # we can drive the witness toward a maximal/minimal value of a
    # named variable.  Optimize shares the entire Solver interface
    # (add/check/model/push/pop/assert_and_track/unsat_core) so the
    # rest of the encoder is agnostic to which backend is in use.
    if prefer_witness is not None:
        solver = (
            _new_optimizer(timeout_ms) if timeout_ms is not None
            else _new_optimizer()
        )
    else:
        solver = (
            _new_solver(timeout_ms) if timeout_ms is not None
            else _new_solver()
        )
    batch = _classify_conditions(conditions, vars_, tautology_solver, profile=profile,
                                 use_call_summaries=use_call_summaries)
    return _solve_pending(
        batch.pending, solver, batch.satisfied, batch.unknown, batch.rejections,
        profile=profile, anon_map=batch.anon_map,
        prefer_witness=prefer_witness, vars_=vars_,
        axioms=batch.axioms, wp_timeout_ms=timeout_ms, reduce_constraints=reduce_constraints,
        pending_call_terms=batch.pending_call_terms,
        pending_epochs=batch.pending_epochs, axiom_epochs=batch.axiom_epochs,
    )


def _robust_contradiction_result(
    candidate: frozenset[str],
    conditions: list[PathCondition],
    profiles: tuple[BVProfile, BVProfile],
    timeout_ms: int | None,
    *, use_call_summaries: bool = True,
) -> PathSMTResult | None:
    """Return a subset proof independent of the signedness guess.

    Preserve the native-core dependencies of both re-solves. A caller must
    report this exhibited proof rather than a different original core.

    ``candidate`` holds display texts from a leg's ``unsatisfied``
    list; they are matched back to the original conditions by the same
    rendering ``_classify_text_condition`` used (``NOT (text)`` for
    negated conditions). Call-summary axiom labels have no matching
    condition and simply drop out — the shrunken subset is weaker, so
    the check can only fail toward refusal, never toward suppression.

    Return the exhibited proof only when BOTH hold:

    * the subset mentions at most ONE identifier. Each profile forces
      every variable to one signedness, so for a single variable the
      two profiles enumerate its whole interpretation space — unsat
      under both is conclusive. A multi-identifier subset has mixed
      per-variable interpretations neither profile encodes (the
      ``[r == s, s > SSIZE_MAX, r <= SSIZE_MAX]`` shape is unsat under
      both shared profiles yet satisfiable in C at r = -1,
      s = UINT64_MAX), so it must never be honored as agreement —
      per-variable profiles are the full fix for those. Call heads
      count as identifiers, which errs toward refusal.
    * the subset re-solves unsat under BOTH profiles on its own. A
      subset satisfiable under either profile is that profile's
      counterexample — the leg refuted through profile-specific
      semantics, not a genuine contradiction.
    """
    require_bool(use_call_summaries, argument="use_call_summaries")
    subset = [
        c for c in conditions
        if (f"NOT ({c.text})" if c.negated else c.text) in candidate
    ]
    if not subset:
        return None
    idents = {
        tok
        for c in subset
        for tok in _TOKEN_RE.findall(c.text)
        if _IDENT_RE.match(tok) and not _NULL_RE.match(tok)
    }
    if len(idents) > 1:
        return None
    proofs = []
    for profile in profiles:
        proof = check_path_feasibility(
            subset, profile=profile, timeout_ms=timeout_ms, reduce_constraints=False,
            use_call_summaries=use_call_summaries,
        )
        if proof.feasible is not False:
            return None
        proofs.append(proof)
    flags = [proof.refutation_uses_call_terms for proof in proofs]
    proofs[0].refutation_uses_call_terms = (
        True if any(flag is True for flag in flags)
        else False if all(flag is False for flag in flags)
        else None
    )
    return proofs[0]


def check_path_feasibility_dual(
    conditions: list[PathCondition],
    *,
    profile: BVProfile = BV_C_UINT64,
    timeout_ms: int | None = None,
    prefer_witness: str | tuple[str, str] | None = None,
    reduce_constraints: bool = True,
    use_call_summaries: bool = True,
) -> PathSMTResult:
    """Signedness-agnostic feasibility check for callers whose profile
    signedness is a GUESS rather than a known fact.

    The two encodings disagree on exactly the guards that matter:
    ``ret < 0`` — the ubiquitous C signed error check — is UNSAT as
    ``ULT(ret, 0)`` under an unsigned profile, so a heuristic-unsigned
    caller would refute (and thereby suppress) any path carrying one.
    A refutation must survive the signedness ambiguity within this
    path's modeled conditions; flat guards from unrelated source sites
    cannot establish that an operation is unreachable.

    Semantics:

    * ``profile``'s verdict is authoritative whenever it is anything
      but ``False`` — sat results (model, witness steering) are
      byte-identical to :func:`check_path_feasibility` and the
      signedness-flipped sibling is never solved (no extra cost on
      the common path).
    * A ``feasible=False`` verdict is honored only when the
      signedness-flipped sibling profile ALSO reports ``False``
      AND a core subset exhibits a single-identifier contradiction
      that re-solves unsat under BOTH profiles on its own
      (:func:`_robust_contradiction_result`).
      Both-legs-unsat alone is NOT agreement: each shared profile
      forces EVERY variable to one signedness, so a mixed set like
      ``[ret < 0, size > SSIZE_MAX]`` — a signed error-guard beside
      an unsigned high-bound, the standard C overflow-path idiom —
      is unsat under BOTH profiles for DIFFERENT conditions while
      being jointly feasible in C, where each variable carries its
      own signedness. Nor is a shared core CONDITION agreement:
      ``[r == s, s > SSIZE_MAX, r <= SSIZE_MAX]`` puts the high
      bound in both cores yet is satisfiable in C (r = -1,
      s = UINT64_MAX) — condition-identity is not
      contradiction-identity. When no candidate subset exhibits a
      cross-profile contradiction the verdict is ``feasible=None``.
      (Per-variable profiles are the full fix; the exhibited-subset
      rule closes the known false refutations without them.)
      Sibling sat → the sibling's (feasible) result is returned;
      sibling inconclusive → ``feasible=None`` (a single-profile
      refutation under guessed signedness carries no weight — the
      fail direction must be "run the expensive analysis", never
      "suppress the finding").

    Callers that KNOW the signedness (explicit type info, a trusted
    per-path hint) should call :func:`check_path_feasibility` directly
    with the known profile. ``use_call_summaries`` follows that API's
    conditional-model policy and is preserved in both legs and every
    contradiction-subset probe. Agreement still assumes the selected width;
    it does not establish an opaque call's source return type.
    """
    prefer_witness = parse_witness_preference(prefer_witness)
    require_bool(reduce_constraints, argument="reduce_constraints")
    require_bool(use_call_summaries, argument="use_call_summaries")
    primary = check_path_feasibility(
        conditions, profile=profile,
        timeout_ms=timeout_ms, prefer_witness=prefer_witness, reduce_constraints=reduce_constraints,
        use_call_summaries=use_call_summaries,
    )
    if primary.feasible is not False:
        return primary
    sibling_profile = BVProfile(width=profile.width, signed=not profile.signed)
    sibling = check_path_feasibility(
        conditions, profile=sibling_profile,
        timeout_ms=timeout_ms, prefer_witness=prefer_witness, reduce_constraints=reduce_constraints,
        use_call_summaries=use_call_summaries,
    )
    if sibling.feasible is False:
        # Both legs unsat is NOT signedness agreement by itself: each
        # shared profile forces EVERY variable to one signedness, so a
        # mixed set like [ret < 0, size > SSIZE_MAX] is unsat under
        # BOTH profiles for DIFFERENT conditions while being jointly
        # feasible in C. And a merely SHARED core condition is no
        # better: [r == s, s > SSIZE_MAX, r <= SSIZE_MAX] puts the
        # high bound in both cores yet is satisfiable in C (r = -1,
        # s = UINT64_MAX) — condition-identity is not
        # contradiction-identity. The refutation is honored only when
        # some candidate core subset — the cores' intersection or
        # either leg's core — EXHIBITS a single-identifier
        # contradiction that re-solves unsat under BOTH profiles on
        # its own (see _robust_contradiction_result). Checking the
        # legs' cores individually is load-bearing: Z3's minimal core
        # under the unsigned default is the lone signed guard whenever
        # one rides beside an independent contradiction ([ret < 0,
        # x > 100, x < 50] presents disjoint cores), and guard shapes
        # are ubiquitous on C paths — without it every guard-carrying
        # infeasible path would refuse. Cost: a few bounded re-solves
        # of tiny subsets on the already-rare both-legs-unsat path.
        #
        # Trade-off, both directions: a genuinely-infeasible set whose
        # only contradiction spans MULTIPLE variables now refuses —
        # that costs a refutation (recoverable: the path is analysed),
        # while honoring multi-variable agreement cost live overflow
        # paths (suppressed pre-LLM). When core extraction failed,
        # ``unsatisfied`` is EVERY pending condition; the candidates
        # then degenerate to the full set, which still refutes only
        # via a single-identifier contradiction. Per-variable profiles
        # remain the full fix.
        primary_core = frozenset(primary.unsatisfied)
        sibling_core = frozenset(sibling.unsatisfied)
        candidates: list[frozenset[str]] = []
        for candidate in (
            primary_core & sibling_core, primary_core, sibling_core,
        ):
            if candidate and candidate not in candidates:
                candidates.append(candidate)
        exhibited: frozenset[str] | None = None
        for candidate in candidates:
            proof = _robust_contradiction_result(
                candidate, conditions, (profile, sibling_profile),
                timeout_ms, use_call_summaries=use_call_summaries,
            )
            if proof is not None:
                primary.unsatisfied = proof.unsatisfied
                primary.reasoning = proof.reasoning
                primary.refutation_uses_call_terms = proof.refutation_uses_call_terms
                exhibited = candidate
                break
        if exhibited is not None:
            primary.reasoning += (
                f" [signedness-robust: also unsat at "
                f"{sibling_profile.describe()}; exhibited cross-profile "
                f"contradiction: {', '.join(sorted(exhibited)[:3])}]"
            )
            return primary
        return PathSMTResult(
            wp_complete=reduce_constraints,
            feasible=None,
            satisfied=primary.satisfied,
            unsatisfied=[],
            unknown=primary.unknown,
            model={},
            smt_available=primary.smt_available,
            reasoning=(
                f"signedness-ambiguous: unsat at {profile.describe()} "
                f"(core: {', '.join(primary.unsatisfied[:3])}) and at "
                f"{sibling_profile.describe()} (core: "
                f"{', '.join(sibling.unsatisfied[:3])}), but no core "
                f"subset exhibits a single-identifier contradiction "
                f"under BOTH profiles on its own — the mixed-signedness "
                f"shape a per-variable encoding could satisfy — "
                f"refusing the refutation"
            ),
            unknown_reasons=primary.unknown_reasons,
            anon_var_map=primary.anon_var_map,
            summary_axioms=primary.summary_axioms,
        )
    if sibling.feasible is True:
        sibling.reasoning += (
            f" [note: unsat at {profile.describe()} but satisfiable at "
            f"{sibling_profile.describe()} — signedness unknown, so the "
            f"path is treated as feasible]"
        )
        return sibling
    return PathSMTResult(
        wp_complete=reduce_constraints,
        feasible=None,
        satisfied=primary.satisfied,
        unsatisfied=primary.unsatisfied,
        unknown=primary.unknown,
        model={},
        smt_available=primary.smt_available,
        reasoning=(
            f"signedness-ambiguous: unsat at {profile.describe()} but "
            f"inconclusive at {sibling_profile.describe()} "
            f"({sibling.reasoning}) — refusing the refutation because "
            f"the profiles disagree and the signedness was not "
            f"caller-asserted"
        ),
        unknown_reasons=primary.unknown_reasons,
        anon_var_map=primary.anon_var_map,
        summary_axioms=primary.summary_axioms,
    )
