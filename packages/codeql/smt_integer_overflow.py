#!/usr/bin/env python3
"""
SMT ADD-ON: CWE-190 Integer Overflow Reachability
==================================================
Extracts the arithmetic expression at a CodeQL sink and uses Z3
bitvector overflow predicates (BVAddNoOverflow / BVSubNoOverflow /
BVMulNoOverflow and their Underflow siblings) to decide whether
attacker input can wrap the expression past the fixed-width integer
boundary under the upstream guards extracted by smt_sanitizer.

Z3 is an OPTIONAL soft dependency.  If unavailable every function
returns an IntegerOverflowSMTResult with smt_available=False and
overflow_found=None — no existing behaviour changes.

Install: pip install z3-solver

Integration point (do not call from outside this location):
  - packages/codeql/dataflow_validator.py
    DataflowValidator.validate_dataflow_path()  -
    pre-pass alongside smt_sanitizer.analyze_sanitizers.

Scope (v1):
  - Binary +, -, * only.  No division / modulo / shifts.
  - Sink contexts: malloc/calloc/realloc size, memcpy/memmove/memset
    length, assignment to a declared integer variable.
  - Operands: bare identifiers, integer literals (dec/hex), and
    sizeof(TYPE) (modeled as a small unknown positive constant).
  - C/C++ only.  Python arbitrary-precision ints are out of scope.
  - Width/signedness inferred from a declared type when available;
    otherwise falls back to RAPTOR_SMT_WIDTH / RAPTOR_SMT_SIGNED.

Attestation - Written by Claude, prompted by Mark C.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import z3
    _Z3_Around = True
except ImportError:
    _Z3_Around = False

# Reuse the shared bitvector configuration and pattern extractor from
# smt_sanitizer so guard extraction stays identical across the two passes.
from .smt_sanitizer import (
    _smt_enabled,
    _bv_width,
    _is_signed,
    _mode_tag,
    _extract_from_snippet,
)


# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------

@dataclass
class _ArithExpression:
    """A binary arithmetic expression extracted at a sink."""
    op: str                          # "+", "-", "*"
    lhs: str                         # operand token (variable | literal | sizeof(T))
    rhs: str
    context: str                     # "malloc", "calloc", "realloc", "memcpy", "assign", "other"
    snippet: str                     # truncated original (<=120 chars)
    declared_type: Optional[str] = None   # e.g. "unsigned int", "size_t"
    width: Optional[int] = None           # inferred bitvector width
    signed: Optional[bool] = None         # inferred signedness


@dataclass
class IntegerOverflowSMTResult:
    """Result of SMT-based integer overflow analysis."""
    overflow_found: Optional[bool]                # True/False/None (None = z3 unavailable / nothing modeled)
    overflow_input: Optional[Dict[str, int]]      # concrete operand values that trigger overflow
    operation: Optional[str]                      # "+", "-", "*" of the first overflowing expression
    contexts: List[str]                           # sink contexts of overflowing expressions
    overflowing_expressions: List[str]            # snippets proven SAT
    safe_expressions: List[str]                   # snippets proven UNSAT (overflow not reachable)
    unparsed_sinks: List[str]                     # sink snippets with no extractable arithmetic
    smt_available: bool
    reasoning: str                                # human-readable summary (injected into LLM prompt)


# ---------------------------------------------------------------------------
# Type -> (width, signed) inference
# ---------------------------------------------------------------------------
# LP64 assumption (Linux / macOS): long == 64-bit.  This matches CodeQL's
# default C analysis target; Windows LLP64 is out of scope for v1.

_TYPE_WIDTH_HINTS: Dict[str, Tuple[int, bool]] = {
    "char":                (8,  True),
    "signed char":         (8,  True),
    "unsigned char":       (8,  False),
    "short":               (16, True),
    "unsigned short":      (16, False),
    "int":                 (32, True),
    "signed":              (32, True),
    "unsigned":            (32, False),
    "unsigned int":        (32, False),
    "signed int":          (32, True),
    "long":                (64, True),
    "unsigned long":       (64, False),
    "long long":           (64, True),
    "unsigned long long":  (64, False),
    "size_t":              (64, False),
    "ssize_t":             (64, True),
    "ptrdiff_t":           (64, True),
    "int8_t":   (8,  True),  "uint8_t":  (8,  False),
    "int16_t":  (16, True),  "uint16_t": (16, False),
    "int32_t":  (32, True),  "uint32_t": (32, False),
    "int64_t":  (64, True),  "uint64_t": (64, False),
}

# Call sites whose size argument defaults to size_t when no explicit type seen.
_SIZE_T_SINKS = {"malloc", "calloc", "realloc", "memcpy", "memmove", "memset"}


# ---------------------------------------------------------------------------
# Regex infrastructure
# ---------------------------------------------------------------------------
# Operand: bare identifier, decimal literal, hex literal, or sizeof(TYPE).
_TERM = r'(?:[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+|sizeof\s*\(\s*\w+\s*\))'
_OP = r'([+\-*])'
_BIN = rf'({_TERM})\s*{_OP}\s*({_TERM})'

# An integer type word sequence like "unsigned long long" / "uint32_t" / "size_t".
_INT_TYPE = (
    r'(?:unsigned\s+long\s+long|signed\s+long\s+long|long\s+long|'
    r'unsigned\s+long|signed\s+long|long|'
    r'unsigned\s+int|signed\s+int|unsigned|signed|int|short|char|'
    r'u?int(?:8|16|32|64)_t|s?size_t|ptrdiff_t)'
)

_SINK_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # malloc(EXPR)
    (re.compile(rf'\b(malloc|realloc)\s*\([^,()]*?{_BIN}[^,()]*?\)'), "malloc"),
    # calloc(EXPR, _) or calloc(_, EXPR)
    (re.compile(rf'\bcalloc\s*\(\s*{_BIN}\s*,'), "calloc"),
    (re.compile(rf'\bcalloc\s*\([^,()]*,\s*{_BIN}\s*\)'), "calloc"),
    # memcpy/memmove/memset(_, _, EXPR)
    (re.compile(rf'\b(memcpy|memmove|memset)\s*\([^,()]*,[^,()]*,\s*{_BIN}\s*\)'), "memcpy"),
    # Declared-int assignment: "<TYPE> name = EXPR;"
    (re.compile(rf'\b({_INT_TYPE})\s+\w+\s*=\s*{_BIN}\s*;'), "assign"),
]


def _extract_arith_from_snippet(snippet: str) -> List[_ArithExpression]:
    """Extract binary arithmetic at recognised sinks from a single snippet."""
    if not snippet:
        return []

    out: List[_ArithExpression] = []
    seen: set = set()
    trunc = snippet[:120]

    for pat, ctx in _SINK_PATTERNS:
        for m in pat.finditer(snippet):
            groups = m.groups()
            declared_type = None
            # Groups shape varies by pattern.  All _BIN groups are the last 3.
            lhs, op, rhs = groups[-3], groups[-2], groups[-1]
            if ctx == "assign":
                declared_type = groups[0].strip()
            elif ctx in ("malloc",) and len(groups) >= 4:
                # First group is the function name ("malloc"|"realloc"),
                # but we already labelled ctx as "malloc".
                pass
            elif ctx == "memcpy" and len(groups) >= 4:
                pass  # first group is function name

            key = (ctx, lhs, op, rhs, declared_type)
            if key in seen:
                continue
            seen.add(key)

            width = signed = None
            if declared_type:
                hint = _TYPE_WIDTH_HINTS.get(declared_type.lower().strip())
                if hint:
                    width, signed = hint
            elif ctx in ("malloc", "calloc", "realloc", "memcpy"):
                # size_t-context defaults (LP64)
                width, signed = 64, False

            out.append(_ArithExpression(
                op=op, lhs=lhs, rhs=rhs, context=ctx, snippet=trunc,
                declared_type=declared_type, width=width, signed=signed,
            ))

    return out


# ---------------------------------------------------------------------------
# Operand handling
# ---------------------------------------------------------------------------

_SIZEOF_RE = re.compile(r'sizeof\s*\(\s*(\w+)\s*\)')
_HEX_RE = re.compile(r'0[xX][0-9a-fA-F]+')
_DEC_RE = re.compile(r'\d+')
_IDENT_RE = re.compile(r'[A-Za-z_]\w*')


def _operand_to_z3(
    tok: str,
    vars_: Dict[str, Any],
    implicit: List[Any],
    width: int,
) -> Optional[Any]:
    """
    Convert a single operand token to a Z3 BitVec(width) expression.

    sizeof(T) is modeled as a fresh unsigned variable constrained to
    [1, 2**16] — a conservative upper bound covering realistic C types.
    """
    tok = tok.strip()

    m = _SIZEOF_RE.fullmatch(tok)
    if m:
        name = f"_sizeof_{m.group(1)}"
        if name not in vars_:
            v = z3.BitVec(name, width)
            vars_[name] = v
            implicit.append(z3.UGE(v, z3.BitVecVal(1, width)))
            implicit.append(z3.ULE(v, z3.BitVecVal(1 << 16, width)))
        return vars_[name]

    if _HEX_RE.fullmatch(tok):
        return z3.BitVecVal(int(tok, 16), width)

    if _DEC_RE.fullmatch(tok):
        return z3.BitVecVal(int(tok), width)

    if _IDENT_RE.fullmatch(tok):
        if tok not in vars_:
            vars_[tok] = z3.BitVec(tok, width)
        return vars_[tok]

    return None


# ---------------------------------------------------------------------------
# Overflow query and guard-constraint builder (width-parametric)
# ---------------------------------------------------------------------------

def _overflow_condition(
    lhs: Any, rhs: Any, op: str, signed: bool,
) -> Optional[Any]:
    """Return a Z3 expression asserting op(lhs, rhs) overflows or underflows."""
    if op == "+":
        if signed:
            return z3.Or(
                z3.Not(z3.BVAddNoOverflow(lhs, rhs, True)),
                z3.Not(z3.BVAddNoUnderflow(lhs, rhs)),
            )
        return z3.Not(z3.BVAddNoOverflow(lhs, rhs, False))

    if op == "-":
        if signed:
            return z3.Or(
                z3.Not(z3.BVSubNoOverflow(lhs, rhs)),
                z3.Not(z3.BVSubNoUnderflow(lhs, rhs, True)),
            )
        return z3.Not(z3.BVSubNoUnderflow(lhs, rhs, False))

    if op == "*":
        if signed:
            return z3.Or(
                z3.Not(z3.BVMulNoOverflow(lhs, rhs, True)),
                z3.Not(z3.BVMulNoUnderflow(lhs, rhs)),
            )
        return z3.Not(z3.BVMulNoOverflow(lhs, rhs, False))

    return None


def _guard_to_z3(
    c: Any,               # smt_sanitizer._Constraint (typed Any to dodge private import)
    vars_: Dict[str, Any],
    width: int,
    signed: bool,
) -> Optional[Any]:
    """Width-parametric version of smt_sanitizer._constraint_to_bypass_z3.

    The overflow-session may run at a width that differs from the global
    RAPTOR_SMT_WIDTH (e.g., a declared ``unsigned int`` sink at bv32
    while the sanitizer pre-pass used bv64), so we re-encode guards here
    at the session's width rather than reusing the global helper.
    """
    if c.variable not in vars_:
        vars_[c.variable] = z3.BitVec(c.variable, width)
    v = vars_[c.variable]

    def le(a, b): return a <= b if signed else z3.ULE(a, b)
    def lt(a, b): return a < b if signed else z3.ULT(a, b)
    def ge(a, b): return a >= b if signed else z3.UGE(a, b)

    if c.guard_type == "upper_bound":
        return le(v, z3.BitVecVal(c.bound, width))
    if c.guard_type == "lower_bound":
        return ge(v, z3.BitVecVal(c.bound, width))
    if c.guard_type == "null":
        return v != z3.BitVecVal(0, width)
    if c.guard_type == "range":
        return z3.And(
            ge(v, z3.BitVecVal(0, width)),
            lt(v, z3.BitVecVal(c.bound_hi, width)),
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SOLVER_TIMEOUT_MS = 5000


def _format_witness(
    model: Any,
    width_by_var: Dict[str, int],
    signed: bool,
) -> Dict[str, int]:
    """Render a Z3 model as a dict[var -> python int]."""
    out: Dict[str, int] = {}
    for decl in model.decls():
        val = model[decl]
        if not z3.is_bv_value(val):
            continue
        raw = val.as_long()
        w = val.size()
        if signed and w > 0 and raw >= (1 << (w - 1)):
            out[str(decl)] = raw - (1 << w)
        else:
            out[str(decl)] = raw
    return out


def analyze_integer_overflow(
    path: Any,            # DataflowPath; typed Any to avoid import cycle
    repo_path: Path,
) -> IntegerOverflowSMTResult:
    """
    Analyze whether the arithmetic at a CodeQL sink can overflow under
    upstream guards.

    Operates on ``path.sink.snippet`` (primary) and falls back to the
    last intermediate step when the sink snippet is empty — CodeQL
    sometimes places the arithmetic on the final hop.

    Guard constraints are extracted from all intermediate steps and the
    source snippet, using the same regex battery as smt_sanitizer.

    Returns:
        IntegerOverflowSMTResult.  overflow_found=None when z3 is
        unavailable, when no arithmetic could be extracted, or when
        every expression returned ``unknown`` from the solver.
    """
    # ---- availability gate
    if not _smt_enabled():
        return IntegerOverflowSMTResult(
            overflow_found=None, overflow_input=None,
            operation=None, contexts=[],
            overflowing_expressions=[], safe_expressions=[],
            unparsed_sinks=[],
            smt_available=False,
            reasoning="z3 not available - install z3-solver for integer overflow analysis",
        )

    # ---- collect sink candidate snippets
    sink_snips: List[str] = []
    if getattr(path, "sink", None) and path.sink.snippet:
        sink_snips.append(path.sink.snippet)
    if not sink_snips and path.intermediate_steps:
        last = path.intermediate_steps[-1]
        if last.snippet:
            sink_snips.append(last.snippet)

    # ---- extract arithmetic expressions at those sinks
    arith: List[_ArithExpression] = []
    unparsed: List[str] = []
    for snip in sink_snips:
        found = _extract_arith_from_snippet(snip)
        if found:
            arith.extend(found)
        else:
            unparsed.append(snip.strip()[:120])

    if not arith:
        return IntegerOverflowSMTResult(
            overflow_found=None, overflow_input=None,
            operation=None, contexts=[],
            overflowing_expressions=[], safe_expressions=[],
            unparsed_sinks=unparsed,
            smt_available=True,
            reasoning="no modellable binary arithmetic found at sink",
        )

    # ---- collect guard constraints from the rest of the path
    guard_snips: List[str] = []
    for step in path.intermediate_steps:
        if step.snippet:
            guard_snips.append(step.snippet)
    if getattr(path, "source", None) and path.source.snippet:
        guard_snips.append(path.source.snippet)

    guard_constraints: List[Any] = []
    for snip in guard_snips:
        guard_constraints.extend(_extract_from_snippet(snip))

    # ---- solve each arithmetic expression independently
    overflowing: List[str] = []
    safe: List[str] = []
    witness: Optional[Dict[str, int]] = None
    witness_op: Optional[str] = None
    witness_contexts: List[str] = []
    witness_mode: Optional[str] = None       # per-expression bvW-signed|unsigned tag
    safe_mode: Optional[str] = None          # first safe expression's mode (for unsat reasoning)
    unknown_count = 0

    default_width = _bv_width()
    default_signed = _is_signed()

    def _tag(w: int, s: bool) -> str:
        return f"bv{w}-{'signed' if s else 'unsigned'}"

    for expr in arith:
        width = expr.width if expr.width is not None else default_width
        signed = expr.signed if expr.signed is not None else default_signed

        vars_: Dict[str, Any] = {}
        implicit: List[Any] = []

        lhs_z = _operand_to_z3(expr.lhs, vars_, implicit, width)
        rhs_z = _operand_to_z3(expr.rhs, vars_, implicit, width)
        if lhs_z is None or rhs_z is None:
            unparsed.append(expr.snippet)
            continue

        query = _overflow_condition(lhs_z, rhs_z, expr.op, signed)
        if query is None:
            unparsed.append(expr.snippet)
            continue

        solver = z3.Solver()
        solver.set("timeout", _SOLVER_TIMEOUT_MS)
        for clause in implicit:
            solver.add(clause)
        for c in guard_constraints:
            if c.variable in vars_:
                g = _guard_to_z3(c, vars_, width, signed)
                if g is not None:
                    solver.add(g)
        solver.add(query)

        result = solver.check()

        if result == z3.sat:
            overflowing.append(expr.snippet)
            if witness is None:
                model = solver.model()
                wmap: Dict[str, int] = {}
                for v_name, v_obj in vars_.items():
                    val = model.eval(v_obj, model_completion=True)
                    if z3.is_bv_value(val):
                        raw = val.as_long()
                        w = val.size()
                        if signed and w > 0 and raw >= (1 << (w - 1)):
                            wmap[v_name] = raw - (1 << w)
                        else:
                            wmap[v_name] = raw
                witness = wmap or None
                witness_op = expr.op
                witness_contexts = [expr.context]
                witness_mode = _tag(width, signed)
            else:
                if expr.context not in witness_contexts:
                    witness_contexts.append(expr.context)
        elif result == z3.unsat:
            safe.append(expr.snippet)
            if safe_mode is None:
                safe_mode = _tag(width, signed)
        else:
            unknown_count += 1
            unparsed.append(expr.snippet)

    # ---- aggregate verdict
    if overflowing:
        reasoning = (
            f"SMT overflow reachable ({witness_mode}): "
            f"{len(overflowing)} arithmetic expression(s) at sink can wrap; "
            f"first witness {witness_op!r} in {witness_contexts} with input {witness}"
        )
        if safe:
            reasoning += f"; {len(safe)} expression(s) proven safe"
        if unparsed:
            reasoning += f"; {len(unparsed)} sink snippet(s) not modeled"
        return IntegerOverflowSMTResult(
            overflow_found=True,
            overflow_input=witness,
            operation=witness_op,
            contexts=witness_contexts,
            overflowing_expressions=overflowing,
            safe_expressions=safe,
            unparsed_sinks=unparsed,
            smt_available=True,
            reasoning=reasoning,
        )

    if safe and unknown_count == 0:
        return IntegerOverflowSMTResult(
            overflow_found=False,
            overflow_input=None,
            operation=None,
            contexts=[],
            overflowing_expressions=[],
            safe_expressions=safe,
            unparsed_sinks=unparsed,
            smt_available=True,
            reasoning=(
                f"SMT proves no overflow reachable ({safe_mode}): "
                f"{len(safe)} arithmetic expression(s) at sink cannot wrap under modeled guards"
                + (f"; {len(unparsed)} sink snippet(s) not modeled" if unparsed else "")
            ),
        )

    return IntegerOverflowSMTResult(
        overflow_found=None,
        overflow_input=None,
        operation=None,
        contexts=[],
        overflowing_expressions=[],
        safe_expressions=safe,
        unparsed_sinks=unparsed,
        smt_available=True,
        reasoning=(
            f"SMT inconclusive (default {_mode_tag()}): "
            f"{unknown_count} unknown / {len(unparsed)} unmodeled sink snippet(s)"
        ),
    )
