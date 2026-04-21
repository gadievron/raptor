#!/usr/bin/env python3
"""
SMT ADD-ON: Dataflow Sanitizer Bypass Analyzer
===============================================
Extracts constraint patterns from source code snippets embedded in CodeQL
dataflow paths and uses Z3 to determine whether all sanitizers can be
simultaneously bypassed by a single attacker-controlled input.

Handles C/C++ and Python guard patterns.  Anything outside the supported
subset is reported as unparsed - the LLM in DataflowValidator still handles
those cases unchanged.

Z3 is an OPTIONAL soft dependency, gated through ``core.smt_solver``.  If
unavailable every function returns a SanitizerSMTResult with
smt_available=False and bypass_found=None - no existing behaviour changes.

Install: pip install z3-solver

Variables are modeled as fixed-width bitvectors (default 64-bit signed) so
that integer overflow, wrap-around, and signed/unsigned comparison
mismatches in C/C++ sinks are handled correctly rather than silently
ignored (as the previous z3.Int model did).  Tunables:
  RAPTOR_SMT_WIDTH   - 32 or 64         (default 64)
  RAPTOR_SMT_SIGNED  - signed|unsigned  (default signed)

Integration point (do not call from outside this location):
  - packages/codeql/dataflow_validator.py
    DataflowValidator.validate_dataflow_path()  - pre-pass before LLM call

Usage from validate_dataflow_path():
    from .smt_sanitizer import analyze_sanitizers
    smt = analyze_sanitizers(dataflow, repo_path)
    # smt.reasoning is injected into the LLM prompt as additional context
    # If smt.bypass_found is False (proven effective), skip LLM sanitizer check

Attestation - Written by Claude, prompted by Mark C.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.smt_solver import (
    bv_width as _bv_width,
    ge as _ge,
    is_signed as _is_signed,
    le as _le,
    lt as _lt,
    mk_val as _mk_val,
    mk_var as _mk_var,
    mode_tag as _mode_tag,
    smt_enabled as _smt_enabled,
    z3,
)
from core.smt_solver.witness import format_witness as _format_witness

# DataflowPath is imported at function call time to avoid circular imports
# (this module is in the same package as dataflow_validator)


# ---------------------------------------------------------------------------
# Internal extracted constraint representation
# ---------------------------------------------------------------------------

@dataclass
class _Constraint:
    """A sanitizer guard extracted from a source snippet."""
    raw_snippet: str   # truncated original snippet (for reporting)
    variable: str      # inferred symbolic variable name
    guard_type: str    # "upper_bound", "lower_bound", "null", "non_null", "range"
    # For upper/lower bounds: the attacker must stay BELOW/ABOVE this to bypass
    bound: Optional[int] = None
    bound_hi: Optional[int] = None  # for "range" only (lower <= x < upper)


# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------
# Each entry: (compiled_regex, guard_type, notes)
# Capture groups must be: (var_or_bound, operator_or_None, bound_or_var)
# OR specialised tuples handled explicitly in _extract_from_snippet.

_C_REGEX: List[Tuple[re.Pattern, str]] = [
    # if (len > N)  /  if (len >= N)  - guard fires when too large
    (re.compile(r'if\s*\(\s*(\w+)\s*(>|>=)\s*(\d+)\s*\)', re.I), "c_upper"),
    # if (N < len)  /  if (N <= len)  - reversed form
    (re.compile(r'if\s*\(\s*(\d+)\s*(<|<=)\s*(\w+)\s*\)', re.I), "c_upper_rev"),
    # if (len < N)  /  if (len <= N)  - guard fires when too small
    (re.compile(r'if\s*\(\s*(\w+)\s*(<|<=)\s*(\d+)\s*\)', re.I), "c_lower"),
    # if (N > len)  /  if (N >= len)  - reversed form
    (re.compile(r'if\s*\(\s*(\d+)\s*(>|>=)\s*(\w+)\s*\)', re.I), "c_lower_rev"),
    # if (!ptr)  - null check, guard fires when null
    (re.compile(r'if\s*\(\s*!\s*(\w+)\s*\)', re.I), "c_null"),
    # if (ptr == NULL)  /  if (ptr == 0)
    (re.compile(r'if\s*\(\s*(\w+)\s*==\s*(?:NULL|0)\s*\)', re.I), "c_null"),
    # strlen(s) >= N  /  strlen(s) > N
    (re.compile(r'strlen\s*\(\s*(\w+)\s*\)\s*(>|>=)\s*(\d+)', re.I), "c_strlen_upper"),
    # strlen(s) < N  /  strlen(s) <= N
    (re.compile(r'strlen\s*\(\s*(\w+)\s*\)\s*(<|<=)\s*(\d+)', re.I), "c_strlen_lower"),
    # assert(size <= N)  /  assert(size < N)
    (re.compile(r'assert\s*\(\s*(\w+)\s*(<|<=)\s*(\d+)\s*\)', re.I), "c_lower"),
    # if (n < 0 || n > N)  - classic range guard
    (re.compile(r'if\s*\(\s*(\w+)\s*<\s*0\s*\|\|\s*\1\s*(>|>=)\s*(\d+)\s*\)', re.I), "c_range"),
]

_PY_REGEX: List[Tuple[re.Pattern, str]] = [
    # if len(x) > N:
    (re.compile(r'if\s+len\s*\(\s*(\w+)\s*\)\s*(>|>=)\s*(\d+)\s*:', re.I), "py_len_upper"),
    # if len(x) < N:
    (re.compile(r'if\s+len\s*\(\s*(\w+)\s*\)\s*(<|<=)\s*(\d+)\s*:', re.I), "py_len_lower"),
    # if x > N:
    (re.compile(r'if\s+(\w+)\s*(>|>=)\s*(\d+)\s*:', re.I), "py_upper"),
    # if N < x:  (reversed)
    (re.compile(r'if\s+(\d+)\s*(<|<=)\s*(\w+)\s*:', re.I), "py_upper_rev"),
    # if x < N:
    (re.compile(r'if\s+(\w+)\s*(<|<=)\s*(\d+)\s*:', re.I), "py_lower"),
    # if N > x:  (reversed)
    (re.compile(r'if\s+(\d+)\s*(>|>=)\s*(\w+)\s*:', re.I), "py_lower_rev"),
    # if not 0 <= x < N:
    (re.compile(r'if\s+not\s+0\s*<=\s*(\w+)\s*<\s*(\d+)\s*:', re.I), "py_range"),
    # if x is None:
    (re.compile(r'if\s+(\w+)\s+is\s+None\s*:', re.I), "py_null"),
    # if not x:
    (re.compile(r'if\s+not\s+(\w+)\s*:', re.I), "py_null"),
    # if x < 0 or x > N:
    (re.compile(r'if\s+(\w+)\s*<\s*0\s+or\s+\1\s*(>|>=)\s*(\d+)\s*:', re.I), "py_range"),
    # raise X if len(y) > N
    (re.compile(r'raise\s+\w+.*if\s+len\s*\(\s*(\w+)\s*\)\s*(>|>=)\s*(\d+)', re.I), "py_len_upper"),
]


def _detect_lang(snippet: str) -> str:
    """Heuristic language detection from a code snippet."""
    if re.search(r'if\s+\w', snippet) and snippet.rstrip().endswith(":"):
        return "python"
    if re.search(r'if\s*\(', snippet):
        return "c"
    # Fallback: Python uses 'is None', C uses 'NULL'
    if "is None" in snippet or "is not None" in snippet:
        return "python"
    return "c"


def _extract_from_snippet(snippet: str) -> List[_Constraint]:
    """Extract Z3-modelable constraint patterns from a single source snippet."""
    lang = _detect_lang(snippet)
    patterns = _PY_REGEX if lang == "python" else _C_REGEX
    results: List[_Constraint] = []
    seen: set = set()

    for pat, guard_type in patterns:
        for m in pat.finditer(snippet):
            g = m.groups()
            try:
                if guard_type in ("c_upper", "py_upper", "c_strlen_upper", "py_len_upper"):
                    var, op, bound_s = g[0], g[1], g[2]
                    bound = int(bound_s)
                    # bypass: var must be <= bound (for >) or < bound (for >=)
                    effective_bound = bound if op == ">" else bound - 1
                    key = (var, "upper", effective_bound)
                    if key not in seen:
                        seen.add(key)
                        results.append(_Constraint(snippet[:120], var, "upper_bound", effective_bound))

                elif guard_type in ("c_upper_rev", "py_upper_rev"):
                    # N < var  →  same as var > N
                    bound_s, op, var = g[0], g[1], g[2]
                    bound = int(bound_s)
                    effective_bound = bound if op == "<" else bound - 1
                    key = (var, "upper", effective_bound)
                    if key not in seen:
                        seen.add(key)
                        results.append(_Constraint(snippet[:120], var, "upper_bound", effective_bound))

                elif guard_type in ("c_lower", "py_lower", "c_strlen_lower", "py_len_lower"):
                    var, op, bound_s = g[0], g[1], g[2]
                    bound = int(bound_s)
                    effective_bound = bound if op == "<" else bound + 1
                    key = (var, "lower", effective_bound)
                    if key not in seen:
                        seen.add(key)
                        results.append(_Constraint(snippet[:120], var, "lower_bound", effective_bound))

                elif guard_type in ("c_lower_rev", "py_lower_rev"):
                    bound_s, op, var = g[0], g[1], g[2]
                    bound = int(bound_s)
                    effective_bound = bound if op == ">" else bound + 1
                    key = (var, "lower", effective_bound)
                    if key not in seen:
                        seen.add(key)
                        results.append(_Constraint(snippet[:120], var, "lower_bound", effective_bound))

                elif guard_type in ("c_null", "py_null"):
                    var = g[0]
                    key = (var, "null")
                    if key not in seen:
                        seen.add(key)
                        results.append(_Constraint(snippet[:120], var, "null"))

                elif guard_type in ("c_range", "py_range"):
                    if len(g) == 3:
                        var, op, bound_s = g[0], g[1], g[2]
                    else:
                        var, bound_s = g[0], g[1]
                        op = "<"
                    bound = int(bound_s)
                    key = (var, "range", bound)
                    if key not in seen:
                        seen.add(key)
                        results.append(_Constraint(snippet[:120], var, "range",
                                                   bound=0, bound_hi=bound))

            except (ValueError, IndexError):
                continue

    return results


def _constraint_to_bypass_z3(c: _Constraint, vars_: Dict[str, Any]) -> Optional[Any]:
    """
    Return a Z3 expression representing the BYPASS condition for a sanitizer guard.

    The guard fires (and rejects input) when its condition is True.
    Bypass = the guard's condition is False = attacker passes through.

    Variables are modeled as fixed-width bitvectors (see core.smt_solver) so
    that wrap-around and signed/unsigned coercion match C/C++ integer
    semantics.

    Example:
        Guard: if (len > 100) return error;
        Bypass: len <= 100  →  z3: BitVec('len', 64) <= 100  (signed compare)
    """
    if c.variable not in vars_:
        vars_[c.variable] = _mk_var(c.variable)
    v = vars_[c.variable]

    if c.guard_type == "upper_bound":
        # Guard fires when v > bound; bypass when v <= bound
        return _le(v, _mk_val(c.bound))
    elif c.guard_type == "lower_bound":
        # Guard fires when v < bound; bypass when v >= bound
        return _ge(v, _mk_val(c.bound))
    elif c.guard_type == "null":
        # Guard fires when v is null/falsy; bypass when v != 0
        return v != _mk_val(0)
    elif c.guard_type == "range":
        # Guard fires when v < 0 or v >= bound_hi; bypass when 0 <= v < bound_hi.
        # Under unsigned mode the "v >= 0" clause is trivially true and the
        # upper bound carries all the information, which is the correct
        # semantics for size_t-typed inputs.
        return z3.And(_ge(v, _mk_val(0)), _lt(v, _mk_val(c.bound_hi)))
    return None


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class SanitizerSMTResult:
    """Result of SMT-based sanitizer bypass analysis."""
    bypass_found: Optional[bool]           # True/False/None (None = z3 unavailable / no patterns)
    bypass_input: Optional[Dict[str, int]] # concrete bypass variable assignments if found
    effective_sanitizers: List[str]        # snippets proven to individually block bypass
    bypassable_sanitizers: List[str]       # snippets with at least one individual bypass
    unparsed_sanitizers: List[str]         # snippets with no Z3-modelable patterns
    smt_available: bool
    reasoning: str                         # human-readable summary (injected into LLM prompt)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_sanitizers(
    path: Any,        # DataflowPath - typed as Any to avoid import cycle
    repo_path: Path,
) -> SanitizerSMTResult:
    """
    Analyze whether the sanitizers in a CodeQL dataflow path can all be bypassed.

    Extracts constraint patterns from intermediate step snippets (C/C++ and Python),
    models each guard as a Z3 integer constraint, and checks joint satisfiability of
    all bypass conditions.  If a satisfying assignment exists, returns it as
    bypass_input for injection into the LLM validation prompt.

    Snippets with no recognisable constraint patterns are reported as unparsed and
    handled by the LLM as before.

    Args:
        path:      DataflowPath from
                    DataflowValidator.extract_dataflow_from_sarif().
        repo_path: Repository root (unused currently; reserved
                    for future source reads).

    Returns:
        SanitizerSMTResult.  bypass_found=None when z3 unavailable or no patterns found.
    """
    if not _smt_enabled():
        all_snippets = [s.snippet for s in path.intermediate_steps if s.snippet]
        return SanitizerSMTResult(
            bypass_found=None, bypass_input=None,
            effective_sanitizers=[], bypassable_sanitizers=[],
            unparsed_sanitizers=all_snippets,
            smt_available=False,
            reasoning="z3 not available - install z3-solver for sanitizer analysis",
        )

    # Collect snippets: intermediate steps are the primary sanitizer locations;
    # include source snippet too (sometimes guards appear right at source)
    snippets = [s.snippet for s in path.intermediate_steps if s.snippet]
    if path.source.snippet:
        snippets.append(path.source.snippet)

    if not snippets:
        return SanitizerSMTResult(
            bypass_found=None, bypass_input=None,
            effective_sanitizers=[], bypassable_sanitizers=[],
            unparsed_sanitizers=[],
            smt_available=True,
            reasoning="no source snippets available in dataflow path",
        )

    all_constraints: List[_Constraint] = []
    unparsed: List[str] = []

    for snip in snippets:
        extracted = _extract_from_snippet(snip)
        if extracted:
            all_constraints.extend(extracted)
        else:
            unparsed.append(snip.strip()[:120])

    if not all_constraints:
        return SanitizerSMTResult(
            bypass_found=None, bypass_input=None,
            effective_sanitizers=[], bypassable_sanitizers=[],
            unparsed_sanitizers=unparsed,
            smt_available=True,
            reasoning="no Z3-modelable constraint patterns found in dataflow snippets",
        )

    vars_: Dict[str, Any] = {}
    bypass_pairs: List[Tuple[_Constraint, Any]] = []
    local_unparsed: List[str] = []

    for c in all_constraints:
        expr = _constraint_to_bypass_z3(c, vars_)
        if expr is None:
            local_unparsed.append(c.raw_snippet)
        else:
            bypass_pairs.append((c, expr))

    if not bypass_pairs:
        return SanitizerSMTResult(
            bypass_found=None, bypass_input=None,
            effective_sanitizers=[], bypassable_sanitizers=[],
            unparsed_sanitizers=unparsed + local_unparsed,
            smt_available=True,
            reasoning="patterns extracted but none could be converted to Z3 expressions",
        )

    # Classify each sanitizer individually before the joint check
    effective:   List[str] = []
    bypassable:  List[str] = []
    for c, expr in bypass_pairs:
        s = z3.Solver()
        s.add(expr)
        if s.check() == z3.unsat:
            effective.append(c.raw_snippet)
        else:
            bypassable.append(c.raw_snippet)

    # Joint satisfiability: can ALL guards be bypassed at the same time?
    joint = z3.Solver()
    for _, expr in bypass_pairs:
        joint.add(expr)

    result = joint.check()

    if result == z3.sat:
        bypass_vals = _format_witness(joint.model(), signed=_is_signed())

        return SanitizerSMTResult(
            bypass_found=True,
            bypass_input=bypass_vals or None,
            effective_sanitizers=effective,
            bypassable_sanitizers=bypassable,
            unparsed_sanitizers=unparsed + local_unparsed,
            smt_available=True,
            reasoning=(
                f"SMT bypass found ({_mode_tag()}): all {len(bypass_pairs)} modeled sanitizer(s) can be bypassed "
                f"simultaneously with input {bypass_vals}"
                + (f"; {len(unparsed + local_unparsed)} snippet(s) not modeled by SMT" if unparsed or local_unparsed else "")
            ),
        )

    elif result == z3.unsat:
        return SanitizerSMTResult(
            bypass_found=False,
            bypass_input=None,
            effective_sanitizers=[c.raw_snippet for c, _ in bypass_pairs],
            bypassable_sanitizers=[],
            unparsed_sanitizers=unparsed + local_unparsed,
            smt_available=True,
            reasoning=(
                f"SMT proves sanitizers effective ({_mode_tag()}): modeled constraints cannot all be bypassed "
                f"simultaneously ({len(bypass_pairs)} checked)"
                + (f"; {len(unparsed + local_unparsed)} snippet(s) not modeled - LLM should verify those" if unparsed or local_unparsed else "")
            ),
        )

    else:
        return SanitizerSMTResult(
            bypass_found=None,
            bypass_input=None,
            effective_sanitizers=[],
            bypassable_sanitizers=[],
            unparsed_sanitizers=unparsed + local_unparsed + [c.raw_snippet for c, _ in bypass_pairs],
            smt_available=True,
            reasoning=f"Z3 returned unknown for joint satisfiability check ({_mode_tag()})",
        )
