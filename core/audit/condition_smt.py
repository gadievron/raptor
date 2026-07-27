"""Constant-to-SMT bridge for guard sufficiency.

Bridges the concrete_values extracted by condition_extraction (Layer 0/2)
into Z3 SMT queries via the existing path_feasibility infrastructure.

Answers: "Given this guard checks `len < MAX_SIZE` where MAX_SIZE=1024,
and the sink is memcpy(dst, src, len) where dst is 256 bytes, is the
guard sufficient to prevent overflow?"

The key insight from the CPG paper: once you have CONCRETE values from
constant resolution, you can PROVE guard insufficiency mechanically.
A guard `if (n < 4096)` doesn't prevent overflow into a 256-byte buffer.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .condition_extraction import GuardCondition, SinkGuard

logger = logging.getLogger(__name__)


@dataclass
class SmtSufficiencyResult:
    """Result of SMT check on guard sufficiency."""

    guard_text: str
    feasible: Optional[bool] = None  # True=guard insufficient, False=guard sufficient
    reasoning: str = ""
    concrete_values: Dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def guard_sufficient(self) -> Optional[bool]:
        """True if the guard provably prevents the bug."""
        if self.feasible is None:
            return None
        return not self.feasible  # infeasible overflow = sufficient guard

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "guard_text": self.guard_text,
            "reasoning": self.reasoning,
        }
        if self.feasible is not None:
            d["feasible"] = self.feasible
            d["guard_sufficient"] = self.guard_sufficient
        if self.concrete_values:
            d["concrete_values"] = self.concrete_values
        if self.error:
            d["error"] = self.error
        return d


# ---------------------------------------------------------------------------
# Comparison extraction
# ---------------------------------------------------------------------------

# Matches comparisons: var <op> value, value <op> var
_COMPARISON_RE = re.compile(
    r"([a-zA-Z_]\w*(?:\.\w+)*)\s*(==|!=|<=|>=|<|>)\s*"
    r"([a-zA-Z_]\w*(?:\.\w+)*|0x[0-9a-fA-F]+|\d+(?:\.\d+)?)",
)

# Reverse comparisons: value <op> var
_COMPARISON_REV_RE = re.compile(
    r"(0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\s*(==|!=|<=|>=|<|>)\s*"
    r"([a-zA-Z_]\w*(?:\.\w+)*)",
)


@dataclass
class BoundsConstraint:
    """A concrete bounds constraint extracted from a guard."""
    variable: str
    operator: str  # <, <=, >, >=, ==, !=
    bound_value: int
    source_text: str = ""


def extract_bounds_constraints(
    guard: GuardCondition,
) -> List[BoundsConstraint]:
    """Extract numeric bounds constraints from a guard condition.

    Uses concrete_values when available for constant resolution.
    """
    constraints: List[BoundsConstraint] = []
    text = guard.text

    # Resolve constants in the text
    resolved_text = text
    for name, value in sorted(guard.concrete_values.items(), key=lambda kv: -len(kv[0])):
        resolved_text = re.sub(r'\b' + re.escape(name) + r'\b', value, resolved_text)

    # Forward: var op value
    for m in _COMPARISON_RE.finditer(resolved_text):
        var, op, val_str = m.group(1), m.group(2), m.group(3)
        val = _try_parse_int(val_str)
        if val is not None:
            constraints.append(BoundsConstraint(
                variable=var, operator=op, bound_value=val,
                source_text=m.group(0),
            ))

    # Reverse: value op var → flip operator
    for m in _COMPARISON_REV_RE.finditer(resolved_text):
        val_str, op, var = m.group(1), m.group(2), m.group(3)
        val = _try_parse_int(val_str)
        if val is not None:
            flipped_op = _flip_operator(op)
            if flipped_op:
                constraints.append(BoundsConstraint(
                    variable=var, operator=flipped_op, bound_value=val,
                    source_text=m.group(0),
                ))

    return constraints


def _try_parse_int(s: str) -> Optional[int]:
    """Try to parse an integer from string (decimal or hex)."""
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _flip_operator(op: str) -> Optional[str]:
    """Flip a comparison operator for reversed operands."""
    flips = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
    return flips.get(op)


# ---------------------------------------------------------------------------
# SMT sufficiency check
# ---------------------------------------------------------------------------


def check_guard_sufficiency(
    sink_guard: SinkGuard,
    *,
    buffer_size: Optional[int] = None,
    sink_context: Optional[Dict[str, Any]] = None,
) -> List[SmtSufficiencyResult]:
    """Check whether guard conditions are sufficient via SMT.

    For each resolvable guard with concrete values, formulates a query:
    "Can the constrained variable still violate the safety property?"

    Args:
        sink_guard: The guard set to check.
        buffer_size: Known buffer size for overflow sinks (from allocation).
        sink_context: Additional context (e.g., from annotations).

    Returns:
        List of SMT results, one per resolvable guard.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    results: List[SmtSufficiencyResult] = []

    for guard in sink_guard.guards:
        if not guard.resolvable or not guard.concrete_values:
            continue

        constraints = extract_bounds_constraints(guard)
        if not constraints:
            continue

        result = _check_constraints_vs_safety(
            constraints=constraints,
            guard=guard,
            buffer_size=buffer_size,
            sink_api=sink_guard.sink_api,
            sink_context=sink_context,
        )
        results.append(result)

    return results


def _check_constraints_vs_safety(
    constraints: List[BoundsConstraint],
    guard: GuardCondition,
    buffer_size: Optional[int],
    sink_api: str,
    sink_context: Optional[Dict[str, Any]],
) -> SmtSufficiencyResult:
    """Check if constraints are sufficient for the safety property.

    For buffer overflow sinks: can the constrained length still exceed
    the buffer size?
    """
    # Try Z3 first
    z3_result = _try_z3_check(constraints, buffer_size, sink_api)
    if z3_result is not None:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=z3_result[0],
            reasoning=z3_result[1],
            concrete_values=guard.concrete_values,
        )

    # Fallback: simple arithmetic reasoning
    return _arithmetic_check(constraints, guard, buffer_size, sink_api)


def _try_z3_check(
    constraints: List[BoundsConstraint],
    buffer_size: Optional[int],
    sink_api: str,
) -> Optional[Tuple[bool, str]]:
    """Try Z3 SMT check. Returns None if Z3 unavailable."""
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    # Memory copy sinks: check if constrained length can exceed buffer
    memcpy_sinks = {
        "memcpy", "memmove", "strncpy", "strncat", "bcopy",
        "copy_from_user", "copy_to_user", "wmemcpy",
        "CopyMemory", "RtlCopyMemory",
    }
    alloc_sinks = {
        "malloc", "calloc", "realloc", "kmalloc", "kzalloc",
    }

    api_base = sink_api.split(".")[-1] if "." in sink_api else sink_api

    if api_base in memcpy_sinks and buffer_size is not None:
        return _z3_overflow_check(constraints, buffer_size)
    elif api_base in alloc_sinks:
        return _z3_integer_overflow_check(constraints)

    # Generic: check if constraints are internally consistent
    return _z3_consistency_check(constraints)


def _z3_overflow_check(
    constraints: List[BoundsConstraint],
    buffer_size: int,
) -> Tuple[bool, str]:
    """Z3: Can length still overflow given the guard constraints?"""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)

    # Create variables for each constraint's subject
    vars_map: Dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    # Add guard constraints
    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    # Ask: can any constrained variable exceed buffer_size?
    for v in vars_map.values():
        solver.push()
        solver.add(v > buffer_size)
        solver.add(v >= 0)  # lengths are non-negative
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            val = model[v]
            solver.pop()
            return (True, f"overflow possible: {v} can be {val} > {buffer_size}")
        solver.pop()

    return (False, f"guard sufficient: all constrained vars ≤ {buffer_size}")


def _z3_integer_overflow_check(
    constraints: List[BoundsConstraint],
) -> Tuple[bool, str]:
    """Z3: Can an allocation size integer-overflow given the constraints?"""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)

    vars_map: Dict[str, z3.BitVecRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.BitVec(c.variable, 64)

    for c in constraints:
        v = vars_map[c.variable]
        bv_val = z3.BitVecVal(c.bound_value, 64)
        if c.operator == "<":
            solver.add(z3.ULT(v, bv_val))
        elif c.operator == "<=":
            solver.add(z3.ULE(v, bv_val))
        elif c.operator == ">":
            solver.add(z3.UGT(v, bv_val))
        elif c.operator == ">=":
            solver.add(z3.UGE(v, bv_val))
        elif c.operator == "==":
            solver.add(v == bv_val)
        elif c.operator == "!=":
            solver.add(v != bv_val)

    # Check: can multiplication of any two constrained vars wrap?
    var_list = list(vars_map.values())
    if len(var_list) >= 2:
        for i in range(len(var_list)):
            for j in range(i + 1, len(var_list)):
                a, b = var_list[i], var_list[j]
                solver.push()
                # Overflow: upper 64 bits of 128-bit product are non-zero
                a_ext = z3.ZeroExt(64, a)
                b_ext = z3.ZeroExt(64, b)
                full_product = a_ext * b_ext
                upper_bits = z3.Extract(127, 64, full_product)
                solver.add(upper_bits != z3.BitVecVal(0, 64))

                result = solver.check()
                solver.pop()
                if result == z3.sat:
                    return (True, "integer overflow in allocation size is possible")
        return (False, "allocation size cannot overflow given constraints")

    return (False, "insufficient variables for multiplication overflow check")


def _z3_consistency_check(
    constraints: List[BoundsConstraint],
) -> Tuple[bool, str]:
    """Z3: Are the constraints internally consistent?"""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)

    vars_map: Dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    result = solver.check()
    if result == z3.sat:
        return (True, "constraints are satisfiable (guard does not block all paths)")
    elif result == z3.unsat:
        return (False, "constraints are unsatisfiable (guard blocks all paths)")
    else:
        return (True, "solver timeout — conservatively assume insufficient")


def _arithmetic_check(
    constraints: List[BoundsConstraint],
    guard: GuardCondition,
    buffer_size: Optional[int],
    sink_api: str,
) -> SmtSufficiencyResult:
    """Simple arithmetic reasoning when Z3 is unavailable.

    For `len < MAX_SIZE` where MAX_SIZE=4096 and buffer=256:
    The guard allows len up to 4095, but buffer is only 256 → insufficient.

    When multiple upper-bound constraints exist (conjunctive guard),
    the tightest (minimum max_allowed) determines sufficiency.
    """
    if buffer_size is None:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=None,
            reasoning="no buffer size known for arithmetic check",
            concrete_values=guard.concrete_values,
        )

    tightest_max: Optional[int] = None
    tightest_var: str = ""

    for c in constraints:
        max_allowed: Optional[int] = None
        if c.operator == "<":
            max_allowed = c.bound_value - 1
        elif c.operator == "<=":
            max_allowed = c.bound_value

        if max_allowed is not None:
            if tightest_max is None or max_allowed < tightest_max:
                tightest_max = max_allowed
                tightest_var = c.variable

    if tightest_max is None:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=None,
            reasoning="no upper-bound constraint found for arithmetic check",
            concrete_values=guard.concrete_values,
        )

    if tightest_max > buffer_size:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=True,
            reasoning=(
                f"guard allows {tightest_var} up to {tightest_max}, "
                f"but buffer is only {buffer_size} bytes"
            ),
            concrete_values=guard.concrete_values,
        )

    return SmtSufficiencyResult(
        guard_text=guard.text,
        feasible=False,
        reasoning=(
            f"guard limits {tightest_var} to ≤{tightest_max}, "
            f"within buffer size {buffer_size}"
        ),
        concrete_values=guard.concrete_values,
    )


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


def check_all_sufficiency(
    guards: List[SinkGuard],
    *,
    buffer_sizes: Optional[Dict[int, int]] = None,
) -> List[List[SmtSufficiencyResult]]:
    """Check sufficiency for all guards.

    Args:
        guards: List of SinkGuard instances.
        buffer_sizes: Map of sink_line → known buffer size.

    Returns:
        List of results per guard (one inner list per SinkGuard).
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    if buffer_sizes is None:
        buffer_sizes = {}

    return [
        check_guard_sufficiency(
            sg,
            buffer_size=buffer_sizes.get(sg.sink_line),
        )
        for sg in guards
    ]
