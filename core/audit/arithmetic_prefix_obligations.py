"""Bounded mechanical definedness proofs for primitive integer prefixes."""

import logging
from time import monotonic

from core.smt_solver import new_solver, z3, z3_available
from core.smt_solver.csem import (
    division_undefined, left_shift_undefined, shift_count_invalid,
    sadd_overflows, ssub_overflows, smul_overflows,
)
from core.smt_solver.session import check_solver, query_budget, solver_reason_unknown

from .arithmetic_operation import _unwrap
from .arithmetic_expression_types import promoted

logger = logging.getLogger(__name__)

_MAX_CHECKS = 8
_BUDGET_MS = 100


class PrefixProofBudget:
    """At most eight queries within one soft budget for one source binder."""

    def __init__(self):
        self.checks = 0
        self.deadline = None

    def impossible(self, predicate, domains):
        if not z3_available() or self.checks >= _MAX_CHECKS:
            return False
        now = monotonic()
        if self.deadline is None:
            self.deadline = now + _BUDGET_MS / 1000
        remaining = int((self.deadline - now) * 1000)
        if remaining <= 0:
            return False
        self.checks += 1
        solver = new_solver(timeout_ms=remaining)
        for variable, low, high, signed in domains:
            solver.add(variable >= low if signed else z3.UGE(variable, low))
            solver.add(variable <= high if signed else z3.ULE(variable, high))
        solver.add(predicate)
        remaining = max(0, int((self.deadline - monotonic()) * 1000))
        with query_budget(remaining):
            result = check_solver(solver)
        if result == z3.unknown:
            logger.debug("Prefix definedness proof undecided: %s", solver_reason_unknown(solver))
        return result == z3.unsat


def binary_domain(model, node, depth):
    """Admit pure integer arithmetic with full-domain definedness.

    Guard refinement and local value flow are intentionally absent: these
    intervals overapproximate each operand independently. A proof therefore
    remains valid without assuming a relation between their values.
    """
    if not z3_available() or model.abi is None:
        return None
    operator = model.text(node.child_by_field_name('operator'))
    left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
    if left is None or right is None:
        return None
    domains = [model.value_domain(item, depth + 1) for item in (left, right)]
    if any(domain is None or None in domain for domain in domains):
        return None
    if operator in {'<<', '>>'}:
        left_kind = model.expression_kind(node, depth)
        raw_count_kind = model.expression_kind(right, depth + 1)
        count_kind = promoted(raw_count_kind) if raw_count_kind is not None else None
        if left_kind is None or count_kind is None or (operator == '>>' and domains[0][0] < 0):
            return None  # negative signed right shifts need implementation assumptions
        count = z3.FreshConst(z3.BitVecSort(count_kind.width), prefix='prefix_count')
        if operator == '>>':
            invalid = shift_count_invalid(count, left_kind.width, signed=count_kind.signed)
            if model.proofs.impossible(invalid, [(count, *domains[1], count_kind.signed)]):
                return domains[0][0] >> domains[1][1], domains[0][1] >> domains[1][0]
            return None
        value = z3.FreshConst(z3.BitVecSort(left_kind.width), prefix='prefix_value')
        invalid = left_shift_undefined(value, count, value_signed=left_kind.signed, count_signed=count_kind.signed)
        # Strict signed C definedness is sufficient for both supported C and
        # C++ prefixes; extra cases allowed by some C++ versions still abstain.
        if not model.proofs.impossible(invalid, [(value, *domains[0], left_kind.signed),
                                                (count, *domains[1], count_kind.signed)]):
            return None
        low, high = domains[0][0] << domains[1][0], domains[0][1] << domains[1][1]
        maximum = (1 << (left_kind.width - (1 if left_kind.signed else 0))) - 1
        return (low, high) if high <= maximum else (0, maximum)
    kind = model.expression_kind(node, depth)
    if kind is None:
        return None
    if operator in {'&', '|', '^'}:
        from .arithmetic_bitwise_domains import bitwise_domain
        return bitwise_domain(model, operator, kind, domains)
    a, b = (z3.FreshConst(z3.BitVecSort(kind.width), prefix='prefix_operand') for _ in range(2))
    if operator in {'+', '-', '*'}:
        if kind.signed:
            fault = {'+': sadd_overflows, '-': ssub_overflows, '*': smul_overflows}[operator](a, b)
            if not model.proofs.impossible(fault, [(a, *domains[0], True), (b, *domains[1], True)]):
                return None
        # Unsigned add/sub/mul are defined modulo the promoted range.
        # Retain a tight interval only when no mathematical result wraps.
        (low_a, high_a), (low_b, high_b) = domains
        if operator == '+':
            low, high = low_a + low_b, high_a + high_b
        elif operator == '-':
            low, high = low_a - high_b, high_a - low_b
        else:
            corners = [a * b for a in (low_a, high_a) for b in (low_b, high_b)]
            low, high = min(corners), max(corners)
        if kind.signed:
            return low, high
        maximum = (1 << kind.width) - 1
        return (low, high) if 0 <= low <= high <= maximum else (0, maximum)
    invalid = division_undefined(a, b, signed=kind.signed)
    if not model.proofs.impossible(invalid, [(a, *domains[0], kind.signed), (b, *domains[1], kind.signed)]):
        return None
    (low_a, high_a), (low_b, high_b) = domains
    if operator == '/':
        def quotient(a, b):
            magnitude = abs(a) // abs(b)
            return -magnitude if (a < 0) != (b < 0) else magnitude
        corners = [quotient(a, b) for a in (low_a, high_a) for b in (low_b, high_b)]
        return min(corners), max(corners)
    if operator == '%':
        bound = min(max(abs(low_a), abs(high_a)), max(abs(low_b), abs(high_b)) - 1)
        return (-bound if low_a < 0 else 0, bound if high_a > 0 else 0)
    return None


def unary_domain(model, node, depth):
    """Promote pure unary integers; prove signed negation before executing it."""
    if not z3_available():
        return None
    child = node.child_by_field_name('argument')
    domain = model.value_domain(child, depth + 1)
    kind = model.expression_kind(node, depth)
    if domain is None or None in domain or kind is None:
        return None
    low, high = domain
    operator = model.text(node.child_by_field_name('operator'))
    if operator == '+':
        return domain
    if operator == '~':
        # The explicit ABI requires two's-complement integers without padding.
        maximum = (1 << kind.width) - 1
        return (-high - 1, -low - 1) if kind.signed else (maximum - high, maximum - low)
    if operator != '-':
        return None
    if kind.signed:
        value = z3.FreshConst(z3.BitVecSort(kind.width), prefix='prefix_negated')
        zero = z3.BitVecVal(0, kind.width)
        if not model.proofs.impossible(ssub_overflows(zero, value), [(value, low, high, True)]):
            return None
        return -high, -low
    return (0, 0) if low == high == 0 else (0, (1 << kind.width) - 1)
