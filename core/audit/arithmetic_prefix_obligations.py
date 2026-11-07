"""Bounded mechanical definedness proofs for primitive integer prefixes."""

from time import monotonic

from core.smt_solver import new_solver, z3, z3_available
from core.smt_solver.csem import division_undefined, shift_count_invalid
from core.smt_solver.session import check_solver, query_budget

from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type
from .integer_literals import source_integer_atom
from .narrowing_bindings import visible_declarations

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
            return check_solver(solver) == z3.unsat


def binary_domain(model, node, depth):
    """Admit atomic /, %, >> only after proving full-domain definedness.

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
    atoms = []
    for item in (left, right):
        if item.type == 'identifier':
            if model.kind_for_name(item) is None:
                return None
            atoms.append(model.text(item))
        else:
            atom = source_integer_atom(item, model.data)
            if atom is None:
                return None
            atoms.append(atom)
    domains = [model.value_domain(item, depth + 1) for item in (left, right)]
    if any(domain is None or None in domain for domain in domains):
        return None
    declarations = visible_declarations(node, model.data)
    types = [(name, value[0]) for name, value in declarations.items()]
    if operator == '>>':
        left_kind = common_integer_type([atoms[0]], types, model.abi)
        count_kind = common_integer_type([atoms[1]], types, model.abi)
        if left_kind is None or count_kind is None or domains[0][0] < 0:
            return None  # negative signed right shifts need implementation assumptions
        count = z3.FreshConst(z3.BitVecSort(count_kind.width), prefix='prefix_count')
        invalid = shift_count_invalid(count, left_kind.width, signed=count_kind.signed)
        if model.proofs.impossible(invalid, [(count, *domains[1], count_kind.signed)]):
            return (0, domains[0][1])  # conservative for all admitted counts
        return None
    kind = common_integer_type(atoms, types, model.abi)
    if kind is None:
        return None
    a, b = (z3.FreshConst(z3.BitVecSort(kind.width), prefix='prefix_operand') for _ in range(2))
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
