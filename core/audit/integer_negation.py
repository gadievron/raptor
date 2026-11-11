"""Source-bound signed unary-negation faults under explicit integer promotions.

A counterexample establishes an arithmetic fault in the admitted entry model,
not application reachability. Safe or unsupported sites never clear a claim.
"""

from collections import Counter

from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import ssub_overflows
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from ._util import IDENTIFIER_RE
from .arithmetic_evaluation import unevaluated_context
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import integer_type, model_for_integer_terms
from .integer_comparison_model import ComparisonModel, UnsupportedComparison
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_witness import source_model_scope, validate_integer_witness

_GOALS = {"signed negation overflow": "negation"}


def _shape(node, data, language):
    if node.type != 'unary_expression':
        return None
    operator = node.child_by_field_name('operator')
    operand = _unwrap(node.child_by_field_name('argument'))
    if (operator is None or data[operator.start_byte:operator.end_byte] != b'-'
            or operand is None or operand.type != 'identifier'):
        return None
    parent = node.parent
    while parent is not None and parent.type != 'function_definition':
        # Variable sizeof extents require a separate evaluation model too.
        if unevaluated_context(parent, data, language):
            return None
        parent = parent.parent
    return node, data[operand.start_byte:operand.end_byte].decode()


def negation_candidates(source, *, language, integer_abi):
    """Pure bounded candidates only when the storage domain reaches promoted MIN."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _body, nodes = frame
    shapes = [shape for node in nodes
              if (shape := _shape(node, data, language)) is not None]
    occurrences = Counter(name for _, name in shapes)
    candidates = []
    for shape in shapes:
        target, name = shape
        if occurrences[name] != 1:
            continue
        binding = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
        kind = integer_type(dict(binding.types).get(name), integer_abi)
        if (binding.status == 'bound' and kind is not None and kind.signed
                and kind.promoted_signed and kind.width == kind.promoted_width):
            candidates.append(shape)
        if len(candidates) >= 16:
            break
    return candidates


def check_integer_negation(source, hypothesis, *, language, integer_abi=None):
    """Require unique unary source, feasible entry, fault SAT and Python replay."""
    unavailable = {'negation_status': 'unavailable', 'violation': None, 'witness_validated': False}
    if parse_integer_goal(hypothesis, _GOALS) is None or not z3_available():
        return unavailable
    expression = hypothesis.split('`')[1].strip()
    if not expression.startswith('-') or not IDENTIFIER_RE.fullmatch(expression[1:].strip()):
        return unavailable
    name = expression[1:].strip()
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return unavailable
    data, body, nodes = frame
    targets = [shape for node in nodes if (shape := _shape(node, data, language)) is not None and shape[1] == name]
    if len(targets) != 1:
        return unavailable
    target, _ = targets[0]
    guards = guards_for_operation(body, target, data, [name], language=language, integer_abi=integer_abi)
    if guards.status == 'unavailable':
        return unavailable
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        kind = model.kind(name)
        if not kind.signed:
            return unavailable
        predicates = [predicate.split() for predicate in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'negation_status': 'checked', **source_model_scope()}
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        solver.add(ssub_overflows(mk_val(0, kind.width), model.registry[name]))
        answer = check_solver(solver)
        if answer == z3.unsat:
            return {**details, 'violation': False}
        if answer != z3.sat:
            return details
        values = format_vars(solver.model(), model.registry,
                             {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True)
    checked = validate_integer_witness(values, tuple(model.types.items()), (), integer_abi)
    if checked is None or any(not model.evaluate(*parts, checked) for parts in predicates):
        return details
    mathematical = -checked[name]
    low, high = -(1 << (kind.width - 1)), (1 << (kind.width - 1)) - 1
    if low <= mathematical <= high:
        return details
    return {**details, 'violation': True, 'witness_validated': True, 'model': checked,
            'mathematical_result': mathematical, 'result_range': [low, high],
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'operator': '-', 'operand': name, 'types': dict(model.types),
                                 'promoted_width': kind.width, 'premises': list(guards.premises)}}
