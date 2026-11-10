"""Diagnostic signed arithmetic faults at standalone builtin ++/-- sites.

Only a direct return value or standalone update is admitted. Prefix/postfix
result values and narrowing stores are not interchangeable with promoted
arithmetic overflow, and no safe result refutes the original source claim.
"""

import re

from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import sadd_overflows, ssub_overflows
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_evaluation import unevaluated_context
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import integer_type, model_for_integer_terms
from .integer_comparison_model import ComparisonModel, UnsupportedComparison
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_witness import source_model_scope, validate_integer_witness
from .narrowing_bindings import visible_declarations

_GOALS = {'signed increment overflow': '++', 'signed decrement overflow': '--'}
_UPDATE = re.compile(r'(?:(\+\+|--)\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*(\+\+|--))')


def _shape(node, data, language):
    if node.type != 'update_expression':
        return None
    operator = node.child_by_field_name('operator')
    operand = _unwrap(node.child_by_field_name('argument'))
    if operator is None or operand is None or operand.type != 'identifier':
        return None
    op = data[operator.start_byte:operator.end_byte].decode()
    if op not in {'++', '--'}:
        return None
    name = data[operand.start_byte:operand.end_byte].decode()
    selected, parent = node, node.parent
    while parent is not None and parent.type == 'parenthesized_expression':
        selected, parent = parent, parent.parent
    if (parent is None or parent.type not in {'return_statement', 'expression_statement'}
            or [n for n in parent.named_children if n.type != 'comment'] != [selected]):
        return None  # no unsequenced sibling reads or implicit store/result model
    ancestor = parent
    while ancestor is not None and ancestor.type != 'function_definition':
        if unevaluated_context(ancestor, data, language):
            return None
        ancestor = ancestor.parent
    record = visible_declarations(node, data, language=language).get(name)
    if record is None or any(n.type == 'type_qualifier' and data[n.start_byte:n.end_byte] == b'const'
                             for n in record[1].named_children):
        return None
    return node, name, op, operator.start_byte < operand.start_byte


def update_candidates(source, *, language, integer_abi):
    """Pure bounded leads only when storage can reach promoted signed limits."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _body, nodes = frame
    result = []
    for node in nodes:
        shape = _shape(node, data, language)
        if shape is None:
            continue
        target, name, _op, _prefix = shape
        model = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
        kind = integer_type(dict(model.types).get(name), integer_abi)
        if (model.status == 'bound' and kind is not None and kind.signed
                and kind.promoted_signed and kind.width == kind.promoted_width):
            result.append(shape)
        if len(result) >= 16:
            break
    return result


def check_integer_update(source, hypothesis, *, language, integer_abi=None):
    """Bind exact fixity, prove entry SAT/fault SAT, then replay without Z3."""
    unavailable = {'update_status': 'unavailable', 'violation': None, 'witness_validated': False}
    goal = parse_integer_goal(hypothesis, _GOALS)
    if goal is None or not z3_available():
        return unavailable
    claim = _UPDATE.fullmatch(hypothesis.split('`')[1].strip())
    if claim is None:
        return unavailable
    prefix = claim[1] is not None
    name, op = (claim[2], claim[1]) if prefix else (claim[3], claim[4])
    if op != goal:
        return unavailable
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return unavailable
    data, body, nodes = frame
    matches = [shape for node in nodes if (shape := _shape(node, data, language)) is not None
               and shape[1:] == (name, op, prefix)]
    if len(matches) != 1:
        return unavailable
    target = matches[0][0]
    guards = guards_for_operation(body, target, data, [name], language=language, integer_abi=integer_abi)
    if guards.status == 'unavailable':
        return unavailable
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        kind = model.kind(name)
        storage = integer_type(model.types[name], integer_abi)
        if not kind.signed or storage is None or storage.width == 1:
            return unavailable
        predicates = [predicate.split() for predicate in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'update_status': 'checked', **source_model_scope()}
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        value, one = model.registry[name], mk_val(1, kind.width)
        solver.add(sadd_overflows(value, one) if op == '++' else ssub_overflows(value, one))
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
    mathematical = checked[name] + (1 if op == '++' else -1)
    low, high = -(1 << (kind.width - 1)), (1 << (kind.width - 1)) - 1
    if low <= mathematical <= high:
        return details
    return {**details, 'violation': True, 'witness_validated': True, 'model': checked,
            'mathematical_result': mathematical, 'result_range': [low, high],
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'operator': op, 'prefix': prefix, 'operand': name,
                                 'types': dict(model.types), 'promoted_width': kind.width,
                                 'premises': list(guards.premises)}}
