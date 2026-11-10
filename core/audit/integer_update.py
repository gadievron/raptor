"""Diagnostic signed arithmetic faults and unsigned stored-value update wrap.

Signed arithmetic admits a direct return value or standalone update; unsigned
storage wrap requires a standalone statement. Prefix/postfix result values and
narrowing stores are not interchangeable with promoted arithmetic overflow,
and no safe result refutes the original source claim.
"""

import operator
import re

from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import cast, sadd_overflows, smul_overflows, ssub_overflows
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_evaluation import unevaluated_context
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type, integer_type, model_for_integer_terms
from .integer_comparison_model import ComparisonModel, UnsupportedComparison
from .integer_comparison_types import comparison_frame
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_literals import integer_literal_value, source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness
from .narrowing_bindings import visible_declarations

_GOALS = {'signed increment overflow': '++', 'signed decrement overflow': '--',
          'signed compound overflow': 'compound', 'unsigned increment wrap': 'unsigned++',
          'unsigned decrement wrap': 'unsigned--'}
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
    if goal in {'unsigned++', 'unsigned--'}:
        from .unsigned_update import check_unsigned_update_wrap
        return check_unsigned_update_wrap(source, hypothesis, language=language, integer_abi=integer_abi)
    if goal == 'compound':
        return _check_compound_update(source, hypothesis, language=language, integer_abi=integer_abi)
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


def _compound_shape(node, data, language):
    if node.type != 'assignment_expression':
        return None
    op_node = node.child_by_field_name('operator')
    left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
    op = data[op_node.start_byte:op_node.end_byte].decode() if op_node is not None else ''
    if op not in {'+=', '-=', '*='} or left is None or left.type != 'identifier' or right is None:
        return None
    rhs = (data[right.start_byte:right.end_byte].decode() if right.type == 'identifier'
           else source_integer_atom(right, data))
    if rhs is None:
        return None
    selected, parent = node, node.parent
    while parent is not None and parent.type == 'parenthesized_expression':
        selected, parent = parent, parent.parent
    if (parent is None or parent.type != 'expression_statement'
            or [n for n in parent.named_children if n.type != 'comment'] != [selected]):
        return None
    ancestor = parent
    while ancestor is not None and ancestor.type != 'function_definition':
        if unevaluated_context(ancestor, data, language):
            return None
        ancestor = ancestor.parent
    return node, data[left.start_byte:left.end_byte].decode(), op, rhs


def _compound_writable(target, name, data, language):
    record = visible_declarations(target, data, language=language).get(name)
    return record is not None and not any(
        node.type == 'type_qualifier' and data[node.start_byte:node.end_byte] == b'const'
        for node in record[1].named_children)


def compound_update_candidates(source, *, language, integer_abi):
    """Pure source/type shapes; the discovery owner filters impossible ranges."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _body, nodes = frame
    candidates = []
    for node in nodes:
        shape = _compound_shape(node, data, language)
        if shape is None:
            continue
        target, lhs, op, rhs = shape
        if not _compound_writable(target, lhs, data, language):
            continue
        types, kinds = {}, []
        for atom in (lhs, rhs):
            if integer_literal_value(atom) is not None:
                kind = common_integer_type([atom], (), integer_abi)
            else:
                model = model_for_integer_terms(target, data, [atom], (), integer_abi, language=language)
                types.update(model.types)
                kind = integer_type(dict(model.types).get(atom), integer_abi) if model.status == 'bound' else None
            if kind is None:
                break
            kinds.append(kind)
        if len(kinds) != 2:
            continue
        result = comparison_frame(*kinds)
        if result.signed:
            candidates.append((*shape, tuple(types.items()), result))
        if len(candidates) >= 16:
            break
    return candidates


def _compound_claim(hypothesis, integer_abi, language):
    expression = hypothesis.split('`')[1]
    if len(expression) > 512:
        return None
    frame = _frame('void Query(void){' + expression + ';}', integer_abi, language)
    if frame is None:
        return None
    data, body, nodes = frame
    statements = [n for n in body.named_children if n.type != 'comment']
    if len(statements) != 1 or statements[0].type != 'expression_statement':
        return None
    shapes = [shape for node in nodes if (shape := _compound_shape(node, data, language)) is not None]
    return shapes[0][1:] if len(shapes) == 1 else None


def _check_compound_update(source, hypothesis, *, language, integer_abi):
    unavailable = {'update_status': 'unavailable', 'violation': None, 'witness_validated': False}
    wanted = _compound_claim(hypothesis, integer_abi, language)
    frame = _frame(source, integer_abi, language) if wanted is not None else None
    if frame is None:
        return unavailable
    data, body, nodes = frame
    matches = [shape for node in nodes if (shape := _compound_shape(node, data, language)) is not None
               and shape[1:] == wanted]
    if len(matches) != 1:
        return unavailable
    target, lhs, op, rhs = matches[0]
    if not _compound_writable(target, lhs, data, language):
        return unavailable
    guards = guards_for_operation(body, target, data, [lhs, rhs], language=language, integer_abi=integer_abi)
    if guards.status == 'unavailable':
        return unavailable
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        left_kind, right_kind = model.kind(lhs), model.kind(rhs)
        kind = comparison_frame(left_kind, right_kind)
        if not kind.signed:
            return unavailable
        predicates = [predicate.split() for predicate in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())

        def native(atom, source_kind):
            raw = model.registry[atom] if atom in model.registry else mk_val(integer_literal_value(atom), source_kind.width)
            return cast(raw, kind.width, source_kind.signed)

        left, right = native(lhs, left_kind), native(rhs, right_kind)
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'update_status': 'checked', **source_model_scope()}
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        solver.add({'+=': sadd_overflows, '-=': ssub_overflows, '*=': smul_overflows}[op](left, right))
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

    def converted(atom):
        value = checked[atom] if atom in checked else integer_literal_value(atom)
        bits = value % (1 << kind.width)
        return bits - (1 << kind.width) if bits >= 1 << (kind.width - 1) else bits

    mathematical = {'+=': operator.add, '-=': operator.sub, '*=': operator.mul}[op](converted(lhs), converted(rhs))
    low, high = -(1 << (kind.width - 1)), (1 << (kind.width - 1)) - 1
    if low <= mathematical <= high:
        return details
    return {**details, 'violation': True, 'witness_validated': True, 'model': checked,
            'mathematical_result': mathematical, 'result_range': [low, high],
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'operator': op, 'operands': [lhs, rhs], 'types': dict(model.types),
                                 'promoted_width': kind.width, 'premises': list(guards.premises)}}
