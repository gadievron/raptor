"""Actual left-associated builtin comparison truth, without range rewriting."""

from core.smt_solver import DEFAULT_TIMEOUT_MS, ge, gt, le, lt, mk_val, z3, z3_available
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type, model_for_integer_terms
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_condition import CONDITION_GOALS, _selected_position
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_literals import integer_literal_value, source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness


def _shape(node, data, language, integer_abi, *, selected=True):
    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    if node is None or node.type != 'binary_expression':
        return None
    if selected:
        if not _selected_position(node, data, language):
            return None
        current, parent = node, node.parent
        while parent is not None and parent.type == 'parenthesized_expression':
            current, parent = parent, parent.parent
        if parent is not None and parent.type == 'condition_clause':
            current, parent = parent, parent.parent
        if parent is None or parent.type != 'if_statement' or parent.child_by_field_name('condition') != current:
            return None
    outer_op = text(node.child_by_field_name('operator'))
    inner = _unwrap(node.child_by_field_name('left'))
    outer_literal = source_integer_atom(node.child_by_field_name('right'), data)
    if outer_op not in COMPARISONS or inner is None or inner.type != 'binary_expression' or outer_literal is None:
        return None
    inner_op = text(inner.child_by_field_name('operator'))
    inner_literal = source_integer_atom(inner.child_by_field_name('left'), data)
    name = _unwrap(inner.child_by_field_name('right'))
    if inner_op not in COMPARISONS or inner_literal is None or name is None or name.type != 'identifier':
        return None
    if common_integer_type([inner_literal, outer_literal], (), integer_abi) is None:
        return None
    return inner_literal, inner_op, text(name), outer_op, outer_literal


def _claim(hypothesis, language, integer_abi):
    expression = hypothesis.split('`')[1]
    if len(expression) > 512:
        return None
    frame = _frame('int Query(void){return ' + expression + ';}', integer_abi, language)
    if frame is None:
        return None
    data, body, _ = frame
    statements = [node for node in body.named_children if node.type != 'comment']
    if len(statements) != 1 or statements[0].type != 'return_statement':
        return None
    values = [node for node in statements[0].named_children if node.type != 'comment']
    return _shape(_unwrap(values[0]), data, language, integer_abi, selected=False) if len(values) == 1 else None


def chain_condition_candidates(source, *, language, integer_abi):
    """Pure leads when both possible promoted comparison results agree."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _, nodes = frame
    candidates = []
    for node in nodes:
        shape = _shape(node, data, language, integer_abi)
        if shape is None:
            continue
        _, _, name, op, literal = shape
        outcomes = {COMPARISONS[op](value, integer_literal_value(literal)) for value in (0, 1)}
        if len(outcomes) != 1:
            continue
        model = model_for_integer_terms(node, data, [name], (), integer_abi, language=language)
        if model.status == 'bound':
            candidates.append((node, shape, outcomes.pop()))
        if len(candidates) >= 16:
            break
    return candidates


def check_integer_chain_condition(source, hypothesis, *, language, integer_abi):
    """Entry SAT, opposite-truth UNSAT and independent promoted-result replay."""
    unavailable = {'comparison_status': 'unavailable', 'matches_claim': None, 'entry_witness_validated': False}
    goal = parse_integer_goal(hypothesis, CONDITION_GOALS)
    if goal is None or not z3_available():
        return unavailable
    wanted = _claim(hypothesis, language, integer_abi)
    frame = _frame(source, integer_abi, language) if wanted is not None else None
    if frame is None:
        return unavailable
    data, body, nodes = frame
    matches = [node for node in nodes if _shape(node, data, language, integer_abi) == wanted]
    if len(matches) != 1:
        return unavailable
    target = matches[0]
    literal, inner_op, name, outer_op, outer_literal = wanted
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        inner = model.predicate(literal, inner_op, name)
        # Both C int and C++ bool comparison results promote to target int.
        # The inner operand conversion frame must not become the outer frame.
        result_kind = model.kind('0')
        truth = z3.If(inner, mk_val(1, result_kind.width), mk_val(0, result_kind.width))
        bound = mk_val(integer_literal_value(outer_literal), result_kind.width)
        if outer_op in {'==', '!='}:
            condition = truth == bound if outer_op == '==' else truth != bound
        else:
            condition = {'<': lt, '<=': le, '>': gt, '>=': ge}[outer_op](truth, bound, True)
        guards = guards_for_operation(body, target, data, [name], language=language,
                                      integer_abi=integer_abi, selected_condition=True)
        if guards.status == 'unavailable':
            return unavailable
        premises = [item.split() for item in guards.premises]
        constraints = [model.predicate(*parts) for parts in premises]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'comparison_status': 'checked', 'checked_property': 'constant-chained-comparison',
               **source_model_scope()}
    requested = goal == 'true'
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        values = validate_integer_witness(format_vars(solver.model(), model.registry,
                                                      {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True),
                                          tuple(model.types.items()), (), integer_abi)
        if values is None or any(not model.evaluate(*parts, values) for parts in premises):
            return details
        replay = int(model.evaluate(literal, inner_op, name, values))
        if COMPARISONS[outer_op](replay, integer_literal_value(outer_literal)) != requested:
            return {**details, 'matches_claim': False}
        solver.add(z3.Not(condition) if requested else condition)
        contrary = check_solver(solver)
        if contrary == z3.sat:
            return {**details, 'matches_claim': False}
        if contrary != z3.unsat:
            return details
    return {**details, 'matches_claim': True, 'constant_truth': requested,
            'entry_witness_validated': True, 'entry_witness': values,
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'inner_comparison': [literal, inner_op, name], 'operator': outer_op,
                                 'outer_literal': outer_literal, 'comparison_result_width': result_kind.width,
                                 'comparison_result_signed': True, 'types': dict(model.types),
                                 'premises': list(guards.premises)}}
