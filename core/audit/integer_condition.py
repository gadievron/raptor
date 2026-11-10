"""Diagnostic truth of an exact builtin bitwise/literal-comparison condition.

The actual AST is preserved: Flags & 4 == 0 is Flags & (4 == 0), not a
rewritten grouped mask comparison. Constant truth does not prove bug intent.
"""

from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import cast
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_evaluation import unevaluated_context
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type, model_for_integer_terms
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_comparison_types import comparison_frame
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_literals import integer_literal_value, source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness

CONDITION_GOALS = {'condition is always true': 'true', 'condition is always false': 'false'}


def _selected_position(node, data, language):
    selected, parent = node, node.parent
    while parent is not None and parent.type == 'parenthesized_expression':
        selected, parent = parent, parent.parent
    if parent is not None and parent.type == 'condition_clause':
        if (parent.child_by_field_name('value') != selected
                or [n for n in parent.named_children if n.type != 'comment'] != [selected]):
            return False
        selected, parent = parent, parent.parent
    if parent is None:
        return False
    if parent.type == 'if_statement':
        if parent.child_by_field_name('condition') != selected:
            return False
    elif parent.type != 'return_statement' or [n for n in parent.named_children if n.type != 'comment'] != [selected]:
        return False
    ancestor = parent
    while ancestor is not None and ancestor.type != 'function_definition':
        if unevaluated_context(ancestor, data, language):
            return False
        ancestor = ancestor.parent
    return True


def _shape(node, data, language, integer_abi):
    if node.type != 'binary_expression':
        return None

    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    if text(node.child_by_field_name('operator')) != '&' or not _selected_position(node, data, language):
        return None
    flags, comparison = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
    if flags is None or flags.type != 'identifier' or comparison is None or comparison.type != 'binary_expression':
        return None
    op = text(comparison.child_by_field_name('operator'))
    left, right = (source_integer_atom(comparison.child_by_field_name(field), data) for field in ('left', 'right'))
    if op not in COMPARISONS or left is None or right is None or common_integer_type([left, right], (), integer_abi) is None:
        return None
    return node, text(flags), left, op, right


def condition_candidates(source, *, language, integer_abi):
    """Pure candidates for a false literal comparison making the actual AND zero."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _body, nodes = frame
    result = []
    for node in nodes:
        shape = _shape(node, data, language, integer_abi)
        if shape is None:
            continue
        target, name, left, op, right = shape
        if COMPARISONS[op](integer_literal_value(left), integer_literal_value(right)):
            continue  # AND 1 is generally not a constant condition
        model = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
        if model.status == 'bound':
            result.append(shape)
        if len(result) >= 16:
            break
    return result


def _claim(hypothesis, language, integer_abi):
    expression = hypothesis.split('`')[1]
    if len(expression) > 512:
        return None
    frame = _frame('int Query(void){return ' + expression + ';}', integer_abi, language)
    if frame is None:
        return None
    data, body, _nodes = frame
    statements = [n for n in body.named_children if n.type != 'comment']
    if len(statements) != 1 or statements[0].type != 'return_statement':
        return None
    values = [n for n in statements[0].named_children if n.type != 'comment']
    target = _unwrap(values[0]) if len(values) == 1 else None
    shape = _shape(target, data, language, integer_abi) if target is not None else None
    return shape[1:] if shape is not None else None


def check_integer_condition(source, hypothesis, *, language, integer_abi=None):
    """Entry SAT, contrary-truth UNSAT and independent converted C truth replay."""
    unavailable = {'comparison_status': 'unavailable', 'matches_claim': None, 'entry_witness_validated': False}
    goal = parse_integer_goal(hypothesis, CONDITION_GOALS)
    if goal is None or not z3_available():
        return unavailable
    wanted = _claim(hypothesis, language, integer_abi)
    frame = _frame(source, integer_abi, language) if wanted is not None else None
    if frame is None:
        return unavailable
    data, body, nodes = frame
    matches = [shape for node in nodes if (shape := _shape(node, data, language, integer_abi)) is not None
               and shape[1:] == wanted]
    if len(matches) != 1:
        return unavailable
    target, name, left, op, right = matches[0]
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        flag_kind = model.kind(name)
        inner = model.predicate(left, op, right)
        # C int and C++ bool comparison results both promote to target int.
        truth_kind = model.kind('0')
        kind = comparison_frame(flag_kind, truth_kind)
        raw = cast(model.registry[name], kind.width, flag_kind.signed)
        truth = z3.If(inner, mk_val(1, truth_kind.width), mk_val(0, truth_kind.width))
        condition = (raw & cast(truth, kind.width, truth_kind.signed)) != mk_val(0, kind.width)
        # Only this fully bound, pure typed subtree receives selected-test credit.
        guards = guards_for_operation(body, target, data, [name], language=language,
                                      integer_abi=integer_abi, selected_condition=True)
        if guards.status == 'unavailable':
            return unavailable
        predicates = [predicate.split() for predicate in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'comparison_status': 'checked', 'checked_property': 'constant-bitwise-condition',
               **source_model_scope()}
    requested = goal == 'true'
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        values = format_vars(solver.model(), model.registry,
                             {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True)
        checked = validate_integer_witness(values, tuple(model.types.items()), (), integer_abi)
        if checked is None or any(not model.evaluate(*parts, checked) for parts in predicates):
            return details
        bits = checked[name] % (1 << kind.width)
        converted = bits - (1 << kind.width) if kind.signed and bits >= 1 << (kind.width - 1) else bits
        literal_truth = int(COMPARISONS[op](integer_literal_value(left), integer_literal_value(right)))
        if bool(converted & literal_truth) != requested:
            return {**details, 'matches_claim': False}
        solver.add(z3.Not(condition) if requested else condition)
        contrary = check_solver(solver)
        if contrary == z3.sat:
            return {**details, 'matches_claim': False}
        if contrary != z3.unsat:
            return details
    return {**details, 'matches_claim': True, 'constant_truth': requested,
            'entry_witness_validated': True, 'entry_witness': checked,
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'operator': '&', 'operand': name, 'literal_comparison': [left, op, right],
                                 'types': dict(model.types), 'result_width': kind.width, 'result_signed': kind.signed,
                                 'premises': list(guards.premises)}}
