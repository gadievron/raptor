"""Diagnostic truth of an exact whole-if negated builtin comparison."""

from core.smt_solver import DEFAULT_TIMEOUT_MS, z3, z3_available
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_condition import CONDITION_GOALS, _selected_position
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_literals import source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness


def _shape(node, data, language, integer_abi, *, selected=True):
    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    if node is None or node.type != 'unary_expression' or text(node.child_by_field_name('operator')) != '!':
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
    comparison = _unwrap(node.child_by_field_name('argument'))
    if comparison is None or comparison.type != 'binary_expression':
        return None
    op = text(comparison.child_by_field_name('operator'))
    if op not in COMPARISONS:
        return None
    atoms, literals, names = [], [], []
    for field in ('left', 'right'):
        atom = _unwrap(comparison.child_by_field_name(field))
        if atom is not None and atom.type == 'identifier':
            value = text(atom)
            names.append(value)
        else:
            value = source_integer_atom(atom, data)
            if value is None:
                return None
            literals.append(value)
        atoms.append(value)
    if not names or (literals and common_integer_type(literals, (), integer_abi) is None):
        return None
    return atoms[0], op, atoms[1]


def negated_comparison_site(comparison, data, *, language, integer_abi):
    """Pure exact-node translation for an already typed comparison candidate."""
    current, parent = comparison, comparison.parent
    while parent is not None and parent.type == 'parenthesized_expression':
        current, parent = parent, parent.parent
    if parent is None or parent.type != 'unary_expression' or parent.child_by_field_name('argument') != current:
        return None
    return parent if _shape(parent, data, language, integer_abi) is not None else None


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


def check_integer_negated_condition(source, hypothesis, *, language, integer_abi):
    """Prove the whole NOT's truth after nonvacuous typed entry validation."""
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
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        condition = z3.Not(model.predicate(*wanted))
        guards = guards_for_operation(body, target, data, tuple(model.registry), language=language,
                                      integer_abi=integer_abi, selected_condition=True)
        if guards.status == 'unavailable':
            return unavailable
        premises = [item.split() for item in guards.premises]
        constraints = [model.predicate(*parts) for parts in premises]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'comparison_status': 'checked', 'checked_property': 'constant-negated-comparison',
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
        if (not model.evaluate(*wanted, values)) != requested:
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
                                 'operator': '!', 'comparison': list(wanted), 'types': dict(model.types),
                                 'premises': list(guards.premises)}}
