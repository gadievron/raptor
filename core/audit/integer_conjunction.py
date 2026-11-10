"""Diagnostic truth of two pure builtin comparisons in a whole if condition."""

from core.smt_solver import DEFAULT_TIMEOUT_MS, z3, z3_available
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type, model_for_integer_terms
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_condition import CONDITION_GOALS
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_literals import source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness

_RELATIONS = {'<': {-1}, '<=': {-1, 0}, '>': {1}, '>=': {0, 1}, '==': {0}, '!=': {-1, 1}}


def _shape(node, data, *, selected=True):
    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    if node is None or node.type != 'binary_expression' or text(node.child_by_field_name('operator')) != '&&':
        return None
    if selected:
        current, parent = node, node.parent
        while parent is not None and parent.type == 'parenthesized_expression':
            current, parent = parent, parent.parent
        if parent is not None and parent.type == 'condition_clause':
            if parent.child_by_field_name('value') != current or [n for n in parent.named_children if n.type != 'comment'] != [current]:
                return None
            current, parent = parent, parent.parent
        if parent is None or parent.type != 'if_statement' or parent.child_by_field_name('condition') != current:
            return None
    leaves = []
    for field in ('left', 'right'):
        leaf = _unwrap(node.child_by_field_name(field))
        if leaf is None or leaf.type != 'binary_expression':
            return None
        op = text(leaf.child_by_field_name('operator'))
        if op not in COMPARISONS:
            return None
        atoms = []
        for side in ('left', 'right'):
            atom = _unwrap(leaf.child_by_field_name(side))
            value = text(atom) if atom is not None and atom.type == 'identifier' else source_integer_atom(atom, data)
            if value is None:
                return None
            atoms.append(value)
        leaves.append((atoms[0], op, atoms[1]))
    return tuple(leaves)


def _claim(hypothesis, language, abi):
    expression = hypothesis.split('`')[1]
    if len(expression) > 512:
        return None
    frame = _frame('int Query(void){return ' + expression + ';}', abi, language)
    if frame is None:
        return None
    data, body, _ = frame
    statements = [n for n in body.named_children if n.type != 'comment']
    if len(statements) != 1 or statements[0].type != 'return_statement':
        return None
    values = [n for n in statements[0].named_children if n.type != 'comment']
    return _shape(_unwrap(values[0]), data, selected=False) if len(values) == 1 else None


def conjunction_candidates(source, *, language, integer_abi):
    """Solver-free leads for disjoint relations over the same ordered operands."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _, nodes = frame
    candidates = []
    for node in nodes:
        leaves = _shape(node, data)
        if leaves is None:
            continue
        left, right = leaves
        if (left[0], left[2]) != (right[0], right[2]) or _RELATIONS[left[1]] & _RELATIONS[right[1]]:
            continue
        atoms = [left[0], left[2]]
        model = model_for_integer_terms(node, data, atoms, (), integer_abi, language=language)
        if model.status == 'bound' and common_integer_type(atoms, model.types, integer_abi) is not None:
            candidates.append((node, leaves))
        if len(candidates) >= 16:
            break
    return candidates


def check_integer_conjunction(source, hypothesis, *, language, integer_abi):
    """Check nonvacuous constant truth with per-comparison C conversions."""
    unavailable = {'comparison_status': 'unavailable', 'matches_claim': None, 'entry_witness_validated': False}
    goal = parse_integer_goal(hypothesis, CONDITION_GOALS)
    if goal is None or not z3_available():
        return unavailable
    wanted = _claim(hypothesis, language, integer_abi)
    frame = _frame(source, integer_abi, language) if wanted is not None else None
    if frame is None:
        return unavailable
    data, body, nodes = frame
    matches = [node for node in nodes if _shape(node, data) == wanted]
    if len(matches) != 1:
        return unavailable
    target = matches[0]
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        # Every selected leaf is pure and total before guards may skip its subtree.
        condition = z3.And(*(model.predicate(*leaf) for leaf in wanted))
        names = tuple(model.registry)
        guards = guards_for_operation(body, target, data, names, language=language,
                                      integer_abi=integer_abi, selected_condition=True)
        if guards.status == 'unavailable':
            return unavailable
        premises = [item.split() for item in guards.premises]
        constraints = [model.predicate(*parts) for parts in premises]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'comparison_status': 'checked', 'checked_property': 'constant-integer-conjunction',
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
        if all(model.evaluate(*leaf, values) for leaf in wanted) != requested:
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
                                 'operator': '&&', 'comparisons': [list(leaf) for leaf in wanted],
                                 'types': dict(model.types), 'premises': list(guards.premises)}}
