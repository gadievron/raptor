"""Diagnostic unsigned stored-value wrap at standalone builtin ++/-- sites."""

from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import cast, uadd_overflows, usub_underflows
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_guards import guards_for_operation
from .arithmetic_types import integer_type, model_for_integer_terms
from .integer_comparison_model import ComparisonModel, UnsupportedComparison
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_update import _UPDATE, _shape
from .integer_witness import source_model_scope, validate_integer_witness

_GOALS = {'unsigned increment wrap': '++', 'unsigned decrement wrap': '--'}


def _standalone_shape(node, data, language):
    shape = _shape(node, data, language)
    if shape is None:
        return None
    parent = node.parent
    while parent is not None and parent.type == 'parenthesized_expression':
        parent = parent.parent
    return shape if parent is not None and parent.type == 'expression_statement' else None


def _defined_unsigned_update(kind, op):
    if kind is None or kind.signed or kind.width == 1:
        return False  # Boolean conversion is not unsigned modular storage.
    if kind.promoted_signed:
        delta = 1 if op == '++' else -1
        low, high = delta, (1 << kind.width) - 1 + delta
        return -(1 << (kind.promoted_width - 1)) <= low and high <= (1 << (kind.promoted_width - 1)) - 1
    return True


def unsigned_update_candidates(source, *, language, integer_abi):
    """Pure typed leads, without a proof or assumption about intended wrap."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _, nodes = frame
    candidates = []
    for node in nodes:
        shape = _standalone_shape(node, data, language)
        if shape is None:
            continue
        target, name, op, _prefix = shape
        model = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
        kind = integer_type(dict(model.types).get(name), integer_abi)
        if model.status == 'bound' and _defined_unsigned_update(kind, op):
            candidates.append(shape)
        if len(candidates) >= 16:
            break
    return candidates


def check_unsigned_update_wrap(source, hypothesis, *, language, integer_abi):
    """Require entry SAT, storage-wrap SAT and independent pre/post replay."""
    unavailable = {'update_status': 'unavailable', 'violation': None, 'witness_validated': False}
    op = parse_integer_goal(hypothesis, _GOALS)
    if op is None or not z3_available():
        return unavailable
    claim = _UPDATE.fullmatch(hypothesis.split('`')[1].strip())
    if claim is None:
        return unavailable
    prefix = claim[1] is not None
    name, claimed_op = (claim[2], claim[1]) if prefix else (claim[3], claim[4])
    if claimed_op != op:
        return unavailable
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return unavailable
    data, body, nodes = frame
    matches = [shape for node in nodes if (shape := _standalone_shape(node, data, language)) is not None
               and shape[1:] == (name, op, prefix)]
    if len(matches) != 1:
        return unavailable
    target = matches[0][0]
    guards = guards_for_operation(body, target, data, [name], language=language, integer_abi=integer_abi)
    if guards.status == 'unavailable':
        return unavailable
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        promoted = model.kind(name)
        storage = integer_type(model.types[name], integer_abi)
        if not _defined_unsigned_update(storage, op):
            return unavailable
        predicates = [item.split() for item in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, 'update_status': 'checked', 'checked_property': 'unsigned-update-wrap',
               **source_model_scope()}
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        value = cast(model.registry[name], storage.width, promoted.signed)
        one = mk_val(1, storage.width)
        solver.add(uadd_overflows(value, one) if op == '++' else usub_underflows(value, one))
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
    maximum = (1 << storage.width) - 1
    if 0 <= mathematical <= maximum:
        return details
    stored = mathematical % (1 << storage.width)
    return {**details, 'violation': True, 'witness_validated': True, 'model': checked,
            'mathematical_result': mathematical, 'stored_result': stored, 'storage_range': [0, maximum],
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'operator': op, 'prefix': prefix, 'operand': name, 'types': dict(model.types),
                                 'storage_width': storage.width, 'promoted_width': promoted.width,
                                 'promoted_signed': promoted.signed, 'premises': list(guards.premises)}}
