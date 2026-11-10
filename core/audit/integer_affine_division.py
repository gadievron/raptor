"""Source-bound division faults with one affine denominator expression."""
from .integer_conversion import _frame
from .array_index import source_index
from .arithmetic_operation import _unwrap
from .arithmetic_guards import guards_for_operation
from .arithmetic_prefix import PrefixIntegerModel
from .arithmetic_types import common_integer_type, integer_type, model_for_integer_terms
from .integer_comparison_model import ComparisonModel, UnsupportedComparison
from .integer_comparison_types import comparison_frame
from .integer_abi import resolve_integer_abi, integer_abi_record
from .integer_literals import integer_literal_value, source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness
from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import cast, division_undefined
from core.smt_solver.session import new_solver, check_solver, query_budget
from core.smt_solver.witness import format_vars

from .integer_goal import DIVISION_GOALS, parse_integer_goal


def _shape(node, data):
    if node is None or node.type != 'binary_expression':
        return None
    operator_node = node.child_by_field_name('operator')
    operator = data[operator_node.start_byte:operator_node.end_byte].decode() if operator_node is not None else ''
    if operator not in {'/', '%'}:
        return None
    left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
    numerator = data[left.start_byte:left.end_byte].decode() if left is not None and left.type == 'identifier' else source_integer_atom(left, data)
    affine = source_index(right, data)
    return (node, right, numerator, affine, operator) if numerator is not None and affine is not None and affine[1] else None


def _claim(hypothesis, abi, language):
    goal = parse_integer_goal(hypothesis, DIVISION_GOALS)
    if goal is None:
        return None
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
    shape = _shape(_unwrap(values[0]), data) if len(values) == 1 else None
    return (shape, {'zero-divisor': 'zero', 'signed-division-overflow': 'overflow', 'any': 'any'}[goal]) if shape is not None else None



def affine_division_candidates(source, *, language, integer_abi):
    """Pure storage/type leads, without path, definedness or solver credit."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _, nodes = frame
    result = []
    for node in nodes:
        shape = _shape(node, data)
        if shape is None:
            continue
        target, _, numerator, (count, op, offset), operator = shape
        count_binding = model_for_integer_terms(target, data, [count], (), integer_abi, language=language)
        count_kind = integer_type(dict(count_binding.types).get(count), integer_abi)
        denominator_kind = common_integer_type([count, str(offset)], count_binding.types, integer_abi)
        if count_binding.status != 'bound' or count_kind is None or denominator_kind is None:
            continue
        literal = integer_literal_value(numerator)
        if literal is not None:
            numerator_kind = common_integer_type([numerator], (), integer_abi)
            numerator_low = numerator_high = literal
        else:
            binding = model_for_integer_terms(target, data, [numerator], (), integer_abi, language=language)
            numerator_kind = integer_type(dict(binding.types).get(numerator), integer_abi) if binding.status == 'bound' else None
            if numerator_kind is None:
                continue
            numerator_low = -(1 << (numerator_kind.width - 1)) if numerator_kind.signed else 0
            numerator_high = (1 << (numerator_kind.width - (1 if numerator_kind.signed else 0))) - 1
        if numerator_kind is None:
            continue
        division_kind = comparison_frame(numerator_kind, denominator_kind)
        low = -(1 << (count_kind.width - 1)) if count_kind.signed else 0
        high = (1 << (count_kind.width - (1 if count_kind.signed else 0))) - 1
        zero_count = offset if op == '-' else -offset
        if not denominator_kind.signed:
            zero_count %= 1 << denominator_kind.width
        kinds = ['zero-divisor'] if low <= zero_count <= high else []
        overflow_count = offset - 1 if op == '-' else -1 - offset
        minimum = -(1 << (division_kind.width - 1))
        if (division_kind.signed and denominator_kind.signed and numerator_low <= minimum <= numerator_high
                and low <= overflow_count <= high):
            kinds.append('signed-division-overflow')
        for kind in kinds:
            result.append((target, numerator, count, op, offset, operator, kind))
            if len(result) >= 16:
                return result
    return result


def check_affine_division(source, hypothesis, *, language, integer_abi=None):
    unavailable = {'division_status': 'unavailable', 'violation': None, 'witness_validated': False}
    abi = integer_abi
    claim = _claim(hypothesis, abi, language)
    frame = _frame(source, abi, language) if claim is not None else None
    if frame is None or not z3_available():
        return unavailable
    data, body, nodes = frame

    wanted, requested = claim
    sites = [shape for node in nodes if (shape := _shape(node, data)) is not None
             and (shape[2], shape[3], shape[4]) == (wanted[2], wanted[3], wanted[4])]
    if len(sites) != 1:
        return unavailable
    target, right, numerator, (count, op, offset), division_operator = sites[0]
    guards = guards_for_operation(body, target, data, [numerator, count], language=language, integer_abi=abi,
                                  selected_value=right)
    if guards.status == 'unavailable':
        return unavailable
    model = ComparisonModel(target, data, abi, language)
    try:
        numerator_kind, count_kind = model.kind(numerator), model.kind(count)
        prefix = PrefixIntegerModel(data, language, resolve_integer_abi(abi))
        denominator_kind = prefix.expression_kind(right)
        if denominator_kind is None or common_integer_type([str(offset)], (), abi) is None:
            return unavailable
        division_kind = comparison_frame(numerator_kind, denominator_kind)
        native_numerator = model.registry[numerator] if numerator in model.registry else mk_val(integer_literal_value(numerator), numerator_kind.width)
        native_numerator = cast(native_numerator, division_kind.width, numerator_kind.signed)
        raw_count = cast(model.registry[count], denominator_kind.width, count_kind.signed)
        native_denominator = raw_count + mk_val(offset, denominator_kind.width) if op == '+' else raw_count - mk_val(offset, denominator_kind.width)
        native_denominator = cast(native_denominator, division_kind.width, denominator_kind.signed)
        predicates = [p.split() for p in guards.premises]
        constraints = [model.predicate(*p) for p in predicates]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, TypeError, ValueError):
        return unavailable
    details = {**unavailable, 'division_status': 'checked', 'integer_abi': integer_abi_record(abi),
               **source_model_scope(),
               'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                    'operator': division_operator, 'operands': [numerator, f'({count}{op}{offset})'],
                                    'types': dict(model.types), 'premises': list(guards.premises),
                                    'denominator_width': denominator_kind.width, 'denominator_signed': denominator_kind.signed,
                                    'division_width': division_kind.width, 'division_signed': division_kind.signed}}
    zero = native_denominator == 0
    fault = division_undefined(native_numerator, native_denominator, signed=division_kind.signed)
    fault = zero if requested == 'zero' else z3.And(fault, z3.Not(zero)) if requested == 'overflow' else fault
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return unavailable
        solver.add(fault)
        result = check_solver(solver)
        if result == z3.unsat:
            return {**details, 'violation': False, 'reason': 'no requested division fault in the admitted source model'}
        if result != z3.sat:
            return unavailable
        values = format_vars(solver.model(), model.registry,
                             {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True)
    values = validate_integer_witness(values, tuple(model.types.items()), (), abi)
    if values is None or any(not model.evaluate(*p, values) for p in predicates):
        return unavailable

    def converted(value, kind):
        bits = value % (1 << kind.width)
        return bits - (1 << kind.width) if kind.signed and bits >= (1 << (kind.width - 1)) else bits

    raw_denominator = values[count] + offset if op == '+' else values[count] - offset
    if denominator_kind.signed and not -(1 << (denominator_kind.width - 1)) <= raw_denominator < (1 << (denominator_kind.width - 1)):
        return unavailable
    denominator = converted(converted(raw_denominator, denominator_kind), division_kind)
    numerator_value = converted(values[numerator] if numerator in values else integer_literal_value(numerator), division_kind)
    fault_kind = 'zero' if denominator == 0 else 'overflow' if division_kind.signed and numerator_value == -(1 << (division_kind.width - 1)) and denominator == -1 else None
    if fault_kind is None or (requested != 'any' and requested != fault_kind):
        return unavailable
    return {**details, 'violation': True, 'witness_validated': True, 'model': values,
            'denominator': denominator, 'numerator': numerator_value, 'fault_kind': 'zero-divisor' if fault_kind == 'zero' else 'signed-division-overflow',
            'division_width': division_kind.width, 'division_signed': division_kind.signed,
            'operator': division_operator, 'operands': [numerator, f'({count}{op}{offset})']}
