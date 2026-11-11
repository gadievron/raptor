"""Source-bound grouped builtin mask comparisons, without defect-intent credit."""

from collections import Counter

from core.smt_solver import DEFAULT_TIMEOUT_MS, mk_val, z3, z3_available
from core.smt_solver.csem import cast
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_prefix import PrefixIntegerModel
from .arithmetic_types import common_integer_type, model_for_integer_terms
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_comparison_model import ComparisonModel, UnsupportedComparison
from .integer_comparison_types import comparison_frame
from .integer_conversion import _frame
from .integer_goal import COMPARISON_GOALS, parse_integer_goal
from .integer_literals import integer_literal_value, source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness


def _shape(node, data):
    """Read the actual comparison tree, preserving C operator precedence."""
    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    if node is None or node.type != 'binary_expression':
        return None
    op = text(node.child_by_field_name('operator'))
    left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
    if op not in {'==', '!='} or left is None or left.type != 'binary_expression':
        return None
    if text(left.child_by_field_name('operator')) != '&':
        return None
    name, mask = (_unwrap(left.child_by_field_name(field)) for field in ('left', 'right'))
    if name is None or name.type != 'identifier':
        return None
    mask_atom, value_atom = source_integer_atom(mask, data), source_integer_atom(right, data)
    mask_value, value = integer_literal_value(mask_atom), integer_literal_value(value_atom)
    if mask_value is None or value is None or mask_value < 0:
        return None
    return node, left, text(name), mask_value, value_atom, value, op


def _claim(hypothesis, abi, language):
    requested = parse_integer_goal(hypothesis, COMPARISON_GOALS)
    if requested is None:
        return None
    expression = hypothesis.split('`')[1]
    if len(expression) > 512:
        return None
    # Parse the complete quoted expression with the same grammar as source.
    # A semicolon, statement or extra return cannot become a partial claim.
    frame = _frame('int Query(void){return ' + expression + ';}', abi, language)
    if frame is None:
        return None
    data, body, _ = frame
    children = [node for node in body.named_children if node.type != 'comment']
    if len(children) != 1 or children[0].type != 'return_statement':
        return None
    values = [node for node in children[0].named_children if node.type != 'comment']
    shape = _shape(_unwrap(values[0]), data) if len(values) == 1 else None
    return (shape, requested == 'true') if shape is not None else None


def mask_comparison_candidates(source, *, language, integer_abi):
    """Pure bounded syntax/type leads, without any native query or grade."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _, nodes = frame
    shapes = [shape for node in nodes if (shape := _shape(node, data)) is not None]
    occurrences = Counter((shape[2], shape[3], shape[5], shape[6]) for shape in shapes)
    result = []
    for shape in shapes:
        if occurrences[(shape[2], shape[3], shape[5], shape[6])] != 1:
            continue
        target, left, name, mask, value_atom, value, op = shape
        binding = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
        if (binding.status != 'bound'
                or common_integer_type([str(mask), value_atom], (), integer_abi) is None):
            continue
        # A bit absent from a nonnegative AND mask cannot appear in its
        # result. Exact native validation still owns every source obligation.
        if value >= 0 and value & ~mask:
            result.append((target, name, mask, value, op))
        if len(result) >= 16:
            break
    return result


def check_mask_comparison(source, hypothesis, *, language, integer_abi=None):
    """Prove constant truth with entry SAT, contrary UNSAT and replay."""
    unavailable = {'comparison_status': 'unavailable', 'matches_claim': None,
                   'entry_witness_validated': False}
    claim = _claim(hypothesis, integer_abi, language)
    frame = _frame(source, integer_abi, language) if claim is not None else None
    if frame is None or not z3_available():
        return unavailable
    wanted, requested = claim
    data, body, nodes = frame
    sites = [shape for node in nodes if (shape := _shape(node, data)) is not None
             and (shape[2], shape[3], shape[5], shape[6]) == (wanted[2], wanted[3], wanted[5], wanted[6])]
    if len(sites) != 1:
        return unavailable
    target, left, name, mask, value_atom, value, op = sites[0]
    binding = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
    guards = guards_for_operation(body, target, data, [name], language=language, integer_abi=integer_abi)
    if binding.status != 'bound' or guards.status == 'unavailable':
        return unavailable
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        source_kind = model.kind(name)
        predicates = [predicate.split() for predicate in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
        prefix = PrefixIntegerModel(data, language, resolve_integer_abi(integer_abi))
        kind = prefix.expression_kind(left)
        literal_kind = common_integer_type([value_atom, str(mask)], (), integer_abi)
        if kind is None or literal_kind is None:
            return unavailable
        comparison_kind = comparison_frame(kind, literal_kind)
        raw = cast(model.registry[name], kind.width, source_kind.signed)
        masked = raw & mk_val(mask, kind.width)
        compared = cast(masked, comparison_kind.width, kind.signed)
        equality = compared == mk_val(value, comparison_kind.width)
        condition = equality if op == '==' else z3.Not(equality)
    except (UnsupportedComparison, TypeError, ValueError):
        return unavailable
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return unavailable
        values = format_vars(solver.model(), model.registry,
                             {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True)
        checked = validate_integer_witness(values, tuple(model.types.items()), (), integer_abi)
        if checked is None or any(not model.evaluate(*parts, checked) for parts in predicates):
            return unavailable
        bits = (checked[name] & mask) % (1 << comparison_kind.width)
        actual = bits - (1 << comparison_kind.width) if comparison_kind.signed and bits >= (1 << (comparison_kind.width - 1)) else bits
        expected_bits = value % (1 << comparison_kind.width)
        expected = expected_bits - (1 << comparison_kind.width) if comparison_kind.signed and expected_bits >= (1 << (comparison_kind.width - 1)) else expected_bits
        replay = actual == expected if op == '==' else actual != expected
        if replay != requested:
            return {**unavailable, 'comparison_status': 'checked', 'matches_claim': False}
        solver.add(z3.Not(condition) if requested else condition)
        if check_solver(solver) != z3.unsat:
            return unavailable
    return {'comparison_status': 'checked', 'matches_claim': True, 'constant_truth': requested,
            'entry_witness_validated': True, 'entry_witness': checked,
            'checked_property': 'constant-mask-comparison', 'integer_abi': integer_abi_record(integer_abi),
            'source_operation': {'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                 'name': name, 'mask': mask, 'value': value, 'operator': op,
                                 'types': dict(model.types), 'premises': list(guards.premises),
                                 'comparison_width': comparison_kind.width, 'comparison_signed': comparison_kind.signed},
            **source_model_scope()}
