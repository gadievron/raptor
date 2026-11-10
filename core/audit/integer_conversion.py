"""Source-bound value-changing conversions to builtin unsigned integer locals.

A witnessed conversion is a mathematical observation, not proof of unintended
truncation or application-entry reachability. Boolean and signed destinations,
compound initializers and implicit user-defined conversions are outside this frame.
"""

from hashlib import sha256

from core.smt_solver import DEFAULT_TIMEOUT_MS, z3, z3_available
from core.smt_solver.session import check_solver, new_solver, query_budget, solver_reason_unknown
from core.smt_solver.witness import format_vars

from ._util import IDENTIFIER_RE
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import has_builtin_integer_type, integer_type, model_for_integer_terms
from .condition_extraction import _get_parser
from .function_execution_frame import ordinary_function_frame
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_goal import parse_integer_goal
from .integer_witness import source_model_scope, validate_integer_witness

_GOALS = {"non representable unsigned conversion": "conversion"}
_MAX_SOURCE_CHARS = 65536
_MAX_NODES = 2048
_MAX_CANDIDATES = 16


def _claim(hypothesis):
    if parse_integer_goal(hypothesis, _GOALS) is None:
        return None
    parts = [part.strip() for part in hypothesis.split('`')[1].split('=')]
    if len(parts) != 2 or any(not IDENTIFIER_RE.fullmatch(part) for part in parts) or parts[0] == parts[1]:
        return None
    destination, incoming = parts
    return incoming, destination


def _frame(source, abi, language):
    if (language not in {'c', 'cpp'} or resolve_integer_abi(abi) is None
            or not isinstance(source, str) or len(source) > _MAX_SOURCE_CHARS):
        return None
    try:
        parser = _get_parser(language)
        if parser is None:
            return None
        data = source.encode('utf-8')
        root = parser.parse(data).root_node
    except Exception:
        return None  # optional syntax/encoding failures carry no source credit
    if root.has_error or any(n.type not in {'comment', 'function_definition'} for n in root.named_children):
        return None
    functions = [n for n in root.named_children if n.type == 'function_definition']
    if len(functions) != 1 or not ordinary_function_frame(functions[0], data, language):
        return None
    body = functions[0].child_by_field_name('body')
    stack, nodes = [body], []
    while stack:
        node = stack.pop()
        nodes.append(node)
        if len(nodes) > _MAX_NODES or node.type.startswith('preproc_') or node.type in {
            'function_definition', 'lambda_expression', 'generic_expression',
        }:
            return None
        stack.extend(reversed(node.named_children))
    return data, body, nodes


def _initializer(node, data):
    if node.type != 'declaration' or node.parent.type != 'compound_statement':
        return None
    declarations = node.children_by_field_name('declarator')
    if len(declarations) != 1:
        return None
    init = declarations[0]
    if init.type != 'init_declarator' or not any(n.type == '=' for n in init.children):
        return None
    name = init.child_by_field_name('declarator')
    if name is None or name.type != 'identifier':
        return None
    return init, name, _unwrap(init.child_by_field_name('value'))


def _binding(frame, incoming, destination, abi, language):
    data, body, nodes = frame
    if incoming == destination:
        return None

    def text(node):
        return data[node.start_byte:node.end_byte].decode('utf-8') if node is not None else ''

    matches = []
    for node in nodes:
        parts = _initializer(node, data)
        if parts is None:
            continue
        init, name, value = parts
        if text(name) != destination:
            continue
        if value is None or value.type != 'identifier' or text(value) != incoming:
            return None
        type_node = node.child_by_field_name('type')
        spelling = text(type_node)
        if not has_builtin_integer_type(type_node, spelling, language):
            return None
        if any(n not in (type_node, init) and n.type != 'comment' for n in node.named_children):
            return None
        destination_kind = integer_type(spelling, abi)
        if destination_kind is None or destination_kind.signed or spelling in {'bool', '_Bool'}:
            return None
        model = model_for_integer_terms(value, data, [incoming], (), abi, language=language)
        source_spelling = dict(model.types).get(incoming)
        source_kind = integer_type(source_spelling, abi)
        if model.status != 'bound' or source_kind is None:
            return None
        matches.append(dict(target=node, value=value, body=body, data=data,
                            incoming=incoming, destination=destination,
                            source_type=source_spelling, source_kind=source_kind,
                            destination_type=spelling, destination_kind=destination_kind))
    return matches[0] if len(matches) == 1 else None


def conversion_candidates(source, *, language, integer_abi):
    """Pure syntax/type leads; no guards, solver objects or proof authority."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _, nodes = frame
    pairs = []
    for node in nodes:
        parts = _initializer(node, data)
        if parts is None:
            continue
        _, name, value = parts
        if value is None or value.type != 'identifier':
            continue
        pair = (data[value.start_byte:value.end_byte].decode(), data[name.start_byte:name.end_byte].decode())
        if pair not in pairs:
            pairs.append(pair)
            if len(pairs) >= _MAX_CANDIDATES:
                break
    candidates = []
    for incoming, destination in pairs:
        bound = _binding(frame, incoming, destination, integer_abi, language)
        if bound is None:
            continue
        kind, dest = bound['source_kind'], bound['destination_kind']
        low = -(1 << (kind.width - 1)) if kind.signed else 0
        high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        if low < 0 or high > (1 << dest.width) - 1:
            candidates.append(bound)
    return candidates


def check_integer_conversion(source, hypothesis, *, language, integer_abi=None):
    """Check one positive conversion objective in a defined entry model."""
    result = {'conversion_status': 'unavailable', 'value_loss': None,
              'entry_feasible': None, 'witness_validated': False}
    claim = _claim(hypothesis)
    frame = _frame(source, integer_abi, language) if claim is not None else None
    bound = _binding(frame, *claim, integer_abi, language) if frame is not None else None
    if bound is None or not z3_available():
        return {**result, 'reason': 'closed objective, unique builtin conversion or target ABI unavailable'}
    incoming, destination = claim
    target, data = bound['target'], bound['data']
    guards = guards_for_operation(bound['body'], target, data, [incoming],
                                  language=language, integer_abi=integer_abi)
    if guards.status == 'unavailable':
        return {**result, 'reason': 'source prefix, reaching path or input identity unavailable'}
    model = ComparisonModel(bound['value'], data, integer_abi, language)
    predicates = []
    for predicate in guards.premises:
        parts = predicate.split()
        if len(parts) != 3 or parts[1] not in COMPARISONS:
            return {**result, 'reason': 'unsupported typed guard'}
        predicates.append(parts)
    try:
        source_kind = model.kind(incoming)
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
    except UnsupportedComparison as error:
        return {**result, 'reason': str(error)}
    width = bound['destination_kind'].width
    value = z3.BV2Int(model.registry[incoming], is_signed=source_kind.signed)
    maximum = (1 << width) - 1
    result.update(integer_abi=integer_abi_record(integer_abi), source_types=dict(model.types),
                  destination_type=bound['destination_type'], destination_width=width,
                  checked_property='nonrepresentable-unsigned-initializer', premises=list(guards.premises),
                  source_operation={'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                    'byte_start': target.start_byte, 'byte_end': target.end_byte,
                                    'incoming': incoming, 'destination': destination},
                  source_sha256=sha256(source.encode()).hexdigest(), **source_model_scope())
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        entry = check_solver(solver)
        if entry != z3.sat:
            result.update(entry_feasible=False if entry == z3.unsat else None,
                          reason='entry infeasible or undecided')
            return result
        result['entry_feasible'] = True
        solver.add(z3.Or(value < 0, value > maximum))
        verdict = check_solver(solver)
        if verdict == z3.unknown:
            return {**result, 'reason': 'conversion query undecided: ' + solver_reason_unknown(solver)}
        if verdict != z3.sat and verdict != z3.unsat:
            return {**result, 'reason': 'conversion query has no definitive verdict'}
        result.update(conversion_status='checked', value_loss=verdict == z3.sat,
                      reason='conversion property solved in the admitted source model')
        if verdict != z3.sat:
            return result
        values = format_vars(solver.model(), model.registry,
                             {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True)
    checked = validate_integer_witness(values, tuple(model.types.items()), (), integer_abi)
    if checked is None or any(not model.evaluate(*parts, checked) for parts in predicates):
        return {**result, 'value_loss': None, 'reason': 'witness violates source guards or storage domains'}
    original = checked[incoming]
    converted = original % (1 << width)
    if 0 <= original <= maximum or original == converted:
        return {**result, 'value_loss': None, 'reason': 'witness does not exhibit conversion value loss'}
    result.update(witness=checked, source_value=original, converted_value=converted, witness_validated=True)
    return result
