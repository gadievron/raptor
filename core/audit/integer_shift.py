"""Source-bound shift-count faults with independent operand promotions.

This checks negative or oversized counts in C and C++, not signed left-shift
value rules or the implementation's treatment of a negative right-shift value.
"""

from core.smt_solver import DEFAULT_TIMEOUT_MS, ge, gt, le, lt, mk_val, mk_var, new_solver, z3, z3_available
from core.smt_solver.csem import cast, shift_count_invalid
from core.smt_solver.session import check_solver, query_budget, solver_reason_unknown
from core.smt_solver.witness import format_vars

from .arithmetic_claim import parse_shift_claim
from .arithmetic_expression_types import promoted
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _select_arithmetic_site
from .arithmetic_types import common_integer_type, integer_type, model_for_integer_terms
from .integer_goal import SHIFT_GOALS, parse_integer_goal
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_literals import integer_literal_value
from .integer_witness import source_model_scope, validate_integer_witness


class _Unsupported(Exception):
    pass


def check_shift_count(source, hypothesis, *, language, integer_abi=None):
    """Find an invalid count at one uniquely bound atomic source shift."""
    details = {'shift_status': 'unavailable', 'violation': None, 'witness_validated': False}
    claim = parse_shift_claim(hypothesis)
    abi = resolve_integer_abi(integer_abi)
    if claim is None or abi is None or not z3_available():
        return details
    requested = parse_integer_goal(hypothesis, SHIFT_GOALS)
    if requested is None:
        details["reason"] = "closed positive integer goal required"
        return details
    status, data, body, target = _select_arithmetic_site(source, claim.operands, claim.operator, language=language)
    if status != 'bound':
        details['reason'] = 'source shift is unavailable or ambiguous'
        return details
    guards = guards_for_operation(body, target, data, claim.operands, language=language, integer_abi=abi)
    if guards.status == 'unavailable':
        details['reason'] = 'source prefix or reaching guards unavailable'
        return details
    registry, kinds, types = {}, {}, {}

    def term(atom):
        value = integer_literal_value(atom)
        if value is not None:
            kind = common_integer_type([atom], (), abi)
            if kind is None:
                raise _Unsupported('literal type requires a wider conversion model')
            return mk_val(value, kind.width), kind
        if atom not in registry:
            model = model_for_integer_terms(target, data, [atom], (), abi, language=language)
            spelling = dict(model.types).get(atom)
            kind = integer_type(spelling, abi)
            if model.status != 'bound' or kind is None or len(registry) >= 8:
                raise _Unsupported('immutable builtin entry parameter required')
            registry[atom] = mk_var(atom, kind.promoted_width)
            kinds[atom], types[atom] = kind, spelling
        return registry[atom], promoted(kinds[atom])

    constraints = []
    try:
        _, left_kind = term(claim.operands[0])
        count, count_kind = term(claim.operands[1])
        for predicate in guards.premises:
            parts = predicate.split()
            if len(parts) != 3 or parts[1] not in {'<', '<=', '>', '>=', '==', '!='}:
                raise _Unsupported('unsupported source guard')
            a, op, b = parts
            model = model_for_integer_terms(target, data, [a, b], (), abi, language=language)
            frame = common_integer_type([a, b], model.types, abi)
            if model.status != 'bound' or frame is None:
                raise _Unsupported('guard conversions require a richer type model')
            av, ak = term(a)
            bv, bk = term(b)
            av, bv = cast(av, frame.width, ak.signed), cast(bv, frame.width, bk.signed)
            if op in {'==', '!='}:
                constraints.append(av == bv if op == '==' else av != bv)
            else:
                constraints.append({'<': lt, '<=': le, '>': gt, '>=': ge}[op](av, bv, frame.signed))
    except _Unsupported as refusal:
        details['reason'] = str(refusal)
        return details
    for name, kind in kinds.items():
        low = -(1 << (kind.width - 1)) if kind.signed else 0
        high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        value = registry[name]
        constraints.extend((ge(value, mk_val(low, value.size()), kind.promoted_signed),
                            le(value, mk_val(high, value.size()), kind.promoted_signed)))
    zero = mk_val(0, count.size())
    negative = lt(count, zero, True) if count_kind.signed else z3.BoolVal(False)
    invalid = shift_count_invalid(count, left_kind.width, signed=count_kind.signed)
    fault = negative if requested == 'negative' else z3.And(invalid, z3.Not(negative)) if requested == 'oversized' else invalid
    details.update(shift_status='checked', integer_abi=integer_abi_record(abi),
                   source_operation={'line': target.start_point[0] + 1, 'column': target.start_point[1] + 1,
                                     'operands': list(claim.operands), 'operator': claim.operator,
                                     'left_promoted_width': left_kind.width, 'count_promoted_width': count_kind.width,
                                     'count_signed': count_kind.signed, 'types': dict(types), 'premises': list(guards.premises)},
                   checked_property='shift-count-definedness', **source_model_scope())
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if guards.premises:
            entry = check_solver(solver)
            if entry != z3.sat:
                details['reason'] = 'entry path is infeasible or undecided'
                if entry == z3.unknown:
                    details['reason'] += ': ' + solver_reason_unknown(solver)
                return details
        solver.add(fault)
        verdict = check_solver(solver)
        if verdict == z3.unknown:
            details['reason'] = solver_reason_unknown(solver)
            return details
        if verdict != z3.sat:
            details.update(violation=False, reason='no invalid count in the admitted source model')
            return details
        model = format_vars(solver.model(), registry, {name: kind.promoted_signed for name, kind in kinds.items()}, completion=True)
    values = validate_integer_witness(model, tuple(types.items()), guards.premises, abi) if types else {}
    if values is None:
        details['reason'] = 'witness violates source guards or storage domains'
        return details
    count_value = values[claim.operands[1]] if claim.operands[1] in values else integer_literal_value(claim.operands[1])
    fault_kind = 'negative' if count_value < 0 else 'oversized' if count_value >= left_kind.width else None
    if fault_kind is None or (requested != 'any' and fault_kind != requested):
        details['reason'] = 'witness does not exhibit the requested shift count fault'
        return details
    details.update(violation=True, witness_validated=True, model=values, fault_kind=fault_kind,
                   count_value=count_value, reason='source count is negative or at least the promoted left width')
    return details
