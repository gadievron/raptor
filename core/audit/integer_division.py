"""Source-bound integer division/remainder faults under an explicit target ABI.

A witness establishes a fault in the admitted function-entry model, not
caller reachability. Safe or unsupported sites cannot refute a function.
"""

from dataclasses import asdict

from core.smt_solver import DEFAULT_TIMEOUT_MS, z3, z3_available
from core.smt_solver.csem import division_undefined
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility, check_verb_feasibility, make_val, make_var
from core.smt_solver.session import query_budget

from .arithmetic_claim import parse_division_claim
from .arithmetic_operation import bind_arithmetic_operation
from .arithmetic_types import common_integer_type
from .integer_abi import integer_abi_record
from .integer_literals import integer_literal_value
from .integer_witness import source_model_scope, validate_integer_witness


def check_integer_division(source, hypothesis, *, language, integer_abi=None):
    """Find a defined-prefix input causing zero division or signed MIN/-1."""
    details = {'division_status': 'unavailable', 'violation': None, 'witness_validated': False}
    claim = parse_division_claim(hypothesis)
    if claim is None or integer_abi_record(integer_abi) is None or not z3_available():
        return details
    prose = ' '.join(hypothesis.split('`')[::2]).lower().replace('-', ' ')
    words = [word.strip('.,:;()!?') for word in prose.split()]
    pairs = {tuple(words[i:i + 2]) for i in range(len(words) - 1)}
    triples = {tuple(words[i:i + 3]) for i in range(len(words) - 2)}
    zero_claim = ('zero', 'divisor') in pairs or any(
        (operation, 'by', zero) in triples
        for operation in ('division', 'divide', 'remainder', 'modulo') for zero in ('zero', '0'))
    overflow_claim = bool(pairs & {('division', 'overflow'), ('remainder', 'overflow')})
    generic_claim = bool(triples & {('undefined', 'integer', 'division'), ('undefined', 'integer', 'remainder')})
    if (zero_claim and overflow_claim) or not (zero_claim or overflow_claim or generic_claim):
        details['reason'] = 'division fault subject is unsupported or ambiguous'
        return details
    requested = 'zero-divisor' if zero_claim else 'signed-division-overflow' if overflow_claim else 'any'
    operation = bind_arithmetic_operation(source, claim.operands, claim.operator,
                                          language=language, integer_abi=integer_abi)
    if operation.status != 'bound' or operation.guard_status == 'unavailable' or operation.type_status != 'bound':
        details['reason'] = 'source operation, prefix or integer types unavailable'
        return details
    kind = common_integer_type(claim.operands, operation.types, integer_abi)
    if kind is None or operation.profile != kind.profile:
        return details
    from core.smt_solver import BVProfile

    profile = BVProfile(kind.width, kind.signed)
    registry = {}
    operands = [make_val(atom, profile=profile) if integer_literal_value(atom) is not None
                else make_var(atom, registry, profile=profile) for atom in claim.operands]
    guards = [PathCondition(text, index) for index, text in enumerate(operation.premises + operation.domains)]
    details.update(division_status='checked', source_operation=asdict(operation),
                   integer_abi=integer_abi_record(integer_abi), **source_model_scope())
    with query_budget(DEFAULT_TIMEOUT_MS):
        if guards:
            entry = check_path_feasibility(guards, profile=profile, reduce_constraints=False)
            if entry.feasible is not True or entry.unknown or entry.unknown_reasons:
                details.update(reason='entry path is infeasible or unencodable', entry_feasible=entry.feasible,
                               unknown=entry.unknown, unknown_reasons=[asdict(r) for r in entry.unknown_reasons])
                return details
        fault = division_undefined(*operands, signed=kind.signed)
        zero = z3.BitVecVal(0, kind.width)
        if requested == 'zero-divisor':
            fault = operands[1] == zero
        elif requested == 'signed-division-overflow':
            fault = z3.And(fault, operands[1] != zero)
        result = check_verb_feasibility([('integer division/remainder is undefined', fault)], guards,
                                        registry, profile=profile, reduce_constraints=False)
    if result.feasible is None or result.unknown or result.unknown_reasons:
        details.update(reason='division obligation not completely solved', unknown=result.unknown,
                       unknown_reasons=[asdict(r) for r in result.unknown_reasons])
        return details
    details.update(violation=result.feasible, reason=result.reasoning)
    if result.feasible is False:
        return details
    values = validate_integer_witness(result.model, operation.types, operation.premises, integer_abi)
    if values is None:
        details.update(violation=None, reason='witness violates source guards or storage domains')
        return details
    a, b = [values[atom] if atom in values else integer_literal_value(atom) for atom in claim.operands]
    fault_kind = ('zero-divisor' if b == 0 else 'signed-division-overflow'
                  if kind.signed and a == -(1 << (kind.width - 1)) and b == -1 else None)
    if fault_kind is None or (requested != 'any' and fault_kind != requested):
        details.update(violation=None, reason='witness does not exhibit a source division fault')
        return details
    details.update(model=values, witness_validated=True, fault_kind=fault_kind,
                   operands=list(claim.operands), operator=claim.operator)
    return details
