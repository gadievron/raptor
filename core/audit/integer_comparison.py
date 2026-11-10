"""Source-bound constant integer comparisons, without defect-intent claims."""

import operator

from core.smt_solver import DEFAULT_TIMEOUT_MS, ge, gt, le, lt, mk_val, mk_var, z3, z3_available
from core.smt_solver.session import check_solver, new_solver, query_budget, solver_reason_unknown
from core.smt_solver.witness import format_vars

from .arithmetic_claim import parse_comparison_claim
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _select_comparison_site
from .arithmetic_types import common_integer_type, integer_type, model_for_integer_terms
from .integer_abi import integer_abi_record
from .integer_literals import integer_literal_value
from .integer_witness import source_model_scope, validate_integer_witness

_COMPARISONS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
                "==": operator.eq, "!=": operator.ne}


def check_integer_comparison(source, hypothesis, *, language, integer_abi=None):
    """Prove the claimed constant truth at a unique, defined source test."""
    details = {"comparison_status": "unavailable", "matches_claim": None, "entry_witness_validated": False}
    claim = parse_comparison_claim(hypothesis)
    abi = integer_abi_record(integer_abi)
    if claim is None or abi is None or not z3_available():
        return details
    prose = " ".join(hypothesis.split("`")[::2]).lower()
    words = [word.strip(".,:;()!?") for word in prose.split()]
    subjects = {tuple(words[i:i + 4]) for i in range(len(words) - 3)}
    true_claim = ("comparison", "is", "always", "true") in subjects
    false_claim = ("comparison", "is", "always", "false") in subjects
    if (true_claim == false_claim or {"true", "false"}.issubset(words)
            or {"not", "never"}.intersection(words)):
        details["reason"] = "one explicit always true or always false subject required"
        return details
    status, data, body, target = _select_comparison_site(source, claim.operands, claim.operator, language=language)
    if status != "bound":
        details["reason"] = "source comparison unavailable or ambiguous"
        return details
    guards = guards_for_operation(body, target, data, claim.operands, language=language, integer_abi=integer_abi)
    if guards.status == "unavailable":
        details["reason"] = "source prefix or comparison evaluation path unavailable"
        return details
    model = model_for_integer_terms(target, data, claim.operands, guards.premises, integer_abi, language=language)
    frame = common_integer_type(claim.operands, model.types, integer_abi)
    if model.status != "bound" or frame is None:
        details["reason"] = "builtin immutable entry types and supported comparison conversions required"
        return details
    registry = {name: mk_var(name, frame.width) for name, _ in model.types}

    def term(atom):
        return registry[atom] if atom in registry else mk_val(integer_literal_value(atom), frame.width)

    def predicate(a, op, b):
        left, right = term(a), term(b)
        if op in {"==", "!="}:
            return left == right if op == "==" else left != right
        return {"<": lt, "<=": le, ">": gt, ">=": ge}[op](left, right, frame.signed)

    constraints = []
    for name, spelling in model.types:
        kind = integer_type(spelling, integer_abi)
        low = -(1 << (kind.width - 1)) if kind.signed else 0
        high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        constraints.extend((ge(registry[name], mk_val(low, frame.width), frame.signed),
                            le(registry[name], mk_val(high, frame.width), frame.signed)))
    for text in guards.premises:
        parts = text.split()
        if len(parts) != 3 or parts[1] not in _COMPARISONS:
            details["reason"] = "unsupported reaching predicate"
            return details
        constraints.append(predicate(*parts))
    condition = predicate(claim.operands[0], claim.operator, claim.operands[1])
    details.update(comparison_status="checked", integer_abi=abi, checked_property="constant-integer-comparison",
                   source_operation={"line": target.start_point[0] + 1, "column": target.start_point[1] + 1,
                                     "operator": claim.operator, "operands": list(claim.operands),
                                     "types": dict(model.types), "premises": list(guards.premises),
                                     "comparison_width": frame.width, "comparison_signed": frame.signed},
                   **source_model_scope())
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        entry = check_solver(solver)
        if entry != z3.sat:
            details["reason"] = "entry infeasible or undecided"
            if entry == z3.unknown:
                details["reason"] += ": " + solver_reason_unknown(solver)
            return details
        values = validate_integer_witness(format_vars(solver.model(), registry, frame.signed, completion=True),
                                          model.types, guards.premises, integer_abi)
        if values is None:
            details["reason"] = "entry witness violates source domains or guards"
            return details
        a, b = [values[atom] if atom in values else integer_literal_value(atom) for atom in claim.operands]
        if _COMPARISONS[claim.operator](a, b) != true_claim:
            details.update(matches_claim=False, reason="reachable entry witness contradicts claimed truth")
            return details
        solver.add(z3.Not(condition) if true_claim else condition)
        contrary = check_solver(solver)
        if contrary == z3.unknown:
            details["reason"] = solver_reason_unknown(solver)
            return details
        if contrary == z3.sat:
            details.update(matches_claim=False, reason="comparison is not constant in the claimed direction")
            return details
    details.update(matches_claim=True, constant_truth=true_claim, entry_witness=values,
                   entry_witness_validated=True,
                   reason="opposite comparison truth is infeasible in the admitted source model")
    return details
