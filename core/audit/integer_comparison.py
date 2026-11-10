"""Source-bound constant integer comparisons, without defect-intent claims."""

from core.smt_solver import DEFAULT_TIMEOUT_MS, z3, z3_available
from core.smt_solver.session import check_solver, new_solver, query_budget, solver_reason_unknown
from core.smt_solver.witness import format_vars

from .arithmetic_claim import parse_comparison_claim
from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _select_comparison_site
from .integer_abi import integer_abi_record
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_witness import source_model_scope, validate_integer_witness


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
    model = ComparisonModel(target, data, integer_abi, language)
    predicates = []
    for text in guards.premises:
        parts = text.split()
        if len(parts) != 3 or parts[1] not in COMPARISONS:
            details["reason"] = "unsupported reaching predicate"
            return details
        predicates.append(parts)
    target_predicate = (claim.operands[0], claim.operator, claim.operands[1])
    try:
        condition = model.predicate(*target_predicate)
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
        frame = model.frame(*claim.operands)
    except UnsupportedComparison as refusal:
        details["reason"] = str(refusal)
        return details
    details.update(comparison_status="checked", integer_abi=abi, checked_property="constant-integer-comparison",
                   source_operation={"line": target.start_point[0] + 1, "column": target.start_point[1] + 1,
                                     "operator": claim.operator, "operands": list(claim.operands),
                                     "types": dict(model.types), "premises": list(guards.premises),
                                     "parameter_promotions": {name: {"width": kind.promoted_width, "signed": kind.promoted_signed}
                                                              for name, kind in model.kinds.items()},
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
        values = validate_integer_witness(format_vars(solver.model(), model.registry,
                                                      {name: kind.promoted_signed for name, kind in model.kinds.items()},
                                                      completion=True),
                                          tuple(model.types.items()), (), integer_abi)
        if values is None or any(not model.evaluate(*parts, values) for parts in predicates):
            details["reason"] = "entry witness violates source domains or guards"
            return details
        if model.evaluate(*target_predicate, values) != true_claim:
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
