"""Independent integer checks on source-bound SMT counterexamples.

This evaluator uses Python integers, never Z3 expressions or wrapped arithmetic.
It covers only the admitted atomic comparisons and common promoted profile.
"""

import operator

from ._util import IDENTIFIER_RE
from .integer_literals import integer_literal_value
from .arithmetic_types import integer_type

_COMPARISONS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "==": operator.eq, "!=": operator.ne}
_ARITHMETIC = {"+": operator.add, "-": operator.sub, "*": operator.mul}


def source_model_scope():
    """Explicit scope shared by admitted source integer obligations."""
    return {
        "proof_scope": "function-entry-source-model",
        "line_basis": "supplied-source",
        "assumptions": [
            "supplied declarations describe the active build",
            "entry parameters have their declared value domains",
            "no additional caller constraints are encoded",
        ],
    }


def _atom(text, values):
    if IDENTIFIER_RE.fullmatch(text):
        return values.get(text)
    return integer_literal_value(text)


def validate_integer_witness(model, types, premises, integer_abi):
    """Return a completed, checked source assignment, or None.

    Omitted unconstrained parameters may take zero. This completion is
    accepted only after all declared storage ranges and source guards pass.
    Extra solver symbols cannot become source parameter assignments.
    """
    if not isinstance(model, dict) or not types:
        return None
    values = {}
    for name, spelling in types:
        value = model.get(name, 0)
        kind = integer_type(spelling, integer_abi)
        if type(value) is not int or kind is None:
            return None
        low = -(1 << (kind.width - 1)) if kind.signed else 0
        high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        if not low <= value <= high:
            return None
        values[name] = value
    for premise in premises:
        parts = premise.split()
        if len(parts) != 3 or parts[1] not in _COMPARISONS:
            return None
        left, op, right = parts
        a, b = _atom(left, values), _atom(right, values)
        if type(a) is not int or type(b) is not int or not _COMPARISONS[op](a, b):
            return None
    return values


def evaluate_integer_operation(operation, operands, op, values, integer_abi):
    """Exact binary result and promoted range, or None for unsupported input."""
    if len(operands) != 2 or op not in _ARITHMETIC or not operation.types:
        return None
    a, b = (_atom(atom, values) for atom in operands)
    kind = integer_type(operation.types[0][1], integer_abi)
    if type(a) is not int or type(b) is not int or kind is None:
        return None
    width, signed = kind.promoted_width, kind.promoted_signed
    low = -(1 << (width - 1)) if signed else 0
    high = (1 << (width - (1 if signed else 0))) - 1
    return _ARITHMETIC[op](a, b), low, high


def validate_overflow_result(result, operation, operands, op, integer_abi):
    """A SAT verdict must exhibit an actual out-of-range mathematical result."""
    checked = dict(result)

    def decline(reason):
        checked.update(feasible=None, model={}, reasoning=reason, witness_validated=False)
        return checked

    if result.get("unknown") or result.get("unknown_reasons") or result.get("smt_available") is False:
        return decline("overflow obligation was not completely encoded or solved")
    if type(result.get("feasible")) is not bool:
        return decline("overflow obligation has no definitive solver verdict")
    if result["feasible"] is False:
        return checked  # UNSAT is not a counterexample and carries no model authority.
    if len(operands) != 2 or op not in _ARITHMETIC:
        return decline("unsupported source overflow witness expression")
    values = validate_integer_witness(result.get("model"), operation.types, operation.premises, integer_abi)
    if values is None:
        return decline("overflow witness violates a source guard or declared value domain")
    evaluated = evaluate_integer_operation(operation, operands, op, values, integer_abi)
    if evaluated is None:
        return decline("overflow witness does not bind the source operands")
    value, low, high = evaluated
    if low <= value <= high:
        return decline("overflow witness produces an in-range mathematical result")
    checked.update(model=values, witness_validated=True, mathematical_result=value,
                   result_range={"minimum": low, "maximum": high})
    return checked
