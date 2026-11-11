"""Diagnostic truth difference under an explicit alternative mask grouping.

Neither grouping is declared intended. A witness proves only that the actual
source condition and the reported alternative differ at an admitted entry.
"""

from collections import Counter

from core.smt_solver import DEFAULT_TIMEOUT_MS, ge, gt, le, lt, mk_val, z3, z3_available
from core.smt_solver.csem import cast
from core.smt_solver.session import check_solver, new_solver, query_budget
from core.smt_solver.witness import format_vars

from .arithmetic_guards import guards_for_operation
from .arithmetic_types import model_for_integer_terms
from .integer_comparison_model import COMPARISONS, ComparisonModel, UnsupportedComparison
from .integer_comparison_types import comparison_frame
from .integer_condition import _claim, _shape
from .integer_conversion import _frame
from .integer_goal import parse_integer_goal
from .integer_literals import integer_literal_value
from .integer_witness import source_model_scope, validate_integer_witness

GROUPING_GOALS = {"condition grouping changes truth": "different"}


def _supported(shape):
    return shape is not None and all(
        (value := integer_literal_value(atom)) is not None and value >= 0
        for atom in (shape[2], shape[4])
    )


def grouping_candidates(source, *, language, integer_abi):
    """Append hints for unparenthesized cases outside constant-false discovery."""
    frame = _frame(source, integer_abi, language)
    if frame is None:
        return []
    data, _body, nodes = frame
    shapes = [shape for node in nodes
              if (shape := _shape(node, data, language, integer_abi)) is not None]
    occurrences = Counter(shape[1:] for shape in shapes)
    rows = []
    for shape in shapes:
        if not _supported(shape) or occurrences[shape[1:]] != 1:
            continue
        target, name, left, op, right = shape
        # Explicitly grouping the inner comparison is deliberate syntax;
        # do not manufacture an alternative-intent hint for that spelling.
        if target.child_by_field_name("right").type != "binary_expression":
            continue
        a, b = integer_literal_value(left), integer_literal_value(right)
        if a <= 1 or not COMPARISONS[op](a, b):
            continue  # preserve existing false-literal comparison candidates
        model = model_for_integer_terms(target, data, [name], (), integer_abi, language=language)
        if model.status == "bound":
            rows.append(shape)
        if len(rows) >= 16:
            break
    return rows


def _convert(value, kind):
    bits = value % (1 << kind.width)
    return bits - (1 << kind.width) if kind.signed and bits >= (1 << (kind.width - 1)) else bits


def check_integer_grouping(source, hypothesis, *, language, integer_abi=None):
    """Find and independently replay an actual/alternative truth difference."""
    unavailable = {"comparison_status": "unavailable", "matches_claim": None, "entry_witness_validated": False}
    if parse_integer_goal(hypothesis, GROUPING_GOALS) is None or not z3_available():
        return unavailable
    wanted = _claim(hypothesis, language, integer_abi)
    frame = _frame(source, integer_abi, language)
    if wanted is None or frame is None:
        return unavailable
    data, body, nodes = frame
    shapes = [shape for node in nodes if (shape := _shape(node, data, language, integer_abi)) is not None
              and shape[1:] == wanted and _supported(shape)]
    if len(shapes) != 1:
        return unavailable
    target, name, left, op, right = shapes[0]
    model = ComparisonModel(target, data, integer_abi, language)
    try:
        flag_kind, int_kind = model.kind(name), model.kind("0")
        actual_kind = comparison_frame(flag_kind, int_kind)
        flag = model.registry[name]
        inner = model.predicate(left, op, right)
        truth = z3.If(inner, mk_val(1, int_kind.width), mk_val(0, int_kind.width))
        actual = (cast(flag, actual_kind.width, flag_kind.signed)
                  & cast(truth, actual_kind.width, int_kind.signed)) != mk_val(0, actual_kind.width)
        mask_kind = comparison_frame(flag_kind, model.kind(left))
        mask = cast(flag, mask_kind.width, flag_kind.signed) & mk_val(integer_literal_value(left), mask_kind.width)
        grouped_kind = comparison_frame(mask_kind, model.kind(right))
        a = cast(mask, grouped_kind.width, mask_kind.signed)
        b = mk_val(integer_literal_value(right), grouped_kind.width)
        grouped = (a == b if op == "==" else a != b if op == "!=" else
                   {"<": lt, "<=": le, ">": gt, ">=": ge}[op](a, b, grouped_kind.signed))
        guards = guards_for_operation(body, target, data, [name], language=language,
                                      integer_abi=integer_abi, selected_condition=True)
        if guards.status == "unavailable":
            return unavailable
        predicates = [text.split() for text in guards.premises]
        constraints = [model.predicate(*parts) for parts in predicates]
        constraints.extend(model.storage_constraints())
    except (UnsupportedComparison, ValueError, TypeError):
        return unavailable
    details = {**unavailable, "comparison_status": "checked",
               "checked_property": "integer-grouping-truth-difference", **source_model_scope()}
    with query_budget(DEFAULT_TIMEOUT_MS):
        solver = new_solver()
        solver.add(*constraints)
        if check_solver(solver) != z3.sat:
            return details
        solver.add(z3.Xor(actual, grouped))
        verdict = check_solver(solver)
        if verdict == z3.unsat:
            return {**details, "matches_claim": False}
        if verdict != z3.sat:
            return details
        values = format_vars(solver.model(), model.registry,
                             {n: k.promoted_signed for n, k in model.kinds.items()}, completion=True)
    checked = validate_integer_witness(values, tuple(model.types.items()), (), integer_abi)
    if checked is None or any(not model.evaluate(*parts, checked) for parts in predicates):
        return details
    left_value, right_value = integer_literal_value(left), integer_literal_value(right)
    actual_truth = bool(_convert(checked[name], actual_kind) & int(COMPARISONS[op](left_value, right_value)))
    mask_value = _convert(_convert(checked[name], mask_kind) & _convert(left_value, mask_kind), mask_kind)
    grouped_truth = COMPARISONS[op](_convert(mask_value, grouped_kind), _convert(right_value, grouped_kind))
    if actual_truth == grouped_truth:
        return details
    return {**details, "matches_claim": True, "entry_witness_validated": True, "entry_witness": checked,
            "actual_expression": data[target.start_byte:target.end_byte].decode(),
            "grouped_expression": f"({name} & {left}) {op} {right}",
            "actual_truth": actual_truth, "grouped_truth": grouped_truth,
            "source_operation": {"line": target.start_point[0] + 1, "column": target.start_point[1] + 1,
                                 "operand": name, "literal_comparison": [left, op, right],
                                 "types": dict(model.types), "premises": list(guards.premises),
                                 "actual_width": actual_kind.width, "grouped_width": grouped_kind.width}}
