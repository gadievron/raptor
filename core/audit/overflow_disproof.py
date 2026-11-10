"""Bounded, query-bound transport for source overflow disproofs."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from typing import TYPE_CHECKING

from core.json import dumps_canonical

from .integer_abi import integer_abi_record, resolve_integer_abi
from .probe_function_scope import source_binding

if TYPE_CHECKING:
    from .condition_smt import HypothesisDisproofResult

_MAX_SOURCE = 65536
_MAX_HYPOTHESIS = 8192
_MAX_HINTS = 64
_RESULT_FIELDS = frozenset(
    {"hypothesis_class", "disproved", "reasoning", "witness", "error"}
)
_REQUEST_FIELDS = frozenset(
    {
        "hypothesis",
        "source_context",
        "var_types",
        "file_path",
        "function_name",
        "integer_abi",
    }
)


def _request(
    hypothesis, source_context, var_types, file_path, function_name, integer_abi
):
    record = integer_abi_record(integer_abi)
    hints = {} if var_types is None else var_types
    if (
        record is None
        or not isinstance(hypothesis, str)
        or len(hypothesis) > _MAX_HYPOTHESIS
        or not isinstance(source_context, str)
        or len(source_context) > _MAX_SOURCE
        or not isinstance(file_path, str)
        or len(file_path) > 4096
        or (
            function_name is not None
            and (not isinstance(function_name, str) or len(function_name) > 1024)
        )
        or not isinstance(hints, dict)
        or len(hints) > _MAX_HINTS
    ):
        return None
    if any(
        not isinstance(name, str)
        or not isinstance(spelling, str)
        or len(name) > 256
        or len(spelling) > 256
        for name, spelling in hints.items()
    ):
        return None
    try:
        source_context.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return dict(
        hypothesis=hypothesis,
        source_context=source_context,
        var_types=dict(hints),
        file_path=file_path,
        function_name=function_name,
        integer_abi=record,
    )


def _binding(request):
    return {
        "query_contract": "source-overflow-disproof-v2",
        "request_sha256": hashlib.sha256(
            dumps_canonical(request).encode("utf-8", "surrogatepass")
        ).hexdigest(),
        "source_contract": source_binding(
            request["source_context"],
            request["function_name"] or "",
            verb="check-overflow",
            hypothesis=request["hypothesis"],
            integer_abi=request["integer_abi"],
        ),
    }


def run_disproof(
    hypothesis,
    source_context,
    var_types=None,
    *,
    file_path="",
    function_name=None,
    integer_abi=None,
):
    """Parent-side validation and transport only; never build a native query."""
    from .condition_smt import HypothesisDisproofResult, _run_z3_child, _z3_importable
    from .arithmetic_claim import parse_overflow_claim

    def decline(reason):
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow", reasoning=reason
        )

    if resolve_integer_abi(integer_abi) is None:
        return decline("target integer ABI unavailable — inconclusive")
    request = _request(
        hypothesis, source_context, var_types, file_path, function_name, integer_abi
    )
    if request is None:
        return decline(
            "overflow request is unsupported or exceeds the input budget — inconclusive"
        )
    if parse_overflow_claim(hypothesis) is None:
        return decline("explicit arithmetic expression unavailable — inconclusive")
    if not _z3_importable():
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow", error="z3 not installed"
        )
    if (file_path or function_name is not None) and (
        not file_path or not function_name
    ):
        return decline("function scope unavailable — inconclusive")
    expected = _binding(request)
    reply = _run_z3_child("overflow_disproof", request)
    if not isinstance(reply, dict) or reply.get("binding") != expected:
        return decline(
            "overflow worker failed or returned an unbound result — inconclusive"
        )
    result = reply.get("result")
    if (
        not isinstance(result, dict)
        or set(result) != _RESULT_FIELDS
        or result.get("hypothesis_class") != "integer_overflow"
    ):
        return decline("overflow worker result schema unavailable — inconclusive")
    state, witness = result["disproved"], result["witness"]
    if (
        (state is not None and type(state) is not bool)
        or not isinstance(result["reasoning"], str)
        or not isinstance(result["error"], str)
        or len(result["reasoning"]) > _MAX_SOURCE
        or len(result["error"]) > _MAX_SOURCE
    ):
        return decline("overflow worker verdict is malformed — inconclusive")
    if state is False:
        if (
            not isinstance(witness, dict)
            or not 0 < len(witness) <= 8
            or any(
                not isinstance(name, str)
                or type(value) is not int
                or not -(1 << 63) <= value < (1 << 64)
                for name, value in witness.items()
            )
        ):
            return decline("overflow worker counterexample is malformed — inconclusive")
    elif witness is not None:
        return decline(
            "overflow worker verdict carries an inconsistent witness — inconclusive"
        )
    if state is not None and (result["error"] or not result["reasoning"].strip()):
        return decline("overflow worker verdict is incomplete — inconclusive")
    result = dict(result)
    if witness is not None:
        result["witness"] = dict(witness)
    return HypothesisDisproofResult(**result)


def run_request(args):
    """Confined dispatcher entry: bind the original complete query and result."""
    if not isinstance(args, dict) or set(args) != _REQUEST_FIELDS:
        return None
    request = _request(**args)
    if request is None:
        return None
    binding = _binding(request)
    result = _check_source(**request)
    return {"binding": binding, "result": asdict(result)}


def _check_source(
    hypothesis: str,
    source_context: str,
    var_types: dict[str, str] | None = None,
    *,
    file_path: str = "",
    function_name: str | None = None,
    integer_abi=None,
) -> HypothesisDisproofResult:
    """Attempt to disprove an integer overflow/underflow hypothesis via SMT.

    Extracts the claimed overflow expression from the hypothesis, resolves
    variable types from source context, and checks whether the overflow
    is feasible in the resolved type model. Pipeline callers provide the
    file/function scope. Legacy callers without scope metadata must supply
    one complete function; unknown operation or guard contexts decline.

    Returns disproved=True if UNSAT (overflow cannot happen),
    disproved=False if SAT (overflow is feasible), None if inconclusive.
    """
    from .condition_smt import HypothesisDisproofResult, _SMT_ASCII_IDENT_RE

    from .safety_contract import assert_boost_only

    assert_boost_only("condition_smt")

    from .integer_abi import resolve_integer_abi

    abi = resolve_integer_abi(integer_abi)
    if abi is None:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="target integer ABI unavailable — inconclusive",
        )

    import importlib.util

    if not importlib.util.find_spec("z3"):
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            error="z3 not installed",
        )

    from .condition_extraction import language_for_file

    language = language_for_file(file_path) if file_path else "c"
    if file_path or function_name is not None:
        from .probe_function_scope import source_for_function

        _, selected = source_for_function(
            source_context, file_path, function_name or ""
        )
        if selected is None:
            return HypothesisDisproofResult(
                hypothesis_class="integer_overflow",
                reasoning="function scope unavailable — inconclusive",
            )
        source_context = selected

    var_types = var_types or {}

    from .arithmetic_claim import parse_overflow_claim

    claim = parse_overflow_claim(hypothesis)
    if claim is None:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="explicit arithmetic expression unavailable — inconclusive",
        )
    operands, op_char = list(claim.operands), claim.operator
    var_names = [value for value in operands if _SMT_ASCII_IDENT_RE.fullmatch(value)]

    from .arithmetic_operation import bind_arithmetic_operation
    from .sweep import _premise_gate

    # Preserve expression order, including literals. Reordering variables
    # ahead of constants would change subtraction's intrinsic predicate.
    operation = bind_arithmetic_operation(
        source_context, operands, op_char, language=language, integer_abi=abi
    )
    if operation.status != "bound" or operation.guard_status == "unavailable":
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="source operation or guard context unavailable — inconclusive",
        )
    if operation.type_status != "bound":
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="source integer types or conversions unavailable — inconclusive",
        )
    from .arithmetic_types import integer_type

    if any(
        name in var_types
        and integer_type(var_types[name], abi) != integer_type(spelling, abi)
        for name, spelling in operation.types
    ):
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="provided integer types disagree with source declarations — inconclusive",
        )
    profile, overflow_kind = operation.profile, operation.kind
    premises = list(operation.premises + operation.domains)
    overflow_premises = (
        premises if operation.guard_status != "no-guards" or operation.domains else []
    )
    gate = _premise_gate(overflow_premises, profile)
    if gate is not None:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning=f"inconclusive: {gate}",
        )

    try:
        from packages.exploit_feasibility.smt_verbs import check_overflow

        result = check_overflow(
            operands,
            op_char,
            profile=profile,
            guards=premises,
            kind=overflow_kind,
            reduce_constraints=False,
        )
        from .integer_witness import validate_overflow_result

        result = validate_overflow_result(result, operation, operands, op_char, abi)
    except Exception as exc:  # noqa: BLE001 — degrade to inconclusive
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="overflow verb failed — inconclusive",
            error=f"{type(exc).__name__}: {exc}",
        )

    feasible = result.get("feasible")
    if feasible is False:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            disproved=True,
            reasoning=(
                f"Z3 UNSAT: {op_char}-chain over {var_names} cannot "
                f"wrap at {profile} ({overflow_kind}) within the "
                f"extracted guard premises {premises} — hypothesis "
                f"disproved"
            ),
        )
    if feasible is True:
        model = result.get("model")
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            disproved=False,
            reasoning=(
                f"Z3 SAT: overflow IS feasible for {var_names} at "
                f"{profile} ({overflow_kind}) within the guarded "
                f"value space"
            ),
            witness=model if isinstance(model, dict) else None,
        )
    return HypothesisDisproofResult(
        hypothesis_class="integer_overflow",
        reasoning=(
            "Z3 inconclusive: " + str(result.get("reasoning") or "solver punted")
        ),
    )
