"""Bounded invariant queries and query-bound replies for the confined SMT worker."""

from dataclasses import asdict
import hashlib
import math

from core.json import dumps_canonical
from core.smt_solver import session
from .invariant_outcomes import aggregate_verdicts
from .integer_abi import integer_abi_record

_MAX_SOURCE = 65536
_MAX_TEXT = 8192
_MAX_SITES = 256
_REQUEST_FIELDS = frozenset(
    {
        "mode",
        "invariant",
        "source",
        "line",
        "pre_conditions",
        "timeout_ms",
        "deadline",
        "integer_abi",
    }
)
_SITE_FIELDS = frozenset({"line", "code", "verdict", "reason", "model", "integer_abi"})
_RESULT_FIELDS = frozenset({"outcome", "invariant", "sites", "reason", "rule_id"})


def _request(
    mode,
    invariant,
    source,
    line,
    pre_conditions,
    timeout_ms,
    deadline,
    integer_abi=None,
):
    abi_record = integer_abi_record(integer_abi)
    if integer_abi is not None and integer_abi != "unknown" and abi_record is None:
        return None
    if (
        not isinstance(mode, str)
        or mode not in {"function", "site"}
        or not isinstance(invariant, str)
        or len(invariant) > _MAX_TEXT
        or not isinstance(source, str)
        or len(source) > _MAX_SOURCE
        or type(line) is not int
        or not 0 <= line < (1 << 31)
        or not isinstance(pre_conditions, (list, tuple))
        or len(pre_conditions) > 64
        or any(
            not isinstance(text, str) or len(text) > _MAX_TEXT
            for text in pre_conditions
        )
        or type(timeout_ms) is not int
        or timeout_ms < 0
        or type(deadline) is not float
        or not math.isfinite(deadline)
    ):
        return None
    if mode == "function" and (line != 0 or pre_conditions):
        return None
    try:
        for text in [invariant, source, *pre_conditions]:
            text.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return dict(
        mode=mode,
        invariant=invariant,
        source=source,
        line=line,
        pre_conditions=list(pre_conditions),
        timeout_ms=min(timeout_ms, (1 << 31) - 1),
        deadline=deadline,
        integer_abi=abi_record,
    )


def _binding(request):
    return {
        "query_contract": "mathematical-invariant-worker-v9",
        "request_sha256": hashlib.sha256(
            dumps_canonical(request).encode("utf-8")
        ).hexdigest(),
    }


def _site(raw, integer_abi=None):
    from .invariant_smt import SiteResult

    if (
        not isinstance(raw, dict)
        or set(raw) != _SITE_FIELDS
        or type(raw["line"]) is not int
        or not 0 <= raw["line"] < (1 << 31)
        or not isinstance(raw["code"], str)
        or len(raw["code"]) > _MAX_SOURCE
        or not isinstance(raw["reason"], str)
        or len(raw["reason"]) > _MAX_SOURCE
        or not isinstance(raw["verdict"], str)
        or raw["verdict"]
        not in {"preserved", "preserved_nonneg", "violable", "unknown", "out_of_scope"}
        or raw["integer_abi"] != integer_abi
        or (
            raw["integer_abi"] is not None
            and integer_abi_record(raw["integer_abi"]) != raw["integer_abi"]
        )
        or not isinstance(raw["model"], dict)
        or len(raw["model"]) > 256
    ):
        return None
    model = raw["model"]
    if any(
        not isinstance(name, str)
        or len(name) > _MAX_TEXT
        or type(value) is not int
        or value.bit_length() > 4096
        for name, value in model.items()
    ):
        return None
    if bool(model) != (raw["verdict"] in {"violable", "preserved_nonneg"}):
        return None
    return SiteResult(
        **{
            **raw,
            "model": dict(model),
            "integer_abi": dict(integer_abi) if integer_abi is not None else None,
        }
    )


def _result(raw, request):
    from .invariant_smt import InvariantPreservationResult, RULE_ID

    if request["mode"] == "site":
        site = _site(raw, request["integer_abi"])
        if site is not None and request["line"] and site.line != request["line"]:
            return None
        return site
    if (
        not isinstance(raw, dict)
        or set(raw) != _RESULT_FIELDS
        or raw["rule_id"] != RULE_ID
        or raw["invariant"] != request["invariant"]
        or not isinstance(raw["outcome"], str)
        or raw["outcome"] not in {"preserved", "violable", "inconclusive"}
        or not isinstance(raw["reason"], str)
        or len(raw["reason"]) > _MAX_SOURCE
        or not isinstance(raw["sites"], list)
        or len(raw["sites"]) > _MAX_SITES
    ):
        return None
    sites = [_site(item, request["integer_abi"]) for item in raw["sites"]]
    if any(site is None for site in sites):
        return None
    if sites:
        expected = aggregate_verdicts(site.verdict for site in sites)
        if raw["outcome"] != expected:
            return None
    elif raw["outcome"] == "violable":
        return None
    return InvariantPreservationResult(**{**raw, "sites": sites})


def run_check(
    mode,
    invariant,
    source,
    *,
    line=0,
    pre_conditions=(),
    timeout_ms=5000,
    deadline,
    integer_abi=None,
):
    """Parent-side transport: no source binding or native solver execution."""
    from .condition_smt import _run_z3_child
    from .invariant_smt import InvariantPreservationResult, SiteResult

    def decline(reason):
        if mode == "site":
            return SiteResult(
                line=line if type(line) is int and line >= 0 else 0,
                code=source[:_MAX_SOURCE] if isinstance(source, str) else "",
                verdict="unknown",
                reason=reason,
            )
        return InvariantPreservationResult(
            outcome="inconclusive",
            invariant=invariant if isinstance(invariant, str) else "",
            reason=reason,
        )

    request = _request(
        mode, invariant, source, line, pre_conditions, timeout_ms, deadline, integer_abi
    )
    if request is None:
        return decline(
            "invariant worker request is malformed or exceeds the input budget"
        )
    remaining = max(
        0.0, min(request["timeout_ms"] / 1000, deadline - session.monotonic())
    )
    if remaining <= 0:
        return decline("shared query budget exhausted (timeout)")
    reply = _run_z3_child(
        "invariant_preservation",
        request,
        timeout=min(300, max(2, math.ceil(remaining) + 1)),
    )
    if (
        not isinstance(reply, dict)
        or set(reply) != {"binding", "result"}
        or reply["binding"] != _binding(request)
    ):
        return decline("invariant worker failed or returned an unbound result")
    result = _result(reply["result"], request)
    return (
        result
        if result is not None
        else decline("invariant worker returned a malformed or inconsistent result")
    )


def run_request(args):
    """Worker entry: all parsing and native queries share the original deadline."""
    from .invariant_smt import _check_invariant_preservation, _check_site_preservation

    if not isinstance(args, dict) or set(args) != _REQUEST_FIELDS:
        return None
    request = _request(**args)
    if request is None:
        return None
    remaining_ms = max(
        0,
        int(
            min(request["timeout_ms"] / 1000, request["deadline"] - session.monotonic())
            * 1000
        ),
    )
    with session.query_budget(remaining_ms):
        if request["mode"] == "function":
            result = _check_invariant_preservation(
                request["invariant"],
                request["source"],
                timeout_ms=request["timeout_ms"],
                integer_abi=request["integer_abi"],
            )
        else:
            result = _check_site_preservation(
                request["invariant"],
                request["source"],
                line=request["line"],
                pre_conditions=tuple(request["pre_conditions"]),
                timeout_ms=request["timeout_ms"],
                integer_abi=request["integer_abi"],
            )
    for site in result.sites if request["mode"] == "function" else [result]:
        site.integer_abi = (
            dict(request["integer_abi"]) if request["integer_abi"] is not None else None
        )
    return {"binding": _binding(request), "result": asdict(result)}
