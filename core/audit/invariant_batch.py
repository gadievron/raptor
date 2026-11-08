"""One confined worker for a bounded, ordered set of invariant site obligations."""

from dataclasses import asdict
import hashlib
import math

from core.json import dumps_canonical
from core.smt_solver import session

from .invariant_worker import _request as site_request, _site

_MAX_SITES = 256
_MAX_CHARS = 262144
_REQUEST_FIELDS = frozenset(
    {"invariant", "sites", "timeout_ms", "deadline", "integer_abi"}
)
_INPUT_FIELDS = frozenset({"code", "line", "pre_conditions"})


def _digest(value):
    return hashlib.sha256(dumps_canonical(value).encode("utf-8")).hexdigest()


def _request(invariant, sites, timeout_ms, deadline, integer_abi=None):
    base = site_request("site", invariant, "", 0, (), timeout_ms, deadline, integer_abi)
    if base is None or not isinstance(sites, (list, tuple)) or len(sites) > _MAX_SITES:
        return None
    normalized = []
    count = len(invariant)
    for site in sites:
        if not isinstance(site, dict) or set(site) != _INPUT_FIELDS:
            return None
        request = site_request(
            "site",
            invariant,
            site["code"],
            site["line"],
            site["pre_conditions"],
            timeout_ms,
            deadline,
            base["integer_abi"],
        )
        if request is None:
            return None
        count += len(site["code"]) + sum(map(len, request["pre_conditions"]))
        if count > _MAX_CHARS:
            return None
        normalized.append(
            dict(
                code=request["source"],
                line=request["line"],
                pre_conditions=request["pre_conditions"],
            )
        )
    return dict(
        invariant=invariant,
        sites=normalized,
        timeout_ms=base["timeout_ms"],
        deadline=deadline,
        integer_abi=base["integer_abi"],
    )


def _binding(request):
    return {
        "query_contract": "mathematical-invariant-site-batch-v10",
        "request_sha256": _digest(request),
    }


def run_batch(invariant, sites, *, timeout_ms, deadline, integer_abi=None):
    """Return all per-site results, or None; never credit an incomplete reply."""
    from .condition_smt import _run_z3_child

    request = _request(invariant, sites, timeout_ms, deadline, integer_abi)
    if request is None:
        return None
    if not request["sites"]:
        return []
    remaining = max(
        0.0, min(request["timeout_ms"] / 1000, deadline - session.monotonic())
    )
    if remaining <= 0:
        return None
    reply = _run_z3_child(
        "invariant_site_batch",
        request,
        timeout=min(300, max(2, math.ceil(remaining) + 1)),
    )
    if (
        not isinstance(reply, dict)
        or set(reply) != {"binding", "sites"}
        or reply["binding"] != _binding(request)
        or not isinstance(reply["sites"], list)
        or len(reply["sites"]) != len(request["sites"])
    ):
        return None
    results = []
    for index, (site, row) in enumerate(
        zip(request["sites"], reply["sites"], strict=True)
    ):
        if (
            not isinstance(row, dict)
            or set(row) != {"site_id", "input_sha256", "result"}
            or type(row["site_id"]) is not int
            or row["site_id"] != index
            or row["input_sha256"] != _digest(site)
        ):
            return None
        result = _site(row["result"], request["integer_abi"])
        if result is None or (site["line"] and result.line != site["line"]):
            return None
        results.append(result)
    return results


def run_request(args):
    """Solve each site separately, sharing the batch deadline and a 5s site cap."""
    from .invariant_smt import SiteResult, _check_site_preservation

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
    rows = []
    with session.query_budget(remaining_ms):
        for index, site in enumerate(request["sites"]):
            if session.monotonic() >= request["deadline"]:
                result = SiteResult(
                    line=site["line"],
                    code=site["code"],
                    verdict="unknown",
                    reason="shared query budget exhausted (timeout)",
                )
            else:
                with session.query_budget(5000):
                    result = _check_site_preservation(
                        request["invariant"],
                        site["code"],
                        line=site["line"],
                        pre_conditions=tuple(site["pre_conditions"]),
                        timeout_ms=5000,
                        integer_abi=request["integer_abi"],
                    )
            result.integer_abi = (
                dict(request["integer_abi"])
                if request["integer_abi"] is not None
                else None
            )
            rows.append(
                dict(site_id=index, input_sha256=_digest(site), result=asdict(result))
            )
    return {"binding": _binding(request), "sites": rows}
