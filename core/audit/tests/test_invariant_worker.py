"""Invariant query transport cannot grant authority to stale or malformed data."""

from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit import condition_smt, invariant_smt as inv, invariant_worker as worker
from core.smt_solver import session


def call(mode="site", source="Count++;", *, timeout_ms=5000):
    if mode == "function":
        return inv.check_invariant_preservation(
            "Count <= Limit", source, timeout_ms=timeout_ms
        )
    return inv.check_site_preservation(
        "Count <= Limit",
        source,
        line=7,
        pre_conditions=("Count == Limit",),
        timeout_ms=timeout_ms,
    )


def decline(result):
    if isinstance(result, inv.SiteResult):
        assert result.verdict == "unknown" and result.model == {}
    else:
        assert result.outcome == "inconclusive" and result.sites == []


def receipt(args):
    site = inv.SiteResult(
        line=7,
        code="Count++;",
        verdict="violable",
        model={"Count": 0, "Limit": 0, "Count'": 1},
    )
    result = (
        site
        if args["mode"] == "site"
        else inv.InvariantPreservationResult(
            outcome="violable", invariant=args["invariant"], sites=[site]
        )
    )
    return {"binding": worker._binding(args), "result": asdict(result)}


@pytest.mark.parametrize("mode", ["site", "function"])
def test_parsing_and_native_queries_run_only_inside_worker_dispatch(monkeypatch, mode):
    pytest.importorskip("z3")
    original = inv._parse_invariant
    inside, calls = False, []

    def parse(*args):
        assert inside, "parent parsed the native obligation"
        return original(*args)

    def dispatch(tag, args, **kwargs):
        nonlocal inside
        assert tag == "invariant_preservation"
        assert 2 <= kwargs["timeout"] <= 300
        calls.append(args)
        inside = True
        try:
            return condition_smt._z3_dispatch_json({"tag": tag, "args": args})
        finally:
            inside = False

    monkeypatch.setattr(inv, "_parse_invariant", parse)
    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    result = call(mode)
    site = result.sites[0] if mode == "function" else result
    assert site.verdict == "violable"
    assert site.model["Count'"] > site.model["Limit"]
    assert len(calls) == 1


@pytest.mark.parametrize(
    "field",
    ["mode", "invariant", "source", "line", "pre_conditions", "timeout_ms", "deadline"],
)
def test_bound_request_fields_cannot_drift(monkeypatch, field):
    def dispatch(tag, args, **kwargs):
        other = deepcopy(args)
        changes = {
            "mode": "function",
            "invariant": "Count < Limit",
            "source": "Count=0;",
            "line": 8,
            "pre_conditions": [],
            "timeout_ms": 6000,
            "deadline": args["deadline"] + 1,
        }
        other[field] = changes[field]
        return receipt(other)

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    decline(call())


@pytest.mark.parametrize("mode", ["site", "function"])
@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "version",
        "verdict-list",
        "bad-model",
        "bool-model",
        "oversized-model",
        "model-on-safe",
        "missing-model",
        "line-bool",
        "extra-field",
    ],
)
def test_bad_worker_records_cannot_become_evidence(monkeypatch, mode, case):
    def dispatch(tag, args, **kwargs):
        reply = receipt(args)
        if case == "missing":
            return None
        if case == "version":
            reply["binding"]["query_contract"] = "old"
            return reply
        site = reply["result"] if mode == "site" else reply["result"]["sites"][0]
        if case == "verdict-list":
            site["verdict"] = []
        elif case == "bad-model":
            site["model"] = []
        elif case == "bool-model":
            site["model"]["Count"] = True
        elif case == "oversized-model":
            site["model"]["Count"] = 1 << 4097
        elif case == "model-on-safe":
            site["verdict"] = "preserved"
        elif case == "missing-model":
            site["model"] = {}
        elif case == "line-bool":
            site["line"] = True
        else:
            site["extra"] = 1
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    decline(call(mode))


def test_inconsistent_aggregate_outcome_cannot_preserve_a_violable_invariant(
    monkeypatch,
):
    def dispatch(tag, args, **kwargs):
        reply = receipt(args)
        reply["result"]["outcome"] = "preserved"
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    decline(call("function"))


def test_valid_model_is_a_snapshot(monkeypatch):
    replies = []

    def dispatch(tag, args, **kwargs):
        replies.append(receipt(args))
        return replies[-1]

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    result = call()
    replies[0]["result"]["model"]["Count"] = 9
    assert result.model["Count"] == 0


@pytest.mark.parametrize(
    "changes",
    [
        dict(source="x" * 65537),
        dict(invariant="x" * 8193),
        dict(pre_conditions=["x"] * 65),
        dict(pre_conditions=[None]),
        dict(line=True),
        dict(source="\ud800"),
    ],
    ids=["source", "invariant", "guard-count", "guard-type", "line", "unicode"],
)
def test_input_budgets_refuse_before_worker_dispatch(monkeypatch, changes):
    monkeypatch.setattr(
        condition_smt,
        "_run_z3_child",
        lambda *a, **kw: pytest.fail("invalid request dispatched"),
    )
    args = dict(
        mode="site",
        invariant="Count <= Limit",
        source="Count++;",
        line=7,
        pre_conditions=(),
        timeout_ms=5000,
        deadline=session.monotonic() + 5,
    )
    args.update(changes)
    decline(worker.run_check(**args))


def test_setup_time_consumes_the_original_deadline(monkeypatch):
    pytest.importorskip("z3")
    clock = [0.0]
    monkeypatch.setattr(session, "monotonic", lambda: clock[0])

    def dispatch(tag, args, **kwargs):
        assert args["deadline"] == 5.0
        clock[0] = 6.0
        return condition_smt._z3_dispatch_json({"tag": tag, "args": args})

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    from core.smt_solver.session import new_solver

    def construct(*args):
        solver = new_solver(*args)
        monkeypatch.setattr(
            solver, "check", lambda: pytest.fail("expired handoff queried Z3")
        )
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    decline(call())


def test_isolation_refusal_propagates_without_native_fallback(monkeypatch):
    from core.sandbox import SandboxSetupError

    def refuse(*a, **kw):
        raise SandboxSetupError("owned refusal")

    monkeypatch.setattr(condition_smt, "_run_z3_child", refuse)
    monkeypatch.setattr(
        inv,
        "_check_site_preservation",
        lambda *a, **kw: pytest.fail("in-process fallback"),
    )
    with pytest.raises(SandboxSetupError, match="owned refusal"):
        call()


@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_unit_fixture_restores_borrowed_transport(request, exit_mode):
    from core.audit.tests.conftest import invariant_unit_worker

    original = condition_smt._run_z3_child
    failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}.get(exit_mode)
    with pytest.raises(failure, match="owned exit") if failure else nullcontext():
        with pytest.MonkeyPatch.context() as scope:
            invariant_unit_worker.__wrapped__(scope, request)
            assert condition_smt._run_z3_child is not original
            if failure:
                raise failure("owned exit")
    assert condition_smt._run_z3_child is original


@pytest.mark.slow
@pytest.mark.parametrize(
    "mode,source,expected",
    [
        ("function", "Count++;", "violable"),
        ("function", "Count=Limit;", "preserved"),
        ("site", "Count++;", "violable"),
        ("site", "Count=(unsigned char)300;", "out_of_scope"),
        ("site", "grow(&Count);", "out_of_scope"),
    ],
    ids=[
        "function-model",
        "function-proof",
        "guarded-site",
        "cast-refusal",
        "alias-refusal",
    ],
)
def test_native_confined_invariant_worker(mode, source, expected):
    pytest.importorskip("z3")
    result = call(mode, source, timeout_ms=30_000)
    assert (result.outcome if mode == "function" else result.verdict) == expected, (
        result.to_dict()
    )
