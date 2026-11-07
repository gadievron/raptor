"""One complete ordered invariant census per worker, never a partial safety proof."""

from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit import condition_smt, invariant_batch as batch, invariant_smt as inv
from core.smt_solver import session


SITES = [
    {"code": "Count=Limit;", "line": 7, "pre_conditions": ()},
    {"code": "Count++;", "line": 7, "pre_conditions": ("Count == Limit",)},
]


def call(sites=None, timeout_ms=5000):
    return inv.check_site_batch(
        "Count <= Limit",
        deepcopy(SITES if sites is None else sites),
        timeout_ms=timeout_ms,
    )


def receipt(args):
    rows = []
    for index, site in enumerate(args["sites"]):
        result = inv.SiteResult(
            line=site["line"], code=site["code"], verdict="preserved"
        )
        rows.append(
            dict(site_id=index, input_sha256=batch._digest(site), result=asdict(result))
        )
    return {"binding": batch._binding(args), "sites": rows}


@pytest.fixture
def actual_dispatch(monkeypatch):
    pytest.importorskip("z3")
    calls = []

    def dispatch(tag, args, **kwargs):
        calls.append(deepcopy(args))
        assert tag == "invariant_site_batch"
        return condition_smt._z3_dispatch_json({"tag": tag, "args": args})

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    return calls


def test_multiple_independent_obligations_share_one_worker(actual_dispatch):
    results = call()
    assert [result.verdict for result in results] == ["preserved", "violable"]
    assert len(actual_dispatch) == 1
    model = results[1].model
    assert model["Count"] == model["Limit"]
    assert model["Count'"] == model["Count"] + 1 > model["Limit"]


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "truncated",
        "extra",
        "reordered",
        "duplicate",
        "bool-id",
        "wrong-hash",
        "old-contract",
        "line",
        "bad-model",
    ],
)
def test_incomplete_or_misattributed_batch_cannot_refute(monkeypatch, case):
    def dispatch(tag, args, **kwargs):
        reply = receipt(args)
        rows = reply["sites"]
        if case == "missing":
            return None
        if case == "truncated":
            rows.pop()
        elif case == "extra":
            rows.append(deepcopy(rows[-1]))
        elif case == "reordered":
            rows.reverse()
        elif case == "duplicate":
            rows[1] = deepcopy(rows[0])
        elif case == "bool-id":
            rows[0]["site_id"] = False
        elif case == "wrong-hash":
            rows[1]["input_sha256"] = rows[0]["input_sha256"]
        elif case == "old-contract":
            reply["binding"]["query_contract"] = "old"
        elif case == "line":
            rows[0]["result"]["line"] = 8
        else:
            rows[0]["result"]["model"] = {"Count": 0}
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    assert call() is None


@pytest.mark.parametrize(
    "field", ["invariant", "deadline", "timeout_ms", "code", "guards", "line", "order"]
)
def test_exact_batch_query_is_bound(monkeypatch, field):
    def dispatch(tag, args, **kwargs):
        other = deepcopy(args)
        if field == "invariant":
            other[field] = "Count < Limit"
        elif field == "deadline":
            other[field] += 1
        elif field == "timeout_ms":
            other[field] += 1
        elif field == "code":
            other["sites"][0]["code"] += " "
        elif field == "guards":
            other["sites"][1]["pre_conditions"] = []
        elif field == "line":
            other["sites"][0]["line"] += 1
        else:
            other["sites"].reverse()
        return receipt(other)

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    assert call() is None


@pytest.mark.parametrize(
    "sites",
    [
        SITES * 129,
        [{"code": "x" * 65537, "line": 1, "pre_conditions": []}],
        [dict(code="x" * 65536, line=1, pre_conditions=[]) for _ in range(5)],
        [dict(code="Count++;", line=True, pre_conditions=[])],
        [dict(code="Count++;", line=1, pre_conditions=[], extra=True)],
    ],
    ids=["site-count", "site-source", "total-source", "bool-line", "unexpected-field"],
)
def test_input_limits_do_not_dispatch(monkeypatch, sites):
    monkeypatch.setattr(
        condition_smt,
        "_run_z3_child",
        lambda *a, **kw: pytest.fail("over-budget batch dispatched"),
    )
    assert call(sites) is None


def test_empty_or_expired_batch_does_not_dispatch(monkeypatch):
    monkeypatch.setattr(
        condition_smt,
        "_run_z3_child",
        lambda *a, **kw: pytest.fail("empty/expired batch dispatched"),
    )
    assert call([]) == []
    assert call(timeout_ms=0) is None


def test_reply_models_are_owned_snapshots(monkeypatch):
    replies = []

    def dispatch(tag, args, **kwargs):
        reply = receipt(args)
        reply["sites"][0]["result"].update(
            verdict="violable", model={"Count": 0, "Limit": 0, "Count'": 1}
        )
        replies.append(reply)
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    results = call()
    replies[0]["sites"][0]["result"]["model"]["Count"] = 8
    assert results[0].model["Count"] == 0


def test_one_global_deadline_preserves_complete_unknown_rows(
    actual_dispatch, monkeypatch
):
    clock = [0.0]
    monkeypatch.setattr(session, "monotonic", lambda: clock[0])
    original = inv.new_solver
    caps = []

    def construct(timeout_ms):
        assert timeout_ms == 5000
        solver = original(timeout_ms)
        check = solver.check

        def native():
            with session.query_budget(100000) as deadline:
                caps.append(deadline)
            verdict = check()
            clock[0] += 4
            return verdict

        monkeypatch.setattr(solver, "check", native)
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    sites = [
        dict(code="Count=Limit;", line=line, pre_conditions=[]) for line in [1, 2, 3]
    ]
    results = call(sites, timeout_ms=7000)
    assert [result.verdict for result in results] == [
        "preserved",
        "preserved",
        "unknown",
    ]
    assert results[2].model == {} and "budget exhausted" in results[2].reason
    assert caps == [5.0, 7.0]
    assert len(actual_dispatch) == 1


def test_protocol_census_dispatches_once_and_retains_each_sites_metadata(
    actual_dispatch,
):
    from core.audit.protocol_state import check_invariant_multi_site

    sites = [
        dict(
            file="a.c",
            function="",
            line=7,
            code="Count=Limit;",
            rhs_class="literal_const",
        ),
        dict(file="b.c", function="", line=7, code="Count++;", rhs_class="from_param"),
    ]
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": sites}}}, {}
    )
    assert result["outcome"] == "violable"
    assert [site["file"] for site in result["sites"]] == ["a.c", "b.c"]
    assert [site["rhs_class"] for site in result["sites"]] == [
        "literal_const",
        "from_param",
    ]
    assert len(actual_dispatch) == 1


@pytest.mark.parametrize("failure", ["none", "short"])
def test_protocol_consumer_never_calls_a_partial_census_preserved(monkeypatch, failure):
    from core.audit.protocol_state import check_invariant_multi_site

    monkeypatch.setattr(
        inv,
        "check_site_batch",
        lambda *a, **kw: (
            None
            if failure == "none"
            else [inv.SiteResult(line=7, code="Count=Limit;", verdict="preserved")]
        ),
    )
    sites = [
        dict(file="a.c", function="", line=7, code="Count=Limit;") for _ in range(2)
    ]
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": sites}}}, {}
    )
    assert result["outcome"] == "inconclusive"
    assert [site["verdict"] for site in result["sites"]] == ["unknown", "unknown"]


def test_isolation_refusal_never_falls_back_to_individual_native_queries(monkeypatch):
    from core.sandbox import SandboxSetupError

    def refuse(*a, **kw):
        raise SandboxSetupError("owned batch refusal")

    monkeypatch.setattr(condition_smt, "_run_z3_child", refuse)
    monkeypatch.setattr(
        inv,
        "check_site_preservation",
        lambda *a, **kw: pytest.fail("per-site fallback"),
    )
    with pytest.raises(SandboxSetupError, match="owned batch refusal"):
        call()


@pytest.mark.slow
@pytest.mark.parametrize(
    "guarded,count",
    [(False, 2), (True, 2), (True, 40)],
    ids=["violable", "preserved", "forty-sites"],
)
def test_native_confined_batch(guarded, count):
    pytest.importorskip("z3")
    sites = deepcopy(SITES)
    if guarded:
        sites = [
            dict(code="Count=Limit;", line=index + 1, pre_conditions=[])
            for index in range(count)
        ]
    # This is worker delivery coverage; deterministic clock tests own expiry.
    results = call(sites, timeout_ms=30_000)
    assert results is not None, "native invariant batch returned no complete reply"
    assert [result.verdict for result in results] == (
        ["preserved"] * count if guarded else ["preserved", "violable"]
    ), [result.to_dict() for result in results]


def test_site_formulas_remain_independent_with_conflicting_preconditions(
    actual_dispatch,
):
    sites = [
        dict(
            code="Count++;",
            line=value + 1,
            pre_conditions=(f"Count == {value}", f"Limit == {value}"),
        )
        for value in [0, 1]
    ]
    results = call(sites)
    assert [result.verdict for result in results] == ["violable", "violable"]
    assert [result.model["Count"] for result in results] == [0, 1]
    assert len(actual_dispatch) == 1


def test_forty_site_census_needs_only_one_dispatch(actual_dispatch):
    sites = [
        dict(code="Count=Limit;", line=index + 1, pre_conditions=[])
        for index in range(40)
    ]
    results = call(sites)
    assert len(results) == 40 and all(
        result.verdict == "preserved" for result in results
    )
    assert len(actual_dispatch) == 1
