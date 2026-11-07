"""Mathematical invariant steps must not invent safety by changing transitions."""

import pytest

from core.audit import invariant_smt as inv

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def solver_available():
    pytest.importorskip("z3")


@pytest.mark.parametrize(
    "name", ["Count", "Count__post", "State.Count", "State->Count"]
)
def test_internal_post_symbol_cannot_alias_an_invariant_variable(name):
    bound = name + "__post"
    result = inv.check_site_preservation(f"{name} <= {bound}", name + "++;")
    assert result.verdict == "violable", result.to_dict()
    model = result.model
    assert model[name] <= model[bound]
    assert model[name + "'"] == model[name] + 1
    assert model[name + "'"] > model[bound]


@pytest.mark.parametrize(
    "code,operators",
    [
        ("Count = 0; Count++;", ["=", "++"]),
        ("++Count; Count = 0; ++Count;", ["++", "=", "++"]),
        ("Count = 0; --Count;", ["=", "--"]),
        ("Limit = 0; Count++;", ["=", "++"]),
    ],
    ids=["two-postfix", "three-mixed", "prefix-decrement", "two-variables"],
)
def test_every_direct_same_line_mutation_is_discovered_in_source_order(code, operators):
    sites = inv.find_mutation_sites(code, {"Count", "Limit"})
    assert [site[3] for site in sites] == operators
    assert all(site[0] == 1 for site in sites)
    result = inv.check_site_preservation("Count <= Limit", code)
    assert result.verdict == "out_of_scope"
    assert "joint transition" in result.reason


def test_full_source_checker_does_not_omit_a_later_same_line_violation():
    result = inv.check_invariant_preservation("Count <= Limit", "Count=0; Count++;")
    assert result.outcome == "violable"
    assert len(result.sites) == 2
    assert result.sites[1].verdict == "violable"


@pytest.mark.parametrize(
    "code",
    [
        "Count=(unsigned char)300;",
        "Count=(int)Value;",
        "Count=(size_t)(Value+1);",
        "Count=010;",
        "Count=00;",
    ],
    ids=["narrowing-cast", "int-cast", "alias-cast", "octal", "leading-zero"],
)
def test_unsupported_conversion_or_literal_never_gets_silently_rewritten(code):
    result = inv.check_invariant_preservation("Count == 300", code)
    assert result.outcome == "inconclusive", result.to_dict()
    assert result.sites[0].verdict == "out_of_scope"
    site = inv.check_site_preservation("Count == 300", code)
    assert site.verdict == "out_of_scope"


@pytest.mark.parametrize("condition", ["(unsigned char)Count <= 10", "Count <= 010"])
def test_source_guard_conversion_cannot_be_erased(condition):
    result = inv.check_site_preservation(
        "Count <= Limit", "Count++;", pre_conditions=(condition,)
    )
    assert result.verdict == "out_of_scope"
    assert "dominating condition" in result.reason
    assert inv.negate_comparison(condition) is None


@pytest.mark.parametrize(
    "code", ["grow(&Count);", "Count=0; grow(&Count);", "State->Count=0;"]
)
def test_single_site_cannot_claim_vacuous_or_direct_safety_over_an_alias(code):
    result = inv.check_site_preservation("Count <= Limit", code)
    assert result.verdict == "out_of_scope"
    assert result.model == {}
    assert "alias" in result.reason


@pytest.mark.parametrize("timeout", [True, 1.5, "5", -1])
@pytest.mark.parametrize(
    "entry", [inv.check_invariant_preservation, inv.check_site_preservation]
)
def test_invalid_timeouts_are_rejected_before_native_queries(
    monkeypatch, timeout, entry
):
    monkeypatch.setattr(
        inv, "new_solver", lambda *a, **kw: pytest.fail("allocated a native solver")
    )
    with pytest.raises(ValueError, match="budget"):
        entry("Count <= Limit", "Count++;", timeout_ms=timeout)


@pytest.mark.parametrize(
    "entry", [inv.check_invariant_preservation, inv.check_site_preservation]
)
def test_zero_budget_never_calls_native_check(monkeypatch, entry):
    original = inv.new_solver

    def construct(*args, **kwargs):
        solver = original(*args, **kwargs)
        monkeypatch.setattr(
            solver, "check", lambda *a: pytest.fail("expired budget ran a native query")
        )
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    result = entry("Count <= Limit", "Count++;", timeout_ms=0)
    if hasattr(result, "sites"):
        assert result.outcome == "inconclusive" and result.sites == []
    else:
        assert result.verdict == "unknown" and result.model == {}
    assert "budget exhausted" in result.reason


def test_nonnegative_regime_cannot_restart_the_first_query_budget(monkeypatch):
    from core.smt_solver import session

    clock = [0.0]
    monkeypatch.setattr(session, "monotonic", lambda: clock[0])
    original = inv.new_solver
    calls = []

    def construct(*args, **kwargs):
        solver = original(*args, **kwargs)
        check = solver.check

        def native(*args):
            calls.append(1)
            result = check(*args)
            clock[0] = 5.0
            return result

        monkeypatch.setattr(solver, "check", native)
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    result = inv.check_site_preservation("Count <= Limit", "Count++;", timeout_ms=5000)
    assert result.verdict == "unknown" and result.model == {}
    assert calls == [1]
    assert "budget exhausted" in result.reason


def test_all_mutation_sites_share_one_query_budget(monkeypatch):
    from core.smt_solver import session
    z3 = pytest.importorskip("z3")

    clock = [0.0]
    monkeypatch.setattr(session, "monotonic", lambda: clock[0])
    original = inv.new_solver
    checks = []

    def construct(*args, **kwargs):
        solver = original(*args, **kwargs)

        def native(*args):
            checks.append(1)
            clock[0] = 5.0
            # This tests deadline sharing, not whether a real native
            # solver finishes within 10ms on a loaded pytest worker.
            return z3.unsat

        monkeypatch.setattr(solver, "check", native)
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    result = inv.check_invariant_preservation(
        "Count >= 0", "Count=0;\nCount=0;", timeout_ms=10
    )
    assert result.outcome == "inconclusive"
    assert [site.verdict for site in result.sites] == ["preserved", "unknown"]
    assert checks == [1]


@pytest.mark.parametrize(
    "code", ["if(Limit>=0)Count=0;", "Count=min(Value,Limit);"],
    ids=["guarded-reset", "clamp"],
)
def test_ordinary_mathematical_preservation_still_works(code):
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == "preserved"


@pytest.mark.parametrize("rhs", ["(int)+Value", "(size_t)-Value", "(Alias)+1"])
def test_cast_followed_by_unary_arithmetic_is_not_a_grouped_variable(rhs):
    result = inv.check_site_preservation("Count <= Limit", "Count=" + rhs + ";")
    assert result.verdict == "out_of_scope"
    assert "ambiguous cast" in result.reason


@pytest.mark.parametrize(
    "source,expected",
    [("Count++;", "confirmed"), ("Count=(unsigned char)300;", "inconclusive")],
    ids=["post-symbol-independent", "conversion-refused"],
)
def test_audit_consumer_records_corrected_invariant_outcome(tmp_path, source, expected):
    from core.audit.orchestrator import (
        OrchestratorConfig,
        TierCounters,
        _run_tool_chain,
    )

    counters = {"smt_invariant": TierCounters()}
    result = _run_tool_chain(
        [{"type": "smt_invariant", "config": {"invariant": "Count <= Count__post"}}],
        config=OrchestratorConfig(target_path=tmp_path, out_dir=None),
        file_path="record.c",
        function_name="Read",
        source=source,
        hypothesis="Count exceeds its bound",
        tier_counters=counters,
    )
    if expected == "confirmed":
        assert result == ["smt:invariant-preservation"]
        assert counters["smt_invariant"].confirmed == 1
    else:
        assert result == []
        assert counters["smt_invariant"].inconclusive == 1
        assert counters["smt_invariant"].refuted == 0


@pytest.mark.parametrize(
    "code,outcome",
    [
        ("Count++;", "violable"),
        ("Count=0; Count++;", "inconclusive"),
        ("Count=(unsigned char)300;", "inconclusive"),
        ("grow(&Count);", "inconclusive"),
    ],
    ids=["independent-post-state", "multiple-updates", "cast", "alias"],
)
def test_protocol_state_consumer_does_not_promote_a_partial_transition(code, outcome):
    from core.audit.protocol_state import check_invariant_multi_site

    site = {
        "file": "record.c",
        "function": "",
        "line": 1,
        "code": code,
        "rhs_class": "unknown",
    }
    index = {"fields": {"Count": {"writes": [site], "reads": []}}}
    result = check_invariant_multi_site(
        "Count <= Count__post", index, {"record.c": code}
    )
    assert result["outcome"] == outcome, result
    assert len(result["sites"]) == 1
    if outcome == "inconclusive":
        assert result["sites"][0]["verdict"] == "out_of_scope"


@pytest.mark.parametrize("budget,expected", [(1.0, [1000]), (10.0, [10000])])
def test_protocol_consumer_passes_remaining_budget_without_raising_site_cap(
    monkeypatch, budget, expected
):
    from types import SimpleNamespace

    from core.audit import protocol_state

    clock = [0.0]
    monkeypatch.setattr(
        protocol_state, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    observed = []

    def check(invariant, sites, **kwargs):
        observed.append(kwargs["timeout_ms"])
        clock[0] += 0.4
        return [
            inv.SiteResult(line=site["line"], code=site["code"], verdict="preserved")
            for site in sites
        ]

    monkeypatch.setattr(inv, "check_site_batch", check)
    sites = [
        {"file": "record.c", "function": "", "line": line, "code": "Count=0;"}
        for line in [1, 2]
    ]
    result = protocol_state.check_invariant_multi_site(
        "Count <= Limit",
        {"fields": {"Count": {"writes": sites}}},
        {"record.c": "Count=0;\nCount=0;"},
        budget_s=budget,
    )
    assert result["outcome"] == "preserved"
    assert observed == expected


def test_guard_discovery_time_is_charged_before_site_solver_budget(monkeypatch):
    from types import SimpleNamespace

    from core.audit import protocol_state

    clock = [0.0]
    monkeypatch.setattr(
        protocol_state, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    def guards(*args):
        clock[0] = 0.5
        return []

    observed = []

    def check(invariant, sites, **kwargs):
        observed.append(kwargs["timeout_ms"])
        return [
            inv.SiteResult(line=site["line"], code=site["code"], verdict="preserved")
            for site in sites
        ]

    monkeypatch.setattr(protocol_state, "_branch_guards", guards)
    monkeypatch.setattr(inv, "check_site_batch", check)
    site = {"file": "record.c", "function": "Read", "line": 1, "code": "Count=0;"}
    result = protocol_state.check_invariant_multi_site(
        "Count <= Limit",
        {"fields": {"Count": {"writes": [site]}}},
        {"record.c": "Count=0;"},
        budget_s=1.0,
    )
    assert result["outcome"] == "preserved"
    assert observed == [500]


@pytest.mark.parametrize("name", ["sizeof_Count", "sizeofValue", "sizeof_State.Count"])
def test_sizeof_prefix_does_not_turn_a_source_variable_into_a_size_constant(name):
    result = inv.check_invariant_preservation(f"{name} <= Limit", name + "++;")
    assert result.outcome == "violable", result.to_dict()
    model = result.sites[0].model
    assert model[name] <= model["Limit"]
    assert model[name + "'"] == model[name] + 1
    assert model[name + "'"] > model["Limit"]


def test_actual_sizeof_remains_a_nonnegative_opaque_constant():
    result = inv.check_site_preservation("Count <= sizeof(Data)", "Count=0;")
    assert result.verdict == "preserved"


@pytest.mark.parametrize(
    "text",
    [
        "(unsigned char)Count <= Limit",
        "(Alias)+Count <= Limit",
        "-Count <= Limit",
        "Count * Factor <= Limit",
        "Count <= Limit * Factor",
        "Count <= Limit[Index]",
    ],
)
def test_candidate_extraction_does_not_drop_unsupported_expression_parts(text):
    assert inv.extract_invariants(text) == []
