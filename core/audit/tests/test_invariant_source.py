"""Proof-bearing invariant transitions require source-bound lvalues and guards."""

import pytest

from core.audit import invariant_smt as inv, invariant_source as source

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.mark.parametrize(
    "prefix",
    ["int Count=Limit;", "int Limit=Count;", 'asm volatile("" : "+r"(Count));'],
    ids=["shadow-written-value", "shadow-bound", "assembly-output"],
)
def test_protocol_snapshot_rejects_rebound_names_and_opaque_effects(prefix):
    from core.audit.protocol_state import _branch_guards, check_invariant_multi_site

    code = (
        "void Read(int Count,int Limit){\n if(Count<Limit){\n "
        + prefix
        + "\n Count++;\n }}"
    )
    assert not source.guard_snapshot_supported(code, "Read", 4)
    assert _branch_guards(code, "Read", 4) is None
    site = dict(file="a.c", function="Read", line=4, code="Count++;")
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": [site]}}}, {"a.c": code}
    )
    assert result["guard_leg"] is False


@pytest.mark.parametrize(
    "prefix",
    ["int Other=0;", "{int Count=Limit;}", "sizeof(Count++);"],
    ids=["unrelated-local", "ended-shadow-scope", "unevaluated-write"],
)
def test_protocol_snapshot_keeps_unchanged_bindings(prefix):
    code = (
        "void Read(int Count,int Limit){\n if(Count<Limit){\n "
        + prefix
        + "\n Count++;\n }}"
    )
    assert source.guard_snapshot_supported(code, "Read", 4)


def test_protocol_snapshot_keeps_a_local_captured_before_the_guard():
    code = "void Read(int Count,int Limit){int Bound=Limit;\n if(Count<Bound){\n Count++;\n }}"
    assert source.guard_snapshot_supported(code, "Read", 3)


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize(
    "code", ["(Count)++;", "++(Count);", "((Count))+=1;", "++((Count));"]
)
def test_parenthesized_updates_are_not_vacuous_preservation(code):
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == "violable", result.to_dict()
    model = result.sites[0].model
    assert model["Count'"] == model["Count"] + 1 > model["Limit"]


@pytest.mark.parametrize(
    "code", ["++State->Count;", "--State.Count;", "(State->Count)++;"]
)
def test_unqualified_member_updates_require_binding_instead_of_vacuous_safety(code):
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == "inconclusive"
    assert any("alias" in site.reason for site in result.sites)


@pytest.mark.parametrize("code", ["++(State -> Count);", "( (State) -> Count )++;"])
def test_exact_qualified_lvalue_is_bound_across_whitespace_and_grouping(code):
    result = inv.check_site_preservation("State->Count <= Limit", code)
    assert result.verdict == "violable", result.to_dict()
    model = result.model
    assert model["State->Count'"] == model["State->Count"] + 1 > model["Limit"]


@pytest.mark.parametrize(
    "body,outcome",
    [
        ("if(Count<Limit) Count++;", "preserved"),
        ("if(Count>=Limit) Count++;", "violable"),
        ("if(Count>=Limit) {} else (Count)++;", "preserved"),
        ("if(!(Count>=Limit)) ++Count;", "preserved"),
        ("if(Count<Limit && Step>0) Count++;", "preserved"),
        ("if(Count>=Limit || Step<=0) {} else Count++;", "preserved"),
    ],
    ids=[
        "true-edge",
        "violable-edge",
        "false-edge",
        "negation",
        "conjunction",
        "negated-disjunction",
    ],
)
def test_source_branch_polarity_reaches_the_mathematical_obligation(body, outcome):
    code = "void Read(int Count,int Limit,int Step){" + body + "}"
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == outcome, result.to_dict()


@pytest.mark.parametrize(
    "prefix", ["Count=Limit;", "Limit=Count;", "touch();", "*Pointer=Limit;"]
)
def test_reaching_guards_are_not_reused_after_intervening_state_changes(prefix):
    code = "void Read(int Count,int Limit){if(Count<Limit){" + prefix + "Count++;}}"
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == "inconclusive", result.to_dict()
    assert any(
        "guard" in site.reason or "alias" in site.reason for site in result.sites
    )


@pytest.mark.parametrize(
    "code", ["sizeof(Count++);", "sizeof((Count)++);", "sizeof(touch());"]
)
def test_unevaluated_expression_operands_do_not_mint_mutation_sites(code):
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == "preserved" and result.sites == [], result.to_dict()


@pytest.mark.parametrize(
    "code",
    [
        "sizeof(int[Count++]);",
        "while(Flag)Count++;",
        "int Count=0;",
        "int Count;",
        "Count=0;touch();",
        "*Pointer=0;",
        "if(Count<Limit){",
    ],
    ids=[
        "evaluated-size",
        "loop",
        "local-initialization",
        "local-binding",
        "call",
        "indirect-write",
        "incomplete-source",
    ],
)
def test_unmodeled_frames_never_mint_preservation(code):
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == "inconclusive", result.to_dict()


def test_no_c_parser_never_falls_back_to_regex_safety(monkeypatch):
    monkeypatch.setattr(source, "_get_parser", lambda language: None)
    result = inv.check_invariant_preservation("Count <= Limit", "(Count)++;")
    assert result.outcome == "inconclusive" and "parser unavailable" in result.reason


def test_legacy_line_inventory_keeps_its_non_parser_contract():
    assert inv.find_mutation_sites("Count++\n", {"Count"}) == [
        (1, "Count++", "Count", "++", "")
    ]


def test_protocol_guard_leg_rejects_a_stale_source_snapshot():
    from core.audit.protocol_state import _branch_guards, check_invariant_multi_site

    code = "void Read(int Count,int Limit){\n if(Count<Limit){\n Count=Limit;\n Count++;\n }}"
    assert _branch_guards(code, "Read", 4) is None
    site = dict(file="a.c", function="Read", line=4, code="Count++;")
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": [site]}}}, {"a.c": code}
    )
    assert result["guard_leg"] is False


def test_c_branch_metadata_survives_batch_dispatch():
    results = inv.check_site_batch(
        "Count <= Limit",
        [
            dict(code="if(Count<Limit)(Count)++;", line=1, pre_conditions=[]),
            dict(code="if(Count>=Limit)++(Count);", line=2, pre_conditions=[]),
        ],
    )
    assert [result.verdict for result in results] == ["preserved", "violable"]


@pytest.mark.slow
@pytest.mark.parametrize(
    "code,verdict",
    [("(Count)++;", "violable"), ("if(Count<Limit)++Count;", "preserved")],
    ids=["grouped-update", "guarded-update"],
)
def test_native_source_bound_invariant_worker(code, verdict):
    result = inv.check_site_preservation("Count <= Limit", code, timeout_ms=30_000)
    assert result.verdict == verdict, result.to_dict()


@pytest.mark.parametrize(
    "body",
    [
        "int Bound=0;if(Count<Bound)Count++;",
        "if(Count<UNKNOWN_BOUND)Count++;",
        "if(Count<sizeof(int[Count++]))Count++;",
    ],
)
def test_guards_cannot_invent_free_values_for_locals_macros_or_evaluated_sizes(body):
    result = inv.check_invariant_preservation(
        "Count <= Limit", "void Read(int Count,int Limit){" + body + "}"
    )
    assert result.outcome == "inconclusive", result.to_dict()


@pytest.mark.parametrize(
    "code", ["State=Other;", "struct State *State;", "State=Other;State->Count=Limit;"]
)
def test_changing_the_owner_of_a_field_needs_a_binding_model(code):
    result = inv.check_invariant_preservation("State->Count <= Limit", code)
    assert result.outcome == "inconclusive", result.to_dict()


def test_assembly_is_not_vacuous_source_preservation():
    result = inv.check_invariant_preservation("Count <= Limit", 'asm("nop");')
    assert result.outcome == "inconclusive", result.to_dict()


@pytest.mark.parametrize("mode", ["site", "batch"])
@pytest.mark.parametrize("version", [2, 3, 4, 5, 6])
def test_pre_source_admission_receipts_are_not_reused(monkeypatch, mode, version):
    from core.audit import condition_smt

    def dispatch(tag, args, **kwargs):
        result = condition_smt._z3_dispatch_json({"tag": tag, "args": args})
        result["binding"]["query_contract"] = (
            f"mathematical-invariant-worker-v{version}"
            if mode == "site"
            else f"mathematical-invariant-site-batch-v{version}"
        )
        return result

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    if mode == "site":
        assert (
            inv.check_site_preservation("Count <= Limit", "(Count)++;").verdict
            == "unknown"
        )
    else:
        assert (
            inv.check_site_batch(
                "Count <= Limit", [dict(code="(Count)++;", line=1, pre_conditions=[])]
            )
            is None
        )
