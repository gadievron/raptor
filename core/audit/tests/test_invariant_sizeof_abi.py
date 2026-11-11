"""Target integer storage sizes and ABI-bound invariant receipts."""

import pytest

from core.audit import invariant_smt as inv
from core.audit.integer_abi import INTEGER_ABIS
from core.audit.invariant_expression import parse_expr, validate_counterexample
from core.audit.invariant_sizeof import resolved_sizeof_values

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize(
    "abi,spelling,size",
    [
        ("ilp32", "long", 4),
        ("lp64", "long", 8),
        ("llp64", "long", 4),
        ("ilp64", "int", 8),
        ("i16", "int", 2),
        ("lp64", "char", 1),
    ],
)
def test_builtin_storage_sizes_use_the_selected_target(abi, spelling, size):
    result = inv.check_invariant_preservation(
        f"Count == {size}", f"Count=sizeof({spelling});", integer_abi=abi
    )
    assert result.outcome == "preserved", result.to_dict()
    assert result.sites[0].integer_abi == INTEGER_ABIS[abi].record()


def test_target_bytes_are_not_assumed_to_be_eight_bits():
    abi = dict(INTEGER_ABIS["lp64"].record(), name="wide-char", char_bits=16)
    result = inv.check_site_preservation(
        "Count == 4", "Count=sizeof(long);", integer_abi=abi
    )
    assert result.verdict == "preserved", result.to_dict()
    assert result.integer_abi == abi


def test_wrong_target_size_has_an_abi_constrained_counterexample():
    result = inv.check_site_preservation(
        "Count == 4", "Count=sizeof(long);", integer_abi="lp64"
    )
    assert result.verdict == "violable", result.to_dict()
    assert result.model["sizeof(long)"] == result.model["Count'"] == 8


@pytest.mark.parametrize("spelling", ["Data", "long*", "struct Data", "float", "_Bool"])
def test_missing_storage_layout_is_not_inferred_from_integer_value_bits(spelling):
    assert resolved_sizeof_values([parse_expr(f"sizeof({spelling})")], "lp64") == {}


def test_replay_rejects_a_size_that_contradicts_the_bound_abi():
    lhs, rhs, new = parse_expr("Count"), parse_expr("4"), parse_expr("sizeof(long)")
    for size, expected in [(0, False), (4, False), (8, True)]:
        model = {"Count": 4, "sizeof(long)": size, "Count'": size}
        assert (
            validate_counterexample(
                lhs, "==", rhs, new, "Count", [], model, integer_abi="lp64"
            )
            is expected
        )


@pytest.mark.parametrize("mode", ["site", "batch"])
def test_reply_cannot_change_the_query_abi(monkeypatch, mode):
    from core.audit import condition_smt

    def dispatch(tag, args, **kwargs):
        reply = condition_smt._z3_dispatch_json({"tag": tag, "args": args})
        row = reply["result"] if mode == "site" else reply["sites"][0]["result"]
        row["integer_abi"] = INTEGER_ABIS["ilp32"].record()
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    if mode == "site":
        assert (
            inv.check_site_preservation(
                "Count == 8", "Count=sizeof(long);", integer_abi="lp64"
            ).verdict
            == "unknown"
        )
    else:
        assert (
            inv.check_site_batch(
                "Count == 8",
                [dict(code="Count=sizeof(long);", line=1, pre_conditions=[])],
                integer_abi="lp64",
            )
            is None
        )


@pytest.mark.parametrize("abi,outcome,step", [("ilp32", "inconclusive", "preserved"), ("lp64", "confirmed", "violable")])
def test_protocol_adjudication_uses_the_target_abi(abi, outcome, step):
    from core.audit.protocol_state import run_protocol_state_check

    result = run_protocol_state_check(
        ".",
        "a.c",
        "Read",
        "Count == 4",
        invariant="Count == 4",
        source_texts={
            "a.c": "void Read(struct S *State){\nState->Count=sizeof(long);\n}"
        },
        integer_abi=abi,
    )
    assert result.outcome == outcome, result.to_dict()
    assert len(result.invariant["per_site"]) == 1
    assert result.invariant["per_site"][0]["integer_abi"] == INTEGER_ABIS[abi].record()
    assert result.invariant["per_site"][0]["verdict"] == step
    if step == "preserved":
        assert "base case not checked" in result.reason


def test_audit_tool_chain_persists_abi_context(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig, _run_tool_chain

    target = tmp_path / "target"
    target.mkdir()
    source = "void Read(int Count){Count=sizeof(long);}"
    (target / "a.c").write_text(source)
    config = OrchestratorConfig(
        target_path=target, out_dir=tmp_path / "out", integer_abi="lp64"
    )
    config.out_dir.mkdir()
    result = _run_tool_chain(
        [{"type": "smt_invariant", "config": {"invariant": "Count == 8"}}],
        config=config,
        file_path="a.c",
        function_name="Read",
        source=source,
        hypothesis="Count == 8 can be violated",
        line_start=1,
    )
    assert [row.verdict for row in result.outcomes] == ["inconclusive"]
    assert "base case not checked" in result.outcomes[0].reason
    import json
    from core.audit.record import AUDIT_LOG_FILENAME

    records = [
        json.loads(line)
        for line in (config.out_dir / AUDIT_LOG_FILENAME).read_text().splitlines()
    ]
    receipts = [row for row in records if row.get("action") == "invariant_preservation"]
    assert (
        receipts
        and receipts[0]["sites"][0]["integer_abi"] == INTEGER_ABIS["lp64"].record()
    )


def test_standing_protocol_prepass_receives_the_abi(monkeypatch):
    from core.audit import condition_smt, protocol_state
    from core.audit.protocol_state import run_protocol_state_prepass

    calls, adjudications = [], []
    original_worker = condition_smt._run_z3_child
    original_adjudicate = protocol_state._adjudicate_invariant

    def dispatch(tag, args, **kwargs):
        calls.append((tag, args))
        return original_worker(tag, args, **kwargs)

    def adjudicate(*args, **kwargs):
        result = original_adjudicate(*args, **kwargs)
        adjudications.append(result)
        return result

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    monkeypatch.setattr(protocol_state, "_adjudicate_invariant", adjudicate)

    domain = {
        "invariants": [
            dict(
                id="size-rule",
                statement="Count == 4",
                provenance="verbatim",
                receipt={"file": "notes.md", "quote": "the state holds four bytes"},
            )
        ]
    }
    texts = {"a.c": "void Read(struct S *State){\nState->Count=sizeof(long);\n}"}
    result = run_protocol_state_prepass(texts, domain_model=domain, integer_abi="ilp32")
    assert result["telemetry"]["invariants_checked"] == 1
    assert len(adjudications) == 1
    assert len(calls) == 1, adjudications[0].to_dict()
    assert calls[0][0] == "invariant_site_batch"
    assert calls[0][1]["integer_abi"] == INTEGER_ABIS["ilp32"].record()
    site = adjudications[0].invariant["per_site"][0]
    assert site["verdict"] == "preserved" and site["integer_abi"] == INTEGER_ABIS["ilp32"].record()
    assert adjudications[0].outcome == "inconclusive"
    assert "base case not checked" in adjudications[0].reason
    assert result["telemetry"]["refuted"] == 0
    assert result["telemetry"]["inconclusive"] == 1


@pytest.mark.parametrize("bad", ["absent-profile", {"name": "incomplete"}])
def test_invalid_abi_declines_before_worker_dispatch(monkeypatch, bad):
    from core.audit import condition_smt

    def unexpected(*args, **kwargs):
        pytest.fail("invalid ABI reached native dispatch")

    monkeypatch.setattr(condition_smt, "_run_z3_child", unexpected)
    assert (
        inv.check_site_preservation(
            "Count == 8", "Count=sizeof(long);", integer_abi=bad
        ).verdict
        == "unknown"
    )


def test_unknown_abi_never_selects_the_analysis_hosts_layout():
    for abi in (None, "unknown"):
        assert resolved_sizeof_values([parse_expr("sizeof(long)")], abi) == {}


@pytest.mark.parametrize(
    "provenance", ["explicit", "host-assumption", "binary-platform"]
)
def test_receipts_preserve_provenance_without_borrowing_mutable_records(provenance):
    abi = dict(INTEGER_ABIS["lp64"].record(), source=provenance)
    result = inv.check_site_preservation(
        "Count == 8", "Count=sizeof(long);", integer_abi=abi
    )
    assert result.verdict == "preserved"
    abi["long_bits"] = 32
    assert result.integer_abi["long_bits"] == 64
    assert result.integer_abi["source"] == provenance
    record = result.to_dict()
    record["integer_abi"]["long_bits"] = 32
    assert result.integer_abi["long_bits"] == 64


@pytest.mark.slow
@pytest.mark.parametrize("abi,size", [("ilp32", 4), ("lp64", 8), ("i16", 2)])
def test_native_builtin_sizeof_abi(abi, size):
    spelling = "int" if abi == "i16" else "long"
    result = inv.check_site_preservation(
        f"Count == {size}",
        f"Count=sizeof({spelling});",
        integer_abi=abi,
        timeout_ms=30_000,
    )
    assert result.verdict == "preserved", result.to_dict()
    assert result.integer_abi == INTEGER_ABIS[abi].record()
