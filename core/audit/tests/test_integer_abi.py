"""Target layout is explicit, survives dispatch, and partitions cached proofs."""

import json
from dataclasses import asdict

import pytest

from core.audit import arithmetic_operation as operation, orchestrator as orch, sweep
from core.audit.integer_abi import INTEGER_ABIS, IntegerABI, integer_abi_record, resolve_integer_abi
from core.audit.probe_function_scope import source_binding, source_for_function

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


SOURCE = "long Read(long a, long b) { if (a >= 0 && b >= 0 && a <= 65535 && b <= 65535) return a * b; return 0; }"
HYPOTHESIS = "integer overflow in `a` * `b`"


@pytest.fixture
def c_grammar():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("name", list(INTEGER_ABIS))
def test_profiles_round_trip_through_plain_json(name):
    abi = INTEGER_ABIS[name]
    assert resolve_integer_abi(json.loads(json.dumps(abi.record()))) == abi


@pytest.mark.parametrize("value", [None, "native", "host", "auto", "unknown", {}, {"name": "lp64"}])
def test_unknown_is_not_a_host_or_c32_default(value):
    assert resolve_integer_abi(value) is None


@pytest.mark.parametrize("field,value", [("int_bits", True), ("int_bits", 128), ("long_bits", 16), ("name", "bad\nname")])
def test_invalid_broker_records_are_not_target_facts(field, value):
    record = integer_abi_record("lp64")
    record[field] = value
    assert resolve_integer_abi(record) is None


@pytest.mark.parametrize("abi,profile,expected", [
    pytest.param("lp64", "int64", "refuted", id="lp64-long-is-64-bit"),
    pytest.param("llp64", "int32", "confirmed", id="llp64-long-is-32-bit"),
])
def test_same_source_differs_by_target_abi_not_host(c_grammar, abi, profile, expected):
    pytest.importorskip("z3")
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=SOURCE, hypothesis=HYPOTHESIS, integer_abi=abi)
    assert result.outcome == expected, result.errors
    assert result.details["source_operation"]["profile"] == profile
    assert result.details["source_operation"]["integer_abi"] == integer_abi_record(abi)


@pytest.mark.parametrize("abi,profile,expected", [
    pytest.param("ilp32", "int32", "confirmed", id="32-bit-int-promotion"),
    pytest.param("ilp64", "int64", "refuted", id="64-bit-int-promotion"),
])
def test_promotions_use_the_target_int_width(c_grammar, abi, profile, expected):
    pytest.importorskip("z3")
    text = "int Read(unsigned short a, unsigned short b) { if (a <= 65535 && b <= 65535) return a * b; return 0; }"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=text, hypothesis=HYPOTHESIS, integer_abi=abi)
    assert result.outcome == expected, result.errors
    assert result.details["source_operation"]["profile"] == profile


def test_equal_short_and_int_width_promotes_unsigned_short_to_unsigned_int(c_grammar):
    text = "int Read(unsigned short a, unsigned short b) { if (a <= 100 && b <= 100) return a * b; return 0; }"
    result = operation.bind_arithmetic_operation(text, ["a", "b"], "*", language="c", integer_abi="i16")
    assert result.profile == "uint16"
    assert not result.domains


@pytest.mark.parametrize("runner", [sweep._run_smt_verb_inner, sweep._smt_verb_in_subprocess], ids=["worker", "parent"])
def test_unknown_abi_stops_before_vocab_or_solver(monkeypatch, runner):
    def forbidden(*args, **kwargs):
        pytest.fail("an unknown target ABI must not dispatch native work")

    monkeypatch.setattr("core.audit.probe_function_scope.source_for_function", forbidden)
    monkeypatch.setattr(sweep, "_verb_vocab", forbidden)
    monkeypatch.setattr(sweep, "_run_smt_verb_on_source", forbidden)
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", forbidden)
    result = runner(file_path="record.c", function_name="Read", verb="check-overflow", source=SOURCE, hypothesis=HYPOTHESIS)
    assert result.outcome == "inconclusive"
    assert result.details["integer_abi_status"] == "unavailable"


@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
def test_worker_reply_for_another_abi_cannot_be_reused(c_grammar, monkeypatch, outcome):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", rule_id="smt:check-overflow",
                            outcome=outcome, matches=[{}],
                            details={"source_scope": source_binding(selected, "Read", verb="check-overflow", integer_abi="llp64", hypothesis=HYPOTHESIS)})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                         source=SOURCE, hypothesis=HYPOTHESIS, integer_abi="lp64")
    assert result.outcome == "inconclusive"
    assert result.details["source_scope_status"] == "unbound-worker-result"
    assert not result.matches


def test_broker_transports_abi_without_rederiving_it_from_host(c_grammar, monkeypatch):
    pytest.importorskip("z3")
    seen = []

    def child(entry, request, **kwargs):
        seen.append(request["integer_abi"])
        assert request["target_path"] is None
        return sweep._run_smt_verb_inner_json(request)

    monkeypatch.setattr("core.audit.subproc_json.run_json_child", child)
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                         source=SOURCE, hypothesis=HYPOTHESIS, integer_abi="lp64")
    assert seen == [integer_abi_record("lp64")]
    assert result.outcome == "refuted", result.errors


def test_tool_chain_memo_is_partitioned_by_integer_abi(c_grammar, tmp_path, monkeypatch):
    pytest.importorskip("z3")
    (tmp_path / "record.c").write_text(SOURCE)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="lp64")
    seen = []

    def run(**kwargs):
        result = sweep._run_smt_verb_inner(**kwargs)
        seen.append((kwargs["integer_abi"], result.outcome))
        return result

    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", run)
    request = dict(config=config, file_path="record.c", function_name="Read", line_start=1,
                   source=SOURCE, hypothesis=HYPOTHESIS)
    chain = [{"type": "smt", "config": {"verb": "check-overflow"}}]
    orch._run_tool_chain(chain, **request)
    orch._run_tool_chain(chain, **request)
    config.integer_abi = "llp64"
    result = orch._run_tool_chain(chain, **request)
    assert seen == [("lp64", "refuted"), ("llp64", "confirmed")]
    assert "smt:check-overflow" in result


def test_hypothesis_tool_config_cannot_select_the_target_abi(c_grammar, tmp_path, monkeypatch):
    (tmp_path / "record.c").write_text(SOURCE)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    seen = []

    def run(**kwargs):
        seen.append(kwargs["integer_abi"])
        return sweep._run_smt_verb_inner(**kwargs)

    monkeypatch.setattr(sweep, "_smt_verb_in_subprocess", run)
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow", "integer_abi": "lp64"}}],
        config=config, file_path="record.c", function_name="Read", line_start=1,
        source=SOURCE, hypothesis=HYPOTHESIS,
    )
    assert seen == [None]
    assert not result
    assert not result.refutations(file="record.c", function="Read", line_start=1, hypothesis=HYPOTHESIS)


def test_unknown_abi_also_prevents_auxiliary_disproof():
    from core.audit.condition_smt import disprove_integer_overflow

    result = disprove_integer_overflow("integer overflow in `a * b`", SOURCE, file_path="record.c", function_name="Read")
    assert result.disproved is None
    assert "ABI unavailable" in result.reasoning


def test_explicit_record_is_a_seam_for_measured_target_facts():
    abi = IntegerABI("compiler-measured", 8, 16, 32, 64, 64, "twos-complement-no-padding")
    assert resolve_integer_abi(abi.record()) == abi


def test_same_named_measured_layout_still_binds_every_width(c_grammar, monkeypatch):
    expected = IntegerABI("compiler-measured", 8, 16, 32, 64, 64, "twos-complement-no-padding")
    other = IntegerABI("compiler-measured", 8, 16, 32, 32, 64, "twos-complement-no-padding")
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", rule_id="smt:check-overflow",
                            outcome="confirmed", matches=[{}], details={"source_scope": source_binding(
                                selected, "Read", verb="check-overflow", integer_abi=other, hypothesis=HYPOTHESIS)})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                         source=SOURCE, hypothesis=HYPOTHESIS, integer_abi=expected)
    assert result.outcome == "inconclusive"
    assert not result.matches


def test_abi_memo_context_covers_measured_widths_not_just_display_name():
    from core.audit.integer_abi import integer_abi_key

    a = IntegerABI("compiler-measured", 8, 16, 32, 64, 64, "twos-complement-no-padding")
    b = IntegerABI("compiler-measured", 8, 16, 32, 32, 64, "twos-complement-no-padding")
    assert integer_abi_key(a) != integer_abi_key(b)
    assert integer_abi_key(a) == integer_abi_key(a.record())


def test_widths_alone_do_not_imply_signed_representation():
    record = integer_abi_record("lp64")
    del record["representation"]
    assert resolve_integer_abi(record) is None
    record["representation"] = "ones-complement"
    assert resolve_integer_abi(record) is None


@pytest.mark.parametrize("outcome", ["confirmed", "refuted"])
def test_worker_reply_for_another_hypothesis_cannot_be_relabelled(c_grammar, monkeypatch, outcome):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-overflow", integer_abi="llp64",
                             hypothesis="integer overflow in `a` + `b`")
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", rule_id="smt:check-overflow",
                            outcome=outcome, matches=[{}], details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                         source=SOURCE, hypothesis=HYPOTHESIS, integer_abi="llp64")
    assert result.outcome == "inconclusive"
    assert not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"
