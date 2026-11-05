"""Negative-bypass leads must use explicit, case-sensitive code identifiers."""

from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit import evidence_grade as grade
from core.audit.probe_function_scope import source_binding, source_for_function

SOURCE = "int Read(int Amount, int Ceiling) { return Amount + Ceiling; }"


@pytest.mark.parametrize("hypothesis", [
    "negative `Amount` bypasses `Ceiling` check",
    "negative value for `Amount` can bypass the `Ceiling` limit",
    "negative value Amount exceeds Ceiling bound",
    "negative the Amount circumvented the Ceiling check",
    "NEGATIVE `Amount` BYPASSES `Ceiling` CHECK",
    "negative 'Amount' bypassing 'Ceiling' check",
    'negative "Amount" circumvents "Ceiling" bound',
    "negative Amount bypass Ceiling check; negative Amount bypass Ceiling check",
], ids=["quoted", "value-for", "value", "past-tense", "keyword-case", "single-quotes", "double-quotes", "repeated"])
def test_explicit_roles_preserve_case(hypothesis):
    assert sweep._extract_negative_bypass_operands(hypothesis, SOURCE) == ("Amount", "Ceiling")


@pytest.mark.parametrize("hypothesis,expected", [
    pytest.param("negative `Amount`", ("Amount", None), id="no-limit-guess"),
    pytest.param("non-negative Amount bypass Ceiling check", (None, "Ceiling"), id="non-negative-value"),
    pytest.param("negative `Ghost` bypass `Ceiling` check", (None, "Ceiling"), id="missing-value"),
    pytest.param("negative `Amount` bypass `Ghost` check", ("Amount", None), id="missing-limit"),
    pytest.param("negative `amount` bypass `Ceiling` check", (None, "Ceiling"), id="value-case"),
    pytest.param("negative `Amount` bypass `ceiling` check", ("Amount", None), id="limit-case"),
    pytest.param("negative `Amount + 1` bypass `Ceiling` check", (None, "Ceiling"), id="compound-value"),
    pytest.param("negative `Amount` bypass `Ceiling + 1` check", ("Amount", None), id="compound-limit"),
    pytest.param("negative ctx->Amount bypass Ceiling check", (None, "Ceiling"), id="field-value"),
    pytest.param("negative Amount bypass ctx.Ceiling check", ("Amount", None), id="field-limit"),
    pytest.param("negative Amount bypass Ceiling[0] check", ("Amount", None), id="subscript-limit"),
    pytest.param("negative Amount bypass Ceiling() check", ("Amount", None), id="call-limit"),
    pytest.param("negative Amount; negative Other; bypass Ceiling check", (None, "Ceiling"), id="conflicting-values"),
    pytest.param("negative Amount bypass Ceiling check and exceed Other limit", ("Amount", None), id="conflicting-limits"),
    pytest.param("negative Amount bypassesBogus Ceiling check", ("Amount", None), id="not-a-bypass-verb"),
])
def test_missing_unsupported_and_conflicting_roles_decline(hypothesis, expected):
    source = SOURCE.replace("int Ceiling", "int Ceiling, int Other, int size_hint")
    assert sweep._extract_negative_bypass_operands(hypothesis, source) == expected


@pytest.mark.parametrize("source", [
    "int Read(int Amount) { /* Ceiling */ return Amount; }",
    'int Read(int Amount) { const char *s = "Ceiling"; return Amount; }',
    "int Read(int Amount, int CeilingOther) { return Amount; }",
    "int Read(int Amount, int ΩCeiling) { return Amount; }",
], ids=["comment", "string", "identifier-suffix", "unicode-prefix"])
def test_noncode_and_partial_names_do_not_supply_a_limit(source):
    assert sweep._extract_negative_bypass_operands("negative Amount bypass Ceiling check", source) == ("Amount", None)


@pytest.fixture
def c_parser():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


def test_real_model_uses_named_identifiers_without_granting_proof(c_parser):
    pytest.importorskip("z3")
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-negative-bypass",
                                     source=SOURCE, hypothesis="negative Amount bypass Ceiling check")
    assert result.outcome == "confirmed"
    assert result.details["feasible"] is True
    assert result.details["oracle_scope"] == "inferred-arithmetic-model"
    assert set(result.details["model"]) == {"Amount", "Ceiling"}
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("hypothesis", [
    "negative Amount", "negative amount bypass Ceiling check", "negative Amount bypass Ghost check",
])
def test_unresolved_roles_stop_before_solver(c_parser, monkeypatch, hypothesis):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("unresolved operand roles should not start a solve")

    monkeypatch.setattr(smt_verbs, "check_negative_bypass", forbidden)
    source = SOURCE.replace("int Ceiling", "int Ceiling, int max_size")
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-negative-bypass",
                                     source=source, hypothesis=hypothesis)
    assert result.outcome == "inconclusive"
    assert not result.errors


@pytest.mark.parametrize("verb,hypothesis", [
    ("check-oob", "Amount is an index into buffer of size Ceiling"),
    ("check-negative-bypass", "negative Amount bypass Ceiling check"),
])
@pytest.mark.parametrize("stale", [None, "old-operand-parser"])
def test_parent_rejects_results_from_older_operand_parsers(c_parser, monkeypatch, verb, hypothesis, stale):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    binding = source_binding(selected, "Read", verb=verb, hypothesis=hypothesis)
    assert binding.get("query_contract")
    if stale is None:
        binding.pop("query_contract")
    else:
        binding["query_contract"] = stale
    worker = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", rule_id=f"smt:{verb}",
                               outcome="confirmed", matches=[{"model": {"amount": 1}}], details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(worker))
    result = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb=verb,
                                        source=SOURCE, hypothesis=hypothesis)
    assert result.outcome == "inconclusive"
    assert not result.matches
    assert result.details["source_scope_status"] == "unbound-worker-result"
