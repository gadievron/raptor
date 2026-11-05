"""A bound on one C variable must not disprove overflow in its case twin."""

import pytest

from core.audit import sweep
from core.audit.condition_smt import disprove_integer_overflow


@pytest.mark.parametrize("guard_name,feasible", [("value", True), ("Value", False)])
def test_source_overflow_paths_keep_case_distinct_values(guard_name, feasible):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    source = (
        "unsigned Read(unsigned Value, unsigned value, unsigned Step) {"
        f"if ({guard_name} <= 10 && Step <= 10) return Value + Step;"
        "return 0; }"
    )
    hypothesis = "integer overflow in `Value` + `Step`"
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert result.outcome == ("confirmed" if feasible else "refuted")
    auxiliary = disprove_integer_overflow("integer overflow in `Value + Step`", source,
                                          file_path="record.c", function_name="Read", integer_abi="ilp32")
    assert auxiliary.disproved is (not feasible)
    if feasible:
        assert {"Value", "value", "Step"} <= auxiliary.witness.keys()


@pytest.mark.parametrize("verdict", ["confirmed", "refuted"])
def test_parent_rejects_case_folding_overflow_workers(monkeypatch, verdict):
    from dataclasses import asdict
    from core.audit.probe_function_scope import source_binding, source_for_function

    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")
    source = "unsigned Read(unsigned Value, unsigned value) { return Value + value; }"
    hypothesis = "integer overflow in `Value` + `value`"
    _, selected = source_for_function(source, "record.c", "Read")
    binding = source_binding(selected, "Read", verb="check-overflow", hypothesis=hypothesis, integer_abi="ilp32")
    binding["query_contract"] = "abi-typed-overflow-v4"
    old = sweep.SweepResult(tool="smt", file_path="record.c", function_name="Read", rule_id="smt:check-overflow",
                            outcome=verdict, matches=[{"model": {"value": 0}}], details={"source_scope": binding})
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old))
    observed = sweep._smt_verb_in_subprocess(file_path="record.c", function_name="Read", verb="check-overflow",
                                           source=source, hypothesis=hypothesis, integer_abi="ilp32")
    assert observed.outcome == "inconclusive"
    assert not observed.matches
    assert observed.details["source_scope_status"] == "unbound-worker-result"
