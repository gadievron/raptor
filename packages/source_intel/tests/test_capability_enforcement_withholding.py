"""Inert current-record enforcement admission, no native/parser execution."""

import ast
import __future__
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load(relative, names, namespace):
    path = Path(__file__).resolve().parents[3] / relative
    nodes = [n for n in ast.parse(path.read_text()).body
             if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec",
                 flags=__future__.annotations.compiler_flag), namespace)


@pytest.fixture
def scope():
    ns = {"dataclass": dataclass, "SCHEMA_VERSION": 1,
          "__name__": __name__, "_PRIV_BACK_WALK_DEFAULT_DEPTH": 3,
          "GRADE_DOMINATES": "dominates", "GRADE_SAME_PATH": "same_path",
          "GRADE_SAME_FUNCTION": "same_function"}
    _load("packages/source_intel/analyze.py", {"CapabilityEvidence", "SourceIntelResult",
          "PrivilegeBackWalkEvidence", "AbortEvidence", "_function_privileged_cap_site",
          "compute_privilege_back_walk_evidence"}, ns)
    _load("packages/source_intel/adapter.py", {"_privileged_capability_dominates",
          "_function_has_privileged_cap", "_privilege_back_walk_suppresses"}, ns)
    _load("packages/source_intel/render.py", {"Mitigation", "_render_capability_line",
          "_render_privilege_back_walk_line", "derive_mitigations_found"}, ns)
    return ns


def _record(ns, grade="dominates", function="capable"):
    return ns["CapabilityEvidence"](cap_function=function, location=("owned.c", 7),
                                    grade=grade, enclosing_function="owned")


@pytest.mark.parametrize("grade", ["dominates", "same_path", "same_function", "unknown"])
@pytest.mark.parametrize("function", ["capable", "ns_capable", "has_capability"])
def test_callsite_record_withholds_direct_and_edge_gating(scope, grade, function):
    record = _record(scope, grade, function)
    result = scope["SourceIntelResult"](capabilities=(record,))
    finding = SimpleNamespace(rule_id="cpp/null-dereference", sink=SimpleNamespace(file_path="owned.c", line=9))
    assert scope["_privileged_capability_dominates"](finding, result) is False
    assert scope["_function_has_privileged_cap"]("owned", result) is False
    assert scope["_function_privileged_cap_site"]("owned", result) is None
    assert scope["_privilege_back_walk_suppresses"](finding, result, Path("owned")) is False
    assert result.capabilities == (record,)


def test_unknown_relation_does_not_gather_prerequisites_or_mint_ungated_summary(scope):
    class UnavailableTarget:
        def is_dir(self):
            raise AssertionError("unnecessary target/engine preparation")
    result = scope["SourceIntelResult"](capabilities=(_record(scope),))
    assert scope["compute_privilege_back_walk_evidence"]("owned", UnavailableTarget(), result) is None


@pytest.mark.parametrize("grade", ["dominates", "same_path", "same_function", "unknown"])
@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_capability_call_prose_is_informational_for_every_grade(scope, grade, style):
    text = scope["_render_capability_line"](_record(scope, grade), style)
    assert "`capable(...)`" in text and "owned.c:7" in text
    assert "does not establish" in text and "terminating denial branch" in text
    assert "Attacker must already hold" not in text
    assert "ROOT-EQUIVALENT" not in text


@pytest.mark.parametrize("grade", ["dominates", "same_path", "same_function", "unknown"])
@pytest.mark.parametrize("function", ["capable", "ns_capable", "has_capability"])
def test_callsite_record_creates_no_privilege_gate_mitigation(scope, grade, function):
    result = scope["SourceIntelResult"](capabilities=(_record(scope, grade, function),))
    assert scope["derive_mitigations_found"](result, finding_function="owned") == []


def test_unrelated_abort_mitigation_is_preserved(scope):
    abort = scope["AbortEvidence"](macro="BUG_ON", location=("owned.c", 5),
                                   grade="dominates", enclosing_function="owned")
    result = scope["SourceIntelResult"](capabilities=(_record(scope),), aborts=(abort,))
    entries = scope["derive_mitigations_found"](result, finding_function="owned")
    assert len(entries) == 1 and entries[0].name == "abort_dominates"


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
@pytest.mark.parametrize("summary", ["legacy-all", "legacy-empty", "legacy-partial"])
def test_retained_backwalk_flags_do_not_prove_gated_or_ungated_paths(scope, style, summary):
    record = scope["PrivilegeBackWalkEvidence"](
        finding_function="owned", all_paths_gated=summary != "legacy-partial",
        gating_examples=() if summary == "legacy-empty" else (("caller", "capable", "owned.c", 7),),
        ungated_caller="caller" if summary == "legacy-partial" else None, depth_used=3)
    text = scope["_render_privilege_back_walk_line"](record, style)
    assert "Neither all-path privilege gating nor an ungated path is established" in text
    assert "ONLY via" not in text and "reachable from unprivileged context" not in text


def test_no_callers_summary_keeps_existing_omission(scope):
    record = scope["PrivilegeBackWalkEvidence"](finding_function="owned", all_paths_gated=False, no_callers=True)
    assert scope["_render_privilege_back_walk_line"](record, "stage_d") is None
