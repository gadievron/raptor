"""Source-pattern probes need their own function and have diagnostic authority."""

from dataclasses import asdict
from types import SimpleNamespace

import pytest

from core.audit import (
    condition_smt,
    evidence_grade as grade,
    orchestrator as orch,
    sweep,
)
from core.audit.probe_function_scope import (
    FunctionScope,
    source_binding,
    source_for_function,
)
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import (
    ClaimRefutation,
    ProbeOutcome,
    ToolChainResult,
)


CHECKS = [
    ("check-auth-bypass", "check_auth_bypass", "bypass_found"),
    ("check-lock-discipline", "check_lock_discipline", "violation_found"),
    ("check-null-propagation", "check_null_propagation", "null_deref_found"),
    ("check-resource-leak", "check_resource_leak", "leak_found"),
    ("check-early-release", "check_early_release", "early_release_found"),
    ("check-lock-domain", "check_lock_domain", "mismatch_found"),
    ("check-toctou", "check_toctou", "toctou_found"),
]
SOURCE = "int Neighbor(void) { return 37; }\nint Read(void) { return 0; }\n"


def install_checker(monkeypatch, checker, flag, seen):
    def observe(source, *a, **kw):
        seen.append(source)
        found = "37" in source
        return SimpleNamespace(
            **{flag: found},
            applicable=True,
            to_dict=lambda: {flag: found, "reasoning": "test observation"},
        )

    monkeypatch.setattr(condition_smt, checker, observe)


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize("name,found", [("Read", False), ("Neighbor", True)])
def test_all_source_detectors_see_only_their_function(
    monkeypatch, verb, checker, flag, name, found
):
    seen = []
    install_checker(monkeypatch, checker, flag, seen)
    result = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name=name,
        verb=verb,
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == ("confirmed" if found else "inconclusive")
    assert len(seen) == 1
    assert ("37" in seen[0]) is found
    assert seen[0].count("\n") == SOURCE.count("\n")
    assert result.details["source_scope"] == source_binding(seen[0], name, verb=verb)
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize("name", ["Missing", ""])
def test_unresolved_names_never_run_a_source_detector(
    monkeypatch, verb, checker, flag, name
):
    seen = []
    install_checker(monkeypatch, checker, flag, seen)
    result = sweep._run_smt_verb_inner(
        file_path="record.c",
        function_name=name,
        verb=verb,
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
    assert not seen


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize(
    "path,source",
    [
        (
            "record.cpp",
            "int Read(void) { auto callback = [](){return 37;}; return 0; }",
        ),
        (
            "record.go",
            "package example\nfunc Read() int { callback := func() int { return 37 }; _ = callback; return 0 }",
        ),
    ],
)
def test_nested_callable_returns_cannot_become_enclosing_returns(
    monkeypatch, verb, checker, flag, path, source
):
    seen = []
    install_checker(monkeypatch, checker, flag, seen)
    result = sweep._run_smt_verb_inner(
        file_path=path,
        function_name="Read",
        verb=verb,
        source=source,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
    assert len(seen) == 1 and "37" not in seen[0]


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize("verdict", ["confirmed", "refuted"])
def test_legacy_worker_results_without_scope_binding_are_inconclusive(
    monkeypatch, verb, checker, flag, verdict
):
    old = sweep.SweepResult(
        tool="smt",
        file_path="record.c",
        function_name="Read",
        outcome=verdict,
        rule_id="smt:check-overflow:witness",
        matches=[{}],
    )
    monkeypatch.setattr(
        "core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old)
    )
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Read",
        verb=verb,
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
    assert result.details["source_scope_status"] == "unbound-worker-result"
    assert not result.matches
    assert result.rule_id == f"smt:{verb}"


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize("change", ["body", "function", "file", "verb", "rule", "tool"])
def test_parent_rejects_a_worker_binding_to_different_input(
    monkeypatch, verb, checker, flag, change
):
    _, selected = source_for_function(SOURCE, "record.c", "Read")
    binding = source_binding(selected, "Read", verb=verb)
    old = sweep.SweepResult(
        tool="smt",
        file_path="record.c",
        function_name="Read",
        outcome="confirmed",
        rule_id=f"smt:{verb}",
        details={"source_scope": binding},
    )
    if change == "body":
        binding["sha256"] = "wrong source"
    elif change == "function":
        old.function_name = "Neighbor"
    elif change == "file":
        old.file_path = "other.c"
    elif change == "verb":
        binding["verb"] = "check-overflow"
    elif change == "rule":
        old.rule_id = "smt:check-overflow:witness"
    else:
        old.tool = "other"
    monkeypatch.setattr(
        "core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old)
    )
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Read",
        verb=verb,
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
    assert result.details["source_scope_status"] == "unbound-worker-result"


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
def test_bound_worker_observations_are_retained_as_leads(
    monkeypatch, verb, checker, flag
):
    def child(_entry, request, **kw):
        result = sweep._run_smt_verb_inner(
            file_path=request["file_path"],
            function_name=request["function_name"],
            verb=request["verb"],
            source=request["source"],
            hypothesis=request["hypothesis"],
        )
        return asdict(result)

    seen = []
    install_checker(monkeypatch, checker, flag, seen)
    monkeypatch.setattr("core.audit.subproc_json.run_json_child", child)
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Neighbor",
        verb=verb,
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "confirmed"
    assert result.details["source_scope"]["function"] == "Neighbor"
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
@pytest.mark.parametrize("fallback", [False, True])
def test_source_models_cannot_gain_verification_from_a_model_suffix(
    monkeypatch, verb, checker, flag, suffix, fallback
):
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda ns: None)
    stamp = f"smt:{verb}{suffix}"
    assert not grade.is_tool_evidence(stamp)
    assert not grade.is_verification_evidence(stamp)
    assert not orch._promotion_grade_receipt(stamp)
    assert grade.is_verification_evidence(stamp + "+lifecycle")
    assert grade.is_verification_evidence("smt:check-overflow")


@pytest.mark.parametrize("verb,checker,flag", CHECKS)
@pytest.mark.parametrize("prefix", ["", "smt:"])
def test_legacy_source_pattern_refutations_have_no_clean_authority(
    verb, checker, flag, prefix
):
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="claim")
    identity = SourceIdentity("current", (1, 2, 3))
    check = ProbeOutcome("smt", "refuted", prefix + verb + ":witness")
    receipt = ClaimRefutation(**scope, checks=(check,), source_identity=identity)
    assert not receipt.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe(check.tool, check.verdict, check.rule_id)
    assert chain.refutation_record(**scope) is None
    control = ClaimRefutation(
        **scope,
        source_identity=identity,
        checks=(ProbeOutcome("smt", "refuted", "check-overflow"),),
    )
    assert control.matches(**scope, source_identity=identity)


@pytest.mark.parametrize("phase", ["screen", "clean"])
def test_direct_audit_passes_cannot_borrow_a_neighboring_auth_signal(
    tmp_path, monkeypatch, phase
):
    seen = []
    install_checker(monkeypatch, "check_auth_bypass", "bypass_found", seen)
    monkeypatch.setattr(orch, "_read_raw_source", lambda *a, **kw: SOURCE)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=None)
    result = orch.OrchestratorResult()
    if phase == "screen":
        gap = {"file": "record.c", "name": "Read", "line_start": 2}
        assert orch._pre_loop_smt_screen([gap], config, result) == [gap]
        assert not gap.get("_smt_pre_evidence")
    else:
        result.outcomes = [
            orch.ReviewOutcome(
                file="record.c", function="Read", line=2, status="clean", body="review"
            )
        ]
        result.clean = 1
        orch._promote_smt_clean(result, config)
        assert result.outcomes[0].status == "clean"
    assert seen and all("37" not in source for source in seen)


def test_unresolved_scope_cannot_produce_empty_probe_source():
    with pytest.raises(ValueError):
        FunctionScope("missing").source_span(SOURCE)


@pytest.mark.parametrize("name", ["Missing", ""])
def test_parent_does_not_spawn_a_worker_for_an_unresolved_scope(monkeypatch, name):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("unresolved source should not dispatch")

    monkeypatch.setattr("core.audit.subproc_json.run_json_child", forbidden)
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name=name,
        verb="check-auth-bypass",
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
    assert not calls


@pytest.mark.parametrize("details", [None, ["unexpected"], "unexpected"])
def test_malformed_worker_details_cannot_gain_authority(monkeypatch, details):
    old = sweep.SweepResult(
        tool="smt",
        file_path="record.c",
        function_name="Read",
        outcome="refuted",
        details=details,
    )
    monkeypatch.setattr(
        "core.audit.subproc_json.run_json_child", lambda *a, **kw: asdict(old)
    )
    result = sweep._smt_verb_in_subprocess(
        file_path="record.c",
        function_name="Read",
        verb="check-auth-bypass",
        source=SOURCE,
        hypothesis="claim",
    )
    assert result.outcome == "inconclusive"
    assert isinstance(result.details, dict)
