"""Automatic witness spending requires a possible independent defect oracle."""

import ast
import copy
from pathlib import Path

import pytest

from core.audit import dark_verify as dv
from core.audit import orchestrator as orch
from core.audit.dark_verify import _dispatch as dispatch


@pytest.fixture
def probes(tmp_path, monkeypatch):
    counts = {"model": 0, "execute": 0}
    monkeypatch.setattr(dispatch.shutil, "which", lambda name: "/tools/" + name)
    def parse(*args, **kwargs):
        return dv.DarkWitnessSpec(
            finding_key=kwargs["finding_key"], file=kwargs["file"], function=kwargs["function"],
            language=kwargs["language"], expected_crash=True,
        )
    def execute(spec, *args, **kwargs):
        counts["execute"] += 1
        return dv.DarkVerifyResult(finding_key=spec.finding_key, verdict="confirmed", actual_return="7")
    def model(*args):
        counts["model"] += 1
        return "stub"
    monkeypatch.setattr(dv, "parse_witness_response", parse)
    monkeypatch.setattr(dv, "execute_witness", execute)
    return counts, model


def run(tmp_path, probes, lane, *, file="record.py", cwe="CWE-416", diagnostics=False, status="dark", adversarial=False, promoted=False):
    counts, model = probes
    outcomes = [orch.ReviewOutcome(
        file=file, function="Read", line=1, status=status, body="Reviewed.", hypothesis="memory lifetime concern",
        review_result={"cwe_class": cwe, "adversarial_needs_evidence": adversarial},
    )]
    if lane == "parallel":
        outcomes.append(copy.deepcopy(outcomes[0]))
        outcomes[1].function = "Other"
    result = orch.OrchestratorResult(outcomes=outcomes)
    setattr(result, {"dark": "dormant", "suspicious": "suspicious", "clean": "clean", "finding": "findings"}[status], len(outcomes))
    before = copy.deepcopy(outcomes)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    if lane == "early":
        eligible, futures, executor = orch._submit_dark_probes_early(
            result, config, model, include_diagnostics=diagnostics,
        )
        orch._drain_dark_probes(result, config, eligible, futures, executor)
    else:
        orch._run_dark_verification(result, config, llm_client=model,
                                    max_workers=2 if lane == "parallel" else 1,
                                    include_diagnostics=diagnostics)
    if promoted:
        assert all(o.status == "finding" and "dark_verify:sanitizer-violation" in o.evidence_tool for o in outcomes)
        assert result.findings == len(outcomes)
    else:
        assert outcomes == before
    return len(outcomes)


@pytest.mark.parametrize("file", ["record.py", "record.go", "record.js", "record.ts", "record.rb", "record.php", "record.java", "record.lua", "record.pl", "record.unknown"])
@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_unsupported_oracles_spend_no_model_or_execution_calls(tmp_path, probes, file, lane):
    run(tmp_path, probes, lane, file=file)
    assert probes[0] == {"model": 0, "execute": 0}


@pytest.mark.parametrize("cwe", ["CWE-79", "CWE-89", "CWE-287", "CWE-457", "CWE-664"])
@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_known_contract_oracle_mismatch_spends_nothing(tmp_path, probes, cwe, lane):
    run(tmp_path, probes, lane, file="record.c", cwe=cwe)
    assert probes[0] == {"model": 0, "execute": 0}


@pytest.mark.parametrize("file,compiler", [("record.c", "cc"), ("record.cpp", "c++"), ("record.rs", "rustc")])
@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_missing_compiler_spends_nothing(tmp_path, probes, monkeypatch, file, compiler, lane):
    checked = []
    def missing(name):
        checked.append(name)
        return None
    monkeypatch.setattr(dispatch.shutil, "which", missing)
    run(tmp_path, probes, lane, file=file)
    assert checked and set(checked) == {compiler}
    assert probes[0] == {"model": 0, "execute": 0}


@pytest.mark.parametrize("file", ["record.c", "record.cpp", "record.rs"])
@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_native_oracle_candidate_remains_eligible(tmp_path, probes, file, lane):
    count = run(tmp_path, probes, lane, file=file)
    assert probes[0] == {"model": count, "execute": count}


@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_diagnostic_opt_in_still_observes_scripting_behavior(tmp_path, probes, lane):
    count = run(tmp_path, probes, lane, diagnostics=True)
    assert probes[0] == {"model": count, "execute": count}


@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_return_only_proposal_never_runs_automatically(tmp_path, probes, monkeypatch, lane):
    def parse(*args, **kwargs):
        return dv.DarkWitnessSpec(finding_key=kwargs["finding_key"], file=kwargs["file"],
                                  function=kwargs["function"], language=kwargs["language"], expected_return=7)
    monkeypatch.setattr(dv, "parse_witness_response", parse)
    count = run(tmp_path, probes, lane, file="record.c")
    assert probes[0] == {"model": count, "execute": 0}


@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_adversarial_request_cannot_bypass_oracle_preflight(tmp_path, probes, lane):
    run(tmp_path, probes, lane, file="record.py", status="suspicious", adversarial=True)
    assert probes[0] == {"model": 0, "execute": 0}


def test_missing_cwe_still_allows_a_native_sanitizer_candidate(tmp_path, probes):
    run(tmp_path, probes, "serial", file="record.c", cwe="")
    assert probes[0] == {"model": 1, "execute": 1}


def test_automatic_production_paths_do_not_enable_diagnostics():
    tree = ast.parse(Path(orch.__file__).read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name)
             and node.func.id in {"_run_dark_verification", "_submit_dark_probes_early"}]
    assert calls
    assert all(not any(k.arg == "include_diagnostics" and isinstance(k.value, ast.Constant)
                       and k.value.value for k in call.keywords) for call in calls)


@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
def test_automatic_independent_violation_still_promotes(tmp_path, probes, monkeypatch, lane):
    def independent(spec, *args, **kwargs):
        probes[0]["execute"] += 1
        return dv.DarkVerifyResult(finding_key=spec.finding_key, verdict="confirmed", violation_observed=True)
    monkeypatch.setattr(dv, "execute_witness", independent)
    count = run(tmp_path, probes, lane, file="record.c", promoted=True)
    assert probes[0] == {"model": count, "execute": count}


@pytest.mark.parametrize("cwe", ["416", " cwe-416 "])
def test_dispatch_uses_existing_cwe_spellings(tmp_path, probes, cwe):
    run(tmp_path, probes, "serial", file="record.c", cwe=cwe)
    assert probes[0] == {"model": 1, "execute": 1}
