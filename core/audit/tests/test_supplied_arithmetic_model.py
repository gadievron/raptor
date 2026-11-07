"""Caller-supplied arithmetic has no source/target authority, even with SAT."""

import json
import subprocess

import pytest

from core.audit import evidence_grade as grade, orchestrator as orch, sweep
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome


from core.testing.module_bindings import patch_module_attribute


VERBS = ("check-overflow", "check-oob", "check-overflow-to-oob", "check-negative-bypass")


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("feasible", [True, False, None])
def test_shim_math_is_retained_without_a_source_verdict(tmp_path, monkeypatch, verb, feasible):
    (tmp_path / sweep._SMT_VERBS[verb]).write_text("")
    monkeypatch.setattr(sweep, "_SMT_SHIM_DIR", tmp_path)
    patch_module_attribute(monkeypatch, sweep, 'subprocess', "run", lambda *a, **kw: subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps({"feasible": feasible}), stderr=""))
    result = sweep.run_smt_sweep(file_path="record.c", function_name="Read", verb=verb,
                                 smt_args={"guard": ["a <= 10"], "profile": "uint32"})
    assert result.outcome == ("confirmed" if feasible is True else "inconclusive")
    assert result.rule_id == f"smt:{verb}:supplied-model"
    assert result.details["oracle_scope"] == "supplied-model"
    assert result.details["feasible"] is feasible
    assert not grade.is_verification_evidence(result.rule_id)


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("suffix", ["", ":witness", ":model"])
@pytest.mark.parametrize("fallback", [False, True])
def test_supplied_model_cannot_gain_source_authority(monkeypatch, verb, suffix, fallback):
    receipt = f"smt:{verb}:supplied-model{suffix}"
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda namespace: None)
    assert sweep.is_detection_rule_id(receipt)
    assert not grade.is_tool_evidence(receipt)
    assert not orch._promotion_grade_receipt(receipt)
    identity = SourceIdentity("source", (1, 2, 3))
    scope = dict(file="record.c", function="Read", line_start=1, hypothesis="claim")
    negative = ClaimRefutation(**scope, source_identity=identity,
                               checks=(ProbeOutcome("smt", "refuted", receipt),))
    assert not negative.matches(**scope, source_identity=identity)
    control = ClaimRefutation(**scope, source_identity=identity,
                              checks=(ProbeOutcome("smt", "refuted", "check-overflow"),))
    assert control.matches(**scope, source_identity=identity)
    assert grade.is_verification_evidence(receipt + "+lifecycle")
