"""Observed predictions are not defect oracles; instrumented violations are."""

import concurrent.futures
from dataclasses import replace
import json
import subprocess
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit import dark_verify as dv
from core.audit.dark_verify._admission import SANITIZER_RECEIPT, witness_can_confirm
from core.audit.dark_verify._execute import _classify_native_output
from core.audit.evidence_grade import is_tool_evidence

KEY = "record.c:Read"
TOKEN = "test-oracle-token"


def classified(kind, *, token=TOKEN, active=True):
    spec = dv.DarkWitnessSpec(finding_key=KEY, file="record.c", function="Read", language="c")
    if kind in ("return", "exception"):
        spec = replace(spec, language="python", expected_return=7 if kind == "return" else None,
                       expected_exception="ValueError" if kind == "exception" else "")
        record = {"token": TOKEN, "status": "returned", "value": "7"} if kind == "return" else {
            "token": TOKEN, "status": "exception", "type": "ValueError", "message": "input rejected",
        }
        return dv._classify_output(spec, json.dumps(record), "python", expected_token=TOKEN)
    spec = replace(spec, expected_crash=True)
    proc = subprocess.CompletedProcess([], -11 if kind == "signal" else 1, "", "__raptor_witness_start__:" + TOKEN + "\n")
    if kind == "signal":
        info = {"signal": "SIGSEGV", "signal_num": 11, "crashed": True}
    else:
        proc.stderr += "==1==ERROR: AddressSanitizer: heap-use-after-free\n"
        info = {"sanitizer": "asan", "evidence": "AddressSanitizer: heap-use-after-free"}
    return _classify_native_output(spec, proc, info, "c", expected_token=token, sanitizers_active=active)


@pytest.mark.parametrize("kind", ["return", "exception", "signal", "sanitizer"])
@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
@pytest.mark.parametrize("status", ["dark", "suspicious"])
def test_prediction_vs_violation_through_application_paths(tmp_path, monkeypatch, kind, lane, status):
    observation = classified(kind)
    assert observation.verdict == "confirmed"  # Backend prediction matched in every case.
    original_evidence = "semgrep:independent-proof"
    outcome = orch.ReviewOutcome(file="record.c", function="Read", line=1, status=status,
                                body="Reviewed.", hypothesis="memory access violation",
                                evidence_tool=original_evidence, review_result={"cwe_class": "CWE-416"})
    outcomes = [outcome]
    if lane == "parallel":
        outcomes.append(replace(outcome, function="Other", review_result=dict(outcome.review_result)))
    result = orch.OrchestratorResult(outcomes=outcomes)
    setattr(result, "dormant" if status == "dark" else "suspicious", len(outcomes))
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    if lane == "early":
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(lambda: observation)
        orch._drain_dark_probes(result, config, outcomes, [future], executor)
    else:
        monkeypatch.setattr(dv, "parse_witness_response", lambda *args, **kw: SimpleNamespace(finding_key=f"{kw['file']}:{kw['function']}"))
        monkeypatch.setattr(dv, "execute_witness", lambda spec, *args, **kw: replace(observation, finding_key=spec.finding_key))
        orch._run_dark_verification(result, config, llm_client=lambda *args: "stub", max_workers=2 if lane == "parallel" else 1, include_diagnostics=True)
    promoted = kind == "sanitizer"
    assert all(o.status == ("finding" if promoted else status) for o in outcomes)
    assert all(original_evidence in o.evidence_tool for o in outcomes)
    assert all((SANITIZER_RECEIPT in o.evidence_tool) is promoted for o in outcomes)
    assert result.findings == (len(outcomes) if promoted else 0)
    assert result.clean == 0
    filename = "dark-verify-early-results.json" if lane == "early" else "dark-verify-results.json"
    rows = json.loads((tmp_path / filename).read_text())
    assert all(row["violation_observed"] is promoted for row in rows)
    assert getattr(result, "dormant" if status == "dark" else "suspicious") == (0 if promoted else len(outcomes))


@pytest.mark.parametrize("changes", [
    {"violation_observed": False}, {"violation_observed": "true"},
    {"verdict": "refuted"}, {"verdict": "inconclusive"},
    {"oracle_reliability": "unavailable"}, {"finding_key": "other.c:Other"},
])
def test_incomplete_or_wrong_scope_record_cannot_promote(changes):
    assert not witness_can_confirm(replace(classified("sanitizer"), **changes), finding_key=KEY)


@pytest.mark.parametrize("token,active", [("", True), (TOKEN, False)])
def test_sanitizer_needs_bound_call_window_and_instrumentation(token, active):
    result = classified("sanitizer", token=token, active=active)
    assert not witness_can_confirm(result, finding_key=KEY)


@pytest.mark.parametrize("factory", [lambda d: d, lambda d: SimpleNamespace(**d)])
def test_untyped_record_cannot_promote(factory):
    assert not witness_can_confirm(factory(classified("sanitizer").to_dict()), finding_key=KEY)


@pytest.mark.parametrize("stamp", ["dark_verify:confirmed", "dark_verify:refuted", "dark_verify:invented", "dark_verify"])
def test_legacy_and_unknown_receipts_cannot_regain_verification_grade(stamp):
    assert not is_tool_evidence(stamp)
    assert not orch._promotion_grade_receipt(stamp)


def test_independent_violation_receipt_keeps_confirmed_tier():
    assert is_tool_evidence(SANITIZER_RECEIPT)
    out = orch.ReviewOutcome(file="record.c", function="Read", status="finding", body="Observed.",
                             evidence_tool=SANITIZER_RECEIPT)
    assert out.compute_tier() == "confirmed"


def test_model_cannot_supply_the_independent_oracle_flag():
    spec = dv.parse_witness_response(json.dumps({
        "module_path": "record", "function": "Read", "args": [7],
        "expected_return": 7, "violation_observed": True,
    }), finding_key=KEY, file="record.py", function="Read", language="python")
    assert spec is not None
    result = dv._classify_output(spec, json.dumps({"token": TOKEN, "status": "returned", "value": "7"}),
                                 "python", expected_token=TOKEN)
    assert result.verdict == "confirmed"
    assert not result.violation_observed
    assert not witness_can_confirm(result, finding_key=KEY)
