"""Learning must not manufacture a negative verdict from audit bookkeeping."""

import ast
from dataclasses import replace
from pathlib import Path

import pytest

from core.audit import orchestrator as orch
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome


@pytest.fixture
def observation_case(tmp_path, monkeypatch):
    (tmp_path / "record.c").write_text("int read_value(int n) { return n + 1; }\n")
    outcome = orch.ReviewOutcome(
        file="record.c", function="read_value", line=1,
        status="suspicious", body="An arithmetic claim was demoted.",
        hypothesis="signed addition can overflow",
        tools_dispatched={"smt"},
        review_result={},
    )
    receipt = ClaimRefutation(
        outcome.file, outcome.function, outcome.line, outcome.hypothesis,
        (ProbeOutcome("smt", "refuted", "bounded-addition"),),
        capture_source_identity(tmp_path, outcome.file),
    )
    outcome.claim_refutations = (receipt,)
    stored = []
    monkeypatch.setattr(orch, "_sage_store_observation", lambda *args: stored.append(args))
    return outcome, receipt, stored


def accumulate(outcome, root):
    observations = []
    orch._accumulate_observations(
        observations, outcome,
        {"file": outcome.file, "name": outcome.function},
        sweep_pre_status="finding", target_path=root,
    )
    return observations


def test_explicit_refutation_teaches_only_its_source_version(observation_case, tmp_path):
    outcome, receipt, stored = observation_case
    observations = accumulate(outcome, tmp_path)
    assert len(observations) == len(stored) == 1
    assert observations[0]["kind"] == stored[0][1] == "tool_refutation"
    assert stored[0][2] == "record.c:read_value"
    assert receipt.source_identity.sha256 in stored[0][0]
    assert "line 1" in stored[0][0]
    assert "explicitly refuted" in stored[0][0]
    assert "not confirmed" not in stored[0][0]


@pytest.mark.parametrize("field,value", [
    ("file", "other.c"), ("function", "other_function"),
    ("line_start", 2), ("hypothesis", "different claim"),
    ("source_identity", None), ("checks", ()),
    ("checks", (ProbeOutcome("smt", "inconclusive", "bounded-addition"),)),
    ("checks", (ProbeOutcome("smt", "refuted", ""),)),
])
def test_unmatched_receipt_cannot_teach(observation_case, tmp_path, field, value):
    outcome, receipt, stored = observation_case
    outcome.claim_refutations = (replace(receipt, **{field: value}),)
    assert accumulate(outcome, tmp_path) == stored == []


@pytest.mark.parametrize("change", ["edited", "deleted", "replaced", "other-target"])
def test_source_change_cannot_teach(observation_case, tmp_path, change):
    outcome, _, stored = observation_case
    path = tmp_path / outcome.file
    if change == "edited":
        path.write_text("int read_value(int n) { return n + 2; }\n")
    elif change == "deleted":
        path.unlink()
    elif change == "replaced":
        replacement = tmp_path / "replacement.c"
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
    else:
        other = tmp_path / "other-target"
        other.mkdir()
        (other / outcome.file).write_bytes(path.read_bytes())
        tmp_path = other
    assert accumulate(outcome, tmp_path) == stored == []


@pytest.mark.parametrize("receipts", [(), [{"verdict": "refuted"}], "refuted"])
def test_dispatch_and_forged_records_cannot_teach(observation_case, tmp_path, receipts):
    outcome, _, stored = observation_case
    outcome.claim_refutations = receipts
    assert accumulate(outcome, tmp_path) == stored == []


def test_missing_target_cannot_teach(observation_case):
    outcome, _, stored = observation_case
    assert accumulate(outcome, None) == stored == []


def test_empty_claim_cannot_teach(observation_case, tmp_path):
    outcome, receipt, stored = observation_case
    outcome.hypothesis = ""
    outcome.claim_refutations = (replace(receipt, hypothesis=""),)
    assert accumulate(outcome, tmp_path) == stored == []


def test_unrelated_refutation_does_not_hide_model_observations(observation_case, tmp_path):
    outcome, receipt, stored = observation_case
    outcome.claim_refutations = (replace(receipt, hypothesis="other claim"),)
    outcome.review_result["observations"] = ["The parser advances one token per iteration."]
    observations = accumulate(outcome, tmp_path)
    assert [o["kind"] for o in observations] == ["llm_observation"]
    assert stored == []


def test_valid_receipt_does_not_need_dispatch_bookkeeping(observation_case, tmp_path):
    outcome, _, stored = observation_case
    outcome.tools_dispatched.clear()
    assert len(accumulate(outcome, tmp_path)) == len(stored) == 1


def test_long_claim_keeps_source_identity_when_recalled(observation_case, tmp_path):
    outcome, receipt, stored = observation_case
    outcome.hypothesis = "addition overflow " * 100
    outcome.claim_refutations = (replace(receipt, hypothesis=outcome.hypothesis),)
    assert len(accumulate(outcome, tmp_path)) == 1
    recalled = orch._sanitise_observation(stored[0][0])
    assert receipt.source_identity.sha256 in recalled
    assert "line 1" in recalled


def test_rejected_claim_text_is_not_stored(observation_case, tmp_path, monkeypatch):
    outcome, _, stored = observation_case
    monkeypatch.setattr(orch, "_sanitise_observation", lambda _: "")
    assert accumulate(outcome, tmp_path) == stored == []


def test_all_production_learning_paths_supply_target():
    tree = ast.parse(Path(orch.__file__).read_text())
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id == "_accumulate_observations"]
    assert calls
    assert all(any(keyword.arg == "target_path" for keyword in call.keywords)
               for call in calls)
