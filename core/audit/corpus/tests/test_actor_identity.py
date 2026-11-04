"""Offline benchmark, grading and explicit response-reuse contracts."""

from copy import deepcopy
import json

import pytest

from core.audit.corpus import actor_identity as bench


def cases():
    return bench.load_cases(bench.DEFAULT_CASES)


def answer(case):
    expected = case["expected"]
    return {key: expected[key] for key in ("verdict", "logical_actor", "state_actor")} | {
        "evidence": deepcopy(expected["required_evidence"]), "explanation": "Trace the supplied source.",
    }


def test_fixture_balance_and_expected_trace_evidence():
    fixtures = cases()
    assert len(fixtures) == 9
    assert sum(c["expected"]["verdict"] == "mismatch" for c in fixtures) == 3
    assert sum(c["expected"]["verdict"] == "consistent" for c in fixtures) == 5
    assert sum(c["expected"]["verdict"] == "unknown" for c in fixtures) == 1
    assert sum(c["split"] == "heldout" for c in fixtures) == 7
    assert all(bench.grade(c, answer(c))["match"] for c in fixtures)


def test_gold_fields_and_split_never_enter_request():
    case = cases()[0]
    request = bench.build_request(case)
    case["expected"]["verdict"] = "consistent"
    case["rationale"] = "DO NOT LEAK THIS GOLD ANSWER"
    case["id"] = "positive-example"
    case["split"] = "heldout"
    assert bench.build_request(case) == request


def test_correct_verdict_with_wrong_mechanism_does_not_pass():
    case = cases()[0]
    response = answer(case)
    response["state_actor"] = "claim->account"
    assert not bench.grade(case, response)["match"]
    response = answer(case)
    response["evidence"] = [{"source": "implementation", "quote": "lock(&account->mutex);"}]
    assert not bench.grade(case, response)["match"]


def test_invented_evidence_is_rejected():
    case = cases()[0]
    response = answer(case)
    response["evidence"].append({"source": "implementation", "quote": "assert(account == claim->account);"})
    assert "unanchored evidence" in bench.grade(case, response)["errors"]


def test_source_layout_whitespace_can_fold_but_literals_cannot_change():
    case = cases()[0]
    response = answer(case)
    response["evidence"].append({"source": "implementation", "quote":
        "struct account *account = running_account(); lock(&account->mutex); account->pending = 0;"})
    assert bench.grade(case, response)["match"]
    case["sources"]["implementation"] += '\nchar *name = "a  b";\n'
    response["evidence"].append({"source": "implementation", "quote": 'char *name = "a b";'})
    assert "unanchored evidence" in bench.grade(case, response)["errors"]


def test_locally_enforce_provider_schema_limits():
    case = cases()[0]
    response = answer(case)
    response["evidence"] *= 2
    assert "too many evidence items" in bench.grade(case, response)["errors"]
    response = answer(case)
    response["evidence"].append({"source": "implementation", "quote": "   "})
    assert "invalid evidence" in bench.grade(case, response)["errors"]


def test_explicit_reuse_regrades_without_provider_call():
    case = cases()[0]
    prior = bench.run_cases([case], lambda p, s: (answer(case), 0.01), model="test")
    changed_gold = deepcopy(case)
    changed_gold["expected"]["verdict"] = "consistent"

    def forbidden(*args):
        raise AssertionError("provider must not be called for identical request")

    report = bench.run_cases([changed_gold], forbidden, model="test", prior=prior)
    assert report["reused"] == 1
    assert report["new_cost_usd"] == 0
    assert report["passed"] == 0


@pytest.mark.parametrize("change", ["source", "system", "model", "fallback"])
def test_response_reuse_invalidates_when_request_or_model_changes(change, monkeypatch):
    case = cases()[0]
    prior = bench.run_cases([case], lambda p, s: (answer(case), 0.01), model="test")
    if change == "source":
        case["sources"]["implementation"] += "\n/* changed source */\n"
    elif change == "system":
        monkeypatch.setattr(bench, "SYSTEM_PROMPT", bench.SYSTEM_PROMPT + " Changed instructions.")
    elif change == "fallback":
        prior["cases"][0]["actual_model"] = "other-provider-model"
    calls = []

    def generate(prompt, schema):
        calls.append(prompt)
        return answer(case), 0.02

    report = bench.run_cases([case], generate, model="different" if change == "model" else "test", prior=prior)
    assert len(calls) == 1
    assert report["reused"] == 0
    assert report["new_cost_usd"] == 0.02


def test_missing_provider_result_is_a_failed_case():
    case = cases()[0]
    report = bench.run_cases([case], lambda p, s: ({}, 0.02), model="test")
    assert report["passed"] == 0
    assert report["new_cost_usd"] == 0.02


def test_dry_run_needs_no_provider(capsys):
    assert bench.main([]) == 0
    assert "9 actor-identity cases; no provider calls" in capsys.readouterr().out


def test_offline_regrade_does_not_need_a_client(tmp_path, capsys):
    fixtures = cases()[:2]
    by_prompt = {bench.build_request(case)[0]: case for case in fixtures}
    prior = bench.run_cases(fixtures, lambda p, s: (answer(by_prompt[p]), 0.01), model="offline")
    path = tmp_path / "report.json"
    path.write_text(json.dumps(prior))
    assert bench.main(["--split", "development", "--regrade", str(path)]) == 0
    assert "no provider calls" in capsys.readouterr().out


def test_pin_drift_in_synthetic_evidence_is_rejected(tmp_path):
    data = json.loads(bench.DEFAULT_CASES.read_text())
    data["cases"][0]["expected"]["required_evidence"][0]["quote"] = "absent source evidence"
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="evidence absent"):
        bench.load_cases(path)
