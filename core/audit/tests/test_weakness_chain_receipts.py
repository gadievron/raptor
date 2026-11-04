"""Chain synthesis promotes only an executed checker match, never a model claim."""
from types import SimpleNamespace

import pytest

from core.audit import chain_detector, checker_synthesis, orchestrator
from core.audit.evidence_grade import is_tool_evidence, sanitize_llm_evidence_tool


@pytest.mark.parametrize("matched", [False, True], ids=["no-checker-match", "executed-checker-match"])
def test_chain_checker_receipt_matches_the_execution_result(tmp_path, monkeypatch, matched):
    outcomes = [orchestrator.ReviewOutcome(file="a.c", function=name,
                                         status="weakness", body="owned")
                for name in ("source", "sink")]
    result = SimpleNamespace(outcomes=outcomes, findings=0)
    config = SimpleNamespace(models=["owned-model"], target_path=tmp_path, out_dir=tmp_path)
    chain = dict(weakness_a="a.c:source", weakness_b="a.c:sink",
                 chain_description="owned chain", primitive="execute")
    monkeypatch.setattr(orchestrator, "_run_llm_client", lambda config: object())
    monkeypatch.setattr(orchestrator, "_make_dispatch_gate", lambda *a, **kw: object())
    monkeypatch.setattr(chain_detector, "find_weakness_chain_candidates", lambda *a: [object()])
    monkeypatch.setattr(chain_detector, "evaluate_weakness_chains", lambda *a, **kw: [chain])
    monkeypatch.setattr(checker_synthesis, "_build_llm_callable", lambda config: (object(), object()))
    monkeypatch.setattr(chain_detector, "synthesise_chain_checker",
                        lambda *a, **kw: object() if matched else None)
    monkeypatch.setattr(orchestrator, "save_json", lambda *a, **kw: None)

    orchestrator._run_weakness_chains(result, config)

    assert len(result.outcomes) == 3
    recorded = result.outcomes[-1]
    assert recorded.status == ("finding" if matched else "suspicious")
    assert recorded.evidence_tool == ("semgrep:chain-checker" if matched else "weakness_chain")
    assert is_tool_evidence(recorded.evidence_tool) is matched
    assert result.findings == int(matched)


def test_model_cannot_claim_a_chain_checker_execution():
    assert not is_tool_evidence(sanitize_llm_evidence_tool("semgrep:chain-checker"))
