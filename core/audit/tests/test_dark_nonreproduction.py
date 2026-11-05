"""A failed witness prediction supplies no vulnerability refutation."""

import concurrent.futures
import copy
import json
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit import dark_verify as dv


@pytest.mark.parametrize("lane", ["early", "serial", "parallel"])
@pytest.mark.parametrize("status", ["dark", "suspicious", "finding"])
@pytest.mark.parametrize("evidence", ["", "llm-claimed:smt", "smt:check-overflow"])
def test_nonreproduction_preserves_verdict_evidence_and_counts(tmp_path, monkeypatch, lane, status, evidence):
    (tmp_path / "record.py").write_text("def read(n):\n    return n + 1\n")
    outcome = orch.ReviewOutcome(
        file="record.py", function="read", line=1, status=status,
        body="Needs checking.", hypothesis="integer overflow", evidence_tool=evidence,
        review_result={"cwe_class": "CWE-190"},
    )
    other = copy.deepcopy(outcome)
    other.function = "other"
    outcomes = [outcome, other] if lane == "parallel" else [outcome]
    result = orch.OrchestratorResult(outcomes=outcomes)
    setattr(result, {"dark": "dormant", "suspicious": "suspicious", "finding": "findings"}[status], len(outcomes))
    refutation_calls = []
    monkeypatch.setattr(orch, "_sc_record_refutation", lambda *args, **kwargs: refutation_calls.append(kwargs))
    original = copy.deepcopy(outcomes)
    counts = (result.clean, result.dormant, result.suspicious, result.findings)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    witness = SimpleNamespace(verdict="refuted", match_detail="predicted exception did not occur")
    if lane == "early":
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(lambda: witness)
        orch._drain_dark_probes(result, config, [outcome], [future], executor)
        filename = "dark-verify-early-results.json"
    else:
        monkeypatch.setattr(dv, "execute_witness", lambda *args, **kwargs: witness)
        monkeypatch.setattr(dv, "parse_witness_response", lambda *args, **kwargs: SimpleNamespace())
        orch._run_dark_verification(result, config, llm_client=lambda *args: "stub", max_workers=2 if lane == "parallel" else 1)
        filename = "dark-verify-results.json"
    assert outcomes == original
    assert refutation_calls == []
    assert (result.clean, result.dormant, result.suspicious, result.findings) == counts
    records = json.loads((tmp_path / filename).read_text())
    assert len(records) == len(outcomes)
    assert all(row["verdict"] == "refuted" and row["status"] == status for row in records)
