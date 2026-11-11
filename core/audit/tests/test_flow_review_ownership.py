"""Unbound late flow reviews cannot dispatch under governed execution."""
import inspect
import json
import time

import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.tests.test_processing_limitations import _snapshot


@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("receipt_fails", [False, True])
def test_governed_flow_without_occurrence_owner_defers_before_callback(tmp_path, monkeypatch, closed, receipt_fails):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.py").write_text("def unit(value):\n    return value\n")
    artifact = out / "flow-trace-owned.json"
    artifact.write_text(json.dumps({"source": {"file": "unit.py", "name": "unit"},
        "hops": [{"file": "unit.py", "name": "unit"}],
        "sink": {"file": "unit.py", "name": "unit"}}))
    before_bytes = artifact.read_bytes()
    result = orch.OrchestratorResult()
    prior = orch.ReviewOutcome("unit.py", "unit", "clean", "Prior assessment", line=1, cost_usd=.2)
    orch._tally_outcome(result, prior)
    before = _snapshot(result)
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=time.monotonic() + 60)
    if closed:
        runtime.close("fixture_closed")
    calls, events = [], []
    if receipt_fails:
        def refuse_receipt(*args, **kwargs):
            raise OSError("owned deferral write refusal")
        monkeypatch.setattr(orch, "append_audit_log", refuse_receipt)
    def forbidden(*args, **kwargs):
        calls.append("unowned callback")
        raise AssertionError("unbound flow reviewer must not run")
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    # Allows the unchanged preimage to demonstrate its actual callback bypass.
    kwargs = ({"knowledge_runtime": runtime}
              if "knowledge_runtime" in inspect.signature(orch._review_flow_traces).parameters else {})
    try:
        returned = orch._review_flow_traces(result, config, forbidden, {}, audit_log=events, **kwargs)
    finally:
        runtime.close("fixture_done")
    assert calls == []
    assert returned is result and result.outcomes == [prior]
    assert _snapshot(result) == before
    assert artifact.read_bytes() == before_bytes
    assert any(event.get("action") == "flow_review_deferred"
               and event.get("adjudication") == "unverified" for event in events)
