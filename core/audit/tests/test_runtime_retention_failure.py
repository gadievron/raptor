"""Actual run retention faults preserve durable state and report uncertainty."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit import knowledge_runtime as runtime_mod, orchestrator as orch
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm import telemetry, throttle as throttle_mod
from core.testing.audit_shutdown import isolated_audit_shutdown


LABEL = "knowledge-processing history (persistence failed)"





def _prepare_run(tmp_path, monkeypatch, *, cancellation=False):
    from core.audit import report
    monkeypatch.setattr(telemetry, "_sink", None)
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    runtimes, throttles, writes, failed_writes = [], [], [], []
    saved = {}
    fault = KeyboardInterrupt("owned final history cancellation") if cancellation else OSError("owned final history write fault")
    original_runtime = runtime_mod.AuditKnowledgeRuntime
    original_throttle = throttle_mod.AdaptiveThrottle

    class Runtime(original_runtime):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            runtimes.append(self)

        def write_artifacts(self, out_dir):
            out_dir = Path(out_dir)
            if self._closed:
                failed_writes.append(out_dir)
                saved["journal_before_final_write"] = (out_dir / "review-journal.jsonl").read_bytes()
                raise fault
            value = super().write_artifacts(out_dir)
            writes.append(out_dir)
            saved["knowledge_before_final_write"] = (out_dir / "knowledge-results.json").read_bytes()
            return value

    class Throttle(original_throttle):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            throttles.append(self)

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    monkeypatch.setattr(throttle_mod, "AdaptiveThrottle", Throttle)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False

    return report, configure, runtimes, throttles, writes, failed_writes, saved, fault


def _assert_last_durable_state(out_dir, runtimes, throttles, writes, failed_writes, saved):
    assert len(runtimes) == len(throttles) == 1
    assert writes and failed_writes == [out_dir]
    assert runtimes[0]._closed and not throttles[0]._registered
    assert (out_dir / "knowledge-results.json").read_bytes() == saved["knowledge_before_final_write"]
    journal = (out_dir / "review-journal.jsonl").read_bytes()
    assert journal.startswith(saved["journal_before_final_write"])
    prior_rows = [json.loads(line) for line in saved["journal_before_final_write"].splitlines()]
    prior_review_rows = [row for row in prior_rows if row.get("model") == "test-model"]
    assert len(prior_review_rows) == 2
    assert {(row["file"], row["function"]) for row in prior_review_rows} == {
        ("src/auth.c", "check_pw"), ("src/auth.c", "validate")}
    assert all(row["verdict"] == "clean" and row.get("review_claims") for row in prior_review_rows)
    # The older retained history is genuine recovery material, but it cannot
    # truthfully describe the final retirement that failed to be written.
    history = json.loads(saved["knowledge_before_final_write"])
    assert not any(event.get("event") == "runtime_closed" for event in history["events"])
    assert len([event for event in runtimes[0].events() if event.get("event") == "runtime_closed"]) == 1


@pytest.mark.slow
def test_actual_final_history_write_failure_preserves_assessments_and_reports_partial(tmp_path, monkeypatch):
    report, configure, runtimes, throttles, writes, failed_writes, saved, _fault = _prepare_run(
        tmp_path, monkeypatch)
    with isolated_audit_shutdown(orch):
        result, _guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    out_dir = tmp_path / "out"
    assert result.reviewed == len(result.outcomes) == 2
    assert all(outcome.status == "clean" for outcome in result.outcomes)
    assert result.processing_limitations.count(LABEL) == 1
    _assert_last_durable_state(out_dir, runtimes, throttles, writes, failed_writes, saved)
    knowledge_before = (out_dir / "knowledge-results.json").read_bytes()
    journal_before = (out_dir / "review-journal.jsonl").read_bytes()
    baseline = report.generate_report(out_dir, final_status="completed")
    failed = report.generate_report(out_dir, final_status="completed",
                                    processing_limitations=result.processing_limitations)
    assert failed["completeness"]["partial"] is True
    assert LABEL in failed["completeness"]["missing"]
    assert failed["knowledge_processing"] == {
        "state": "unavailable", "artifact": "knowledge-results.json", "reason": "persistence_failed"}
    assert failed["findings"] == baseline["findings"]
    assert failed["stats"] == baseline["stats"]
    assert "Knowledge processing record unavailable" in failed["summary"]
    assert (out_dir / "knowledge-results.json").read_bytes() == knowledge_before
    assert (out_dir / "review-journal.jsonl").read_bytes() == journal_before


@pytest.mark.slow
def test_actual_final_history_cancellation_propagates_after_other_resources_retire(tmp_path, monkeypatch):
    _report, configure, runtimes, throttles, writes, failed_writes, saved, fault = _prepare_run(
        tmp_path, monkeypatch, cancellation=True)
    with isolated_audit_shutdown(orch):
        with pytest.raises(KeyboardInterrupt) as caught:
            _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert caught.value is fault
    _assert_last_durable_state(tmp_path / "out", runtimes, throttles, writes, failed_writes, saved)
