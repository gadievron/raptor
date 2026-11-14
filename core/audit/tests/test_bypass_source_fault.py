"""inert late-review cancellation control; not journal-ACK fault proof."""
from __future__ import annotations

import json

import pytest

from core.audit import knowledge_runtime as runtime_mod, orchestrator as orch
from core.audit.review_input_scope import ReviewInputScope
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm import telemetry, throttle as throttle_mod
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
def test_late_bypass_review_cancellation_preserves_identity_prior_rows_and_owner_retirement(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry, "_sink", None)
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    runtimes, throttles, retirements, assessments = [], [], [], []
    original_runtime = runtime_mod.AuditKnowledgeRuntime
    original_throttle = throttle_mod.AdaptiveThrottle
    fault = KeyboardInterrupt("owned late bypass reviewer cancellation")

    class Runtime(original_runtime):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            runtimes.append(self)

    class Throttle(original_throttle):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            throttles.append(self)

        def close(self):
            if self._registered:
                retirements.append(self)
            return super().close()

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    monkeypatch.setattr(throttle_mod, "AdaptiveThrottle", Throttle)
    original_run = orch.run_orchestrator

    def observed_run(config, review):
        def observed_review(ctx, cfg):
            outcome = review(ctx, cfg)
            assessments.append(outcome)
            if len(assessments) == 3:
                assert len(runtimes) == len(throttles) == 1
                assert not runtimes[0]._closed and runtimes[0]._sources_closed
                assert throttles[0]._registered
                # Runtime attaches the original live scope before invoking
                # the callback; this outcome is deliberately never returned.
                raise fault
            return outcome
        return original_run(config, observed_review)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False

    monkeypatch.setattr(orch, "run_orchestrator", observed_run)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings", lambda *a, **k: [
        {"source": "iris_refine_loop", "file": "src/auth.c", "function": "check_pw",
         "line_start": 2, "hypothesis": "owned captured advisory concern"}])
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)
    with isolated_audit_shutdown(orch):
        with pytest.raises(KeyboardInterrupt) as caught:
            _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert caught.value is fault
    assert len(assessments) == 3
    assert all(isinstance(outcome.review_input_scope, ReviewInputScope) for outcome in assessments[:2])
    assert len(runtimes) == len(throttles) == 1
    assert runtimes[0]._closed and not throttles[0]._registered
    assert retirements == [throttles[0]]
    events = runtimes[0].events()
    assert len([event for event in events if event.get("event") == "runtime_closed"]) == 1
    assert len([event for event in events if event.get("event") == "review_attempt"]) == 3
    rows = [json.loads(line) for line in (tmp_path / "out" / "review-journal.jsonl").read_text().splitlines()]
    prior = [row for row in rows if row.get("model") == "test-model"]
    assert len(prior) == 2
    assert {(row["file"], row["function"]) for row in prior} == {
        ("src/auth.c", "check_pw"), ("src/auth.c", "validate")}
    assert all(row["verdict"] == "clean" and row.get("review_claims") for row in prior)
