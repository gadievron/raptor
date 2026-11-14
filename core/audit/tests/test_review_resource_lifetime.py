"""Actual run-wrapper resource lifetime prototype; no native/model transport."""
from __future__ import annotations

import json

from core.audit import orchestrator as orch, knowledge_runtime as runtime_mod
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm import throttle as throttle_mod
from core.testing.audit_shutdown import isolated_audit_shutdown
import pytest


def _install(monkeypatch):
    from core.audit import review_resources
    return review_resources



@pytest.mark.slow
def test_run_owner_remains_live_then_retires_before_report_consumers(tmp_path, monkeypatch):
    _install(monkeypatch)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    runtimes, throttles, phase_state, report_state = [], [], [], []
    original_runtime = runtime_mod.AuditKnowledgeRuntime
    original_throttle = throttle_mod.AdaptiveThrottle

    class Runtime(original_runtime):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            runtimes.append(self)

    class Throttle(original_throttle):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            throttles.append(self)

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    monkeypatch.setattr(throttle_mod, "AdaptiveThrottle", Throttle)

    def bypass(*args, **kwargs):
        assert len(runtimes) == len(throttles) == 1
        phase_state.append((runtimes[0]._closed, runtimes[0]._sources_closed, throttles[0]._registered))
        return [{"source": "iris_refine_loop", "file": "src/auth.c", "function": "check_pw",
                 "line_start": 2, "hypothesis": "owned captured advisory concern"}]

    persist = orch._persist_project_learnings
    def report_reader(out_dir, *args, **kwargs):
        record = json.loads((out_dir / "knowledge-results.json").read_text())
        report_state.append((runtimes[0]._closed, throttles[0]._registered,
            [event for event in record["events"] if event.get("event") == "runtime_closed"]))
        return persist(out_dir, *args, **kwargs)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False

    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings", bypass)
    monkeypatch.setattr(orch, "_persist_project_learnings", report_reader)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)
    with isolated_audit_shutdown(orch):
        _result, _guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert phase_state == [(False, True, True)]
    assert len(report_state) == 1
    assert report_state[0] == (True, False, [{"event": "runtime_closed", "reason": "run_review_complete"}])
    assert runtimes[0]._closed and not throttles[0]._registered
    assert len([event for event in runtimes[0].events() if event.get("event") == "runtime_closed"]) == 1


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["primary", "fresh"])
def test_actual_run_wrapper_preserves_cancellation_and_finishes_cleanup(tmp_path, monkeypatch, mode):
    _install(monkeypatch)
    from core.analysis import reach_audit
    from core.llm import telemetry

    monkeypatch.setattr(telemetry, "_sink", None)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    events = []
    primary = KeyboardInterrupt("owned body cancellation")
    fresh = KeyboardInterrupt("owned fresh cleanup cancellation")
    reset = reach_audit.reset_joern_server

    def observed_reset(token):
        events.append("existing-reset")
        return reset(token)

    def body(*args, **kwargs):
        resources = kwargs["review_resources"]
        resources.register(lambda: events.append("other-resource"))
        def failed_close():
            events.append("failed-resource")
            if mode == "primary":
                raise OSError("owned resource cleanup fault")
            raise fresh
        resources.register(failed_close)
        if mode == "primary":
            raise primary
        return kwargs["result"]

    monkeypatch.setattr(reach_audit, "reset_joern_server", observed_reset)
    monkeypatch.setattr(orch, "_run_audit_body", body)
    with isolated_audit_shutdown(orch):
        with pytest.raises(KeyboardInterrupt) as caught:
            _binding_run(tmp_path, monkeypatch)
    assert caught.value is (primary if mode == "primary" else fresh)
    assert events == ["failed-resource", "other-resource", "existing-reset"]
    if mode == "primary":
        assert "Review resource retirement also failed: OSError" in primary.__notes__
