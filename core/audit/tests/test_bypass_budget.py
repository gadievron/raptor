"""late-bypass admission control with owned scripted transport only.

The real Runtime admission callback is exercised; no provider/network/native
call is permitted. A refused owned review can still emit review_attempt before
its first client call, so this asserts no extra underlying reviewer/transport
call, rather than inventing a zero-review-event claim.
"""
import json

import pytest

from core.audit import orchestrator as orch, knowledge_runtime as runtime_mod
from core.audit.knowledge_calls import observed_client
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
def test_bypass_exhausted_original_unit_refuses_scripted_call_and_retains_prior(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    runtimes, assessed, scripted_calls, prior, exhausted = [], [], [], [], []
    original_runtime = runtime_mod.AuditKnowledgeRuntime

    class Runtime(original_runtime):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            runtimes.append(self)

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    from core.audit import executor as executor_mod
    original_executor = executor_mod.run_executor_sync
    run_results = []

    def observed_executor(*args, **kwargs):
        if not run_results:
            run_results.append(args[4])
        return original_executor(*args, **kwargs)

    monkeypatch.setattr(executor_mod, "run_executor_sync", observed_executor)
    original_run = orch.run_orchestrator

    def observed_run(config, review):
        class ScriptedClient:
            _attempt_admission_protocol = 1

            def generate(self, ctx, cfg, *, accounting_attempt_admission):
                assert accounting_attempt_admission() is True
                scripted_calls.append((ctx["file"], ctx["function"]))
                outcome = review(ctx, cfg)
                assessed.append(outcome)
                return outcome

        client = ScriptedClient()

        def observed_review(ctx, cfg):
            return observed_client(client, purpose="owned-scripted-review").generate(ctx, cfg)

        observed_review._knowledge_observed_client_contract = True
        return original_run(config, observed_review)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False

    gap = {"file": "src/auth.c", "name": "check_pw", "line_start": 1}

    def captured_advisory(*args, **kwargs):
        assert len(runtimes) == 1
        runtime = runtimes[0]
        assert not runtime._closed
        key = runtime._gap_key(gap)
        assert key in runtime._calls
        prior.extend(outcome for outcome in run_results[0].outcomes
                     if (outcome.file, outcome.function) == (gap["file"], gap["name"]))
        assert prior
        # Consume remaining allowance through the actual admission ledger,
        # without pretending these owned admissions were provider executions.
        while runtime.admit_client_call(gap, "owned-exhaustion-control", "generate"):
            pass
        exhausted.append((runtime._calls[key], len(scripted_calls), len(assessed)))
        return [{"source": "iris_refine_loop", "file": gap["file"],
                 "function": gap["name"], "line_start": 2,
                 "hypothesis": "owned captured advisory concern"}]

    monkeypatch.setattr(orch, "run_orchestrator", observed_run)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings", captured_advisory)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)
    with isolated_audit_shutdown(orch):
        result, _guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert len(runtimes) == len(exhausted) == 1
    runtime = runtimes[0]
    key = runtime._gap_key(gap)
    count, calls, assessments = exhausted[0]
    assert runtime._calls[key] == count
    assert len(scripted_calls) == calls
    assert len(assessed) == assessments
    assert all(any(outcome is original for outcome in result.outcomes) for original in prior)
    assert runtime._closed
    record = json.loads((tmp_path / "out" / "knowledge-results.json").read_text())
    refusals = [event for event in record["events"]
                if event.get("event") == "client_call_refused"
                and event.get("unit") == list(key)]
    assert len(refusals) >= 2  # exhaustion probe plus bypass call
    assert all(event["reason"] == "model_call_limit" for event in refusals)
    assert any(outcome.status == "deferred" for outcome in result.outcomes)
