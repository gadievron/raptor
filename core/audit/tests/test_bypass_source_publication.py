"""inert bypass source-mutation publication control, not ACK-fault proof."""
import json
from pathlib import Path

import pytest

from core.audit import knowledge_runtime as runtime_mod, orchestrator as orch
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
def test_bypass_source_mutation_cannot_replace_canonical_prior(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    runtimes, assessments, live_results, prior, mutations = [], [], [], [], []
    original_runtime = runtime_mod.AuditKnowledgeRuntime

    class Runtime(original_runtime):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            runtimes.append(self)

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    from core.audit import executor as executor_mod
    original_executor = executor_mod.run_executor_sync

    def observed_executor(*args, **kwargs):
        if not live_results:
            live_results.append(args[4])
        return original_executor(*args, **kwargs)

    monkeypatch.setattr(executor_mod, "run_executor_sync", observed_executor)
    original_run = orch.run_orchestrator

    def observed_run(config, review):
        def observed_review(ctx, cfg):
            outcome = review(ctx, cfg)
            assessments.append(outcome)
            if len(assessments) == 3:
                assert len(runtimes) == 1 and not runtimes[0]._closed
                path = Path(cfg.target_path) / ctx["file"]
                original_bytes = path.read_bytes()
                path.write_bytes(original_bytes + b"\n/* owned late review mutation */\n")
                mutations.append(path)
            return outcome
        return original_run(config, observed_review)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False

    def captured_advisory(*args, **kwargs):
        assert len(live_results) == 1
        prior.extend(outcome for outcome in live_results[0].outcomes
                     if (outcome.file, outcome.function) == ("src/auth.c", "check_pw"))
        assert prior
        return [{"source": "iris_refine_loop", "file": "src/auth.c", "function": "check_pw",
                 "line_start": 2, "hypothesis": "owned captured advisory concern"}]

    monkeypatch.setattr(orch, "run_orchestrator", observed_run)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings", captured_advisory)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)
    with isolated_audit_shutdown(orch):
        result, _guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert len(assessments) == 3 and len(mutations) == 1
    assert all(any(outcome is old for outcome in result.outcomes) for old in prior)
    assert not any(outcome is assessments[-1] for outcome in result.outcomes)
    assert len(runtimes) == 1 and runtimes[0]._closed
    record = json.loads((tmp_path / "out" / "knowledge-results.json").read_text())
    attempts = [event for event in record["events"] if event.get("event") == "review_attempt"]
    assert len(attempts) == 3
    stale = [event for event in record["events"]
             if event.get("event") == "review_assessment"
             and event.get("source_unchanged_after_call") is False]
    assert len(stale) == 1 and stale[0]["attempt_id"] == attempts[-1]["attempt_id"]
