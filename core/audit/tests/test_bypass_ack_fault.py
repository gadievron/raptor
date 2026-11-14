"""owned late-bypass journal-ACK boundary controls.

A durable candidate journal row is not canonical acceptance. These controls
alter only the third reviewer outcome after the actual writer returns its ACK.
"""
import json
from pathlib import Path

import pytest

from core.audit import collector as collector_mod, executor as executor_mod
from core.audit import knowledge_runtime as runtime_mod, orchestrator as orch
from core.audit.review_input_scope import ReviewInputScope
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm import throttle as throttle_mod
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
@pytest.mark.parametrize("fault_kind", ["source_mutation", "cancellation"])
def test_bypass_after_actual_ack_preserves_prior_before_canonical_publication(tmp_path, monkeypatch, fault_kind):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    runtimes, throttles, retired, assessments, live_results, prior, acknowledgements = [], [], [], [], [], [], []
    fault = KeyboardInterrupt("owned late bypass after actual journal ACK")
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

        def close(self):
            if self._registered:
                retired.append(self)
            return super().close()

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    monkeypatch.setattr(throttle_mod, "AdaptiveThrottle", Throttle)
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
            return outcome
        return original_run(config, observed_review)

    original_append = collector_mod.append_journal_for_outcome

    def append_then_fault(**kwargs):
        outcome = kwargs["outcome"]
        is_bypass = len(assessments) == 3 and outcome is assessments[-1]
        if is_bypass:
            assert isinstance(outcome.review_input_scope, ReviewInputScope)
            assert outcome.review_input_scope.current(kwargs["target_path"])
        ack = original_append(**kwargs)
        if is_bypass:
            assert ack is not None
            acknowledgements.append(ack)
            if fault_kind == "cancellation":
                raise fault
            path = Path(kwargs["target_path"]) / outcome.file
            path.write_bytes(path.read_bytes() + b"\n/* owned post-ACK source mutation */\n")
            assert not outcome.review_input_scope.current(kwargs["target_path"])
        return ack

    monkeypatch.setattr(collector_mod, "append_journal_for_outcome", append_then_fault)

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
        if fault_kind == "cancellation":
            with pytest.raises(KeyboardInterrupt) as caught:
                _binding_run(tmp_path, monkeypatch, before_run=configure)
            assert caught.value is fault
        else:
            _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert len(assessments) == 3 and len(acknowledgements) == 1
    result = live_results[0]
    assert all(any(outcome is old for outcome in result.outcomes) for old in prior)
    assert not any(outcome is assessments[-1] for outcome in result.outcomes)
    assert len(runtimes) == len(throttles) == 1
    assert runtimes[0]._closed and not throttles[0]._registered
    assert retired == [throttles[0]]
    events = runtimes[0].events()
    assert len([event for event in events if event.get("event") == "runtime_closed"]) == 1
    assert len([event for event in events if event.get("event") == "review_attempt"]) == 3
    rows = [json.loads(line) for line in (tmp_path / "out" / "review-journal.jsonl").read_text().splitlines()]
    reviewed = [row for row in rows if row.get("model") == "test-model"]
    # The third durable row records an acknowledged candidate, not canonical
    # acceptance; both earlier reviews must remain intact in this journal.
    assert len(reviewed) >= 3
    assert {(row["file"], row["function"]) for row in reviewed[:2]} == {
        ("src/auth.c", "check_pw"), ("src/auth.c", "validate")}
    assert all(row["verdict"] == "clean" and row.get("review_claims") for row in reviewed[:2])
