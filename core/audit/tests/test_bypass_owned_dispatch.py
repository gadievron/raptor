"""Owned inert full-run fixture: post-close bypass review ownership only."""
import json

import pytest

from core.audit import orchestrator as orch
from core.audit.review_input_scope import ReviewInputScope
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
@pytest.mark.parametrize("bypass", [False, True], ids=["main-control", "bypass"])
def test_actual_postclose_bypass_retains_original_run_review_owner(tmp_path, monkeypatch, bypass):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    assessments = []
    original = orch.run_orchestrator

    def observed_run(config, review):
        def observed_review(ctx, cfg):
            outcome = review(ctx, cfg)
            assessments.append(outcome)
            return outcome
        return original(config, observed_review)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False

    monkeypatch.setattr(orch, "run_orchestrator", observed_run)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings",
        lambda *a, **k: [{"source": "iris_refine_loop", "file": "src/auth.c",
            "function": "check_pw", "line_start": 2,
            "hypothesis": "owned captured advisory concern"}] if bypass else [])
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)
    with isolated_audit_shutdown(orch):
        _result, guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert len(assessments) == (3 if bypass else 2), "actual reviewer path must be reached"
    if bypass:
        assert ("_gate", "_tick") in guard.tick_callers
    record = json.loads((tmp_path / "out" / "knowledge-results.json").read_text())
    attempts = [event for event in record["events"] if event.get("event") == "review_attempt"]
    assert all(isinstance(outcome.review_input_scope, ReviewInputScope) for outcome in assessments)
    assert len(attempts) == len(assessments)
