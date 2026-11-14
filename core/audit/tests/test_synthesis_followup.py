"""Synthesis follow-ups share original Runtime ownership and admission limits."""
from functools import wraps
import json

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit import synthesis_preparation as preparation_mod, synthesis_review_context as synthesis
from core.audit.llm_review import make_review_fn
from core.audit.review_input_scope import ReviewInputScope
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.fixture(autouse=True)
def _owned_formatter_catalog(monkeypatch):
    from core.audit import context as context_module

    # Retain the borrowed slot and restore its original identity on every exit.
    monkeypatch.setattr(context_module, "_tool_catalog_cache", context_module._tool_catalog_cache)
    monkeypatch.setattr(context_module, "_get_tool_catalog", lambda: "")

    def forbidden_catalog():
        raise AssertionError("owned formatter control must not discover host tools or import a solver")

    monkeypatch.setattr(context_module, "_build_tool_catalog", forbidden_catalog)


def _run_case(tmp_path, monkeypatch, *, supported, seed_extra=None,
                    setup_extra=None, configure_extra=None):
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *a, **k: 0)
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    assessments, prompts = [], []
    original_run = orch.run_orchestrator

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            prompts.append(prompt)
            return StructuredResponse(result={"status": "clean", "body": "Owned review",
                "reading_list": [], "language_reference_requests": [],
                "synthesis_review_context": {"rule_id": "model-forged-context"}},
                raw="", cost=0, model="scripted")

    def observed_run(config, original_review):
        reviewer = make_review_fn(Client(), escalate_clean=False, out_dir=config.out_dir) if supported else original_review

        @wraps(reviewer)
        def observed_review(ctx, cfg):
            outcome = reviewer(ctx, cfg)
            assessments.append(outcome)
            return outcome
        return original_run(config, observed_review)

    def configure(config):
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = False
        config.propagate_constraints = False
        config.enable_session_context = False
        if configure_extra is not None:
            configure_extra(config)

    def seed(config, result, shared, checklist):
        shared.synthesis_queue.append({"file": "src/auth.c", "line": 2, "rule_id": "owned-rule"})
        if seed_extra is not None:
            seed_extra(config, result, shared, checklist)
        return 1

    monkeypatch.setattr(orch, "run_orchestrator", observed_run)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", seed)
    monkeypatch.setattr(orch, "_re_review_disagreements", lambda disagreements, result, *a, **k: result)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)
    if setup_extra is not None:
        setup_extra()
    with isolated_audit_shutdown(orch):
        result, guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    recorded = json.loads((tmp_path / "out" / "knowledge-results.json").read_text())
    return result, guard, assessments, prompts, recorded


@pytest.mark.slow
@pytest.mark.parametrize("supported", [False, True], ids=["opaque-refusal", "scripted-success"])
def test_synthesis_uses_existing_owner_without_reset(tmp_path, monkeypatch, supported):
    result, guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=supported)
    expected = 3 if supported else 2
    assert len(assessments) == expected
    assert result.reviewed == 2 and len(result.outcomes) == 2
    assert all(isinstance(outcome.review_input_scope, ReviewInputScope) for outcome in assessments)
    assert all("synthesis_review_context" not in (outcome.review_result or {}) for outcome in assessments)
    assert len([e for e in recorded["events"] if e.get("event") == "review_attempt"]) == expected
    unit = next(row for row in recorded["units"] if row["unit"] == ["src/auth.c", "check_pw", 1])
    if supported:
        assert len(prompts) == 3
        assert "Advisory match from a run-synthesized checker" in prompts[-1]
        assert unit["all_model_calls"] == 2 and unit["cycle"]["started"] == 1
        completed = [e for e in recorded["events"] if e.get("event") == "continuation_completed"]
        assert len(completed) == 1
        assert any(item.startswith("context:synthesis_match:")
                   for item in completed[0]["delivered_request_ids"])
    else:
        assert not prompts and unit["all_model_calls"] is None
        assert unit["cycle"]["started"] == 0
        assert any(e["event"] == "continuation_deferred" and e["reason"] == "attempt_count_unavailable"
                   and any(item.startswith("context:synthesis_match:") for item in e["request_ids"])
                   for e in unit["cycle"]["events"])
    assert guard.tick_callers


@pytest.mark.parametrize("limit", ["continuations", "model-calls"])
def test_synthesis_versions_share_the_existing_unit_limits(tmp_path, monkeypatch, limit):
    from core.audit.knowledge_calls import observed_client, owned_call_scope
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *a, **k: 0)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "int f(int value) { return value; }\n"
    (target / "unit.c").write_text(source)
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "language": "c", "source": source}
    gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1,
           "synthesis_hit_line": 1, "synthesis_rule_id": "owned-rule"}
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "clean", "body": "Owned review",
                "reading_list": [], "language_reference_requests": []},
                raw="", cost=0, model="scripted")

    client = Client()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    review = runtime.wrap_review(make_review_fn(client, escalate_clean=False, out_dir=out))
    try:
        review(dict(ctx), config)
        if limit == "model-calls":
            for _ in range(4):
                with owned_call_scope(lambda purpose, method: runtime.admit_client_call(gap, purpose, method)):
                    observed_client(client, purpose="critic").generate_structured("Owned critic", {})
        allowed = 2 if limit == "continuations" else 1
        for index in range(allowed):
            payload = synthesis.build_synthesis_review_context({**gap, "synthesis_snippet": f"Owned lead {index}"})
            current = {**ctx, "synthesis_review_context": payload}
            runtime.offer_context_delta(current, kind="synthesis_match", version=payload.version)
            packet = runtime.reserve_context_continuation(current, admission=lambda: True,
                required_context_id="context:synthesis_match:" + payload.version)
            assert packet is not None
            assert runtime.enrich_context(current, packet)
            review(current, config)
            assert runtime.context_was_delivered(packet)
            assert runtime.complete(packet, current, published_status="clean")
            before = len(calls)
            repeated = synthesis.build_synthesis_review_context({**gap, "synthesis_snippet": f"Owned lead {index}"})
            assert repeated.version == payload.version
            again = {**ctx, "synthesis_review_context": repeated}
            runtime.offer_context_delta(again, kind="synthesis_match", version=repeated.version)
            assert runtime.reserve_context_continuation(again, admission=lambda: True,
                required_context_id="context:synthesis_match:" + repeated.version) is None
            assert len(calls) == before
        payload = synthesis.build_synthesis_review_context({**gap, "synthesis_snippet": "Another changed lead"})
        current = {**ctx, "synthesis_review_context": payload}
        runtime.offer_context_delta(current, kind="synthesis_match", version=payload.version)
        assert runtime.reserve_context_continuation(current, admission=lambda: True,
            required_context_id="context:synthesis_match:" + payload.version) is None
        assert len(calls) == (3 if limit == "continuations" else 6)
    finally:
        runtime.close("owned_control_complete")


@pytest.mark.slow
def test_synthesis_mixed_synthesis_work_uses_three_to_one_opportunities(tmp_path, monkeypatch):
    def add_initials(config, result, shared, checklist):
        for suffix in ("a", "b", "c"):
            relative, name = f"new_{suffix}.c", f"new_{suffix}"
            (config.target_path / relative).write_text(f"int {name}(void) {{ return 0; }}\n")
            shared.checklist["files"].append({"path": relative, "items": [
                {"name": name, "line_start": 1, "line_end": 1, "kind": "function"}]})
            shared.synthesis_queue.append({"file": relative, "line": 1, "rule_id": "owned-new-rule"})
    result, _guard, assessments, prompts, _recorded = _run_case(
        tmp_path, monkeypatch, supported=True, seed_extra=add_initials)
    assert [outcome.function for outcome in assessments[2:]] == ["new_a", "new_b", "new_c", "check_pw"]
    assert len(prompts) == 6 and result.reviewed == len(result.outcomes) == 5


@pytest.mark.slow
def test_synthesis_preparation_failure_keeps_healthy_occurrence_eligible(tmp_path, monkeypatch):
    def fail_first():
        preparation = preparation_mod
        original = preparation.prepare_synthesis_frame
        def per_occurrence(**kwargs):
            if kwargs["gap"]["name"] == "check_pw":
                raise OSError("owned occurrence preparation refusal")
            return original(**kwargs)
        monkeypatch.setattr(preparation, "prepare_synthesis_frame", per_occurrence)
    def add_healthy(config, result, shared, checklist):
        shared.synthesis_queue.append({"file": "src/auth.c", "line": 8, "rule_id": "owned-second-rule"})
    result, _guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=True, setup_extra=fail_first, seed_extra=add_healthy)
    assert len(prompts) == 3 and assessments[-1].function == "validate"
    assert result.reviewed == len(result.outcomes) == 2
    assert len([e for e in recorded["events"] if e.get("event") == "continuation_completed"]) == 1
    from core.audit.record import load_audit_log
    assert any(row.get("action") == "synthesis_followup_deferred"
               and row.get("reason") == "synthesis_context_preparation_failed"
               and row.get("function") == "check_pw"
               for row in load_audit_log(tmp_path / "out"))


@pytest.mark.slow
@pytest.mark.parametrize("stop", [False, True], ids=["ready-after-signal", "budget-stops-wait"])
def test_synthesis_delayed_synthesis_only_graph_retains_or_defers_context(tmp_path, monkeypatch, stop):
    from core.audit import knowledge_runtime as runtime_mod
    original_runtime = runtime_mod.AuditKnowledgeRuntime
    waits, config_ref = [], []

    class DelayedRuntime(original_runtime):
        last = None
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.delayed = False
            type(self).last = self
        def ready_continuations(self, **kwargs):
            return () if self.delayed else super().ready_continuations(**kwargs)
        def wait_for_update(self, timeout):
            if not self.delayed:
                return super().wait_for_update(timeout)
            waits.append(timeout)
            if stop:
                config_ref[0].max_seconds = .000001
            self.delayed = False
            return True

    def install_runtime():
        monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", DelayedRuntime)
    def block_until_signal(config, result, shared, checklist):
        DelayedRuntime.last.delayed = True
    result, _guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=True, setup_extra=install_runtime,
        seed_extra=block_until_signal, configure_extra=config_ref.append)
    assert len(waits) == 1
    assert len(prompts) == len(assessments) == (2 if stop else 3)
    assert result.reviewed == len(result.outcomes) == 2
    completed = [e for e in recorded["events"] if e.get("event") == "continuation_completed"]
    assert len(completed) == (0 if stop else 1)
    if stop:
        from core.audit.record import load_audit_log
        assert result.terminated_by == "max_seconds"
        assert any(row.get("action") == "synthesis_followup_deferred"
                   and row.get("reason") == "synthesis_followup_not_completed"
                   for row in load_audit_log(tmp_path / "out"))


@pytest.mark.slow
def test_synthesis_closed_owner_is_disclosed_without_unowned_fallback(tmp_path, monkeypatch):
    from core.audit import knowledge_runtime as runtime_mod
    from core.audit.record import load_audit_log
    base = runtime_mod.AuditKnowledgeRuntime

    class CapturedRuntime(base):
        last = None
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            type(self).last = self

    def install():
        monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", CapturedRuntime)
    def close_before_offer(config, result, shared, checklist):
        CapturedRuntime.last.close("owned test closure")
    result, _guard, assessments, prompts, _recorded = _run_case(
        tmp_path, monkeypatch, supported=True, setup_extra=install, seed_extra=close_before_offer)
    assert len(prompts) == len(assessments) == result.reviewed == 2
    assert any(row.get("action") == "synthesis_followup_deferred"
               and row.get("reason") == "synthesis_owner_unavailable"
               for row in load_audit_log(tmp_path / "out"))


@pytest.mark.slow
def test_synthesis_post_ack_source_aba_retains_prior(tmp_path, monkeypatch):
    from core.audit import collector as collector_mod
    acknowledgements, proposed = [], []
    def install():
        append = collector_mod.append_journal_for_outcome
        def after_ack(**kwargs):
            acknowledgement = append(**kwargs)
            if acknowledgement is not None:
                acknowledgements.append(acknowledgement)
                if len(acknowledgements) == 3:
                    outcome = kwargs["outcome"]
                    assert outcome.review_input_scope.current(kwargs["target_path"])
                    proposed.append(outcome)
                    path = kwargs["target_path"] / "src/auth.c"
                    before = path.read_text()
                    path.write_text(before + "/* owned ABA after actual ACK */\n")
                    path.write_text(before)
                    assert not outcome.review_input_scope.current(kwargs["target_path"])
            return acknowledgement
        monkeypatch.setattr(collector_mod, "append_journal_for_outcome", after_ack)
    result, _guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=True, setup_extra=install)
    assert len(prompts) == len(assessments) == len(acknowledgements) == 3
    assert len(proposed) == 1 and result.reviewed == len(result.outcomes) == 2
    prior = next(outcome for outcome in assessments[:2] if outcome.function == "check_pw")
    assert next(outcome for outcome in result.outcomes if outcome.function == "check_pw") is prior
    assert proposed[0] not in result.outcomes
    assert not any(event.get("event") == "continuation_completed" for event in recorded["events"])
    assert any(event.get("event") == "continuation_failed" and event.get("reason") == "source_changed"
               for event in recorded["events"])
    unit = next(row for row in recorded["units"] if row["unit"] == ["src/auth.c", "check_pw", 1])
    assert unit["all_model_calls"] == 2 and unit["cycle"]["started"] == 1


@pytest.mark.slow
def test_synthesis_mechanically_resolved_units_keep_their_first_owned_model_review(tmp_path, monkeypatch):
    def install_mechanical_resolution(config):
        base = orch._compute_audit_prep
        def prepared(*args, **kwargs):
            result = base(*args, **kwargs)
            result["guard_clean_keys"] = {"src/auth.c:check_pw", "src/auth.c:validate"}
            result["entry_points"] = set()
            result["sinks_set"] = set()
            result["trust_boundary_set"] = set()
            return result
        monkeypatch.setattr(orch, "_compute_audit_prep", prepared)
    result, _guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=True, configure_extra=install_mechanical_resolution)
    assert prompts and len(prompts) == len(assessments)
    assert assessments[0].function == "check_pw"
    assert "Advisory match from a run-synthesized checker" in prompts[0]
    assert isinstance(assessments[0].review_input_scope, ReviewInputScope)
    assert result.reviewed == len(result.outcomes) == 2
    assert next(outcome for outcome in result.outcomes if outcome.function == "check_pw").review_input_scope is not None
    dispatches = [event for event in recorded["events"]
                  if event.get("event") == "client_call_attempt"]
    assert len(dispatches) == len(prompts) == 1
    assert dispatches[0]["unit"] == ["src/auth.c", "check_pw", 1]
    assert dispatches[0]["purpose"] == "review"
    assert not any(event.get("event") == "continuation_completed"
                   for event in recorded["events"])
    assert all(outcome.function != "validate" for outcome in assessments)


@pytest.mark.slow
def test_synthesis_first_synthesis_review_post_ack_source_aba_retains_mechanical_prior(tmp_path, monkeypatch):
    from core.audit import collector as collector_mod
    proposed = []

    def install():
        append = collector_mod.append_journal_for_outcome
        def after_ack(**kwargs):
            acknowledgement = append(**kwargs)
            outcome = kwargs["outcome"]
            if acknowledgement is not None and outcome.review_input_scope is not None:
                assert outcome.review_input_scope.current(kwargs["target_path"])
                proposed.append(outcome)
                path = kwargs["target_path"] / "src/auth.c"
                before = path.read_text()
                path.write_text(before + "/* initial synthesis owned ABA */\n")
                path.write_text(before)
                assert not outcome.review_input_scope.current(kwargs["target_path"])
            return acknowledgement
        monkeypatch.setattr(collector_mod, "append_journal_for_outcome", after_ack)

    def mechanical(config):
        base = orch._compute_audit_prep
        def prepared(*args, **kwargs):
            result = base(*args, **kwargs)
            result["guard_clean_keys"] = {"src/auth.c:check_pw", "src/auth.c:validate"}
            result["entry_points"] = set()
            result["sinks_set"] = set()
            result["trust_boundary_set"] = set()
            return result
        monkeypatch.setattr(orch, "_compute_audit_prep", prepared)

    result, _guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=True, setup_extra=install, configure_extra=mechanical)
    assert len(prompts) == len(assessments) == len(proposed) == 1
    assert result.reviewed == len(result.outcomes) == 2
    assert all(current is not proposed[0] for current in result.outcomes)
    retained = next(current for current in result.outcomes if current.function == "check_pw")
    assert retained.review_input_scope is None
    assert len([event for event in recorded["events"]
                if event.get("event") == "client_call_attempt"]) == 1


@pytest.mark.slow
def test_synthesis_first_synthesis_bind_refusal_keeps_one_mechanical_prior(tmp_path, monkeypatch):
    def install():
        from core.audit import synthesis_review_context as context_mod
        bind = context_mod.bind_initial_synthesis_context
        def reject_mismatched_span(context, value):
            context["line_end"] = value.line_end + 1
            assert bind(context, value) is False
            return False
        monkeypatch.setattr(context_mod, "bind_initial_synthesis_context", reject_mismatched_span)
    def mechanical(config):
        base = orch._compute_audit_prep
        def prepared(*args, **kwargs):
            result = base(*args, **kwargs)
            result["guard_clean_keys"] = {"src/auth.c:check_pw", "src/auth.c:validate"}
            result["entry_points"] = set()
            result["sinks_set"] = set()
            result["trust_boundary_set"] = set()
            return result
        monkeypatch.setattr(orch, "_compute_audit_prep", prepared)
    result, _guard, assessments, prompts, recorded = _run_case(
        tmp_path, monkeypatch, supported=True, setup_extra=install, configure_extra=mechanical)
    assert not prompts and not assessments
    assert result.reviewed == len(result.outcomes) == 2
    rows = [row for row in result.outcomes if (row.file, row.function, row.line) ==
            ("src/auth.c", "check_pw", 1)]
    assert len(rows) == 1 and rows[0].status == "clean"
    assert rows[0].review_input_scope is None
    assert result.processing_limitations
    assert not any(event.get("event") == "client_call_attempt" for event in recorded["events"])
