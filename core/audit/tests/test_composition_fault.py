"""UNEXECUTED composition actual-ACK fault controls, no discovery calls.

The third checklist occurrence is deliberately omitted from main scheduling,
not added to reviewed_set and not forced through the composition skip guard.
Only captured advisory composition inputs are supplied; their freshness is
not established by this fixture.
"""
import json
from pathlib import Path

import pytest

from core.audit import composition, discovery, orchestrator as orch
from core.audit import collector as collector_mod, executor as executor_mod, knowledge_runtime as runtime_mod
from core.llm import throttle as throttle_mod
from core.audit.composition import ComposedHypothesis, UnguardedPath, WeaknessRecord
from core.audit.review_input_scope import ReviewInputScope
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
@pytest.mark.parametrize("fault_kind", ["source_mutation_after_actual_ACK", "cancellation_after_actual_ACK"])
def test_composition_actual_ack_fault_preserves_prior_and_owner_retirement(tmp_path, monkeypatch, fault_kind):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    assessments, excluded, composed_calls, converted = [], [], [], []
    runtimes, throttles, retired, live_results, prior, acknowledgements = [], [], [], [], [], []
    fault = KeyboardInterrupt("owned composition after actual journal ACK")
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
    original_append = collector_mod.append_journal_for_outcome

    def append_then_fault(**kwargs):
        outcome = kwargs["outcome"]
        is_composition = (len(assessments) == 3 and outcome is assessments[-1]
                          and outcome.function == "compose_only")
        if is_composition:
            assert isinstance(outcome.review_input_scope, ReviewInputScope)
            assert outcome.review_input_scope.current(kwargs["target_path"])
        ack = original_append(**kwargs)
        if is_composition:
            assert ack is not None
            acknowledgements.append(ack)
            if fault_kind == "cancellation_after_actual_ACK":
                raise fault
            path = Path(kwargs["target_path"]) / outcome.file
            path.write_bytes(path.read_bytes() + b"\n/* owned composition post-ACK mutation */\n")
            assert not outcome.review_input_scope.current(kwargs["target_path"])
        return ack

    monkeypatch.setattr(collector_mod, "append_journal_for_outcome", append_then_fault)
    original_run = orch.run_orchestrator
    original_compute = orch.compute_gaps
    original_convert = orch._composed_hypotheses_to_gaps

    def observed_run(config, review):
        def observed_review(ctx, cfg):
            outcome = review(ctx, cfg)
            assessments.append(outcome)
            return outcome
        return original_run(config, observed_review)

    def main_schedule(*args, **kwargs):
        gaps = original_compute(*args, **kwargs)
        excluded.extend(g for g in gaps if g.get("name") == "compose_only")
        return [g for g in gaps if g.get("name") != "compose_only"]

    def observed_convert(hypotheses, checklist, reviewed_set=None, **kwargs):
        assert "src/auth.c:compose_only" not in (reviewed_set or set())
        gaps = original_convert(hypotheses, checklist, reviewed_set=reviewed_set, **kwargs)
        converted.extend(gaps)
        return gaps

    weakness = WeaknessRecord(
        function="compose_only", file="src/auth.c", guard_type="bounds",
        assumed_property="caller bounds the supplied length",
        mechanism="owned advisory unchecked copy", guarded_by=(),
    )
    hypothesis = ComposedHypothesis(
        weakness=weakness,
        unguarded_path=UnguardedPath(chain=[("src/auth.c", "compose_only")]),
        hypothesis_text="owned captured composition concern",
        fids=["src/auth.c:compose_only"], verifiable=True,
    )

    def captured_composition(inventory, reverse, entries, journal, reviewed, **kwargs):
        assert inventory == [weakness]
        assert "src/auth.c:compose_only" not in reviewed
        assert len(live_results) == 1
        prior.extend(live_results[0].outcomes)
        assert len(prior) == 2
        assert all(outcome.function != "compose_only" for outcome in prior)
        composed_calls.append(True)
        return [hypothesis]

    forbidden_calls = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        raise AssertionError("composition ownership fixture must not launch discovery or transport")

    for name in ("build_seam_bundles", "build_state_machine_bundles",
                 "build_workflow_bundles", "build_sweep_targets"):
        monkeypatch.setattr(discovery, name, lambda *a, **k: [])
    for name in ("run_assumption_mining", "run_contract_discovery",
                 "run_state_machine_discovery", "run_workflow_discovery",
                 "run_focused_lens_sweep", "write_discovery_weaknesses",
                 "detect_single_threaded"):
        monkeypatch.setattr(discovery, name, forbidden)
    monkeypatch.setattr(composition, "build_weakness_inventory", lambda *a, **k: [weakness])
    monkeypatch.setattr(composition, "compose_hypotheses", captured_composition)
    monkeypatch.setattr(orch, "run_orchestrator", observed_run)
    monkeypatch.setattr(orch, "compute_gaps", main_schedule)
    monkeypatch.setattr(orch, "_composed_hypotheses_to_gaps", observed_convert)
    monkeypatch.setattr(orch, "_synthesize_external_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(orch, "_refine_bypass_post_loop_findings", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a, **k: [])
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a, **k: None)

    def configure(config):
        path = config.target_path / "src/auth.c"
        path.write_bytes(path.read_bytes() + (
            b"\nint compose_only(char *input, size_t sz) {\n"
            b"  char other[64];\n  memcpy(other, input, sz);\n  return 1;\n}\n"))
        checklist_path = config.out_dir / "checklist.json"
        checklist = json.loads(checklist_path.read_text())
        checklist["files"][0]["items"].append(
            {"name": "compose_only", "line_start": 13, "line_end": 17})
        checklist_path.write_text(json.dumps(checklist))
        config.max_workers = 1
        config.prefilter = False
        config.deepen_suspicious = False
        config.open_discovery = True
        config.propagate_constraints = False
        config.enable_session_context = False

    with isolated_audit_shutdown(orch):
        if fault_kind == "cancellation_after_actual_ACK":
            with pytest.raises(KeyboardInterrupt) as caught:
                _binding_run(tmp_path, monkeypatch, before_run=configure)
            assert caught.value is fault
        else:
            _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert not forbidden_calls
    assert excluded and composed_calls == [True]
    assert len(converted) == 1 and converted[0]["name"] == "compose_only"
    assert not converted[0].get("force_review")
    assert [o.function for o in assessments].count("compose_only") == 1
    assert len(assessments) == 3
    assert len(acknowledgements) == 1
    result = live_results[0]
    assert all(any(outcome is old for outcome in result.outcomes) for old in prior)
    assert not any(outcome is assessments[-1] for outcome in result.outcomes)
    assert len(runtimes) == len(throttles) == 1
    assert runtimes[0]._closed and not throttles[0]._registered
    assert retired == [throttles[0]]
    events = runtimes[0].events()
    assert len([event for event in events if event.get("event") == "runtime_closed"]) == 1
    assert len([event for event in events if event.get("event") == "review_attempt"]) == 3
    assert all(isinstance(o.review_input_scope, ReviewInputScope) for o in assessments)
    rows = [json.loads(line) for line in (tmp_path / "out/review-journal.jsonl").read_text().splitlines()]
    reviewed = [row for row in rows if row.get("model") == "test-model"]
    # Actual ACK leaves a durable candidate row; canonical acceptance is a
    # separate boundary and must not be inferred from that row's presence.
    assert len(reviewed) >= 3
    assert {(row["file"], row["function"]) for row in reviewed[:2]} == {
        ("src/auth.c", "check_pw"), ("src/auth.c", "validate")}
    assert all(row["verdict"] == "clean" and row.get("review_claims") for row in reviewed[:2])
    assert any(row["function"] == "compose_only" for row in reviewed[2:])
