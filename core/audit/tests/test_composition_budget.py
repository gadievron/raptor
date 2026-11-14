"""Unexecuted owned composition admission control; no real transport or tools."""
import json

import pytest

from core.audit import composition, discovery, orchestrator as orch
from core.audit import knowledge_runtime as runtime_mod, executor as executor_mod
from core.audit.knowledge_calls import observed_client
from core.audit.composition import ComposedHypothesis, UnguardedPath, WeaknessRecord
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
def test_composition_exhausted_unit_refuses_scripted_call_and_retains_main(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    assessments, excluded, composed_calls, converted = [], [], [], []
    runtimes, scripted_calls, live_results, prior, exhausted = [], [], [], [], []
    original_runtime = runtime_mod.AuditKnowledgeRuntime

    class Runtime(original_runtime):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            runtimes.append(self)

    monkeypatch.setattr(runtime_mod, "AuditKnowledgeRuntime", Runtime)
    original_executor = executor_mod.run_executor_sync

    def observed_executor(*args, **kwargs):
        if not live_results:
            live_results.append(args[4])
        return original_executor(*args, **kwargs)

    monkeypatch.setattr(executor_mod, "run_executor_sync", observed_executor)
    original_run = orch.run_orchestrator
    original_compute = orch.compute_gaps
    original_convert = orch._composed_hypotheses_to_gaps

    def observed_run(config, review):
        class ScriptedClient:
            _attempt_admission_protocol = 1

            def generate(self, ctx, cfg, *, accounting_attempt_admission):
                assert accounting_attempt_admission() is True
                scripted_calls.append((ctx["file"], ctx["function"]))
                outcome = review(ctx, cfg)
                assessments.append(outcome)
                return outcome

        client = ScriptedClient()

        def observed_review(ctx, cfg):
            return observed_client(client, purpose="owned-composition-review").generate(ctx, cfg)

        observed_review._knowledge_observed_client_contract = True
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
        assert len(runtimes) == len(live_results) == 1
        runtime = runtimes[0]
        assert not runtime._closed
        prior.extend(live_results[0].outcomes)
        assert len(prior) == 2
        assert all(outcome.function != "compose_only" for outcome in prior)
        gap = {"file": "src/auth.c", "name": "compose_only", "line_start": 13}
        key = runtime._gap_key(gap)
        # The omitted main target has no earlier canonical assessment or call.
        assert runtime._calls.get(key, 0) == 0
        while runtime.admit_client_call(gap, "owned-exhaustion-control", "generate"):
            pass
        exhausted.append((key, runtime._calls[key], len(scripted_calls), len(assessments)))
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
        result, guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert not forbidden_calls
    assert excluded and composed_calls == [True]
    assert len(converted) == 1 and converted[0]["name"] == "compose_only"
    assert not converted[0].get("force_review")
    assert len(runtimes) == len(exhausted) == 1
    runtime = runtimes[0]
    key, count, calls, reviewed = exhausted[0]
    assert runtime._calls[key] == count
    assert len(scripted_calls) == calls
    assert len(assessments) == reviewed
    assert all(outcome.function != "compose_only" for outcome in assessments)
    assert all(any(outcome is old for outcome in result.outcomes) for old in prior)
    assert runtime._closed
    assert ("_gate", "_tick") in guard.tick_callers
    record = json.loads((tmp_path / "out/knowledge-results.json").read_text())
    refusals = [event for event in record["events"]
                if event.get("event") == "client_call_refused"
                and event.get("unit") == list(key)]
    assert len(refusals) >= 2  # owned exhaustion probe and actual late dispatch
    assert all(event["reason"] == "model_call_limit" for event in refusals)
    assert any(outcome.function == "compose_only" and outcome.status == "deferred"
               for outcome in result.outcomes)
