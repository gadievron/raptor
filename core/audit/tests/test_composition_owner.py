"""UNEXECUTED canonical-source Phase C ownership control, no discovery calls.

The third checklist occurrence is deliberately omitted from main scheduling,
not added to reviewed_set and not forced through the composition skip guard.
Only captured advisory composition inputs are supplied; their freshness is
not established by this fixture.
"""
import json

import pytest

from core.audit import composition, discovery, orchestrator as orch
from core.audit.composition import ComposedHypothesis, UnguardedPath, WeaknessRecord
from core.audit.review_input_scope import ReviewInputScope
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.slow
def test_actual_composition_review_uses_original_runtime_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)
    assessments, excluded, composed_calls, converted = [], [], [], []
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
        _result, guard = _binding_run(tmp_path, monkeypatch, before_run=configure)
    assert not forbidden_calls
    assert excluded and composed_calls == [True]
    assert len(converted) == 1 and converted[0]["name"] == "compose_only"
    assert not converted[0].get("force_review")
    assert [o.function for o in assessments].count("compose_only") == 1
    assert len(assessments) == 3
    assert ("_gate", "_tick") in guard.tick_callers
    record = json.loads((tmp_path / "out/knowledge-results.json").read_text())
    attempts = [e for e in record["events"] if e.get("event") == "review_attempt"]
    assert all(isinstance(o.review_input_scope, ReviewInputScope) for o in assessments)
    assert len(attempts) == len(assessments)
