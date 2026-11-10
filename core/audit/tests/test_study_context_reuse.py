"""One owned normal-loop control of durable studied-source dependencies."""
import json
import re

import pytest
from core.audit import capabilities, orchestrator as orch
from core.audit.llm_review import make_review_fn
from core.audit.gaps import _verify_entries_fold
from core.audit.journal import load_entries
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline


@pytest.mark.parametrize("initial_status", ["clean", "suspicious"])
@pytest.mark.parametrize("separate_root", [False, True], ids=["target", "study-root"])
@pytest.mark.parametrize("reuse", [False, True], ids=["coverage", "reuse"])
def test_changed_studied_type_cannot_reuse_unchanged_function(tmp_path, monkeypatch, initial_status, separate_root, reuse):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir(); out.mkdir()
    study_root = tmp_path / "full-source" if separate_root else target
    if separate_root:
        study_root.mkdir()
    (study_root / "types.h").write_text("typedef unsigned foo_t;\n")
    source = '#include "types.h"\nfoo_t f(foo_t value) { return value; }\n'
    (target / "unit.c").write_text(source)
    if separate_root:
        (study_root / "unit.c").write_text(source)
    (out / "checklist.json").write_text(json.dumps({"files": [{"path": "unit.c", "items": [
        {"name": "f", "line_start": 2, "line_end": 2}]}]}))
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    calls = []

    class Client:
        _call_cost_history = None
        def is_budget_exhausted(self): return False
        def generate_structured(self, prompt, schema, **kwargs):
            task = kwargs["task_type"]; calls.append(task)
            if task == "study":
                assert "typedef unsigned foo_t" in prompt
                request_id = re.search(r'"request_id"\s*:\s*"([^"]+)"', prompt).group(1)
                return {"subject_answers": [{"request_id": request_id, "status": "answered",
                    "explanation": "The supplied target type is unsigned.", "reason": "",
                    "material_ids": ["material-0"]}]}
            assert task == "audit"
            payload = {"status": "clean", "body": "Scripted assessment", "reading_list": []}
            if calls.count("audit") == 1:
                payload["status"] = initial_status
                if initial_status == "suspicious":
                    payload["hypothesis"] = "type-dependent concern remains unresolved"
                    payload["confidence"] = "medium"
                payload["reading_list"] = [{"subject": "foo_t", "resolution": "identifier", "context": "target type role"}]
            else:
                assert "The supplied target type is unsigned" in prompt
            return StructuredResponse(result=payload, raw="", cost=0, model="scripted")

    client = Client(); monkeypatch.setattr(orch, "_run_llm_client", lambda cfg: client)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, max_workers=1,
        resume=False, prefilter=False, validate=False, immediate_verify=False,
        sweep_validate_findings=False, max_refinements=0, deepen_suspicious=False,
        open_discovery=False, sage_recall=False, iris=False,
        joern_overrides={"enabled": False}, llm_budget_client=client,
        study_root=study_root if separate_root else None)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="study durable input control"):
        result = orch.run_orchestrator(config, make_review_fn(client, escalate_clean=False))
    assert calls == ["audit", "study", "audit"] and result.outcomes[0].status == initial_status
    from core.audit.source_anchor import context_source_anchor_version
    from core.audit.collector import append_journal_for_outcome
    from core.audit.findings_export import build_graded_finding
    from core.audit.orchestrator import _outcome_to_panel_result
    from core.audit.verdict_reuse import outcome_from_entry
    from dataclasses import asdict

    entries = load_entries(out, fresh=True)
    # Initial C reference delivery is already context-bound. Select the
    # corrective row that actually acknowledges the studied header, rather
    # than assuming every context anchor denotes source-study enrichment.
    bound = [row for row in entries
             if context_source_anchor_version(row.source_hash) is not None
             and isinstance(row.review_claims, dict)
             and any(dependency.get("file") == "types.h"
                     for dependency in row.review_claims.get("source_inputs", {}).get("sources", []))]
    assert len(bound) == 1, "unchanged and retained assessments need acknowledged history corrections"
    latest = bound[0]
    assert context_source_anchor_version(latest.source_hash) == 3
    assert latest.verdict == initial_status
    roots = {"study": study_root} if separate_root else {}
    manifest = latest.review_claims["source_inputs"]
    assert {row["root"] for row in manifest["sources"]} == ({"target", "study"} if separate_root else {"target"})
    canonical = result.outcomes[0]
    assert canonical.review_input_scope is not None and canonical.review_input_scope.current(target)
    trace = json.loads((out / "knowledge-results.json").read_text())
    assert any(row["event"] == "runtime_closed" for row in trace["events"])
    # Scope data stays live after the coordinator's drain closes, and remains
    # absent from journal, finding and panel JSON projections.
    assert "review_input_scope" not in asdict(latest)
    assert "review_input_scope" not in build_graded_finding(canonical)
    assert "review_input_scope" not in _outcome_to_panel_result(canonical, "scripted")
    assert str(study_root) not in json.dumps(asdict(latest))
    assert outcome_from_entry(latest).review_input_scope is None
    late = append_journal_for_outcome(out_dir=tmp_path / "late", target_path=target,
        run_id="late", outcome=canonical, gap={"line_start": 2, "line_end": 2}, source_roots=roots)
    assert late is not None

    def fold(mapping):
        covered, sink = set(), {} if reuse else None
        _verify_entries_fold(covered, entries, target_path=target, source_roots=mapping,
            current_spans={"unit.c:f": (2, 2)}, reuse_sink=sink,
            current_strategies_fn=lambda *_: set(latest.strategies), current_model=latest.model,
            source_label="owned-study-control")
        return covered, sink

    assert fold(roots)[0] == {"unit.c:f"}
    if separate_root:
        assert not fold({})[0], "cold reuse cannot invent a missing study-root configuration"
    (study_root / "types.h").write_text("typedef signed foo_t;\n")
    assert (target / "unit.c").read_text() == source
    covered, sink = fold(roots)
    assert not covered and not sink, "changed studied target type was lost from durable review dependencies"
    assert append_journal_for_outcome(out_dir=tmp_path / "late", target_path=target,
        run_id="late", outcome=canonical, gap={"line_start": 2, "line_end": 2}, source_roots=roots) is None
