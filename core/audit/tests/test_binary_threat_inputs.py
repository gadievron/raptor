"""Real project-owned rendered threat-model cache currency.

No threat-model save/report action, graph generation or binary backend is used.
"""
from hashlib import sha256
from pathlib import Path

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.binary_view_snapshot import capture_binary_view_snapshot
from core.audit.collector import Collector
from core.audit.context import format_context_for_prompt
from core.audit.gaps import compute_gaps
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.tests.test_binary_journal_binding import owned_binary_review as owned_binary_review
from core.audit.tests.test_binary_review_availability import _reviewer
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.project.project import ProjectManager
from core.threat_model import ThreatModel, load_for_target, project_threat_model_paths
from packages.ghidra.model import REDatabase, REFunction


def test_changed_owned_project_threat_model_cannot_inherit_binary_review(tmp_path, monkeypatch):
    import core.audit.binary_context as context_module
    import core.project.project as project_module
    import core.run.pin as pin

    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry-home'))
    # The documented registry-directory fixture seam; the real manager still
    # writes and resolves the genuine registration, never a mocked load.
    registry = tmp_path / 'registry-home' / 'projects'
    monkeypatch.setattr(project_module, 'PROJECTS_DIR', registry, raising=False)
    monkeypatch.setattr(context_module, '_lazy_decompile',
                        lambda *a, **kw: pytest.fail('probe dispatched a binary backend'))
    previous_pin, previous_threaded = pin.get_process_project(), pin._process_project_threaded
    pin.set_process_project(None)
    runtime = None
    try:
        target = tmp_path / 'owned.bin'
        target.write_bytes(b'owned inert binary input, not executable')
        project = ProjectManager().create('owned-binary', str(target), output_dir=str(tmp_path / 'project-output'))
        assert ProjectManager().find_project_for_target(str(target)).name == project.name
        model = ThreatModel(project_name=project.name, target=str(target), source='operator',
                            summary='Initial operator risk boundary: local trusted users only.')
        model_path, _markdown_path = project_threat_model_paths(project)
        model_path.write_text(dumps_canonical(model.to_dict()))
        assert load_for_target(target).summary == model.summary
        assert not (Path(project.output_dir) / 'graph/raptor.graph.sqlite').exists()
        out = Path(project.output_dir) / 'run-owned'
        db = REDatabase(source_tool='fixture', binary_path=str(target),
            metadata={'binary_sha256': sha256(target.read_bytes()).hexdigest()},
            functions=[REFunction(name='f', address=4096, size=32, source_tool='fixture',
                                  decompilation='unsigned f(unsigned n) { return n + 1; }')])
        artifact = tmp_path / 're-database.json'
        artifact.write_text(dumps_canonical(db.to_dict()))
        read = load_redb_binding(artifact)
        owner = capture_binary_view_snapshot(read, target)
        assert owner is not None
        checklist = build_binary_checklist(read.database, binary_path=target)
        save_checklist(out, checklist)
        key = checklist['files'][0]['path']
        def context():
            return assemble_binary_context(target_path=target, file_path=key,
                function_name='f', checklist=checklist, db=read.database, out_dir=out)
        original_ctx = context()
        assert model.summary in original_ctx['threat_model']
        runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float('inf'), window=0)
        original_origin = runtime._origin(original_ctx)
        review, calls = _reviewer()
        outcome = runtime.wrap_review(review)(original_ctx, OrchestratorConfig(target_path=target, out_dir=out))
        assert len(calls) == 1 and model.summary in str(calls[0][0])
        item = checklist['files'][0]['items'][0]
        gap = {**item, 'file': key, 'line_start': 0, 'line_end': None}
        assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap)
        def gaps():
            return compute_gaps(checklist, [], out_dir=out, binary_view_snapshot=owner)
        assert not any(g['name'] == 'f' for g in gaps()), 'healthy original threat-model cache setup failed'
        original_projection = read.projection_sha256
        model.summary = 'Changed operator risk boundary: remote unauthenticated users are in scope.'
        model_path.write_text(dumps_canonical(model.to_dict()))
        current_ctx = context()
        assert model.summary in current_ctx['threat_model']
        assert current_ctx['threat_model'] != original_ctx['threat_model']
        assert model.summary in format_context_for_prompt(current_ctx, budget_limit=100000)
        assert read.current() and read.projection_sha256 == original_projection
        current_identity = runtime._origin(current_ctx).binary_identity
        assert original_origin.binary_identity.module_sha256 == current_identity.module_sha256
        assert original_origin.binary_identity.analysis_sha256 == current_identity.analysis_sha256
        assert original_origin.binary_identity.view_sha256 == current_identity.view_sha256
        assert original_origin.binary_identity.threat_model_sha256 != current_identity.threat_model_sha256
        assert not outcome.binary_publication_scope.current(target)
        assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is None
        assert any(g['name'] == 'f' for g in gaps()), 'old clean review hid changed rendered project threat-model input'
    finally:
        if runtime is not None:
            runtime.close('test_complete')
        pin.set_process_project(previous_pin, threaded=previous_threaded)


def test_material_currency_distinguishes_empty_output_and_text_without_authority():
    from core.audit.binary_threat_inputs import binary_threat_material_digest
    absent = binary_threat_material_digest(None)
    empty = binary_threat_material_digest('')
    text = binary_threat_material_digest('none')
    assert len({absent, empty, text}) == 3
    assert all(isinstance(value, str) and len(value) == 64 for value in (absent, empty, text))
    assert binary_threat_material_digest({'summary': 'not a rendered block'}) is None
    assert binary_threat_material_digest(True) is None
    assert binary_threat_material_digest('\ud800') is None


@pytest.mark.parametrize('change', ['missing_digest', 'wrong_digest', 'mutated_material', 'restamped_material'])
def test_original_rendered_material_binding_cannot_be_lost_or_replaced(owned_binary_review, change):
    from core.audit.binary_threat_inputs import binary_threat_material_digest
    target, out, gap, outcome, runtime, original = owned_binary_review
    scope = outcome.binary_publication_scope
    assert scope.current(target) and scope.view_identity.threat_model_sha256 is not None
    ctx = scope.view_context
    if change == 'missing_digest':
        ctx.pop('_binary_threat_model_sha256')
    elif change == 'wrong_digest':
        ctx['_binary_threat_model_sha256'] = 'f' * 64
    else:
        ctx['threat_model'] = 'Unbound replacement material'
        if change == 'restamped_material':
            ctx['_binary_threat_model_sha256'] = binary_threat_material_digest(ctx['threat_model'])
    assert not scope.current(target)
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is None
    assert outcome.cost_usd == .1
    assert any(event['event'] == 'review_assessment' for event in runtime.events())
