"""Parsed analysis inputs remain bound through current review reuse."""
import pytest
from hashlib import sha256
from core.json import dumps_canonical
from core.audit.binary_context import load_redb_binding
from core.audit.binary_view_snapshot import capture_binary_view_snapshot
from core.audit.binary_context import assemble_binary_context
from core.audit.collector import Collector
from core.audit.gaps import compute_gaps
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig,StudyQueue
from core.audit.tests.test_binary_journal_binding import owned_binary_review as owned_binary_review
from core.audit.tests.test_binary_review_availability import _reviewer
from core.coverage.record import build_from_journal
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from packages.ghidra.model import REDatabase,REFunction


@pytest.mark.parametrize('surface', ['journal', 'projection'])
def test_changed_signature_same_body_cannot_inherit_review(tmp_path,monkeypatch,surface):
    import core.audit.binary_context as context_module
    monkeypatch.setattr(context_module,'_lazy_decompile',lambda *a,**k:pytest.fail('cache proof started a backend'))
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path/'data'))
    target,out=tmp_path/'owned.bin',tmp_path/'out'
    target.write_bytes(b'owned input bytes, not executable')
    db=REDatabase(source_tool='ghidra',binary_path=str(target),functions=[
        REFunction(name='f',address=4096,size=32,source_tool='ghidra',decompilation='return n + 1;')])
    db.metadata['binary_sha256'] = sha256(target.read_bytes()).hexdigest()
    artifact = tmp_path / 're-database.json'
    artifact.write_text(dumps_canonical(db.to_dict()))
    read = load_redb_binding(artifact)
    db = read.database
    owner = capture_binary_view_snapshot(read, target)
    assert owner is not None
    checklist=build_binary_checklist(db,binary_path=target)
    save_checklist(out,checklist)
    key=checklist['files'][0]['path']
    def context(current):
        return assemble_binary_context(target_path=target,file_path=key,function_name='f',checklist=current,db=db)
    old_ctx=context(checklist)
    runtime=AuditKnowledgeRuntime(target,StudyQueue(),deadline=float('inf'),window=0)
    try:
        before=runtime._origin(old_ctx)
        review,calls=_reviewer()
        outcome=runtime.wrap_review(review)(old_ctx,OrchestratorConfig(target_path=target,out_dir=out))
        item=checklist['files'][0]['items'][0]
        gap={**item,'file':key,'line_start':0,'line_end':None}
        assert Collector(out_dir=out,target_path=target,run_id=out.name).submit(outcome,gap)
        projected=build_from_journal(out)
        assert len(projected['functions_analysed'])==1
        fresh_run=tmp_path/'fresh'
        fresh_run.mkdir()
        def gaps(current):
            return compute_gaps(current,[] if surface=='journal' else [projected],
                                out_dir=out if surface=='journal' else fresh_run, binary_view_snapshot=owner)
        assert not any(g['name']=='f' for g in gaps(checklist))
        db.functions[0].signature = 'long f(long n)'
        artifact.write_text(dumps_canonical(db.to_dict()))
        read = load_redb_binding(artifact)
        db = read.database
        owner = capture_binary_view_snapshot(read, target)
        assert owner is not None
        fresh=build_binary_checklist(db,binary_path=target)
        assert context(fresh)['ghidra_context'] != old_ctx.get('ghidra_context', '')
        after=runtime._origin(context(fresh))
        assert before.binary_identity.module_sha256==after.binary_identity.module_sha256
        assert before.binary_identity.view_sha256==after.binary_identity.view_sha256
        assert not runtime._same_snapshot(before,after)
        assert before.binary_identity.analysis_sha256 != after.binary_identity.analysis_sha256
        assert any(g['name']=='f' for g in gaps(fresh)), 'old clean review hid changed auxiliary signature input'
    finally:
        runtime.close('test_complete')




@pytest.mark.parametrize('change', ['mutated_database', 'missing_database', 'missing_digest', 'wrong_digest'])
def test_original_analysis_projection_cannot_be_dropped_or_restamped(owned_binary_review, change):
    target, out, gap, outcome, runtime, original = owned_binary_review
    scope = outcome.binary_publication_scope
    assert scope is not None and scope.view_identity.analysis_sha256 is not None
    ctx = scope.view_context
    assert scope.current(target)
    if change == 'mutated_database':
        ctx['_binary_analysis_database'].metadata['changed'] = True
    elif change == 'missing_database':
        ctx.pop('_binary_analysis_database')
    elif change == 'missing_digest':
        ctx.pop('_binary_analysis_projection_sha256')
    else:
        ctx['_binary_analysis_projection_sha256'] = 'f' * 64
    assert not scope.current(target)
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is None
    assert outcome.cost_usd == .1
    assert any(event['event'] == 'review_assessment' for event in runtime.events())


def test_unknown_projection_keeps_live_view_review_without_new_cache_credit(tmp_path):
    from core.audit.tests.test_binary_view_snapshot import _inputs
    target, read, checklist, key = _inputs(tmp_path)
    # Legacy in-memory consumers can hold values outside strict JSON. They
    # must not acquire a complete parsed-input binding by string coercion.
    read.database.metadata['unavailable_projection'] = object()
    ctx = assemble_binary_context(target_path=target, file_path=key, function_name='f',
                                  checklist=checklist, db=read.database)
    assert ctx['_binary_analysis_projection_sha256'] is None
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float('inf'), window=0)
    try:
        review, calls = _reviewer()
        out = tmp_path / 'run'
        save_checklist(out, checklist)
        outcome = runtime.wrap_review(review)(ctx, OrchestratorConfig(target_path=target, out_dir=out))
        assert len(calls) == 1 and outcome.status == 'clean'
        scope = outcome.binary_publication_scope
        assert scope.view_identity.analysis_sha256 is None
        assert scope.anchor().startswith('bin:view1:')
        item = checklist['files'][0]['items'][0]
        gap = {**item, 'file': key, 'line_start': 0, 'line_end': None}
        assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap)
        assert any(g['name'] == 'f' for g in compute_gaps(checklist, [], out_dir=out))
    finally:
        runtime.close('test_complete')


def test_known_projection_change_during_assembly_cannot_downgrade_to_unknown(tmp_path, monkeypatch):
    from core.audit.tests.test_binary_view_snapshot import _inputs
    from core.audit.binary_review_scope import BinaryKnowledgeOrigin
    import core.audit.binary_context as module
    target, read, checklist, key = _inputs(tmp_path)
    original = module._related_types
    def changed_types(func, database):
        result = original(func, database)
        database.functions[0].signature = 'long f(long n)'
        return result
    monkeypatch.setattr(module, '_related_types', changed_types)
    ctx = assemble_binary_context(target_path=target, file_path=key, function_name='f',
                                  checklist=checklist, db=read.database)
    assert ctx['_binary_analysis_projection_sha256'] == read.projection_sha256
    assert ctx['_binary_analysis_database'] is None
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float('inf'), window=0)
    try:
        assert not isinstance(runtime._origin(ctx), BinaryKnowledgeOrigin)
        from core.audit.knowledge_calls import KnowledgeCallRefused
        def forbidden_review(*args, **kwargs):
            pytest.fail('changed assembly reached review')
        with pytest.raises(KnowledgeCallRefused, match='binary_view_identity_unavailable'):
            runtime.wrap_review(forbidden_review)(ctx, OrchestratorConfig(target_path=target, out_dir=tmp_path / 'run'))
        assert not runtime._calls
        read.database.functions[0].signature = None
        assert not isinstance(runtime._origin(ctx), BinaryKnowledgeOrigin)
    finally:
        runtime.close('test_complete')
