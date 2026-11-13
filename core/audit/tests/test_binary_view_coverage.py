"""Actual signed review reuse follows the currently accepted cached view."""
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
from core.audit.tests.test_binary_review_availability import _reviewer
from core.coverage.record import build_from_journal
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from packages.ghidra.model import REDatabase,REFunction


@pytest.mark.parametrize('surface',['journal','projection'])
@pytest.mark.parametrize('timing',['before','during'])
@pytest.mark.parametrize('manual',['none','projection','journal'])
def test_changed_current_view_same_module_cannot_inherit_review(tmp_path,monkeypatch,surface,timing,manual):
    import core.audit.binary_context as context_module
    monkeypatch.setattr(context_module,'_lazy_decompile',lambda *a,**k:pytest.fail('cache proof started a backend'))
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path/'data'))
    target,out=tmp_path/'owned.bin',tmp_path/'out'
    target.write_bytes(b'owned input bytes, not executable')
    db=REDatabase(source_tool='ghidra',binary_path=str(target),functions=[
        REFunction(name='f',address=4096,size=32,source_tool='ghidra',decompilation='return n + 1;')])
    db.metadata['binary_sha256'] = sha256(target.read_bytes()).hexdigest()
    out.mkdir()
    artifact = out / 're-database.json'
    artifact.write_text(dumps_canonical(db.to_dict()))
    read_scope = load_redb_binding(artifact)
    db = read_scope.database
    view_snapshot = capture_binary_view_snapshot(read_scope, target)
    assert view_snapshot is not None
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
        manual_records = []
        def gaps(current):
            return compute_gaps(current,([] if surface=='journal' else [projected]) + manual_records,
                                out_dir=out if surface=='journal' or manual == 'journal' else fresh_run,
                                binary_view_snapshot=None if surface == 'journal' else view_snapshot)
        assert not any(g['name']=='f' for g in gaps(checklist))
        if manual == 'projection':
            from core.coverage import journal_mac
            row = {'file': key, 'function': 'f', 'status': 'clean'}
            row[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(row, 'mark')
            manual_records.append({'tool': 'mark', 'functions_analysed': [row]})
        elif manual == 'journal':
            from core.audit.journal import ReviewJournalEntry, append_entry, now_iso
            # An admitted operator journal fixture, not a CLI execution claim.
            append_entry(out, ReviewJournalEntry(ts=now_iso(), run_id=out.name,
                file=key, function='f', verdict='clean', source_hash='', producer='mark', model='operator'))

        def change_view():
            db.functions[0].decompilation='return n + 2;'
        if timing == 'before':
            change_view()
        else:
            import core.audit.gaps as gap_module
            original_fold = gap_module._fold_journal_into_covered
            def changing_fold(*args, **kwargs):
                result = original_fold(*args, **kwargs)
                change_view()
                return result
            monkeypatch.setattr(gap_module, '_fold_journal_into_covered', changing_fold)
        fresh=build_binary_checklist(db,binary_path=target)
        assert fresh['files']==checklist['files']
        after=runtime._origin(context(fresh))
        assert before.binary_identity.module_sha256==after.binary_identity.module_sha256
        if timing == 'before':
            assert before.binary_identity.view_sha256!=after.binary_identity.view_sha256
            assert not runtime._same_snapshot(before,after)
        resurfaced = any(g['name']=='f' for g in gaps(fresh))
        assert resurfaced == (manual == 'none'), 'automatic view reuse and manual authority were conflated'
        if timing == 'during':
            after = runtime._origin(context(fresh))
            assert before.binary_identity.view_sha256 != after.binary_identity.view_sha256
    finally:
        runtime.close('test_complete')


@pytest.mark.parametrize('stored', [None, '', 'foreign', 'module'])
def test_signed_automatic_binary_rows_need_an_independent_current_view(tmp_path, stored):
    from core.audit.tests.test_binary_view_snapshot import _inputs
    from core.coverage import journal_mac
    target, read, checklist, key = _inputs(tmp_path)
    snapshot = capture_binary_view_snapshot(read, target)
    row = {'file': key, 'function': 'f', 'status': 'clean'}
    if stored is not None:
        row['hash'] = (f"bin:{sha256(target.read_bytes()).hexdigest()}:1000:20"
                       if stored == 'module' else stored)
    row[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(row, 'llm')
    assert journal_mac.coverage_row_provenance(row, 'llm') == journal_mac.ROW_VERIFIED
    gaps = compute_gaps(checklist, [{'tool': 'llm', 'functions_analysed': [row]}],
                        binary_view_snapshot=snapshot)
    assert any(g['name'] == 'f' for g in gaps)


@pytest.mark.parametrize('malformed', ['file_entry', 'item', 'duplicate'])
def test_bulk_view_binding_refuses_ambiguous_inventory_without_backend(tmp_path, monkeypatch, malformed):
    from copy import deepcopy
    from core.audit.tests.test_binary_view_snapshot import _inputs
    import core.audit.binary_context as context_module
    monkeypatch.setattr(context_module, '_lazy_decompile', lambda *a, **kw: pytest.fail('backend dispatched'))
    target, read, checklist, key = _inputs(tmp_path)
    snapshot = capture_binary_view_snapshot(read, target)
    assert snapshot is not None and snapshot.view_identities(checklist)
    current = deepcopy(checklist)
    if malformed == 'file_entry':
        current['files'] = ['invalid']
    elif malformed == 'item':
        current['files'][0]['items'] = ['invalid']
    else:
        current['files'].append(deepcopy(current['files'][0]))
    assert snapshot.view_identities(current) == {}
