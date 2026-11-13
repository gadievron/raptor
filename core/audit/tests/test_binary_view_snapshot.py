"""Actual assembler and bounded JSON reads, with backend dispatch forbidden."""
from hashlib import sha256

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.binary_view_snapshot import capture_binary_view_snapshot
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from packages.ghidra.model import REDatabase, REFunction


def _inputs(tmp_path):
    target = tmp_path / 'owned.bin'
    target.write_bytes(b'owned inert bytes')
    db = REDatabase(source_tool='fixture', binary_path=str(target),
        metadata={'binary_sha256': sha256(target.read_bytes()).hexdigest()},
        functions=[REFunction(name='f', address=4096, size=32, source_tool='fixture',
                              decompilation='return n + 1;')])
    artifact = tmp_path / 're-database.json'
    artifact.write_text(dumps_canonical(db.to_dict()))
    read = load_redb_binding(artifact)
    checklist = build_binary_checklist(read.database, binary_path=target)
    return target, read, checklist, checklist['files'][0]['path']


def test_cached_view_matches_real_assembler_and_refuses_mutated_projection(tmp_path, monkeypatch):
    import core.audit.binary_context as context
    monkeypatch.setattr(context, '_lazy_decompile', lambda *a, **kw: pytest.fail('backend dispatched'))
    target, read, checklist, key = _inputs(tmp_path)
    snapshot = capture_binary_view_snapshot(read, target)
    assert snapshot is not None
    identity = snapshot.view_identity(file=key, function='f', checklist=checklist)
    assert identity is not None
    ctx = assemble_binary_context(target_path=target, file_path=key, function_name='f',
                                  checklist=checklist, db=read.database)
    assert identity.view_sha256 == sha256(ctx['source'].encode()).hexdigest()
    read.database.functions[0].decompilation = 'return n + 2;'
    assert not snapshot.current()
    assert snapshot.view_identity(file=key, function='f', checklist=checklist) is None
    assert capture_binary_view_snapshot(load_redb_binding(read.path), target) is None


def test_missing_cached_implementation_never_dispatches_backend(tmp_path, monkeypatch):
    import core.audit.binary_context as context
    monkeypatch.setattr(context, '_lazy_decompile', lambda *a, **kw: pytest.fail('backend dispatched'))
    target, read, checklist, key = _inputs(tmp_path)
    read.database.functions[0].decompilation = ''
    ctx = assemble_binary_context(target_path=target, file_path=key, function_name='f',
                                  checklist=checklist, db=read.database, cached_only=True)
    assert ctx['representation'] == 'stub'


@pytest.mark.parametrize("change", ["module", "artifact", "declared_bytes"])
def test_current_view_requires_both_original_inputs(tmp_path, change):
    target, read, checklist, key = _inputs(tmp_path)
    snapshot = capture_binary_view_snapshot(read, target)
    assert snapshot is not None
    if change == 'module':
        target.write_bytes(b'different module bytes')
    elif change == 'artifact':
        read.path.write_text('{}')
    else:
        read.database.metadata['binary_sha256'] = 'f' * 64
    assert not snapshot.current()
    assert snapshot.view_identity(file=key, function='f', checklist=checklist) is None


@pytest.mark.parametrize("change", ["file", "name", "size", "metadata_size", "address"])
def test_checklist_cannot_supply_current_view_identity(tmp_path, change):
    from copy import deepcopy
    target, read, checklist, key = _inputs(tmp_path)
    snapshot = capture_binary_view_snapshot(read, target)
    assert snapshot is not None
    forged = deepcopy(checklist)
    entry = forged['files'][0]
    item = entry['items'][0]
    name = 'f'
    if change == 'file':
        key = entry['path'] = 'binary:other.bin'
    elif change == 'name':
        name = item['name'] = 'other'
    elif change == 'size':
        item['size'] += 1
        item['metadata']['size'] += 1
    elif change == 'metadata_size':
        item['metadata']['size'] += 1
    else:
        item['address'] += 1
        item['metadata']['address'] += 1
    assert snapshot.view_identity(file=key, function=name, checklist=forged) is None
