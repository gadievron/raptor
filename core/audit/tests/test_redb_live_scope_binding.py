"""Original descriptor-read bindings; no analysis backend is invoked."""
import json

import core.audit.binary_context as context


def _artifact(tmp_path):
    path = tmp_path / 're-database.json'
    path.write_text(json.dumps({'source_tool': 'fixture', 'functions': [],
                                'metadata': {'note': 'original'}}))
    return path


def test_memo_mutation_cannot_receive_a_fresh_projection_binding(tmp_path):
    path = _artifact(tmp_path)
    original = context.load_redb_binding(path)
    assert original.current()
    assert context.load_redb(path) is original.database
    original.database.metadata['note'] = 'mutated'
    later = context.load_redb_binding(path)
    assert later.database is original.database
    assert later.projection_sha256 == original.projection_sha256
    assert later.file_current()
    assert not original.current()
    assert not later.current()


def test_cache_alias_binding_uses_its_own_lookup_path(tmp_path):
    path = _artifact(tmp_path)
    alias = tmp_path / 'alias.json'
    alias.symlink_to(path)
    first = context.load_redb_binding(alias)
    second = context.load_redb_binding(path)
    assert first.database is second.database
    alias.unlink()
    assert not first.current()
    assert second.current()


def test_replaced_artifact_gets_new_data_without_recurring_old_scope(tmp_path):
    path = _artifact(tmp_path)
    original = context.load_redb_binding(path)
    replacement = tmp_path / 'replacement.json'
    replacement.write_text(path.read_text().replace('original', 'replaced'))
    replacement.replace(path)
    later = context.load_redb_binding(path)
    assert not original.current()
    assert later.current()
    assert later.database is not original.database
    assert later.database.metadata['note'] == 'replaced'
