"""Strict owned projection snapshots keep the frozen canonical byte contract."""
from hashlib import sha256
import json
from types import SimpleNamespace

from core.json import dumps_canonical
from packages.ghidra.model import REDatabase, REFunction


def test_fingerprint_uses_canonical_bytes_without_json_reparse(monkeypatch):
    import core.audit.redb_read_scope as scope
    database = REDatabase(source_tool='fixture', metadata={'unicode': '\u03bb', 'finite': -0.0},
        functions=[REFunction(name=f'f{index}', address=4096 + 32 * index, size=32,
                              source_tool='fixture', decompilation='return n + 1;')
                   for index in range(32)])
    expected = sha256(dumps_canonical(database.to_dict()).encode()).hexdigest()
    decoded_sizes = []
    original_loads = json.loads
    def observed_loads(value, *args, **kwargs):
        decoded_sizes.append(len(value))
        return original_loads(value, *args, **kwargs)
    # Replace this module's lookup, never the process-wide stdlib module.
    monkeypatch.setattr(scope, 'json', SimpleNamespace(dumps=json.dumps, loads=observed_loads), raising=False)
    assert scope.database_projection_digest(database, 1024 * 1024) == expected
    assert decoded_sizes == [], 'fingerprinting reparsed an already parsed analysis projection'


def test_streamed_digest_keeps_exact_existing_byte_budget():
    from core.audit.redb_read_scope import database_projection_digest
    database = REDatabase(source_tool='fixture', metadata={'nested': [None, True, 2**90, 1e-30, 'λ']})
    encoded = dumps_canonical(database.to_dict()).encode('utf-8')
    assert database_projection_digest(database, len(encoded)) == sha256(encoded).hexdigest()
    assert database_projection_digest(database, len(encoded) - 1) is None
    assert database_projection_digest(database, 0) is None


def test_canonical_default_coercion_cannot_observe_late_mutation(monkeypatch):
    import core.audit.redb_read_scope as scope
    document = {'metadata': {'value': 'original'}}
    expected = sha256(dumps_canonical(document).encode()).hexdigest()
    calls = []
    class NotJson:
        def __str__(self):
            calls.append('coerced')
            raise AssertionError('untrusted value reached default=str')
    class Database:
        def to_dict(self):
            return document
    original_encoder = scope.iterencode_canonical
    def mutation_at_encoder_boundary(owned):
        document['metadata']['value'] = NotJson()
        yield from original_encoder(owned)
    monkeypatch.setattr(scope, 'iterencode_canonical', mutation_at_encoder_boundary)
    assert scope.database_projection_digest(Database(), 4096) == expected
    assert calls == []
