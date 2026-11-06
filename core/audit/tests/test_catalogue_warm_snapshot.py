"""Warm catalogue ingestion reuses validated data without changing snapshots."""

import hashlib
import zlib
from contextlib import closing
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import catalogue


@pytest.fixture
def cat(tmp_path):
    root = tmp_path / 'src'
    out = tmp_path / 'out'
    root.mkdir()
    out.mkdir()
    with closing(catalogue.Catalogue(root, out)) as value:
        value.begin()
        yield value


def ingest(cat, source, body=None):
    if body is None:
        body = source.encode('utf-8')
    (cat.root / 'm.c').write_bytes(body)
    sha = hashlib.sha256(body).hexdigest()
    cat.ingest({'m.c': source}, {'m.c': sha})
    return sha


def snapshot(cat):
    row = cat.db.execute('SELECT * FROM files WHERE path=?', ('m.c',)).fetchone()
    return dict(row)


@pytest.mark.parametrize('source', [
    pytest.param('', id='empty'),
    pytest.param('void f(struct item *p){p->value=1;}', id='ascii'),
    pytest.param('/* café 漢字 */ void f(struct item *p){p->value=1;}', id='unicode'),
])
def test_exact_native_snapshot(cat, source):
    sha = ingest(cat, source)
    row = snapshot(cat)
    assert row['sha'] == sha
    assert zlib.decompress(row['body']) == source.encode('utf-8')
    assert row['status'] == 'indexed'
    assert row['error'] == ''
    assert row['version'] == catalogue.VERSION
    terms = {r[0] for r in cat.db.execute('SELECT term FROM terms WHERE path=?', ('m.c',))}
    assert terms == catalogue.retrieval_terms(source)
    assert cat.changed_files() == ['m.c']


def test_native_store_hashes_once_and_avoids_redundant_lookup(cat, monkeypatch):
    calls = []
    queries = []
    original = hashlib.sha256

    def sha256(body):
        calls.append(body)
        return original(body)

    # Patch the consumer's module binding, preserving shared hashlib state.
    monkeypatch.setattr(catalogue, 'hashlib', SimpleNamespace(sha256=sha256))
    cat.db.set_trace_callback(queries.append)
    source = 'void f(struct item *p){p->value=1;}'
    ingest(cat, source)
    assert calls == [source.encode('utf-8')]
    assert not any(q.startswith('SELECT sha FROM files') for q in queries)


def test_custom_encoder_terms_follow_encoded_bytes(cat):
    body = b'void real(struct actual *p){p->encoded=1;}'

    class Source(str):
        def encode(self, *args, **kwargs):
            return body

    sha = ingest(cat, Source('void fake(struct wrong *p){p->misleading=1;}'), body)
    row = snapshot(cat)
    assert row['sha'] == sha
    assert zlib.decompress(row['body']) == body
    assert cat.matching_files({'field:encoded'}) == ['m.c']
    assert cat.matching_files({'field:misleading'}) == []


def test_mismatched_hash_does_not_discover_or_store(cat):
    source = 'void f(void){}'
    (cat.root / 'm.c').write_text(source)
    cat.ingest({'m.c': source}, {'m.c': 'wrong-hash'})
    assert cat.db.execute('SELECT count(*) FROM files').fetchone()[0] == 0
    assert cat.db.execute('SELECT count(*) FROM terms').fetchone()[0] == 0
    assert cat.changed_files() == []


def test_unchanged_indexed_snapshot_is_not_recompressed(cat, monkeypatch):
    calls = []
    original = zlib.compress

    def compress(body):
        calls.append(body)
        return original(body)

    monkeypatch.setattr(catalogue, 'zlib', SimpleNamespace(compress=compress))
    source = 'void f(void){}'
    sha = ingest(cat, source)
    cat.changed.clear()
    before = snapshot(cat)
    cat.ingest({'m.c': source}, {'m.c': sha})
    assert snapshot(cat) == before
    assert cat.changed_files() == []
    assert calls == [source.encode('utf-8')]


def test_replacement_updates_hash_body_and_terms(cat):
    ingest(cat, 'void old(struct item *p){p->old_field=1;}')
    cat.changed.clear()
    source = 'void current(struct item *p){p->new_field=1;}'
    sha = ingest(cat, source)
    assert snapshot(cat)['sha'] == sha
    assert zlib.decompress(snapshot(cat)['body']) == source.encode('utf-8')
    assert cat.matching_files({'field:old_field'}) == []
    assert cat.matching_files({'field:new_field'}) == ['m.c']
    assert cat.changed_files() == ['m.c']


def test_pending_same_hash_reindexes_without_reporting_content_change(cat):
    source = 'void f(void){}'
    sha = ingest(cat, source)
    cat.changed.clear()
    cat.db.execute("UPDATE files SET status='pending' WHERE path='m.c'")
    cat.ingest({'m.c': source}, {'m.c': sha})
    assert snapshot(cat)['status'] == 'indexed'
    assert cat.changed_files() == []


def test_cold_byte_store_keeps_replacement_decoding(cat):
    body = b'/* \xff */ void f(struct item *p){p->value=1;}'
    (cat.root / 'm.c').write_bytes(body)
    cat._discover('m.c')
    cat._store('m.c', body)
    row = snapshot(cat)
    assert row['sha'] == hashlib.sha256(body).hexdigest()
    assert zlib.decompress(row['body']) == body
    assert cat.matching_files({'field:value'}) == ['m.c']
