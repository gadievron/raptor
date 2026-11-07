"""Review context uses fresh point lookups while retaining annotation fallback."""

import json

import pytest

from core.annotations.models import Annotation
from core.annotations import storage
from core.audit import context
from core.audit import journal as audit_journal
from core.coverage import journal


@pytest.fixture(autouse=True)
def private_load_cache():
    cache_patch = pytest.MonkeyPatch()
    try:
        with journal._load_cache_lock:
            cache_patch.setattr(journal, '_load_cache', {})
        yield
    finally:
        with journal._load_cache_lock:
            cache_patch.undo()


def row(body, timestamp, verdict='clean'):
    return json.dumps({'ts': timestamp, 'run_id': 'test', 'file': 'src/a.c',
                       'function': 'f', 'verdict': verdict, 'source_hash': 'hash',
                       'schema_version': 1, 'body': body}) + '\n'


def test_context_uses_point_lookup_and_observes_append(tmp_path, monkeypatch):
    path = tmp_path / 'review-journal.jsonl'
    path.write_text(row('prior review', '2026-01-01T00:00:00Z'))
    calls = []
    lookup = audit_journal.latest_entry

    def point(directory, key):
        calls.append(key)
        return lookup(directory, key)

    def full_view(*args, **kwargs):
        pytest.fail('review context requested a full journal view')

    monkeypatch.setattr(audit_journal, 'latest_entry', point)
    monkeypatch.setattr(audit_journal, 'latest_entries', full_view)
    assert context._load_existing_annotation(None, 'src/a.c', 'f', out_dir=tmp_path) == 'prior review'
    assert context._is_prior_audit_annotation(None, 'src/a.c', 'f', out_dir=tmp_path)
    with path.open('a') as stream:
        stream.write(row('new review', '2026-01-01T00:00:01Z', 'finding'))
    assert context._load_existing_annotation(None, 'src/a.c', 'f', out_dir=tmp_path) == 'new review'
    assert context._is_prior_audit_annotation(None, 'src/a.c', 'f', out_dir=tmp_path)
    assert calls == ['src/a.c:f'] * 4


@pytest.mark.parametrize('source,expected', [('human', False), ('llm', True)])
def test_missing_journal_keeps_annotation_body_and_legacy_status(tmp_path, monkeypatch, source, expected):
    ann = Annotation('src/a.c', 'f', 'annotation body', {'source': source, 'status': 'clean'})
    monkeypatch.setattr(storage, 'read_annotation', lambda *args: ann)
    assert context._load_existing_annotation(tmp_path, 'src/a.c', 'f', out_dir=tmp_path) == ann.body
    assert context._is_prior_audit_annotation(tmp_path, 'src/a.c', 'f', out_dir=tmp_path) is expected


def test_empty_journal_body_falls_back_without_losing_journal_verdict(tmp_path, monkeypatch):
    (tmp_path / 'review-journal.jsonl').write_text(row('', '2026-01-01T00:00:00Z'))
    ann = Annotation('src/a.c', 'f', 'human note', {'source': 'human'})
    monkeypatch.setattr(storage, 'read_annotation', lambda *args: ann)
    assert context._load_existing_annotation(tmp_path, 'src/a.c', 'f', out_dir=tmp_path) == ann.body
    assert context._is_prior_audit_annotation(tmp_path, 'src/a.c', 'f', out_dir=tmp_path)


def test_lookup_error_preserves_annotation_fallback(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError('owned test lookup failure')

    ann = Annotation('src/a.c', 'f', 'legacy review', {'source': 'llm', 'status': 'finding'})
    monkeypatch.setattr(audit_journal, 'latest_entry', unavailable)
    monkeypatch.setattr(storage, 'read_annotation', lambda *args: ann)
    assert context._load_existing_annotation(tmp_path, 'src/a.c', 'f', out_dir=tmp_path) == ann.body
    assert context._is_prior_audit_annotation(tmp_path, 'src/a.c', 'f', out_dir=tmp_path)


def test_audit_shim_reexports_canonical_lookup():
    assert audit_journal.latest_entry is journal.latest_entry
