"""Staleness checks share contained reads and scanner line numbering."""
import hashlib

import pytest

from core.concepts.model import DomainModel, Invariant


@pytest.fixture(params=['model', 'audit-load'])
def is_stale(request, monkeypatch, tmp_path):
    def check(root, span, expected):
        if request.param == 'model':
            invariant = Invariant(id='i', concept='c', statement='s', negation='n',
                                  source_hash=expected, source_hash_span=span)
            return bool(DomainModel(invariants=[invariant]).stale_invariants(root))
        from core.audit import journal
        from core.audit.orchestrator import OrchestratorConfig, _load_domain_model
        model = {'invariants': [{'id': 'i', 'source_hash': expected, 'source_hash_span': span}]}
        monkeypatch.setattr(journal, 'load_domain_model', lambda *args, **kwargs: model)
        result = _load_domain_model(OrchestratorConfig(target_path=root, out_dir=tmp_path / 'out'))
        return result['invariants'][0].get('state') == 'stale'
    return check


@pytest.mark.parametrize('separator', ['\v', '\f', '\r', '\u0085', '\u2028', '\u2029'])
@pytest.mark.parametrize('ending', ['\n', '\r\n'])
def test_exotic_bytes_do_not_shift_source_span(tmp_path, is_stale, separator, ending):
    (tmp_path / 'f.c').write_bytes(('prefix' + separator + 'still first' + ending +
                                  'selected' + ending).encode())
    expected = hashlib.sha256(b'selected\n').hexdigest()[:16]
    assert not is_stale(tmp_path, {'file': 'f.c', 'start': 2, 'end': 2}, expected)


def test_final_line_without_newline_keeps_its_hash(tmp_path, is_stale):
    (tmp_path / 'f.c').write_bytes(b'prefix\nselected')
    expected = hashlib.sha256(b'selected').hexdigest()[:16]
    assert not is_stale(tmp_path, {'file': 'f.c', 'start': 2, 'end': 2}, expected)


@pytest.mark.parametrize('kind', ['traversal', 'absolute', 'symlink'])
def test_escaping_source_path_is_stale_even_when_hash_matches(tmp_path, is_stale, kind):
    root = tmp_path / 'target'
    root.mkdir()
    outside = tmp_path / 'outside.c'
    outside.write_text('selected\n')
    if kind == 'symlink':
        (root / 'alias.c').symlink_to(outside)
        candidate = 'alias.c'
    else:
        candidate = '../outside.c' if kind == 'traversal' else str(outside)
    expected = hashlib.sha256(b'selected\n').hexdigest()[:16]
    assert is_stale(root, {'file': candidate, 'start': 1, 'end': 1}, expected)


@pytest.mark.parametrize('end', [2, '1', True])
def test_invalid_or_unavailable_span_cannot_match(tmp_path, is_stale, end):
    (tmp_path / 'f.c').write_text('selected\n')
    expected = hashlib.sha256(b'selected\n').hexdigest()[:16]
    assert is_stale(tmp_path, {'file': 'f.c', 'start': 1, 'end': end}, expected)
