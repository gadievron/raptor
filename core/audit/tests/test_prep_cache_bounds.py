"""Prep caches retain authentication while bounding reads and published bytes."""
import json

import pytest

from core.audit import prep_cache as cache


PAYLOAD = {'rows': ['café', '𐀀', 'x' * 256]}


def write(root, payload=PAYLOAD, fingerprint='fp'):
    cache.write_prep_cache(root, 'owned.json', fingerprint, payload, label='test')
    return cache.prep_cache_path(root, 'owned.json')


def read(root, fingerprint='fp'):
    return cache.load_prep_cache(root, 'owned.json', fingerprint, label='test')


@pytest.mark.parametrize('slack', [-1, 0, 1])
def test_signed_row_respects_read_byte_budget(tmp_path, monkeypatch, slack):
    path = write(tmp_path)
    size = path.stat().st_size
    monkeypatch.setattr(cache, '_MAX_PREP_CACHE_BYTES', size + slack, raising=False)
    assert read(tmp_path) == (None if slack < 0 else PAYLOAD)


@pytest.mark.parametrize('slack', [-1, 0, 1])
def test_write_size_limit_matches_signed_row_read_limit(tmp_path, monkeypatch, slack):
    path = write(tmp_path)
    size = path.stat().st_size
    path.unlink()
    monkeypatch.setattr(cache, '_MAX_PREP_CACHE_BYTES', size + slack, raising=False)
    write(tmp_path)
    assert path.exists() is (slack >= 0)
    if slack >= 0:
        assert read(tmp_path) == PAYLOAD
    assert not list(path.parent.glob('*.tmp'))


def test_oversized_replacement_preserves_existing_authenticated_row(tmp_path, monkeypatch):
    path = write(tmp_path, {'old': True}, fingerprint='old-fp')
    original = path.read_bytes()
    monkeypatch.setattr(cache, '_MAX_PREP_CACHE_BYTES', len(original), raising=False)
    write(tmp_path, {'oversized': 'x' * 4096}, fingerprint='new-fp')
    assert path.read_bytes() == original
    assert read(tmp_path, fingerprint='old-fp') == {'old': True}


def test_oversized_write_does_not_allocate_prep_cache_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, '_MAX_PREP_CACHE_BYTES', 1, raising=False)
    write(tmp_path)
    assert not (tmp_path / cache.PREP_CACHE_DIRNAME).exists()


def test_authenticated_bytes_behind_a_link_are_not_loaded(tmp_path):
    path = write(tmp_path)
    target = tmp_path / 'borrowed-copy'
    original = path.read_bytes()
    target.write_bytes(original)
    path.unlink()
    path.symlink_to(target)
    assert read(tmp_path) is None
    assert target.read_bytes() == original


def test_byte_budget_does_not_replace_run_or_payload_authentication(tmp_path):
    path = write(tmp_path)
    original = path.read_bytes()
    data = json.loads(original)
    data['payload'] = {'changed': True}
    path.write_text(json.dumps(data))
    assert read(tmp_path) is None
    other = tmp_path / 'other-run'
    other.mkdir()
    (other / cache.PREP_CACHE_DIRNAME).mkdir()
    (other / cache.PREP_CACHE_DIRNAME / 'owned.json').write_bytes(original)
    assert read(other) is None
