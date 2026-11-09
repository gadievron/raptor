"""Ambiguous separator spellings cannot mutate another cache key's entry."""
from pathlib import Path

import pytest

from core.json import JsonCache


@pytest.mark.parametrize('bad_key,plain_key', [
    pytest.param('alpha\\beta', 'alpha_beta', id='middle'),
    pytest.param('\\alpha', '_alpha', id='leading'),
    pytest.param('alpha\\', 'alpha_', id='trailing'),
    pytest.param('alpha\\\\beta', 'alpha__beta', id='repeated'),
])
@pytest.mark.parametrize('operation', ['put', 'get', 'try_get', 'invalidate'])
def test_separator_alias_is_refused_without_changing_plain_entry(
    tmp_path, bad_key, plain_key, operation,
):
    cache = JsonCache(tmp_path)
    cache.put(plain_key, {'stable': True}, ttl_seconds=60)
    assert cache.try_get(plain_key, ttl_seconds=60) == {'stable': True}
    entry = tmp_path / (plain_key + '.json')
    before = entry.read_bytes()
    with pytest.raises(ValueError):
        if operation == 'put':
            cache.put(bad_key, {'other': True}, ttl_seconds=60)
        elif operation == 'invalidate':
            cache.invalidate(bad_key)
        else:
            getattr(cache, operation)(bad_key, ttl_seconds=60)
    assert entry.read_bytes() == before
    assert cache.try_get(plain_key, ttl_seconds=60) == {'stable': True}
    assert cache.hits == 2 and cache.misses == 0


@pytest.mark.parametrize('key,relative', [
    ('alpha_beta', 'alpha_beta.json'),
    ('alpha%5Cbeta', 'alpha%5Cbeta.json'),
    ('sub/alpha_beta', 'sub/alpha_beta.json'),
    ('versions/1.2.3', 'versions/1.2.3.json'),
])
@pytest.mark.parametrize('value', [None, False, 0, [], {'stable': True}])
def test_existing_encoded_plain_and_dotted_filenames_are_unchanged(tmp_path, key, relative, value):
    cache = JsonCache(tmp_path)
    cache.put(key, value, ttl_seconds=60)
    assert (tmp_path / Path(relative)).is_file()
    assert cache.try_get(key, ttl_seconds=60) == value
