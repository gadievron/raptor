"""Memo resources stay useful and account for retained cache keys."""
import gc
import sys
import weakref

import pytest

from core.json import JsonCache
from core.sentinels import MISSING


@pytest.mark.parametrize('kind', ['missing', 'malformed', 'nonobject', 'missing-fields', 'invalid-utf8', 'directory'])
def test_unsuccessful_queries_do_not_displace_a_useful_memo(tmp_path, monkeypatch, kind):
    cache = JsonCache(tmp_path)
    cache._memo_budget = 1024
    cache.put('hot', {'answer': 42}, ttl_seconds=60)
    original = cache._read_envelope
    hot_reads = []

    def read(path):
        if path.name == 'hot.json':
            hot_reads.append(path)
        return original(path)

    monkeypatch.setattr(cache, '_read_envelope', read)
    assert cache.get('hot', ttl_seconds=60) == {'answer': 42}
    for index in range(32):
        key = f'unsuccessful-{index}'
        path = tmp_path / (key + '.json')
        if kind == 'directory':
            path.mkdir()
        elif kind != 'missing':
            content = {'malformed': b'{', 'nonobject': b'[]',
                       'missing-fields': b'{"value":0}', 'invalid-utf8': b'\xff'}[kind]
            path.write_bytes(content)
        assert cache.try_get(key, ttl_seconds=60) is MISSING
    assert cache.get('hot', ttl_seconds=60) == {'answer': 42}
    assert len(hot_reads) == 1
    assert cache.hits == 2
    assert cache.misses == 32


@pytest.mark.parametrize('shape', ['ascii', 'bmp', 'wide'])
@pytest.mark.parametrize('budget', [512, 1024])
@pytest.mark.parametrize('payload', ['number', 'object', 'list'])
def test_retained_key_memory_respects_the_memo_budget(tmp_path, shape, budget, payload):
    cache = JsonCache(tmp_path)
    cache._memo_budget = budget
    prefix = {'ascii': 'x' * 200, 'bmp': 'é' * 100, 'wide': '𐀀' * 60}[shape]
    value = {'number': 0, 'object': {'ok': 1}, 'list': []}[payload]
    for index in range(8):
        key = prefix + str(index)
        cache.put(key, value, ttl_seconds=60)
        assert cache.try_get(key, ttl_seconds=60) == value
    retained_key_bytes = sum(sys.getsizeof(key) for key in cache._memo)
    assert retained_key_bytes <= budget or len(cache._memo) == 1
    assert cache.memo_evictions > 0
    # Eviction affects memory only; an older on-disk value remains readable.
    assert cache.try_get(prefix + '0', ttl_seconds=60) == value


@pytest.mark.parametrize('change', ['gone', 'malformed', 'nonobject'])
def test_an_unavailable_generation_releases_its_memo_payload(tmp_path, change):
    cache = JsonCache(tmp_path)
    cache.put('key', {'old': 1}, ttl_seconds=60)
    assert cache.try_get('key', ttl_seconds=60) == {'old': 1}
    previous = weakref.ref(cache._memo['key'].payload)
    path = tmp_path / 'key.json'
    if change == 'gone':
        path.unlink()
    else:
        path.write_text('{' if change == 'malformed' else '[]', encoding='utf-8')
    assert cache.try_get('key', ttl_seconds=60) is MISSING
    gc.collect()
    assert previous() is None
    cache.put('key', {'new': 1}, ttl_seconds=60)
    assert cache.try_get('key', ttl_seconds=60) == {'new': 1}


@pytest.mark.parametrize('payload', ['null', 'false', 'zero', 'empty-list'])
def test_false_values_remain_successful_memo_hits(tmp_path, monkeypatch, payload):
    cache = JsonCache(tmp_path)
    value = {'null': None, 'false': False, 'zero': 0, 'empty-list': []}[payload]
    cache.put('key', value, ttl_seconds=60)
    original = cache._read_envelope
    reads = []

    def read(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(cache, '_read_envelope', read)
    assert cache.try_get('key', ttl_seconds=60) == value
    assert cache.try_get('key', ttl_seconds=60) == value
    assert len(reads) == 1
    assert cache.hits == 2
    assert cache.misses == 0
