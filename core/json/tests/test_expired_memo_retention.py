"""Expired disk entries must not consume the useful parsed-cache budget."""
import gc
import json
import time
import weakref

import pytest

from core.json import cache as cache_module
from core.sentinels import MISSING
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('offset', [-7200, 7200], ids=['expired', 'future'])
@pytest.mark.parametrize('stored_ttl', [60, 3600])
def test_unusable_timestamps_do_not_displace_hot_memo(tmp_path, monkeypatch, offset, stored_ttl):
    cache = cache_module.JsonCache(tmp_path)
    cache._memo_budget = 1024
    cache.put('hot', {'answer': 42}, ttl_seconds=3600)
    original = cache._read_envelope
    reads = []

    def read(path):
        if path.name == 'hot.json':
            reads.append(path)
        return original(path)

    monkeypatch.setattr(cache, '_read_envelope', read)
    assert cache.try_get('hot', ttl_seconds=3600) == {'answer': 42}
    for index in range(16):
        key = f'unusable-{index}'
        (tmp_path / (key + '.json')).write_text(json.dumps({
            'written_at': time.time() + offset,
            'ttl_seconds': stored_ttl,
            'value': 'x' * 1024,
        }))
        assert cache.try_get(key, ttl_seconds=stored_ttl) is MISSING
    assert cache.try_get('hot', ttl_seconds=3600) == {'answer': 42}
    assert len(reads) == 1
    assert cache.hits == 2
    assert cache.misses == 16
    assert (tmp_path / 'unusable-0.json').is_file()


def test_expiry_releases_previously_memoised_payload(tmp_path, monkeypatch):
    clock = [10000.0]
    patch_module_attribute(monkeypatch, cache_module, 'time', 'time', lambda: clock[0])
    cache = cache_module.JsonCache(tmp_path)
    cache.put('entry', {'payload': 'x' * 1024}, ttl_seconds=10)
    assert cache.try_get('entry', ttl_seconds=10) == {'payload': 'x' * 1024}
    previous = weakref.ref(cache._memo['entry'].payload)
    clock[0] += 11
    assert cache.try_get('entry', ttl_seconds=10) is MISSING
    gc.collect()
    assert previous() is None
    assert cache._memo_bytes == 0
    assert (tmp_path / 'entry.json').is_file()


def test_caller_ttl_refusal_preserves_still_valid_stored_memo(tmp_path, monkeypatch):
    clock = [10000.0]
    patch_module_attribute(monkeypatch, cache_module, 'time', 'time', lambda: clock[0])
    cache = cache_module.JsonCache(tmp_path)
    cache.put('entry', False, ttl_seconds=3600)
    assert cache.try_get('entry', ttl_seconds=3600) is False
    stored = cache._memo['entry']
    clock[0] += 30
    assert cache.try_get('entry', ttl_seconds=10) is MISSING
    assert cache._memo['entry'] is stored
    assert cache.try_get('entry', ttl_seconds=3600) is False
