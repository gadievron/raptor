"""Integer coercion must not extend a stored TTL into forever."""

import json
import time

import pytest

from core.json import JsonCache, TTL_FOREVER
from core.json.cache import MISSING


def _entry(tmp_path, ttl, written_at=0):
    cache = JsonCache(root=tmp_path)
    (tmp_path / 'entry.json').write_text(json.dumps({
        'written_at': written_at, 'ttl_seconds': ttl, 'value': 'cached',
    }))
    return cache


@pytest.mark.parametrize('ttl', [-1.1, -1.5, -1.999])
def test_fractional_negative_ttl_cannot_become_forever(tmp_path, ttl):
    cache = _entry(tmp_path, ttl)
    assert cache.try_get('entry', ttl_seconds=TTL_FOREVER) is MISSING
    assert cache.try_get('entry', ttl_seconds=TTL_FOREVER) is MISSING
    assert cache.misses == 2


@pytest.mark.parametrize('ttl', [TTL_FOREVER, -1.0, '-1'])
def test_exact_forever_encodings_remain_accepted(tmp_path, ttl):
    cache = _entry(tmp_path, ttl)
    assert cache.try_get('entry', ttl_seconds=TTL_FOREVER) == 'cached'
    assert cache.try_get('entry', ttl_seconds=TTL_FOREVER) == 'cached'


@pytest.mark.parametrize('ttl', [-2, 60])
def test_other_expired_lifetimes_remain_misses(tmp_path, ttl):
    cache = _entry(tmp_path, ttl)
    assert cache.try_get('entry', ttl_seconds=TTL_FOREVER) is MISSING


def test_finite_lifetime_coercion_remains_accepted(tmp_path):
    cache = _entry(tmp_path, 60.5, time.time())
    assert cache.try_get('entry', ttl_seconds=TTL_FOREVER) == 'cached'
