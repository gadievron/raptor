"""Cache decoder refusal is a miss; process cancellation still propagates."""

import json
import time

import pytest

from core.json import cache as cache_module
from core.json.cache import JsonCache, MISSING


def test_decoder_recursion_refusal_is_retryable_miss(tmp_path, monkeypatch):
    cache = JsonCache(root=tmp_path)
    path = tmp_path / 'entry.json'
    raw = json.dumps({'written_at': time.time(), 'ttl_seconds': 60, 'value': 'cached'})
    path.write_text(raw)
    attempted = []

    def refuse(text, **kwargs):
        attempted.append(text)
        raise RecursionError('decoder recursion limit')

    with monkeypatch.context() as patch:
        patch.setattr(cache_module, '_loads', refuse)
        assert cache.try_get('entry', ttl_seconds=60) is MISSING
    assert attempted == [raw]
    assert cache.misses == 1 and cache.hits == 0
    assert path.read_text() == raw
    assert cache.try_get('entry', ttl_seconds=60) == 'cached'
    assert cache.misses == 1 and cache.hits == 1


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_decoder_cancellation_is_not_a_cache_miss(tmp_path, monkeypatch, failure):
    cache = JsonCache(root=tmp_path)
    (tmp_path / 'entry.json').write_text('{}')

    def refuse(*args, **kwargs):
        raise failure('cancelled')

    monkeypatch.setattr(cache_module, '_loads', refuse)
    with pytest.raises(failure, match='cancelled'):
        cache.try_get('entry', ttl_seconds=60)
    assert cache.misses == 0 and cache.hits == 0
