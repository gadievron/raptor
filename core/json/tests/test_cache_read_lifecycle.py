"""Cache misses must not open special nodes or retain future-dated finite entries."""
import os
import subprocess
import sys
import time

import pytest
from core.json.cache import CacheEnvelope, JsonCache, TTL_FOREVER
from core.sentinels import MISSING


@pytest.mark.parametrize('kind', ['fifo', 'directory', 'symlink', 'dangling-link', 'symlink-fifo'])
def test_special_cache_nodes_are_nonblocking_misses(tmp_path, kind):
    root = tmp_path / 'cache'
    root.mkdir()
    path = root / 'key.json'
    outside = tmp_path / 'outside'
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'directory':
        path.mkdir()
    elif kind == 'symlink-fifo':
        os.mkfifo(outside)
        path.symlink_to(outside)
    else:
        if kind == 'symlink':
            outside.write_text('{"written_at":0,"ttl_seconds":-1,"value":"borrowed"}')
        path.symlink_to(outside)
    before = path.lstat()
    script = '''
import sys
from pathlib import Path
from core.json.cache import JsonCache, TTL_FOREVER
from core.sentinels import MISSING
cache = JsonCache(Path(sys.argv[1]))
assert cache.try_get('key', ttl_seconds=TTL_FOREVER) is MISSING
assert cache.misses == 1
'''
    result = subprocess.run([sys.executable, '-c', script, str(root)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert path.lstat().st_ino == before.st_ino
    if kind == 'symlink':
        assert 'borrowed' in outside.read_text()


@pytest.mark.parametrize('kind', ['fifo', 'symlink', 'directory'])
def test_swap_after_stat_is_checked_on_opened_file(tmp_path, kind):
    script = r"""
import os, sys
from pathlib import Path
from core.json.cache import JsonCache, TTL_FOREVER
from core.sentinels import MISSING
root, kind = Path(sys.argv[1]), sys.argv[2]
cache = JsonCache(root)
cache.put('key', 'cached', ttl_seconds=3600)
path = root / 'key.json'
original = cache._read_envelope
def swap(candidate):
    path.unlink()
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'directory':
        path.mkdir()
    else:
        target = root / 'borrowed'
        target.write_text('{"written_at":0,"ttl_seconds":-1,"value":"borrowed"}')
        path.symlink_to(target)
    return original(candidate)
cache._read_envelope = swap
assert cache.try_get('key', ttl_seconds=TTL_FOREVER) is MISSING
"""
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path), kind],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('ttl', [0, 60, 3600])
@pytest.mark.parametrize('offset', [0.001, 1, 86400, 365 * 86400])
def test_future_finite_envelopes_are_misses(ttl, offset):
    assert not CacheEnvelope(1000 + offset, ttl, 'future').is_fresh(1000)


@pytest.mark.parametrize('age', [0, 1, 60])
def test_finite_ttl_boundary_is_inclusive(age):
    assert CacheEnvelope(1000 - age, 60, 'cached').is_fresh(1000)


def test_forever_ttl_retains_content_addressed_semantics():
    assert CacheEnvelope(time.time() + 86400, TTL_FOREVER, 'immutable').is_fresh(time.time())


def test_regular_cached_null_and_unicode_keep_roundtrip_semantics(tmp_path):
    cache = JsonCache(tmp_path)
    for name, value in [('null', None), ('unicode', '東京'), ('plain', {'v': 1})]:
        cache.put(name, value, ttl_seconds=60)
        assert cache.try_get(name, ttl_seconds=60) == value


@pytest.mark.parametrize('ttl', [0, 60, 3600])
@pytest.mark.parametrize('warm', [False, True], ids=['cold', 'memoized'])
def test_future_entry_is_a_miss_after_disk_or_memo_lookup(tmp_path, ttl, warm):
    import json
    cache = JsonCache(tmp_path)
    cache.put('key', 'cached', ttl_seconds=ttl)
    if warm:
        cache.try_get('key', ttl_seconds=ttl)
    (tmp_path / 'key.json').write_text(json.dumps({
        'written_at': time.time() + 86400, 'ttl_seconds': ttl, 'value': 'future',
    }))
    assert cache.try_get('key', ttl_seconds=ttl) is MISSING
