"""Disposable compressed views cannot discard a successfully built index."""
import errno
import hashlib
import json
import zlib

import pytest

from core.audit.cross_entry import cache
from core.audit.cross_entry.model import AccessIndex, Limits
from core.json import dumps_canonical


@pytest.fixture
def builder(monkeypatch):
    calls = []

    def build(sources, **kwargs):
        calls.append(dict(sources))
        return AccessIndex(source_hashes={
            path: hashlib.sha256(text.encode()).hexdigest() for path, text in sources.items()
        }, fingerprint='ready')

    monkeypatch.setattr(cache, 'build_access_index', build)
    return calls


def load(tmp_path):
    return cache.load_or_build_index({'m.c': 'void f(void) {}'}, out_dir=tmp_path, limits=Limits())


def test_cache_directory_failure_preserves_fresh_index(tmp_path, builder):
    blocker = tmp_path / 'cross-entry-index-cache'
    blocker.write_bytes(b'caller-owned file')
    index, hit = load(tmp_path)
    assert index.fingerprint == 'ready'
    assert not hit
    assert len(builder) == 1
    assert blocker.read_bytes() == b'caller-owned file'


@pytest.mark.parametrize('code', [errno.ENOSPC, errno.EDQUOT, errno.EACCES])
def test_cache_publication_errors_preserve_fresh_index(tmp_path, monkeypatch, builder, code):
    attempts = []

    def refuse(path, payload):
        attempts.append(path)
        raise OSError(code, 'owned cache write refusal')

    monkeypatch.setattr(cache, 'write_bytes_atomically', refuse)
    index, hit = load(tmp_path)
    assert index.fingerprint == 'ready'
    assert not hit
    assert len(builder) == 1
    assert len(attempts) == 1


@pytest.mark.parametrize('kind', ['raw', 'compressed'])
@pytest.mark.parametrize('slack', [-1, 0, 1])
def test_write_limits_match_read_limits(tmp_path, monkeypatch, builder, kind, slack):
    first, hit = load(tmp_path)
    assert not hit
    path, = (tmp_path / 'cross-entry-index-cache').glob('*.json.z')
    compressed = path.read_bytes()
    raw = zlib.decompress(compressed)
    path.unlink()
    if kind == 'raw':
        monkeypatch.setattr(cache, '_MAX_SERIALIZED_BYTES', len(raw) + slack)
    else:
        monkeypatch.setattr(cache, '_MAX_COMPRESSED_BYTES', len(compressed) + slack)
    second, hit = load(tmp_path)
    assert second == first
    assert not hit
    assert len(builder) == 2
    assert path.exists() is (slack >= 0)
    if slack >= 0:
        third, hit = load(tmp_path)
        assert hit
        assert third == first
        assert len(builder) == 2


@pytest.mark.parametrize('kind', ['function-map', 'nested-document', 'trailing-bytes'])
def test_malformed_cache_rebuilds_without_losing_fresh_result(tmp_path, builder, kind):
    first, _ = load(tmp_path)
    path, = (tmp_path / 'cross-entry-index-cache').glob('*.json.z')
    if kind == 'nested-document':
        malformed = zlib.compress(b'[' * 2000 + b']' * 2000)
    elif kind == 'trailing-bytes':
        malformed = path.read_bytes() + b'unfinished replacement'
    else:
        data = json.loads(zlib.decompress(path.read_bytes()))
        data['index']['functions'] = []
        malformed = zlib.compress(dumps_canonical(data).encode())
    path.write_bytes(malformed)
    rebuilt, hit = load(tmp_path)
    assert not hit
    assert rebuilt == first
    assert len(builder) == 2
    restored, hit = load(tmp_path)
    assert hit
    assert restored == first


def test_build_errors_are_not_cache_misses(tmp_path, monkeypatch):
    error = RuntimeError('owned index build failure')

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(cache, 'build_access_index', fail)
    with pytest.raises(RuntimeError) as caught:
        load(tmp_path)
    assert caught.value is error
