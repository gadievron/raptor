"""Reachability cache IO admits regular files within the remaining budget."""
import os
import stat
from types import SimpleNamespace

import pytest

from core.analysis import _reach_cache as cache
from core.analysis.reachability import _AdjacencyIndex
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def entry(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, '_CACHE_DIR', tmp_path)
    fingerprint = 'a' * 64
    index = _AdjacencyIndex()
    cache.save_index(fingerprint, index)
    return fingerprint, tmp_path / (fingerprint + '.json'), index


def test_reads_respect_remaining_allowance(entry, monkeypatch):
    fingerprint, path, index = entry
    cap = path.stat().st_size
    monkeypatch.setattr(cache, '_MAX_INDEX_BYTES', cap)
    original = os.read
    consumed = []

    def read(fd, size):
        assert size <= cap - sum(consumed) + 1
        result = original(fd, size)
        consumed.append(len(result))
        return result

    patch_module_attribute(monkeypatch, cache, 'os', 'read', read)
    assert cache.load_index(fingerprint) == index
    assert sum(consumed) == cap


@pytest.mark.parametrize('kind', [stat.S_IFDIR, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK])
def test_opened_nonregular_metadata_is_refused_before_reading(entry, monkeypatch, kind):
    fingerprint, path, _ = entry
    original = os.fstat
    handles = []

    def info(fd):
        observed = original(fd)
        handles.append(fd)
        return SimpleNamespace(st_mode=kind | 0o600, st_uid=observed.st_uid, st_size=observed.st_size)

    def read(fd, size):
        pytest.fail('non-regular cache entry reached the decoder read')

    patch_module_attribute(monkeypatch, cache, 'os', 'fstat', info)
    patch_module_attribute(monkeypatch, cache, 'os', 'read', read)
    assert cache.load_index(fingerprint) is None
    assert len(handles) == 1
    with pytest.raises(OSError):
        original(handles[0])


def test_load_uses_the_opened_file_when_path_preflight_is_unavailable(entry, monkeypatch):
    fingerprint, path, index = entry

    class NoPreflight(type(path)):
        def exists(self):
            raise PermissionError('path preflight unavailable')

    monkeypatch.setattr(cache, '_cache_path_for', lambda key: NoPreflight(path))
    assert cache.load_index(fingerprint) == index


@pytest.mark.parametrize('failure', ['metadata', 'read'])
def test_io_failures_release_the_opened_cache_handle(entry, monkeypatch, failure):
    fingerprint, _, _ = entry
    original = os.fstat
    handles = []

    def info(fd):
        handles.append(fd)
        if failure == 'metadata':
            raise OSError('owned metadata failure')
        return original(fd)

    def read(fd, size):
        raise OSError('owned read failure')

    patch_module_attribute(monkeypatch, cache, 'os', 'fstat', info)
    patch_module_attribute(monkeypatch, cache, 'os', 'read', read)
    assert cache.load_index(fingerprint) is None
    assert len(handles) == 1
    with pytest.raises(OSError):
        original(handles[0])


def test_growth_refusal_does_not_request_more_than_one_byte_over_cap(entry, monkeypatch):
    fingerprint, path, _ = entry
    cap = 32
    monkeypatch.setattr(cache, '_MAX_INDEX_BYTES', cap)
    original_info, original_read = os.fstat, os.read
    requests = []

    def info(fd):
        observed = original_info(fd)
        return SimpleNamespace(st_mode=observed.st_mode, st_uid=observed.st_uid, st_size=1)

    def read(fd, size):
        requests.append(size)
        return original_read(fd, size)

    patch_module_attribute(monkeypatch, cache, 'os', 'fstat', info)
    patch_module_attribute(monkeypatch, cache, 'os', 'read', read)
    assert path.stat().st_size > cap
    assert cache.load_index(fingerprint) is None
    assert sum(requests) <= cap + 1
