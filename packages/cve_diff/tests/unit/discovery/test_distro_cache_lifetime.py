"""Advisory cache reuse follows the shared cache's expiry and retry policy."""
import gc
import json
import time
import weakref

import pytest

from cve_diff.discovery import distro_cache


@pytest.mark.parametrize('error', ['http 403', 'http 429', 'http 500', 'network: offline'])
def test_same_fetcher_can_recover_after_transient_error(tmp_path, error):
    fetcher = distro_cache.DistroFetcher(cache_dir=tmp_path)
    responses = iter([{'error': error}, {'status': 'fixed', 'references': []}])
    calls = []

    def fetch(cve):
        calls.append(cve)
        return next(responses)

    assert fetcher._cached('debian', 'CVE-2024-1234', fetch) == {'error': error}
    assert fetcher._cached('debian', 'CVE-2024-1234', fetch) == {'status': 'fixed', 'references': []}
    assert len(calls) == 2


def test_cache_disabled_fetches_every_time_without_creating_cache(tmp_path):
    root = tmp_path / 'disabled'
    fetcher = distro_cache.DistroFetcher(cache_enabled=False, cache_dir=root)
    calls = []

    def fetch(cve):
        calls.append(cve)
        return {'generation': len(calls)}

    assert fetcher._cached('debian', 'CVE-2024-1234', fetch) == {'generation': 1}
    assert fetcher._cached('debian', 'CVE-2024-1234', fetch) == {'generation': 2}
    assert not root.exists()


@pytest.mark.parametrize('payload', [{'status': 'fixed'}, {'error': 'http 404'}, {'error': 'http 410'}])
def test_reused_fetcher_observes_expired_disk_generation(tmp_path, payload):
    fetcher = distro_cache.DistroFetcher(cache_dir=tmp_path)
    calls = []

    def fetch(cve):
        calls.append(cve)
        return {'status': 'new'}

    key = 'debian/CVE-2024-1234'
    fetcher._disk.put(key, payload, ttl_seconds=distro_cache._CACHE_TTL)
    assert fetcher._cached('debian', 'CVE-2024-1234', fetch) == payload
    path = tmp_path / (key + '.json')
    stored = json.loads(path.read_text())
    stored['written_at'] = time.time() - distro_cache._CACHE_TTL - 3600
    path.write_text(json.dumps(stored))
    assert fetcher._cached('debian', 'CVE-2024-1234', fetch) == {'status': 'new'}
    assert len(calls) == 1


@pytest.mark.parametrize('payload', [{'status': 'fixed'}, {'error': 'http 404'}, {'error': 'http 410'}])
def test_success_and_definitive_absence_remain_reusable(tmp_path, payload):
    fetcher = distro_cache.DistroFetcher(cache_dir=tmp_path)
    calls = []

    def fetch(cve):
        calls.append(cve)
        return payload

    for owner in [fetcher, fetcher, distro_cache.DistroFetcher(cache_dir=tmp_path)]:
        assert owner._cached('debian', 'CVE-2024-1234', fetch) == payload
    assert len(calls) == 1


def test_parallel_distros_retry_only_the_transient_result(tmp_path, monkeypatch):
    fetcher = distro_cache.DistroFetcher(cache_dir=tmp_path)
    calls = {'debian': 0, 'ubuntu': 0, 'redhat': 0}

    def fetch(distro):
        def request(cve):
            calls[distro] += 1
            if distro == 'ubuntu' and calls[distro] == 1:
                return {'error': 'http 429'}
            return {'status': 'fixed'}
        return request

    for distro in calls:
        monkeypatch.setattr(distro_cache, '_fetch_' + distro, fetch(distro))
    first = fetcher.fetch_all('CVE-2024-1234')
    assert first['ubuntu'] == {'error': 'http 429'}
    assert first['debian'] == first['redhat'] == {'status': 'fixed'}
    assert fetcher.fetch_all('CVE-2024-1234') == {
        name: {'status': 'fixed'} for name in calls
    }
    assert calls == {'debian': 1, 'ubuntu': 2, 'redhat': 1}


def test_fetched_payload_is_not_retained_in_a_second_response_cache(tmp_path):
    class Payload(dict):
        pass

    fetcher = distro_cache.DistroFetcher(cache_dir=tmp_path)
    result = fetcher._cached('debian', 'CVE-2024-1234', lambda cve: Payload(status='fixed'))
    reference = weakref.ref(result)
    del result
    gc.collect()
    assert reference() is None
    assert fetcher._disk.get('debian/CVE-2024-1234', ttl_seconds=distro_cache._CACHE_TTL) == {
        'status': 'fixed'
    }
