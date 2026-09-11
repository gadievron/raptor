"""Tests for distro_cache.DistroFetcher.

Per-distro disk cache — Debian success + Ubuntu 404 must cache
independently so a retry only re-hits the failed distro.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.http import HttpError, Response
from cve_diff.discovery import distro_cache
from cve_diff.discovery.distro_cache import DistroFetcher


@pytest.fixture
def tmp_fetcher(tmp_path: Path) -> DistroFetcher:
    return DistroFetcher(cache_dir=tmp_path)


def _ok_response(body: str | bytes = b"", status: int = 200) -> Response:
    if isinstance(body, str):
        body = body.encode()
    return Response(status=status, headers={}, body=body, url="")


def _json_response(data: dict, status: int = 200) -> Response:
    import json
    return Response(status=status, headers={}, body=json.dumps(data).encode(), url="")


def test_invalid_cve_id(tmp_fetcher: DistroFetcher) -> None:
    out = tmp_fetcher.fetch_all("not-a-cve")
    assert all(d["error"] == "invalid cve_id" for d in out.values())


def test_cache_hit_skips_http(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    cve = "CVE-2016-5195"
    # Pre-populate the JsonCache for all 3 distros
    for distro, payload in [
        ("debian", {"status": "fixed", "fix_version": None, "references": ["x"]}),
        ("ubuntu", {"status": "released", "fix_version": None, "references": []}),
        ("redhat", {"status": "fixed", "fix_version": None, "references": []}),
    ]:
        tmp_fetcher._disk.put(f"{distro}/{cve}", payload, ttl_seconds=86400)

    with patch.object(distro_cache, "_client") as mock_client:
        out = tmp_fetcher.fetch_all(cve)
        mock_client.assert_not_called()
    assert out["debian"]["references"] == ["x"]
    assert out["ubuntu"]["status"] == "released"


def test_cache_miss_writes_disk(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    cve = "CVE-2016-5195"

    def fake_request(method, url, **kw):
        if "debian" in url:
            return _ok_response('<a href="https://github.com/o/r/commit/abc1234">x</a>')
        if "ubuntu" in url:
            return _json_response({"cves": [{"id": cve, "references": ["https://x.example/y"]}]})
        if "redhat" in url:
            return _json_response({"references": ["https://r.example/z"], "affected_release": []})
        raise AssertionError(url)

    class _FakeClient:
        def request(self, method, url, **kw):
            return fake_request(method, url, **kw)

    with patch.object(distro_cache, "_client", return_value=_FakeClient()):
        out = tmp_fetcher.fetch_all(cve)

    # Verify entries were written to JsonCache
    assert tmp_fetcher._disk.get(f"debian/{cve}", ttl_seconds=86400) is not None
    assert tmp_fetcher._disk.get(f"ubuntu/{cve}", ttl_seconds=86400) is not None
    assert tmp_fetcher._disk.get(f"redhat/{cve}", ttl_seconds=86400) is not None
    assert "https://github.com/o/r/commit/abc1234" in out["debian"]["references"]
    assert out["ubuntu"]["references"] == ["https://x.example/y"]
    assert out["redhat"]["references"] == ["https://r.example/z"]


def test_per_distro_independence(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    """Debian success + Ubuntu 404: both cached. Retry must not re-hit Debian."""
    cve = "CVE-2016-5195"
    call_log: list[str] = []

    def fake_request(method, url, **kw):
        call_log.append(url)
        if "debian" in url:
            return _ok_response("ok")
        if "ubuntu" in url:
            raise HttpError("http 404", status=404)
        if "redhat" in url:
            raise HttpError("http 404", status=404)
        raise AssertionError(url)

    class _FakeClient:
        def request(self, method, url, **kw):
            return fake_request(method, url, **kw)

    with patch.object(distro_cache, "_client", return_value=_FakeClient()):
        tmp_fetcher.fetch_all(cve)
    first_call_count = len(call_log)
    assert first_call_count == 3

    # All results should be cached (404s too)
    assert tmp_fetcher._disk.get(f"debian/{cve}", ttl_seconds=86400) is not None
    assert tmp_fetcher._disk.get(f"ubuntu/{cve}", ttl_seconds=86400) is not None

    fresh = DistroFetcher(cache_dir=tmp_path)
    with patch.object(distro_cache, "_client", return_value=_FakeClient()):
        out = fresh.fetch_all(cve)
    assert len(call_log) == first_call_count, "second fetch should be all cache hits"
    assert out["ubuntu"]["error"] == "http 404"


def test_network_error_not_cached(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    cve = "CVE-2016-5195"
    call_log: list[str] = []

    def fake_request(method, url, **kw):
        call_log.append(url)
        raise HttpError("boom")

    class _FakeClient:
        def request(self, method, url, **kw):
            return fake_request(method, url, **kw)

    with patch.object(distro_cache, "_client", return_value=_FakeClient()):
        out = tmp_fetcher.fetch_all(cve)
    for d in out.values():
        assert d["error"].startswith("network: ")
    # Network errors should NOT be cached
    assert tmp_fetcher._disk.get(f"debian/{cve}", ttl_seconds=86400) is None
    assert tmp_fetcher._disk.get(f"ubuntu/{cve}", ttl_seconds=86400) is None


def test_rate_limit_errors_not_disk_cached(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    """429/403 are transient (rate limit / load shed): disk-caching one
    run's 429 storm would make every later run — long after the limit
    refilled — read the cached error for the full 7-day TTL. A fresh
    fetcher must go back to the network and succeed."""
    cve = "CVE-2016-5195"

    class _LimitedClient:
        def request(self, method, url, **kw):
            if "debian" in url:
                raise HttpError("http 429", status=429)
            if "ubuntu" in url:
                raise HttpError("http 403", status=403)
            raise HttpError("http 429", status=429)

    with patch.object(distro_cache, "_client", return_value=_LimitedClient()):
        out = tmp_fetcher.fetch_all(cve)
    assert out["debian"]["error"] == "http 429"
    assert out["ubuntu"]["error"] == "http 403"
    # Nothing hit the 7-day disk cache.
    assert tmp_fetcher._disk.get(f"debian/{cve}", ttl_seconds=86400 * 7) is None
    assert tmp_fetcher._disk.get(f"ubuntu/{cve}", ttl_seconds=86400 * 7) is None

    # After the limit refills, a fresh instance fetches successfully.
    class _OkClient:
        def request(self, method, url, **kw):
            if "debian" in url:
                return _ok_response("ok")
            if "ubuntu" in url:
                return _json_response({"cves": [{"id": cve, "references": []}]})
            return _json_response({"references": [], "affected_release": []})

    fresh = DistroFetcher(cache_dir=tmp_path)
    with patch.object(distro_cache, "_client", return_value=_OkClient()):
        out2 = fresh.fetch_all(cve)
    assert "error" not in out2["debian"]


def test_definitive_404_still_disk_cached(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    """The other direction: 404 = "distro has no record" is a definitive
    answer and stays cacheable (a retry must not re-hit the tracker)."""
    cve = "CVE-2016-5195"

    class _NotFoundClient:
        def request(self, method, url, **kw):
            raise HttpError("http 404", status=404)

    with patch.object(distro_cache, "_client", return_value=_NotFoundClient()):
        tmp_fetcher.fetch_all(cve)
    assert tmp_fetcher._disk.get(f"debian/{cve}", ttl_seconds=86400 * 7) is not None
