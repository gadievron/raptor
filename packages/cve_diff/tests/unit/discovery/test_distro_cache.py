"""Tests for distro_cache.DistroFetcher.

Per-distro disk cache — Debian success + Ubuntu 404 must cache
independently so a retry only re-hits the failed distro.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_diff.discovery.distro_cache import DistroFetcher


@pytest.fixture
def tmp_fetcher(tmp_path: Path) -> DistroFetcher:
    return DistroFetcher(cache_dir=tmp_path)


def _fake_response(status: int, text: str = "", json_data=None):
    class R:
        status_code = status
        @staticmethod
        def json():
            if json_data is None:
                raise ValueError
            return json_data
    R.text = text
    return R()


def test_invalid_cve_id(tmp_fetcher: DistroFetcher) -> None:
    out = tmp_fetcher.fetch_all("not-a-cve")
    assert all(d["error"] == "invalid cve_id" for d in out.values())


def test_cache_hit_skips_http(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    cve = "CVE-2016-5195"
    (tmp_path / "debian_CVE-2016-5195.json").write_text(
        json.dumps({"status": "fixed", "fix_version": None, "references": ["x"]})
    )
    (tmp_path / "ubuntu_CVE-2016-5195.json").write_text(
        json.dumps({"status": "released", "fix_version": None, "references": []})
    )
    (tmp_path / "redhat_CVE-2016-5195.json").write_text(
        json.dumps({"status": "fixed", "fix_version": None, "references": []})
    )
    with patch("cve_diff.discovery.distro_cache.requests.get") as mock_get:
        out = tmp_fetcher.fetch_all(cve)
        assert mock_get.call_count == 0
    assert out["debian"]["references"] == ["x"]
    assert out["ubuntu"]["status"] == "released"


def test_cache_miss_writes_disk(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    cve = "CVE-2016-5195"

    def side(url, **kw):
        if "debian" in url:
            return _fake_response(200, text='<a href="https://github.com/o/r/commit/abc1234">x</a>')
        if "ubuntu" in url:
            return _fake_response(200, json_data={"cves": [{"id": cve, "references": ["https://x.example/y"]}]})
        if "redhat" in url:
            return _fake_response(200, json_data={"references": ["https://r.example/z"], "affected_release": []})
        raise AssertionError(url)

    with patch("cve_diff.discovery.distro_cache.requests.get", side_effect=side):
        out = tmp_fetcher.fetch_all(cve)

    assert (tmp_path / "debian_CVE-2016-5195.json").exists()
    assert (tmp_path / "ubuntu_CVE-2016-5195.json").exists()
    assert (tmp_path / "redhat_CVE-2016-5195.json").exists()
    assert any("github.com" in r for r in out["debian"]["references"])
    assert out["ubuntu"]["references"] == ["https://x.example/y"]
    assert out["redhat"]["references"] == ["https://r.example/z"]


def test_per_distro_independence(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    """Debian success + Ubuntu 404: both cached. Retry must not re-hit Debian."""
    cve = "CVE-2016-5195"
    call_log: list[str] = []

    def side(url, **kw):
        call_log.append(url)
        if "debian" in url:
            return _fake_response(200, text="ok")
        if "ubuntu" in url:
            return _fake_response(404)
        if "redhat" in url:
            return _fake_response(404)
        raise AssertionError(url)

    with patch("cve_diff.discovery.distro_cache.requests.get", side_effect=side):
        tmp_fetcher.fetch_all(cve)
    first_call_count = len(call_log)
    assert first_call_count == 3
    assert (tmp_path / "debian_CVE-2016-5195.json").exists()
    assert (tmp_path / "ubuntu_CVE-2016-5195.json").exists()  # 404 cached too

    fresh = DistroFetcher(cache_dir=tmp_path)
    with patch("cve_diff.discovery.distro_cache.requests.get", side_effect=side):
        out = fresh.fetch_all(cve)
    assert len(call_log) == first_call_count, "second fetch should be all cache hits"
    assert out["ubuntu"]["error"] == "http 404"


def test_network_error_not_cached(tmp_fetcher: DistroFetcher, tmp_path: Path) -> None:
    cve = "CVE-2016-5195"
    import requests
    call_log: list[str] = []

    def side(url, **kw):
        call_log.append(url)
        raise requests.RequestException("boom")

    with patch("cve_diff.discovery.distro_cache.requests.get", side_effect=side):
        out = tmp_fetcher.fetch_all(cve)
    for d in out.values():
        assert d["error"].startswith("network: ")
    assert not (tmp_path / "debian_CVE-2016-5195.json").exists()
    assert not (tmp_path / "ubuntu_CVE-2016-5195.json").exists()
