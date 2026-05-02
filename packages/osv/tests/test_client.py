"""Tests for ``packages.osv.client.OsvClient``.

The client is exercised against an in-memory ``HttpClient`` stub so the
test suite never hits the real OSV API. Cache integration uses a real
:class:`core.json.JsonCache` over ``tmp_path``.
"""
from __future__ import annotations

from typing import Any

from core.http import HttpError
from core.json import JsonCache
from packages.osv import OsvClient
from packages.osv.client import OSV_BASE_URL


# --- helpers ------------------------------------------------------------

class _FakeHttp:
    """Minimal HttpClient stub. Records calls; returns canned responses."""
    def __init__(self) -> None:
        self.get_responses: dict[str, Any] = {}
        self.post_responses: dict[str, Any] = {}
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, url: str, **_kw: Any) -> dict[str, Any]:
        self.get_calls.append(url)
        resp = self.get_responses.get(url)
        if isinstance(resp, BaseException):
            raise resp
        if resp is None:
            raise HttpError("not found", status=404)
        return resp

    def post_json(self, url: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.post_calls.append((url, body))
        resp = self.post_responses.get(url)
        if isinstance(resp, BaseException):
            raise resp
        if resp is None:
            raise HttpError("error", status=500)
        return resp


# --- get_vuln -----------------------------------------------------------

def test_get_vuln_returns_parsed_record() -> None:
    http = _FakeHttp()
    http.get_responses[f"{OSV_BASE_URL}/vulns/CVE-2024-1234"] = {
        "id": "CVE-2024-1234",
        "summary": "test",
    }
    client = OsvClient(http=http)  # type: ignore[arg-type]
    rec = client.get_vuln("CVE-2024-1234")
    assert rec is not None
    assert rec.id == "CVE-2024-1234"
    assert http.get_calls == [f"{OSV_BASE_URL}/vulns/CVE-2024-1234"]


def test_get_vuln_returns_none_on_404() -> None:
    http = _FakeHttp()
    # No entry → _FakeHttp raises HttpError(status=404)
    client = OsvClient(http=http)  # type: ignore[arg-type]
    assert client.get_vuln("CVE-9999-0000") is None


def test_get_vuln_returns_none_on_500() -> None:
    http = _FakeHttp()
    http.get_responses[f"{OSV_BASE_URL}/vulns/CVE-X"] = HttpError(
        "server error", status=500,
    )
    client = OsvClient(http=http)  # type: ignore[arg-type]
    assert client.get_vuln("CVE-X") is None


def test_get_vuln_returns_none_on_malformed_record() -> None:
    """Record missing ``id`` is skipped, not raised."""
    http = _FakeHttp()
    http.get_responses[f"{OSV_BASE_URL}/vulns/CVE-Y"] = {"summary": "no id"}
    client = OsvClient(http=http)  # type: ignore[arg-type]
    assert client.get_vuln("CVE-Y") is None


def test_get_vuln_uses_cache_when_provided(tmp_path) -> None:
    http = _FakeHttp()
    http.get_responses[f"{OSV_BASE_URL}/vulns/CVE-Z"] = {
        "id": "CVE-Z", "summary": "first",
    }
    cache = JsonCache(tmp_path / "cache")
    client = OsvClient(http=http, cache=cache)  # type: ignore[arg-type]

    # First call hits HTTP and populates cache.
    rec1 = client.get_vuln("CVE-Z")
    assert rec1 is not None and rec1.id == "CVE-Z"
    assert len(http.get_calls) == 1

    # Second call serves from cache — no second HTTP call.
    rec2 = client.get_vuln("CVE-Z")
    assert rec2 is not None and rec2.id == "CVE-Z"
    assert len(http.get_calls) == 1


def test_offline_mode_skips_network(tmp_path) -> None:
    http = _FakeHttp()
    http.get_responses[f"{OSV_BASE_URL}/vulns/CVE-X"] = {"id": "CVE-X"}
    client = OsvClient(
        http=http, cache=JsonCache(tmp_path / "cache"),  # type: ignore[arg-type]
        offline=True,
    )
    # Cache is empty + offline → returns None without hitting HTTP.
    assert client.get_vuln("CVE-X") is None
    assert http.get_calls == []


def test_offline_mode_serves_cached_hits(tmp_path) -> None:
    cache = JsonCache(tmp_path / "cache")
    cache.put("osv/vulns/CVE-X", {"id": "CVE-X", "summary": "cached"},
              ttl_seconds=3600)
    http = _FakeHttp()
    client = OsvClient(http=http, cache=cache, offline=True)  # type: ignore[arg-type]

    rec = client.get_vuln("CVE-X")
    assert rec is not None and rec.id == "CVE-X"
    assert http.get_calls == []


def test_get_vuln_path_safe_encoding(tmp_path) -> None:
    """Vuln IDs containing ``/`` would corrupt the cache path; safe-id
    transforms them so the cache file lands in a single segment."""
    cache = JsonCache(tmp_path / "cache")
    cache.put("osv/vulns/with_slashes",
              {"id": "with/slashes", "summary": "edge case"},
              ttl_seconds=3600)
    http = _FakeHttp()
    client = OsvClient(http=http, cache=cache, offline=True)  # type: ignore[arg-type]
    rec = client.get_vuln("with/slashes")
    assert rec is not None
    assert rec.id == "with/slashes"


# --- query_batch --------------------------------------------------------

def test_query_batch_returns_id_lists_per_slot() -> None:
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = {
        "results": [
            {"vulns": [{"id": "GHSA-aaa"}, {"id": "GHSA-bbb"}]},
            {"vulns": []},
            {"vulns": [{"id": "GHSA-ccc"}]},
        ]
    }
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.0.0"},
        {"package": {"name": "safe-pkg", "ecosystem": "npm"}, "version": "1.0.0"},
        {"package": {"name": "log4j", "ecosystem": "Maven"}, "version": "2.14.1"},
    ]
    result = client.query_batch(queries)
    assert result == [["GHSA-aaa", "GHSA-bbb"], [], ["GHSA-ccc"]]


def test_query_batch_empty_input_returns_empty() -> None:
    http = _FakeHttp()
    client = OsvClient(http=http)  # type: ignore[arg-type]
    assert client.query_batch([]) == []
    assert http.post_calls == []


def test_query_batch_returns_empty_on_http_error() -> None:
    """Soft-fail: every slot returns empty rather than raising."""
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = HttpError(
        "boom", status=500,
    )
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [{"package": {"name": "foo", "ecosystem": "npm"}, "version": "1.0"}] * 3
    assert client.query_batch(queries) == [[], [], []]


def test_query_batch_returns_empty_on_malformed_shape() -> None:
    """Slot count mismatch → all-empty (rather than misalignment errors)."""
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = {
        "results": [{"vulns": [{"id": "X"}]}],   # 1 slot but caller sent 2 queries
    }
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [
        {"package": {"name": "a", "ecosystem": "npm"}, "version": "1"},
        {"package": {"name": "b", "ecosystem": "npm"}, "version": "1"},
    ]
    assert client.query_batch(queries) == [[], []]


def test_query_batch_skips_non_string_ids() -> None:
    """Defensive against malformed responses where vuln id isn't a string."""
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = {
        "results": [{"vulns": [
            {"id": "GHSA-aaa"},
            {"id": 42},                # non-string → skipped
            "not-a-dict",              # non-dict → skipped
            {"id": "GHSA-bbb"},
        ]}],
    }
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [{"package": {"name": "x", "ecosystem": "npm"}, "version": "1"}]
    assert client.query_batch(queries) == [["GHSA-aaa", "GHSA-bbb"]]


def test_query_batch_offline_returns_empty_per_slot() -> None:
    """Offline mode skips the network entirely; every slot returns empty."""
    http = _FakeHttp()
    client = OsvClient(http=http, offline=True)  # type: ignore[arg-type]
    queries = [{"package": {"name": "x", "ecosystem": "npm"}, "version": "1"}] * 2
    assert client.query_batch(queries) == [[], []]
    assert http.post_calls == []
