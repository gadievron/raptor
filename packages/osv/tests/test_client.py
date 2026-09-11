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


def test_query_batch_returns_none_slots_on_http_error() -> None:
    """Soft-fail: every slot returns the ``None`` error sentinel rather
    than raising — and rather than an empty list, which would be
    indistinguishable from OSV's authoritative "no advisories"."""
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = HttpError(
        "boom", status=500,
    )
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [{"package": {"name": "foo", "ecosystem": "npm"}, "version": "1.0"}] * 3
    assert client.query_batch(queries) == [None, None, None]


def test_query_batch_returns_none_slots_on_malformed_shape() -> None:
    """Slot count mismatch → all error sentinels (rather than
    misalignment errors or fake authoritative empties)."""
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = {
        "results": [{"vulns": [{"id": "X"}]}],   # 1 slot but caller sent 2 queries
    }
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [
        {"package": {"name": "a", "ecosystem": "npm"}, "version": "1"},
        {"package": {"name": "b", "ecosystem": "npm"}, "version": "1"},
    ]
    assert client.query_batch(queries) == [None, None]


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


class _QueueHttp(_FakeHttp):
    """Stub whose querybatch answers come from a FIFO queue, so a
    paginated conversation (same URL, different bodies) can be
    scripted response-by-response."""

    def __init__(self, post_queue: list[Any]) -> None:
        super().__init__()
        self._post_queue = list(post_queue)

    def post_json(self, url: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.post_calls.append((url, body))
        resp = self._post_queue.pop(0)
        if isinstance(resp, BaseException):
            raise resp
        return resp


def test_query_batch_null_slot_is_error_sentinel_not_empty() -> None:
    """A non-dict result slot (proxy mangling, partial upstream failure)
    means "the lookup did not happen" — returning [] would be cached
    downstream as an authoritative "no advisories"."""
    http = _FakeHttp()
    http.post_responses[f"{OSV_BASE_URL}/querybatch"] = {
        "results": [None, {"vulns": [{"id": "GHSA-x"}]}],
    }
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [
        {"package": {"name": "a", "ecosystem": "npm"}, "version": "1"},
        {"package": {"name": "b", "ecosystem": "npm"}, "version": "1"},
    ]
    assert client.query_batch(queries) == [None, ["GHSA-x"]]


def test_query_batch_follows_per_slot_pagination() -> None:
    """Slots carrying next_page_token are re-queried until exhausted;
    the returned ID list spans every page, not just page 1."""
    http = _QueueHttp([
        {"results": [
            {"vulns": [{"id": "OSV-1"}], "next_page_token": "T1"},
            {"vulns": [{"id": "OSV-A"}]},
        ]},
        {"results": [
            {"vulns": [{"id": "OSV-2"}], "next_page_token": "T2"},
        ]},
        {"results": [
            {"vulns": [{"id": "OSV-3"}]},
        ]},
    ])
    client = OsvClient(http=http)  # type: ignore[arg-type]
    q1 = {"package": {"name": "big", "ecosystem": "npm"}}
    q2 = {"package": {"name": "small", "ecosystem": "npm"}}
    assert client.query_batch([q1, q2]) == [["OSV-1", "OSV-2", "OSV-3"], ["OSV-A"]]
    # Continuations carry the page token for ONLY the unfinished slot,
    # without mutating the caller's query dicts.
    assert http.post_calls[1][1] == {"queries": [{**q1, "page_token": "T1"}]}
    assert http.post_calls[2][1] == {"queries": [{**q1, "page_token": "T2"}]}
    assert "page_token" not in q1


def test_query_batch_pagination_failure_demotes_slot_to_none() -> None:
    """A failed continuation must not surface page 1 as the complete
    answer — the slot flips to the None error sentinel; slots that
    finished on page 1 keep their authoritative lists."""
    http = _QueueHttp([
        {"results": [
            {"vulns": [{"id": "OSV-1"}], "next_page_token": "T1"},
            {"vulns": [{"id": "OSV-A"}]},
        ]},
        HttpError("boom", status=500),
    ])
    client = OsvClient(http=http)  # type: ignore[arg-type]
    queries = [
        {"package": {"name": "big", "ecosystem": "npm"}},
        {"package": {"name": "small", "ecosystem": "npm"}},
    ]
    assert client.query_batch(queries) == [None, ["OSV-A"]]


def test_query_batch_pagination_page_cap_demotes_slot_to_none() -> None:
    """A server that never stops handing out tokens cannot loop the
    client forever; past the cap the slot is refused (None), never
    silently truncated."""
    from packages.osv import client as client_mod
    first = {"results": [{"vulns": [{"id": "OSV-1"}], "next_page_token": "T"}]}
    more = {"results": [{"vulns": [{"id": "OSV-n"}], "next_page_token": "T"}]}
    http = _QueueHttp([first] + [more] * client_mod._MAX_QUERY_PAGES)
    client = OsvClient(http=http)  # type: ignore[arg-type]
    result = client.query_batch([{"package": {"name": "x", "ecosystem": "npm"}}])
    assert result == [None]
    # 1 initial + exactly _MAX_QUERY_PAGES continuations.
    assert len(http.post_calls) == 1 + client_mod._MAX_QUERY_PAGES


def test_query_batch_offline_returns_none_per_slot() -> None:
    """Offline mode skips the network entirely; every slot carries the
    "lookup did not happen" sentinel, not an authoritative empty."""
    http = _FakeHttp()
    client = OsvClient(http=http, offline=True)  # type: ignore[arg-type]
    queries = [{"package": {"name": "x", "ecosystem": "npm"}, "version": "1"}] * 2
    assert client.query_batch(queries) == [None, None]
    assert http.post_calls == []
