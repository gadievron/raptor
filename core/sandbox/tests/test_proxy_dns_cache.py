"""DNS cache hygiene in `_cached_getaddrinfo`.

Pre-fix the cache inserted raw case-sensitive (host, port) keys, only
consulted the TTL on a re-lookup of the SAME key, and never evicted —
so audit-mode lanes (where arbitrary hostnames resolve) and
case/port variants of allowlisted hosts grew the proxy singleton's
memory for the life of the process. Under test:

- the key is case-insensitive (one entry, one resolver call for
  spelling variants of a host);
- expired entries are swept on insert (a dead entry does not need its
  own key re-looked-up to disappear);
- the cache is capped, evicting the oldest entries when full.

The resolver is stubbed by monkeypatching getaddrinfo on the proxy's
own event loop — no network needed; coroutines are driven on the
proxy loop via run_coroutine_threadsafe, matching the perf-test
harness conventions.
"""

from __future__ import annotations

import asyncio
import socket
import time

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


@pytest.fixture
def proxy_with_stub_resolver(reset_proxy, monkeypatch):
    proxy = proxy_mod.EgressProxy(allowed_hosts={"x"})
    calls: list[tuple] = []

    async def fake_getaddrinfo(host, port, **kwargs):
        calls.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("192.0.2.10", port))]

    monkeypatch.setattr(proxy._loop, "getaddrinfo", fake_getaddrinfo)
    yield proxy, calls
    proxy.stop()


def _resolve(proxy, host, port):
    return asyncio.run_coroutine_threadsafe(
        proxy._cached_getaddrinfo(host, port), proxy._loop,
    ).result(timeout=5)


class TestDnsCacheKeying:

    def test_host_key_is_case_insensitive(self, proxy_with_stub_resolver):
        proxy, calls = proxy_with_stub_resolver
        _resolve(proxy, "Registry.Example.COM", 443)
        _resolve(proxy, "registry.example.com", 443)
        _resolve(proxy, "REGISTRY.EXAMPLE.COM", 443)
        assert len(calls) == 1, (
            f"case variants must share one cache entry; resolver was "
            f"called for: {calls}"
        )
        assert len(proxy._dns_cache) == 1
        (key,) = proxy._dns_cache.keys()
        assert key == ("registry.example.com", 443)

    def test_distinct_ports_are_distinct_entries(
        self, proxy_with_stub_resolver,
    ):
        proxy, calls = proxy_with_stub_resolver
        _resolve(proxy, "h.example", 443)
        _resolve(proxy, "h.example", 8443)
        assert len(calls) == 2
        assert len(proxy._dns_cache) == 2


class TestDnsCacheEviction:

    def test_expired_entries_swept_on_insert(
        self, proxy_with_stub_resolver,
    ):
        proxy, _calls = proxy_with_stub_resolver
        # Plant already-expired entries under keys nothing re-looks up.
        stale_keys = [(f"stale-{i}.example", 443) for i in range(5)]
        for k in stale_keys:
            proxy._dns_cache[k] = (time.monotonic() - 1.0, [])
        _resolve(proxy, "fresh.example", 443)
        for k in stale_keys:
            assert k not in proxy._dns_cache, (
                f"expired entry {k} survived an insert sweep"
            )
        assert ("fresh.example", 443) in proxy._dns_cache

    def test_cache_is_capped_and_evicts_oldest(
        self, proxy_with_stub_resolver, monkeypatch,
    ):
        proxy, _calls = proxy_with_stub_resolver
        monkeypatch.setattr(proxy_mod, "_DNS_CACHE_MAX_ENTRIES", 8)
        for i in range(20):
            _resolve(proxy, f"host-{i}.example", 443)
        assert len(proxy._dns_cache) <= 8, (
            f"cache exceeded the cap: {len(proxy._dns_cache)} entries"
        )
        # The most recent inserts survive; the earliest were evicted.
        assert ("host-19.example", 443) in proxy._dns_cache
        assert ("host-0.example", 443) not in proxy._dns_cache

    def test_hostile_host_diversity_stays_bounded(
        self, proxy_with_stub_resolver, monkeypatch,
    ):
        """The attack shape from the finding: an audit-mode child
        minting unlimited distinct hostnames must not grow the parent
        proxy's memory without bound."""
        proxy, _calls = proxy_with_stub_resolver
        monkeypatch.setattr(proxy_mod, "_DNS_CACHE_MAX_ENTRIES", 64)
        for i in range(500):
            _resolve(proxy, f"mint-{i}.attacker.example", 443)
        assert len(proxy._dns_cache) <= 64

    def test_cache_hit_still_served_within_ttl(
        self, proxy_with_stub_resolver,
    ):
        proxy, calls = proxy_with_stub_resolver
        first = _resolve(proxy, "hit.example", 443)
        second = _resolve(proxy, "hit.example", 443)
        assert first == second
        assert len(calls) == 1
