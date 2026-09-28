"""Tests for the dispatcher's pooled forwarding-leg clients.

The forwarding leg used to build a fresh ``httpx.Client`` per
request, paying a full TCP + TLS handshake (and, behind chained
proxies, CONNECT negotiation per hop) on every forwarded LLM call.
The dispatcher now owns a small shard pool of clients
(``core.llm.http_pool.ClientShards`` — one shard with HTTP/2 off,
several under HTTP/2 so one multiplexed-connection loss cannot abort
every in-flight relay), keyed on the proxy env (httpx resolves proxy
routes at client construction, and the egress chokepoint mutates
HTTPS_PROXY in-process after the dispatcher may already exist).
Requests pass their timeout per-call so the
``RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S`` knob keeps per-request
semantics.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import _TOKEN_HEADER, LLMDispatcher
from core.llm.http_pool import ClientShards


@pytest.fixture(autouse=True)
def _default_shard_env(monkeypatch):
    # HTTP/2 off + no shard override → one shard, the degenerate
    # single-client shape these relay tests pin. Lifecycle knobs at
    # their defaults too (hermetic against ambient tuning).
    monkeypatch.delenv("RAPTOR_HTTP2", raising=False)
    monkeypatch.delenv("RAPTOR_HTTP2_SHARDS", raising=False)
    monkeypatch.delenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", raising=False)
    monkeypatch.delenv("RAPTOR_HTTP2_SHARD_MAX_AGE_S", raising=False)


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "real-secret-key",
        "openai": None,
        "gemini": None,
    }
    return creds


@pytest.fixture
def dispatcher(fake_creds, tmp_path):
    d = LLMDispatcher(
        run_id="pool-test",
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600,
        token_budget=100,
        creds=fake_creds,
    )
    yield d
    d.shutdown()


def _issue_token(dispatcher, label):
    _, fd = dispatcher.allocate_worker(label=label)
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    return token


def _sole_client(dispatcher) -> httpx.Client:
    """The single shard client the default (HTTP/2-off) pool holds."""
    shards = dispatcher._upstream_client_shards()
    assert len(shards) == 1
    return shards.clients[0]


class TestClientCache:

    def test_same_env_reuses_pool(self, dispatcher):
        first = dispatcher._upstream_client_shards()
        assert isinstance(first, ClientShards)
        assert dispatcher._upstream_client_shards() is first
        assert first.clients == dispatcher._upstream_client_shards().clients

    def test_http2_off_degenerates_to_one_shard(self, dispatcher):
        assert len(dispatcher._upstream_client_shards()) == 1

    def test_proxy_env_change_rebuilds_pool(self, dispatcher, monkeypatch):
        first = dispatcher._upstream_client_shards()
        # The egress chokepoint's startup mutation: HTTPS_PROXY now
        # points at the in-process proxy. A construction-time client
        # would keep dialling the old route and bypass it.
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:59999")
        second = dispatcher._upstream_client_shards()
        assert second is not first
        assert all(client.is_closed for client in first.clients)
        # Stable from there.
        assert dispatcher._upstream_client_shards() is second

    def test_proxy_env_change_spares_in_flight_relay(
        self, dispatcher, monkeypatch,
    ):
        # The rebuild is drain-shaped: a relay mid-stream on the old
        # pool keeps its shard client until it releases the hold —
        # superseding the pool must not abort the stream it still
        # carries.
        first = dispatcher._upstream_client_shards()
        held, index = first.acquire()
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:59999")
        second = dispatcher._upstream_client_shards()
        assert second is not first
        assert not held.is_closed
        first.release(index)
        assert held.is_closed  # superseded shard retired at last hold

    def test_shutdown_closes_upstream_clients(self, fake_creds, tmp_path):
        d = LLMDispatcher(
            run_id="pool-close-test",
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600,
            token_budget=100,
            creds=fake_creds,
        )
        shards = d._upstream_client_shards()
        assert not any(client.is_closed for client in shards.clients)
        d.shutdown()
        assert all(client.is_closed for client in shards.clients)

    def test_shutdown_with_no_client_built_is_clean(self, fake_creds, tmp_path):
        d = LLMDispatcher(
            run_id="pool-lazy-test",
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600,
            token_budget=100,
            creds=fake_creds,
        )
        assert d._upstream_shards is None
        d.shutdown()  # must not raise


class TestForwardingUsesPool:

    def test_requests_reuse_the_dispatcher_client(self, dispatcher, monkeypatch):
        """Two forwarded requests must go through the SAME client
        object — the whole point of the hoist."""
        pooled = _sole_client(dispatcher)
        used = []
        real_stream = pooled.stream

        def recording_stream(method, url, **kwargs):
            used.append(pooled)
            return real_stream(
                "GET", "http://127.0.0.1:1/unreachable",
                timeout=kwargs.get("timeout"),
            )

        monkeypatch.setattr(pooled, "stream", recording_stream)
        token = _issue_token(dispatcher, "pool-e2e")

        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            for _ in range(2):
                # The upstream dial fails (nothing listens on port 1)
                # — the dispatcher maps that to 502. What matters is
                # WHICH client carried the attempt.
                resp = c.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=b"{}",
                )
                assert resp.status_code == 502

        assert len(used) == 2

    def test_relay_returns_its_shard_hold(self, dispatcher, monkeypatch):
        """Every relay exit path releases the shard it acquired —
        a leaked hold would permanently skew least-loaded selection
        toward the other shards."""
        pooled = _sole_client(dispatcher)
        real_stream = pooled.stream

        def failing_stream(method, url, **kwargs):
            return real_stream(
                "GET", "http://127.0.0.1:1/unreachable",
                timeout=kwargs.get("timeout"),
            )

        monkeypatch.setattr(pooled, "stream", failing_stream)
        token = _issue_token(dispatcher, "pool-release")
        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            resp = c.post(
                "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=b"{}",
            )
            assert resp.status_code == 502  # dial fails; relay exits
        shards = dispatcher._upstream_client_shards()
        assert shards.in_flight == (0,)

    def test_per_request_timeout_still_env_driven(self, dispatcher, monkeypatch):
        """The pooled client must not freeze the timeout at
        construction — each request passes the live env value."""
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", "77")
        pooled = _sole_client(dispatcher)
        seen = {}
        real_stream = pooled.stream

        def recording_stream(method, url, **kwargs):
            seen["timeout"] = kwargs.get("timeout")
            return real_stream(
                "GET", "http://127.0.0.1:1/unreachable",
                timeout=kwargs.get("timeout"),
            )

        monkeypatch.setattr(pooled, "stream", recording_stream)
        token = _issue_token(dispatcher, "pool-timeout")

        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            c.post(
                "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=b"{}",
            )

        assert seen["timeout"] is not None
        assert seen["timeout"].read == 77.0


class TestNegotiatedProtocolObservability:

    def test_every_shard_has_protocol_hook(self, dispatcher, monkeypatch):
        from core.llm.http_pool import _response_hook

        monkeypatch.setenv("RAPTOR_HTTP2_SHARDS", "3")
        shards = dispatcher._upstream_client_shards()
        assert len(shards) == 3
        for client in shards.clients:
            assert _response_hook in client.event_hooks["response"]

    def test_dispatch_audit_records_http_version(
        self, dispatcher, tmp_path, monkeypatch,
    ):
        """The request.dispatch audit row carries the negotiated
        protocol of the upstream leg (h1/h2) so HTTP/2 service is
        provable from the dispatch audit trail."""
        import json
        from contextlib import contextmanager

        pooled = _sole_client(dispatcher)

        class FakeUpstreamResponse:
            status_code = 200
            headers = httpx.Headers({"content-type": "application/json"})
            http_version = "HTTP/2"

            def iter_raw(self):
                return iter([b"{}"])

        @contextmanager
        def fake_stream(method, url, **kwargs):
            yield FakeUpstreamResponse()

        monkeypatch.setattr(pooled, "stream", fake_stream)
        token = _issue_token(dispatcher, "http-version-audit")

        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            resp = c.post(
                "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=b"{}",
            )
            assert resp.status_code == 200

        events = [
            json.loads(line)
            for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        ]
        dispatched = [e for e in events if e.get("event") == "request.dispatch"]
        assert dispatched, "no request.dispatch audit row written"
        # AuditEvent.extra is spread flat into the on-disk row.
        assert dispatched[-1]["http_version"] == "h2"


class TestForwardingLegKeepalive:
    """Both forwarding-leg client shapes — the pooled shards and the
    stale-retry one-shot — carry the TCP keepalive options, so a
    silently-dead idle upstream connection is reaped by the kernel
    instead of being discovered by the next relay."""

    def test_shard_clients_carry_keepalive_options(self, dispatcher):
        from core.llm.http_pool import tcp_keepalive_socket_options

        client = _sole_client(dispatcher)
        expected = tcp_keepalive_socket_options()
        assert client._transport._pool._socket_options == expected

    def test_fresh_retry_client_carries_keepalive_options(self, dispatcher):
        from core.llm.http_pool import tcp_keepalive_socket_options

        client = dispatcher._fresh_upstream_client()
        try:
            expected = tcp_keepalive_socket_options()
            assert client._transport._pool._socket_options == expected
        finally:
            client.close()

    def test_proxied_route_uses_keepalive_transport(
        self, dispatcher, monkeypatch,
    ):
        from core.llm.http_pool import _ProxyKeepaliveTransport

        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:59999")
        # Env change → the pool rebuilds; the rebuilt client must
        # route proxied requests through the transport that actually
        # applies the options (base httpx/httpcore drops them on the
        # proxied path — pinned in the http_pool tests).
        client = _sole_client(dispatcher)
        proxied = client._transport_for_url(
            httpx.URL("https://api.anthropic.com/v1/messages"),
        )
        assert isinstance(proxied, _ProxyKeepaliveTransport)


class TestShardHealthSeam:
    """The relay feeds shard health: transport deaths on the shard's
    own client count toward the drain-and-rebuild threshold, clean
    completions reset the counter, worker-side failures stay
    neutral."""

    def _post_via(self, dispatcher, token, body: bytes = b"{}"):
        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            return c.post(
                "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=body,
            )

    def _make_failing(self, monkeypatch, client):
        # Bind the CLASS method, not the instance attribute — the
        # instance attribute may itself be an earlier patch (the
        # reset test alternates fail/ok/fail on one client).
        real_stream = httpx.Client.stream.__get__(client)

        def failing_stream(method, url, **kwargs):
            # Nothing listens on port 1: the open dies with
            # httpx.ConnectError — a shard-health shape that is NOT
            # stale-retry-eligible, so it propagates to the abort
            # path and lands one strike on the shard.
            return real_stream(
                "GET", "http://127.0.0.1:1/unreachable",
                timeout=kwargs.get("timeout"),
            )

        monkeypatch.setattr(client, "stream", failing_stream)

    @staticmethod
    def _wait_for_rebuild(
        dispatcher, pooled: httpx.Client, deadline_s: float = 5.0,
    ) -> httpx.Client:
        """The drain-shaped rebuild lands in the handler thread's
        ``shards.release`` — reached in the relay's ``finally``, AFTER
        the 502 is already on the wire (and the retired client's close
        runs outside the pool lock, after the slot refill). A caller
        that just read the 502 races both; poll briefly instead."""
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            rebuilt = _sole_client(dispatcher)
            if rebuilt is not pooled and pooled.is_closed:
                return rebuilt
            time.sleep(0.01)
        return _sole_client(dispatcher)

    def test_transport_failure_drains_and_rebuilds_the_shard(
        self, dispatcher, monkeypatch,
    ):
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "1")
        pooled = _sole_client(dispatcher)
        self._make_failing(monkeypatch, pooled)
        token = _issue_token(dispatcher, "health-fail")
        assert self._post_via(dispatcher, token).status_code == 502
        # One strike at threshold 1: the shard drained on release and
        # was rebuilt fresh — same pool object, new client.
        shards = dispatcher._upstream_client_shards()
        rebuilt = self._wait_for_rebuild(dispatcher, pooled)
        assert rebuilt is not pooled
        assert pooled.is_closed
        assert not rebuilt.is_closed
        assert shards.in_flight == (0,)

    def test_success_resets_the_failure_counter(
        self, dispatcher, monkeypatch,
    ):
        from contextlib import contextmanager

        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "2")
        pooled = _sole_client(dispatcher)
        token = _issue_token(dispatcher, "health-reset")

        # Strike one.
        self._make_failing(monkeypatch, pooled)
        assert self._post_via(dispatcher, token).status_code == 502
        assert _sole_client(dispatcher) is pooled  # below threshold

        # Clean completion on the same shard client: counter resets.
        class FakeUpstreamResponse:
            status_code = 200
            headers = httpx.Headers({"content-type": "application/json"})
            http_version = "HTTP/1.1"

            def iter_raw(self):
                return iter([b"{}"])

        @contextmanager
        def ok_stream(method, url, **kwargs):
            yield FakeUpstreamResponse()

        monkeypatch.setattr(pooled, "stream", ok_stream)
        assert self._post_via(dispatcher, token).status_code == 200

        # Strike again: only ONE consecutive failure — without the
        # reset this second strike would have hit the threshold and
        # rebuilt the shard.
        self._make_failing(monkeypatch, pooled)
        assert self._post_via(dispatcher, token).status_code == 502
        assert _sole_client(dispatcher) is pooled
        assert not pooled.is_closed

    def test_worker_side_failures_are_not_shard_evidence(self):
        # WorkerDisconnected (the worker left) and RelayLimitExceeded
        # (our own caps) say nothing about the upstream connection's
        # health — they must never feed the drain threshold.
        from core.llm.dispatcher.server import (
            _SHARD_HEALTH_ERRORS,
            RelayLimitExceeded,
            WorkerDisconnected,
        )

        assert not isinstance(WorkerDisconnected("x"), _SHARD_HEALTH_ERRORS)
        assert not isinstance(RelayLimitExceeded("x"), _SHARD_HEALTH_ERRORS)
        # The stall watchdog's trip shape, by contrast, IS shard
        # evidence — a wedged tunnel is exactly what a rebuild fixes.
        assert isinstance(
            httpx.ReadTimeout("stall"), _SHARD_HEALTH_ERRORS,
        )
