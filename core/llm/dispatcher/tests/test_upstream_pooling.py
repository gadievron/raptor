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

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import _TOKEN_HEADER, LLMDispatcher
from core.llm.http_pool import ClientShards


@pytest.fixture(autouse=True)
def _default_shard_env(monkeypatch):
    # HTTP/2 off + no shard override → one shard, the degenerate
    # single-client shape these relay tests pin.
    monkeypatch.delenv("RAPTOR_HTTP2", raising=False)
    monkeypatch.delenv("RAPTOR_HTTP2_SHARDS", raising=False)


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
