"""Pre-response stale-connection retry on the upstream forwarding leg.

The egress path idles out pooled upstream connections (proxy CONNECT
tunnels and provider keep-alives). A settled close is discarded by the
pool's readable-socket checkout guard, but a HALF-OPEN teardown — the
client side held open, no FIN delivered — is invisible until the next
request is written into the dead connection, which then fails with
``RemoteProtocolError``/``ReadError`` before any response byte.
Pre-fix every such reuse surfaced as a 502 + ``request.error`` burst
that the worker retry loop had to absorb; the dispatcher now retries
the buffered request transparently, bounded, and only pre-response.

Hermetic — captive loopback upstream, no LLM, no network.
"""

from __future__ import annotations

import json
import os
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _TOKEN_HEADER,
    LLMDispatcher,
)
from core.llm.tests.mock_upstream import MockUpstream


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


def _make_dispatcher(fake_creds, tmp_path, upstream) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="stale-retry", creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    original = d._rules["anthropic"]
    d._rules["anthropic"] = ProviderRule(
        name=original.name,
        upstream_base_url=upstream.base_url,
        inject_headers=original.inject_headers,
        strip_request_headers=original.strip_request_headers,
    )
    return d


def _worker_token(d: LLMDispatcher) -> str:
    _, fd = d.allocate_worker(label="test-worker")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    return token


def _post(d: LLMDispatcher, token: str) -> httpx.Response:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    with httpx.Client(transport=transport, timeout=30.0) as client:
        return client.post(
            "http://_/anthropic/v1/messages",
            headers={_TOKEN_HEADER: token},
            content=json.dumps({"model": "m", "messages": []}),
        )


def _post_streaming(d: LLMDispatcher, token: str) -> bytes:
    """POST and drain whatever body bytes arrive before the relay
    ends (normally or torn down mid-body)."""
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    received = b""
    try:
        with httpx.Client(transport=transport, timeout=30.0) as client:
            with client.stream(
                "POST", "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=json.dumps({"model": "m", "messages": []}),
            ) as resp:
                for chunk in resp.iter_raw():
                    received += chunk
    except httpx.HTTPError:
        pass
    return received


def _audit_events(d: LLMDispatcher, event: str) -> list[dict]:
    try:
        lines = d._audit_path.read_text().splitlines()
    except OSError:
        return []
    rows = [json.loads(line) for line in lines if line.strip()]
    return [r for r in rows if r.get("event") == event]


def _wait_audit(d: LLMDispatcher, event: str, timeout: float = 5.0) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = _audit_events(d, event)
        if rows:
            return rows
        time.sleep(0.05)
    return []


class TestUpstreamStaleRetry:

    def test_half_open_reuse_recovers_transparently(
        self, fake_creds, tmp_path,
    ):
        """Reuse of a connection whose far side idled out half-open
        (the checkout guard cannot see it) must recover inside the
        dispatcher: the worker sees two clean 200s, the audit records
        a ``request.retry`` and — the pre-fix burst shape — NO
        ``request.error``."""
        upstream = MockUpstream("half-open", idle_s=0.4)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            first = _post(d, token)
            assert first.status_code == 200
            # Idle past the far side's threshold: the pooled upstream
            # connection is now condemned but polls unreadable, so
            # only the next write can discover it.
            time.sleep(0.9)
            second = _post(d, token)
            assert second.status_code == 200
            assert _wait_audit(d, "request.retry")
            assert not _audit_events(d, "request.error")
            counters = upstream.counters()
            # Both logical requests processed exactly once — the
            # stale write never reached request handling upstream.
            assert counters["requests_processed"] == 2
            assert counters["stale_hits"] == 1
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_persistent_pre_response_failure_is_bounded(
        self, fake_creds, tmp_path,
    ):
        """An upstream that dies pre-response on EVERY attempt (fresh
        connections included) must not be chased: a failure on the
        retry's fresh connection rules out reuse artifacts, so exactly
        one retry fires, then the worker gets the ordinary 502 +
        ``request.error`` it always did."""
        upstream = MockUpstream("no-response-close")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            resp = _post(d, token)
            assert resp.status_code == 502
            assert "RemoteProtocolError" in resp.text
            assert _wait_audit(d, "request.error")
            assert len(_audit_events(d, "request.retry")) == 1
            # 1 initial attempt + 1 fresh-connection retry, no more.
            assert upstream.counters()["connections"] == 2
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_mid_response_failure_is_not_retried(
        self, fake_creds, tmp_path,
    ):
        """A connection death AFTER response bytes started flowing may
        follow upstream processing that already cost real money —
        re-sending would double-process. The dispatcher must surface
        it as the ordinary relay failure, with zero retry attempts."""
        upstream = MockUpstream("rst-mid-response")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            _post_streaming(d, token)
            assert _wait_audit(d, "request.error")
            assert not _audit_events(d, "request.retry")
            # Processed exactly once — no transparent re-send.
            assert upstream.counters()["requests_processed"] == 1
        finally:
            upstream.shutdown()
            d.shutdown()
