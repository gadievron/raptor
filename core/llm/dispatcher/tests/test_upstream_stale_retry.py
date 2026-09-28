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

import contextlib
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


def _post(
    d: LLMDispatcher, token: str, *, body_bytes: int = 0,
) -> httpx.Response:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    payload: dict = {"model": "m", "messages": []}
    if body_bytes:
        payload["messages"] = [{"role": "user", "content": "x" * body_bytes}]
    with httpx.Client(transport=transport, timeout=30.0) as client:
        return client.post(
            "http://_/anthropic/v1/messages",
            headers={_TOKEN_HEADER: token},
            content=json.dumps(payload),
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
            retries = _wait_audit(d, "request.retry")
            assert retries
            # Written before the retry's outcome is known — never a
            # recovery claim (trail readers count recoveries from the
            # following dispatch row).
            assert retries[0]["status"] == "attempt"
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
            counters = upstream.counters()
            # 1 initial attempt + 1 fresh-connection retry, no more.
            assert counters["connections"] == 2
            # ACCEPTED RESIDUAL, owned here: this upstream READ both
            # requests before dying, so the retry double-sent a
            # request the error class alone cannot prove unhandled.
            # The elapsed-time ceiling bounds the exposure to deaths
            # within a couple of seconds of the send — too early for
            # real generation work to be at stake — and to exactly
            # one extra send per worker attempt.
            assert counters["requests_processed"] == 2
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_slow_pre_response_death_past_ceiling_is_not_retried(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """The other direction of the retry-eligibility ceiling: a
        pre-response death that arrives SLOWLY (the upstream read the
        request and plausibly spent the dwell handling it — billable
        work, and a SigV4 signature aging all the while) must not be
        re-sent. Ordinary 502, zero retries, single upstream send."""
        monkeypatch.setenv(
            "RAPTOR_LLM_DISPATCHER_STALE_RETRY_CEILING_S", "0.2",
        )
        upstream = MockUpstream("no-response-close", response_delay_s=0.8)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            resp = _post(d, token)
            assert resp.status_code == 502
            assert _wait_audit(d, "request.error")
            assert not _audit_events(d, "request.retry")
            counters = upstream.counters()
            assert counters["connections"] == 1
            # Processed exactly once — the slow death was NOT re-sent.
            assert counters["requests_processed"] == 1
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_large_body_stale_reuse_recovers(
        self, fake_creds, tmp_path,
    ):
        """Large request bodies surface half-open deaths through a
        different wire path (the failure hits mid-request-write, not
        on the response read) — httpcore currently maps those into
        the same read-class shapes ``_STALE_REUSE_ERRORS`` names.
        Version-dependent behaviour: this pins that a large-body
        stale death still lands in the retryable set."""
        upstream = MockUpstream("half-open", idle_s=0.4)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            assert _post(d, token, body_bytes=262144).status_code == 200
            time.sleep(0.9)
            assert _post(d, token, body_bytes=262144).status_code == 200
            assert _wait_audit(d, "request.retry")
            assert not _audit_events(d, "request.error")
            assert upstream.counters()["requests_processed"] == 2
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


class TestStaleRetryShardEvidence:
    """A stale-reuse death that triggers the transparent retry is
    evidence about the SHARD's own connections: one strike toward the
    drain threshold, even when the retry recovers. Pre-change a shard
    whose idle pool kept getting condemned within the retry ceiling
    never drained — every relay on it silently paid a one-shot fresh
    connection while the failure counter stayed at zero. The retry's
    OUTCOME stays neutral both ways: a recovered relay must not reset
    the counter, and a failed one-shot must not strike twice."""

    @pytest.fixture(autouse=True)
    def _single_shard_env(self, monkeypatch):
        # HTTP/2 off + no shard override -> one shard, so the shard
        # under test is the only one relays can ride (hermetic
        # against ambient tuning).
        monkeypatch.delenv("RAPTOR_HTTP2", raising=False)
        monkeypatch.delenv("RAPTOR_HTTP2_SHARDS", raising=False)
        monkeypatch.delenv("RAPTOR_HTTP2_SHARD_MAX_AGE_S", raising=False)

    @staticmethod
    def _sole_shard_client(d: LLMDispatcher) -> httpx.Client:
        clients = d._upstream_client_shards().clients
        assert len(clients) == 1
        return clients[0]

    @staticmethod
    def _condemn_while(monkeypatch, client: httpx.Client, state: dict) -> None:
        """While ``state['fail']`` holds, the shard client's stream
        open dies the stale-reuse death (a read-class error raised
        immediately, well inside the retry ceiling); otherwise the
        real stream serves. The retry's one-shot client is built
        fresh and reaches the captive upstream unharmed."""
        real_stream = httpx.Client.stream.__get__(client)

        @contextlib.contextmanager
        def stale_or_real(method, url, **kwargs):
            if state["fail"]:
                raise httpx.ReadError("stale reuse")
            with real_stream(method, url, **kwargs) as up:
                yield up

        monkeypatch.setattr(client, "stream", stale_or_real)

    def _wait_rebuilt(self, d: LLMDispatcher, old: httpx.Client) -> None:
        """The drained shard is retired at release, which can lag the
        worker-visible response by a beat."""
        deadline = time.monotonic() + 5.0
        while (
            self._sole_shard_client(d) is old
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)

    def test_recovered_stale_death_still_strikes(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Retry success must not mask the strike: at threshold 1 a
        single stale-retried death drains and rebuilds the shard even
        though the worker saw a clean 200."""
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "1")
        upstream = MockUpstream("keepalive")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            pooled = self._sole_shard_client(d)
            self._condemn_while(monkeypatch, pooled, {"fail": True})
            assert _post(d, token).status_code == 200
            assert _wait_audit(d, "request.retry")
            assert not _audit_events(d, "request.error")
            self._wait_rebuilt(d, pooled)
            rebuilt = self._sole_shard_client(d)
            assert rebuilt is not pooled
            assert pooled.is_closed
            assert not rebuilt.is_closed
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_consecutive_stale_deaths_drain_at_threshold(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Strikes accumulate across relays: below the threshold the
        shard stays in rotation, at it the shard drains — the shape
        whose idle pool keeps getting condemned finally gets the
        drain repair instead of paying a one-shot per relay."""
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "2")
        upstream = MockUpstream("keepalive")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            pooled = self._sole_shard_client(d)
            self._condemn_while(monkeypatch, pooled, {"fail": True})

            assert _post(d, token).status_code == 200  # strike one
            assert self._sole_shard_client(d) is pooled
            assert not pooled.is_closed

            assert _post(d, token).status_code == 200  # strike two
            self._wait_rebuilt(d, pooled)
            assert self._sole_shard_client(d) is not pooled
            assert pooled.is_closed
            assert len(_audit_events(d, "request.retry")) == 2
            assert not _audit_events(d, "request.error")
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_clean_completion_still_resets_after_stale_strike(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Reset-on-clean is untouched: a clean completion on the
        shard's OWN client between two stale-retried deaths keeps the
        count below a threshold of 2, so the shard survives where the
        consecutive test above drains."""
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "2")
        upstream = MockUpstream("keepalive")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            pooled = self._sole_shard_client(d)
            state = {"fail": True}
            self._condemn_while(monkeypatch, pooled, state)

            assert _post(d, token).status_code == 200  # strike one
            state["fail"] = False
            assert _post(d, token).status_code == 200  # clean: reset
            state["fail"] = True
            assert _post(d, token).status_code == 200  # strike one again

            # A lagging release is the only async step; give it a
            # beat, then pin that no drain happened.
            time.sleep(0.5)
            assert self._sole_shard_client(d) is pooled
            assert not pooled.is_closed
            assert len(_audit_events(d, "request.retry")) == 2
            assert not _audit_events(d, "request.error")
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_oneshot_failure_never_strikes_twice(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """One relay strikes at most once: a stale-retried relay
        whose one-shot fresh client ALSO fails already struck at the
        retry, so the one-shot's own transport death (the
        _stale_retried gate on the exception path) must add nothing.
        At threshold 2 a double strike from that single relay would
        drain the shard."""
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "2")
        upstream = MockUpstream("keepalive")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        oneshot = httpx.Client()
        try:
            token = _worker_token(d)
            pooled = self._sole_shard_client(d)
            self._condemn_while(monkeypatch, pooled, {"fail": True})

            @contextlib.contextmanager
            def dead_stream(method, url, **kwargs):
                raise httpx.ReadError("one-shot dead too")
                yield  # pragma: no cover

            def dead_oneshot() -> httpx.Client:
                return oneshot

            monkeypatch.setattr(oneshot, "stream", dead_stream)
            monkeypatch.setattr(d, "_fresh_upstream_client", dead_oneshot)

            assert _post(d, token).status_code == 502
            assert _wait_audit(d, "request.retry")
            # A lagging release is the only async step; give it a
            # beat, then pin: exactly one strike from this relay, so
            # no drain at threshold 2.
            time.sleep(0.5)
            assert self._sole_shard_client(d) is pooled, (
                "double strike: one relay drained the shard at threshold 2"
            )
            assert not pooled.is_closed
        finally:
            oneshot.close()
            upstream.shutdown()
            d.shutdown()
