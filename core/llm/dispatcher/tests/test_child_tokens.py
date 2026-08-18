"""Scoped child tokens — mint / enforce / expire / revoke / spend.

The scoping extension of the worker capability-token store: CC CLI
children authenticate with a minted bearer token that is budget-capped
(USD, booked from upstream-reported usage), model-allowlisted, and
short-TTL. All tests are hermetic — the "provider" is a captive HTTP
server inside the test; no LLM, no network.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.client import (
    child_token_spend,
    mint_child_token,
    reconcile_child_spend,
    revoke_child_token,
)
from core.llm.dispatcher.server import (
    _TOKEN_HEADER,
    LLMDispatcher,
    _UsageScanner,
)

# A model with a real entry in the pricing table (needed for booking).
_PRICED_MODEL = "claude-opus-4-8"


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "real-secret-anthropic-key-NOT-LEAKED",
        "openai": "real-secret-openai-key",
        "gemini": None,
    }
    return creds


class _Upstream:
    """Captive provider stub. ``mode`` selects the response shape:

    * ``"json"`` — non-streamed Messages JSON with usage.
    * ``"sse"``  — SSE stream: message_start (model + input tokens),
      one delta, final message_delta with output tokens.
    * ``"abort"`` — SSE that dies after message_start (Content-Length
      overstates the body, then the connection closes) so the
      dispatcher's upstream leg raises mid-stream.
    """

    def __init__(self, mode: str = "json"):
        self.mode = mode
        self.requests: list[dict] = []
        outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                outer.requests.append({
                    "path": self.path,
                    "headers": dict(self.headers.items()),
                    "body": body,
                })
                if outer.mode == "json":
                    resp = json.dumps({
                        "id": "msg_test",
                        "model": _PRICED_MODEL,
                        "content": [{"type": "text", "text": "hi"}],
                        "usage": {
                            "input_tokens": 1000,
                            "output_tokens": 500,
                        },
                    }).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp)))
                    self.end_headers()
                    self.wfile.write(resp)
                    return
                start = (
                    b'event: message_start\n'
                    b'data: {"type":"message_start","message":{"model":"'
                    + _PRICED_MODEL.encode() +
                    b'","usage":{"input_tokens":1000,"output_tokens":1}}}\n\n'
                )
                delta = (
                    b'event: content_block_delta\n'
                    b'data: {"type":"content_block_delta","delta":'
                    b'{"type":"text_delta","text":"hi"}}\n\n'
                )
                final = (
                    b'event: message_delta\n'
                    b'data: {"type":"message_delta","usage":'
                    b'{"output_tokens":500}}\n\n'
                    b'event: message_stop\n'
                    b'data: {"type":"message_stop"}\n\n'
                )
                if outer.mode == "sse":
                    payload = start + delta + final
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                # abort: promise more bytes than we send, then die.
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header(
                    "Content-Length", str(len(start) + 4096),
                )
                self.end_headers()
                self.wfile.write(start)
                self.wfile.flush()
                self.connection.close()

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.base_url = (
            f"http://127.0.0.1:{self._server.server_address[1]}"
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _make_dispatcher(fake_creds, tmp_path, upstream: _Upstream):
    d = LLMDispatcher(
        run_id="child-tok", creds=fake_creds,
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


def _uds_client(d: LLMDispatcher) -> httpx.Client:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    return httpx.Client(transport=transport, timeout=10.0)


def _tcp_client(d: LLMDispatcher) -> httpx.Client:
    port = d.enable_loopback_listener()
    return httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10.0)


def _messages_post(client, token, model=_PRICED_MODEL, url=None):
    return client.post(
        url or "http://_/anthropic/v1/messages",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        content=json.dumps({"model": model, "messages": []}).encode(),
    )


def _expected_cost(in_tokens=1000, out_tokens=500):
    from core.llm.model_data import price_for
    in_rate, out_rate = price_for(_PRICED_MODEL)
    return (in_tokens * in_rate + out_tokens * out_rate) / 1e6


def _wait_spend(d: LLMDispatcher, token_id: str, timeout: float = 2.0) -> dict:
    """Booking happens on the handler thread AFTER the response bytes
    are flushed — the client can observe the response before the
    ledger lands. Poll briefly (same pattern as the audit-lag helper
    in test_dispatcher.py)."""
    deadline = time.time() + timeout
    snapshot: dict = {}
    while time.time() < deadline:
        snapshot = d.child_spend(token_id) or {}
        if snapshot.get("spent_usd"):
            return snapshot
        time.sleep(0.02)
    return snapshot


# ---------------------------------------------------------------------------
# Mint / dispatch / booking
# ---------------------------------------------------------------------------


class TestMintAndDispatch:

    def test_child_token_round_trip_and_booking(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child(
                "cc-test", budget_usd=1.0, models=[_PRICED_MODEL],
                ttl_s=600,
            )
            with _uds_client(d) as client:
                resp = _messages_post(client, token)
            assert resp.status_code == 200
            assert resp.json()["id"] == "msg_test"
            # Real key injected, bearer child token NOT forwarded.
            sent = {
                k.lower(): v
                for k, v in upstream.requests[0]["headers"].items()
            }
            assert sent.get("x-api-key") == (
                "real-secret-anthropic-key-NOT-LEAKED"
            )
            assert token not in json.dumps(upstream.requests[0]["headers"])
            # Identity encoding forced so the usage tee can parse.
            assert sent.get("accept-encoding") == "identity"
            # Booking matches the pricing table.
            spend = _wait_spend(d, info["token_id"])
            assert spend["spent_usd"] == pytest.approx(_expected_cost())
            assert spend["last_model"] == _PRICED_MODEL
            assert spend["requests_made"] == 1
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_streamed_response_books_from_final_usage_frame(
        self, fake_creds, tmp_path,
    ):
        upstream = _Upstream("sse")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child(
                "cc-sse", budget_usd=1.0, ttl_s=600,
            )
            with _uds_client(d) as client:
                resp = _messages_post(client, token)
            assert resp.status_code == 200
            # Streaming passthrough: the SSE body arrives unchanged.
            assert b"message_stop" in resp.content
            spend = _wait_spend(d, info["token_id"])
            # output_tokens from the FINAL message_delta frame (500),
            # not the message_start placeholder (1).
            assert spend["spent_usd"] == pytest.approx(_expected_cost())
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_streamed_abort_books_what_upstream_reported(
        self, fake_creds, tmp_path,
    ):
        upstream = _Upstream("abort")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child(
                "cc-abort", budget_usd=1.0, ttl_s=600,
            )
            with _uds_client(d) as client:
                try:
                    _messages_post(client, token)
                except httpx.HTTPError:
                    pass  # truncated relay is expected client-side
            spend = _wait_spend(d, info["token_id"])
            # message_start landed before the abort: input tokens (and
            # the 1-token output placeholder) are booked — nothing
            # vanishes from the ledger.
            assert spend["spent_usd"] == pytest.approx(
                _expected_cost(in_tokens=1000, out_tokens=1),
            )
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_unpriced_model_books_zero_and_flags(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            # Upstream reports a model absent from the pricing table.
            upstream.mode = "json"
            token, info = d.allocate_child(
                "cc-unpriced", budget_usd=1.0, ttl_s=600,
            )
            # Patch the upstream's reply model by swapping the priced
            # constant at the record level: easiest is a raw request
            # whose body model is unpriced — the upstream echoes the
            # constant model, so instead patch _usage_cost via an
            # unpriced upstream: simulate by scanning directly.
            scanner = _UsageScanner()
            scanner.feed(json.dumps({
                "model": "unknown-model-xyz",
                "usage": {"input_tokens": 10, "output_tokens": 10},
            }).encode())
            rec = d._tokens[token]
            d._book_child_usage(rec, scanner, aborted=False)
            spend = d.child_spend(info["token_id"])
            assert spend["spent_usd"] == 0.0
            assert spend["unpriced_requests"] == 1
        finally:
            upstream.shutdown()
            d.shutdown()


# ---------------------------------------------------------------------------
# Enforcement — allowlist, budget, shape
# ---------------------------------------------------------------------------


class TestEnforcement:

    def test_model_not_in_allowlist_rejected(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, _ = d.allocate_child(
                "cc-allow", budget_usd=1.0, models=[_PRICED_MODEL],
                ttl_s=600,
            )
            with _uds_client(d) as client:
                resp = _messages_post(
                    client, token, model="claude-haiku-4-5",
                )
            assert resp.status_code == 403
            assert "not in allowlist" in resp.json()["error"]
            assert upstream.requests == []  # never forwarded
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_allowlist_matches_across_id_spellings(
        self, fake_creds, tmp_path,
    ):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, _ = d.allocate_child(
                "cc-norm", budget_usd=1.0,
                models=[f"us.anthropic.{_PRICED_MODEL}"], ttl_s=600,
            )
            with _uds_client(d) as client:
                resp = _messages_post(
                    client, token, model=f"anthropic.{_PRICED_MODEL}",
                )
            assert resp.status_code == 200
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_budget_exhaustion_refuses_before_forward(
        self, fake_creds, tmp_path,
    ):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            # Budget below the cost of one call: first call is allowed
            # (spent 0 < budget), booking pushes spent past the cap,
            # second call must 402 WITHOUT touching the upstream.
            token, info = d.allocate_child(
                "cc-budget", budget_usd=_expected_cost() / 2,
                models=[_PRICED_MODEL], ttl_s=600,
            )
            with _uds_client(d) as client:
                first = _messages_post(client, token)
                assert first.status_code == 200
                n_forwarded = len(upstream.requests)
                second = _messages_post(client, token)
            assert second.status_code == 402
            err = second.json()["error"]
            assert "budget exhausted" in err
            assert "spent" in err  # actionable numbers in the message
            assert len(upstream.requests) == n_forwarded
            assert d.child_spend(info["token_id"])["status"] == "exhausted"
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_provider_scope_and_shape(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, _ = d.allocate_child("cc-shape", budget_usd=1.0)
            with _uds_client(d) as client:
                # Provider outside the child set (openai is worker-only).
                r = client.post(
                    "http://_/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {token}"},
                    content=b'{"model":"gpt-x"}',
                )
                assert r.status_code == 403
                # GET is not a scoped-token shape.
                r = client.get(
                    "http://_/anthropic/v1/models",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert r.status_code == 405
                # No model in body.
                r = client.post(
                    "http://_/anthropic/v1/messages",
                    headers={"Authorization": f"Bearer {token}"},
                    content=b'{"messages":[]}',
                )
                assert r.status_code == 400
        finally:
            upstream.shutdown()
            d.shutdown()


# ---------------------------------------------------------------------------
# Lifecycle — expiry, revocation, retention
# ---------------------------------------------------------------------------


class TestLifecycle:

    def test_expiry_enforced_and_spend_survives(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child(
                "cc-ttl", budget_usd=1.0, ttl_s=1,
            )
            with _uds_client(d) as client:
                first = _messages_post(client, token)
                assert first.status_code == 200
                time.sleep(1.1)
                late = _messages_post(client, token)
            assert late.status_code == 401
            assert "expired" in late.json()["error"]
            # The record is retained: post-run reconciliation still
            # reads the spend of an expired token.
            spend = d.child_spend(info["token_id"])
            assert spend is not None
            assert spend["spent_usd"] > 0
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_revocation(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child("cc-rev", budget_usd=1.0)
            assert d.revoke_child(info["token_id"]) is True
            with _uds_client(d) as client:
                resp = _messages_post(client, token)
            assert resp.status_code == 401
            assert "revoked" in resp.json()["error"]
            assert d.revoke_child("no-such-id") is False
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_mint_validation(self, fake_creds, tmp_path):
        d = LLMDispatcher(run_id="mint-val", creds=fake_creds,
                          token_ttl_s=60, token_budget=10)
        try:
            with pytest.raises(ValueError):
                d.allocate_child("bad", budget_usd=0)
            with pytest.raises(ValueError):
                d.allocate_child("bad", budget_usd=-1.0)
            with pytest.raises(ValueError):
                d.allocate_child("bad", budget_usd=1.0, ttl_s=-5)
        finally:
            d.shutdown()

    def test_audit_never_contains_token_value(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child("cc-audit", budget_usd=1.0)
            with _uds_client(d) as client:
                _messages_post(client, token)
            d.revoke_child(info["token_id"])
            audit_text = (tmp_path / "audit.jsonl").read_text()
            assert token not in audit_text
            assert info["token_id"] in audit_text
        finally:
            upstream.shutdown()
            d.shutdown()


# ---------------------------------------------------------------------------
# Planes — TCP listener, admin isolation
# ---------------------------------------------------------------------------


class TestPlanes:

    def test_tcp_plane_serves_child_tokens(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, _ = d.allocate_child("cc-tcp", budget_usd=1.0)
            with _tcp_client(d) as client:
                resp = _messages_post(
                    client, token, url="/anthropic/v1/messages",
                )
            assert resp.status_code == 200
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_tcp_plane_refuses_worker_tokens(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            worker = _worker_token(d)
            with _tcp_client(d) as client:
                resp = client.post(
                    "/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: worker},
                    content=b'{"model":"m","messages":[]}',
                )
            assert resp.status_code == 401
            assert upstream.requests == []
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_admin_unreachable_with_child_token(self, fake_creds, tmp_path):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child("cc-esc", budget_usd=1.0)
            # A child must not mint, revoke, or read spend — on either
            # plane.
            for client, label in (
                (_uds_client(d), "uds"),
                (_tcp_client(d), "tcp"),
            ):
                with client:
                    for op, payload in (
                        ("mint", {"budget_usd": 100.0}),
                        ("revoke", {"token_id": info["token_id"]}),
                        ("spend", {"token_id": info["token_id"]}),
                    ):
                        url = (
                            f"http://_/_child/{op}" if label == "uds"
                            else f"/_child/{op}"
                        )
                        r = client.post(
                            url,
                            headers={
                                "Authorization": f"Bearer {token}",
                            },
                            content=json.dumps(payload).encode(),
                        )
                        assert r.status_code == 403, (label, op)
            # Escalation did NOT happen: token still active, original
            # budget intact.
            spend = d.child_spend(info["token_id"])
            assert spend["status"] in ("pending", "active")
            assert spend["budget_usd"] == 1.0
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_admin_endpoints_with_worker_token_over_uds(
        self, fake_creds, tmp_path,
    ):
        upstream = _Upstream("json")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            worker = _worker_token(d)
            minted = mint_child_token(
                budget_usd=0.5, models=[_PRICED_MODEL], ttl_s=120,
                label="via-client",
                socket_path=str(d.socket_path), token=worker,
            )
            assert minted["token"]
            assert minted["budget_usd"] == 0.5
            # The minted token dispatches.
            with _uds_client(d) as client:
                resp = _messages_post(client, minted["token"])
            assert resp.status_code == 200
            spend = child_token_spend(
                minted["token_id"],
                socket_path=str(d.socket_path), token=worker,
            )
            assert spend["spent_usd"] > 0
            revoked = revoke_child_token(
                minted["token_id"],
                socket_path=str(d.socket_path), token=worker,
            )
            assert revoked["revoked"] is True
            with _uds_client(d) as client:
                resp = _messages_post(client, minted["token"])
            assert resp.status_code == 401
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_mint_fails_fast_when_dispatcher_unreachable(self, tmp_path):
        dead_socket = tmp_path / "no-dispatcher.sock"
        t0 = time.monotonic()
        with pytest.raises(RuntimeError, match="unreachable"):
            mint_child_token(
                budget_usd=1.0, label="orphan",
                socket_path=str(dead_socket), token="whatever",
            )
        assert time.monotonic() - t0 < 5.0  # fail fast, not a hang


# ---------------------------------------------------------------------------
# Reconciliation + scanner unit coverage
# ---------------------------------------------------------------------------


class TestReconcileAndScanner:

    def test_reconcile_is_max_of_ledgers(self):
        assert reconcile_child_spend(0.5, 0.2) == 0.5
        assert reconcile_child_spend(0.2, 0.5) == 0.5
        assert reconcile_child_spend(0.0, 0.0) == 0.0
        # Garbage tolerated, never negative.
        assert reconcile_child_spend(-1.0, "nan-ish") == 0.0  # type: ignore[arg-type]

    def test_scanner_parses_json_body(self):
        s = _UsageScanner()
        s.feed(json.dumps({
            "model": _PRICED_MODEL,
            "usage": {
                "input_tokens": 7, "output_tokens": 3,
                "cache_read_input_tokens": 11,
                "cache_creation_input_tokens": 13,
            },
        }).encode())
        got = s.extract()
        assert got["model"] == _PRICED_MODEL
        assert got["input_tokens"] == 7
        assert got["output_tokens"] == 3
        assert got["cache_read_tokens"] == 11
        assert got["cache_creation_tokens"] == 13

    def test_scanner_parses_sse_across_chunks(self):
        s = _UsageScanner()
        payload = (
            'data: {"type":"message_start","message":{"model":"'
            + _PRICED_MODEL +
            '","usage":{"input_tokens":100,"output_tokens":1}}}\n\n'
            'data: {"type":"message_delta","usage":{"output_tokens":42}}\n\n'
        ).encode()
        # Feed byte-by-byte-ish to prove chunking independence.
        for i in range(0, len(payload), 7):
            s.feed(payload[i:i + 7])
        got = s.extract()
        assert got["model"] == _PRICED_MODEL
        assert got["input_tokens"] == 100
        assert got["output_tokens"] == 42

    def test_scanner_tolerates_garbage(self):
        s = _UsageScanner()
        s.feed(b"\x00\xff not json at all")
        got = s.extract()
        assert got["input_tokens"] == 0
        assert got["model"] is None
