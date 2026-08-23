"""Request-body ceilings and atomic child-budget reservation.

Content-Length is peer-typed input even on the token-authenticated
planes: a huge declared length must be refused (413) BEFORE any read
(pre-fix it was allocated/blocked on per handler thread), and a
negative one must be refused (400) rather than turning ``rfile.read``
into read-until-EOF. The child budget check must reserve atomically
under the token lock — pre-fix N concurrent requests all observed the
pre-spend balance and the USD cap was overshot by concurrency ×
max-single-response cost.

All hermetic — captive loopback upstream, no LLM, no network.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _TOKEN_HEADER,
    LLMDispatcher,
)

_PRICED_MODEL = "claude-opus-4-8"


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


class _Upstream:
    """Captive provider stub returning a priced Messages JSON body."""

    def __init__(self):
        self.requests = 0
        outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                outer.requests += 1
                resp = json.dumps({
                    "id": "msg_test",
                    "model": _PRICED_MODEL,
                    "content": [{"type": "text", "text": "hi"}],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _make_dispatcher(fake_creds, tmp_path, upstream=None):
    d = LLMDispatcher(
        run_id="body-limits", creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    if upstream is not None:
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


def _model_body(model=_PRICED_MODEL, pad: int = 0,
                max_tokens: int = 100) -> bytes:
    return json.dumps(
        {
            "model": model, "max_tokens": max_tokens,
            "messages": [], "pad": "x" * pad,
        },
    ).encode()


# ---------------------------------------------------------------------------
# Content-Length ceilings
# ---------------------------------------------------------------------------


class TestBodyLimits:

    def test_provider_body_over_cap_rejected_413(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_MAX_BODY_BYTES", "1024")
        d = _make_dispatcher(fake_creds, tmp_path)
        try:
            token = _worker_token(d)
            with _uds_client(d) as client:
                resp = client.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=_model_body(pad=4096),
                )
            assert resp.status_code == 413
            assert "limit" in resp.json()["error"]
        finally:
            d.shutdown()

    def test_provider_body_under_cap_accepted(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_MAX_BODY_BYTES", "65536")
        upstream = _Upstream()
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            with _uds_client(d) as client:
                resp = client.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=_model_body(pad=1024),
                )
            assert resp.status_code == 200
            assert upstream.requests == 1
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_negative_content_length_rejected_400(
        self, fake_creds, tmp_path,
    ):
        d = _make_dispatcher(fake_creds, tmp_path)
        try:
            token = _worker_token(d)
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(5.0)
                s.connect(str(d.socket_path))
                s.sendall(
                    (
                        "POST /anthropic/v1/messages HTTP/1.1\r\n"
                        "Host: _\r\n"
                        f"{_TOKEN_HEADER}: {token}\r\n"
                        "Content-Length: -5\r\n"
                        "\r\n"
                    ).encode()
                )
                # Pre-fix rfile.read(-5) read until EOF — the handler
                # sat blocked on our open socket and this recv timed
                # out instead of seeing a response.
                status_line = s.recv(4096).split(b"\r\n", 1)[0]
            assert b" 400 " in status_line
        finally:
            d.shutdown()

    def test_child_admin_body_over_cap_rejected_413(
        self, fake_creds, tmp_path,
    ):
        d = _make_dispatcher(fake_creds, tmp_path)
        try:
            token = _worker_token(d)
            with _uds_client(d) as client:
                resp = client.post(
                    "http://_/_child/mint",
                    headers={_TOKEN_HEADER: token},
                    content=b'{"pad": "' + b"x" * (2 * 1024 * 1024) + b'"}',
                )
            assert resp.status_code == 413
        finally:
            d.shutdown()


# ---------------------------------------------------------------------------
# Atomic child-budget check + reservation
# ---------------------------------------------------------------------------


class TestChildBudgetReservation:

    def test_concurrent_requests_cannot_all_see_prespend_balance(
        self, fake_creds, tmp_path,
    ):
        """Two in-flight authorizations against a budget that only
        covers one reservation: pre-fix BOTH passed (each saw
        spent=0 < budget with nothing reserved) — the second must now
        be refused until the first settles."""
        d = _make_dispatcher(fake_creds, tmp_path)
        try:
            token, _info = d.allocate_child(
                "cc-race", budget_usd=0.30, models=[_PRICED_MODEL],
                ttl_s=600,
            )
            rec = d._tokens[token]
            # Ceiling for one request ≈ $0.20 (8000 output tokens at
            # the priced model's rate): one fits the $0.30 budget,
            # two cannot be in flight at once.
            body = _model_body(max_tokens=8000)

            first, first_reserved = d._authorize_child_request(
                rec, "anthropic", "POST", body,
                upstream_path="/v1/messages",
            )
            assert first is None
            assert first_reserved > 0
            second, _ = d._authorize_child_request(
                rec, "anthropic", "POST", body,
                upstream_path="/v1/messages",
            )
            assert second is not None
            status, why = second
            assert status == 429
            assert "reserved" in why
            # Transient refusal, not terminal exhaustion.
            assert rec.status != "exhausted"

            # First request settles -> its reservation is released and
            # the next request is admissible again.
            d._release_child_reservation(rec, first_reserved)
            third, _ = d._authorize_child_request(
                rec, "anthropic", "POST", body,
                upstream_path="/v1/messages",
            )
            assert third is None
        finally:
            d.shutdown()

    def test_reservation_released_after_forwarded_request(
        self, fake_creds, tmp_path,
    ):
        """End-to-end: a forwarded child request must release its
        reservation once booked — a leak would strangle the token."""
        upstream = _Upstream()
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, _info = d.allocate_child(
                "cc-settle", budget_usd=1.0, models=[_PRICED_MODEL],
                ttl_s=600,
            )
            rec = d._tokens[token]
            with _uds_client(d) as client:
                resp = client.post(
                    "http://_/anthropic/v1/messages",
                    headers={"Authorization": f"Bearer {token}"},
                    content=_model_body(),
                )
            assert resp.status_code == 200
            # Booking/release happen on the handler thread after the
            # bytes are flushed — poll briefly.
            import time
            deadline = time.time() + 2.0
            while time.time() < deadline and rec.reserved_usd:
                time.sleep(0.02)
            assert rec.reserved_usd == 0.0
            assert rec.spent_usd > 0.0
        finally:
            upstream.shutdown()
            d.shutdown()
