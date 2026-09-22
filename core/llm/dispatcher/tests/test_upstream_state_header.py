"""Attempt-state stamp on the dispatcher's worker-facing responses.

The worker's retry loop cannot tell, from its exception alone, a
transport death on a request the upstream never handled (safe to
re-send) from one whose response had already started — the upstream
fully processed (and billed) the generation. The dispatcher knows
which case it saw and stamps ``X-Raptor-Upstream-State`` on the heads
it sends toward the worker: ``response-started`` on a relayed
upstream head, ``pre-response`` on its own pre-response 502. These
tests pin the stamp on both shapes and that an upstream-supplied copy
of the header can never impersonate the dispatcher's.

Hermetic — captive loopback upstreams, no LLM, no network.
"""

from __future__ import annotations

import http.server
import json
import os
import threading

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _TOKEN_HEADER,
    _UPSTREAM_STATE_HEADER,
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


def _make_dispatcher(fake_creds, tmp_path, base_url: str) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="attempt-state", creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    original = d._rules["anthropic"]
    d._rules["anthropic"] = ProviderRule(
        name=original.name,
        upstream_base_url=base_url,
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


class _CannedUpstream:
    """Captive upstream answering a fixed status, optionally with its
    own copy of the attempt-state header — the value the relay must
    never forward."""

    def __init__(self, status: int = 200, *, spoof: bool = False) -> None:
        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                body = b'{"ok":true}'
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if spoof:
                    self.send_header(
                        _UPSTREAM_STATE_HEADER, "pre-response",
                    )
                self.end_headers()
                self.wfile.write(body)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        host, port = self._server.server_address
        self.base_url = f"http://{host}:{port}"
        threading.Thread(
            target=self._server.serve_forever, daemon=True,
        ).start()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class TestUpstreamStateHeader:

    def test_relayed_head_is_stamped_response_started(
        self, fake_creds, tmp_path,
    ):
        """A head that came from the upstream carries the
        ``response-started`` stamp — the worker gate's evidence that
        any later transport death follows billed upstream work."""
        upstream = MockUpstream("keepalive")
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            resp = _post(d, _worker_token(d))
            assert resp.status_code == 200
            assert resp.headers.get(_UPSTREAM_STATE_HEADER) == (
                "response-started"
            )
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_pre_response_502_is_stamped_pre_response(
        self, fake_creds, tmp_path,
    ):
        """The dispatcher's own 502 for a forward-leg failure before
        any upstream response byte carries ``pre-response`` — the
        worker's existing retry policy stays in force for it."""
        upstream = MockUpstream("no-response-close")
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            resp = _post(d, _worker_token(d))
            assert resp.status_code == 502
            assert resp.headers.get(_UPSTREAM_STATE_HEADER) == (
                "pre-response"
            )
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_upstream_copy_of_the_header_cannot_impersonate(
        self, fake_creds, tmp_path,
    ):
        """An upstream-supplied attempt-state header is stripped and
        replaced by the dispatcher's own stamp: a misbehaving (or
        compromised) upstream must not be able to mark its completed
        response ``pre-response`` and steer the worker into blind
        re-sends of consumed generations."""
        upstream = _CannedUpstream(200, spoof=True)
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            resp = _post(d, _worker_token(d))
            assert resp.status_code == 200
            values = resp.headers.get_list(_UPSTREAM_STATE_HEADER)
            assert values == ["response-started"]
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_relayed_error_head_carries_no_stamp(
        self, fake_creds, tmp_path,
    ):
        """A relayed NON-2xx head (here: 429) is never a billed
        generation, so it must NOT carry ``response-started`` — a wire
        death while its body relays (likeliest during the rate-limit
        storms where retry matters most) must keep the worker's
        status-code retry policy, not trip a false billed-spend veto.
        Two-direction with the relayed-200 test above."""
        upstream = _CannedUpstream(429)
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            resp = _post(d, _worker_token(d))
            assert resp.status_code == 429
            assert _UPSTREAM_STATE_HEADER not in resp.headers
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_spoofed_stamp_on_error_head_is_stripped(
        self, fake_creds, tmp_path,
    ):
        """An error head gets no dispatcher stamp AND loses any
        upstream-supplied copy — unstamped, not upstream-controlled."""
        upstream = _CannedUpstream(429, spoof=True)
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            resp = _post(d, _worker_token(d))
            assert resp.status_code == 429
            assert _UPSTREAM_STATE_HEADER not in resp.headers
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_control_plane_responses_carry_no_stamp(
        self, fake_creds, tmp_path,
    ):
        """Responses that never involved the upstream forward leg
        (here: an auth reject) carry no attempt-state header — absence
        means "no signal" to the worker gate, never a verdict."""
        upstream = MockUpstream("keepalive")
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            resp = _post(d, "not-a-valid-token")
            assert resp.status_code == 401
            assert _UPSTREAM_STATE_HEADER not in resp.headers
        finally:
            upstream.shutdown()
            d.shutdown()
