"""Per-provider auth-injection tests.

The dispatcher infrastructure is tested in ``test_dispatcher.py``
against the Anthropic rule. Here we drive the same infrastructure
against OpenAI and Gemini paths, asserting each provider's
auth-header shape lands correctly on the upstream and the worker's
dummy header is stripped.
"""

from __future__ import annotations

import json
import os
import threading
import http.server

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import LLMDispatcher, _TOKEN_HEADER


@pytest.fixture
def all_providers_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "anthropic-real-NOT-LEAKED",
        "openai":    "sk-openai-real-NOT-LEAKED",
        "gemini":    "AIza-gemini-real-NOT-LEAKED",
    }
    return creds


class _CaptiveUpstream:
    def __init__(self):
        self.captured: dict = {}
        self_outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                self_outer.captured["headers"] = {k: v for k, v in self.headers.items()}
                self_outer.captured["path"] = self.path
                self_outer.captured["body"] = body
                resp = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.host, self.port = self._server.server_address
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _setup_with_provider_redirected(creds, tmp_path, provider: str, base_url: str):
    """Build a dispatcher and rewrite the chosen provider's
    upstream_base_url to point at the captive HTTP server."""
    d = LLMDispatcher(
        run_id=f"providers-{provider}",
        creds=creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=10,
    )
    original = d._rules[provider]
    d._rules[provider] = ProviderRule(
        name=original.name,
        upstream_base_url=base_url,
        inject_headers=original.inject_headers,
        strip_request_headers=original.strip_request_headers,
    )
    return d


def _post_via_dispatcher(d: LLMDispatcher, token: str, path: str, body: bytes,
                         dummy_headers: dict[str, str]) -> httpx.Response:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    with httpx.Client(transport=transport, timeout=10.0) as c:
        return c.post(path, content=body, headers={
            _TOKEN_HEADER: token,
            **dummy_headers,
        })


class TestAnthropicProvider:

    def test_x_api_key_injected_dummy_stripped(self, all_providers_creds, tmp_path):
        upstream = _CaptiveUpstream()
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, "anthropic", upstream.base_url,
        )
        try:
            _, fd = d.allocate_worker(label="anthropic-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            _post_via_dispatcher(
                d, token, "http://_/anthropic/v1/messages",
                b'{"x":1}',
                {"x-api-key": "dummy-stripped-please"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("x-api-key") == "anthropic-real-NOT-LEAKED"
            assert sent.get("anthropic-version") == "2023-06-01"
            assert "x-raptor-token" not in sent
        finally:
            upstream.shutdown()
            d.shutdown()


class TestOpenAIProvider:

    def test_authorization_bearer_injected(self, all_providers_creds, tmp_path):
        upstream = _CaptiveUpstream()
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, "openai", upstream.base_url,
        )
        try:
            _, fd = d.allocate_worker(label="openai-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            _post_via_dispatcher(
                d, token, "http://_/openai/v1/chat/completions",
                b'{"model":"gpt-5","messages":[]}',
                {"Authorization": "Bearer dummy-stripped"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("authorization") == "Bearer sk-openai-real-NOT-LEAKED"
            assert sent.get("authorization") != "Bearer dummy-stripped"
            # Path was forwarded under /v1/...
            assert upstream.captured["path"] == "/v1/chat/completions"
            assert "x-raptor-token" not in sent
        finally:
            upstream.shutdown()
            d.shutdown()


class TestGeminiProvider:

    def test_x_goog_api_key_injected_dummy_stripped(self, all_providers_creds, tmp_path):
        upstream = _CaptiveUpstream()
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, "gemini", upstream.base_url,
        )
        try:
            _, fd = d.allocate_worker(label="gemini-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            _post_via_dispatcher(
                d, token, "http://_/gemini/v1beta/models/gemini-2.5-pro:generateContent",
                b'{"contents":[]}',
                {"x-goog-api-key": "dummy-stripped"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("x-goog-api-key") == "AIza-gemini-real-NOT-LEAKED"
            assert sent.get("x-goog-api-key") != "dummy-stripped"
            # Path forwarded under /v1beta/...
            assert upstream.captured["path"] == "/v1beta/models/gemini-2.5-pro:generateContent"
            assert "x-raptor-token" not in sent
        finally:
            upstream.shutdown()
            d.shutdown()


class TestUnconfiguredProvider:

    def test_provider_with_unset_key_returns_503(self, tmp_path):
        creds = CredentialStore.__new__(CredentialStore)
        creds._keys = {"anthropic": None, "openai": None, "gemini": None}
        d = LLMDispatcher(
            run_id="unconf", creds=creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=5,
        )
        try:
            _, fd = d.allocate_worker(label="unconf-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            r = _post_via_dispatcher(
                d, token, "http://_/openai/v1/chat/completions",
                b'{}', {},
            )
            assert r.status_code == 503
            assert "openai" in r.text
        finally:
            d.shutdown()


class TestUnknownProviderPath:

    def test_unknown_path_prefix_returns_404(self, all_providers_creds, tmp_path):
        d = LLMDispatcher(
            run_id="unknown", creds=all_providers_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=5,
        )
        try:
            _, fd = d.allocate_worker(label="unknown-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            r = _post_via_dispatcher(
                d, token, "http://_/unknown-vendor/v1/things",
                b'{}', {},
            )
            assert r.status_code == 404
            assert "unknown" in r.text.lower()
        finally:
            d.shutdown()
