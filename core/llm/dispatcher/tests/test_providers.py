"""Per-provider auth-injection tests.

The dispatcher infrastructure is tested in ``test_dispatcher.py``
against the Anthropic rule. Here we drive the same infrastructure
against OpenAI and Gemini paths, asserting each provider's
auth-header shape lands correctly on the upstream and the worker's
dummy header is stripped.
"""

from __future__ import annotations

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
        # Phase C-β aggregators + ecosystem providers. Distinct
        # values so a header-injection bug that swaps providers
        # (e.g. mistral key landing on groq path) shows up
        # immediately in the upstream-captured headers.
        "mistral":     "mistral-real-NOT-LEAKED",
        "groq":        "gsk-groq-real-NOT-LEAKED",
        "together":    "together-real-NOT-LEAKED",
        "openrouter":  "sk-or-real-NOT-LEAKED",
        "fireworks":   "fw-fireworks-real-NOT-LEAKED",
        "deepinfra":   "deepinfra-real-NOT-LEAKED",
        "perplexity":  "pplx-perplexity-real-NOT-LEAKED",
        "cohere":      "cohere-real-NOT-LEAKED",
        "replicate":   "r8-replicate-real-NOT-LEAKED",
        "azure_openai":          "azure-real-NOT-LEAKED",
        "azure_openai_endpoint": "https://example-azure.invalid",
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


# ---------------------------------------------------------------------
# Phase C-β: 8 OpenAI-compatible aggregators (Bearer auth) +
# Replicate (Token auth) + Azure OpenAI (api-key + operator-set
# endpoint). Each gets the same shape of test:
#   1. Captive upstream stands in for the real provider.
#   2. POST through the dispatcher with a dummy auth header.
#   3. Assert the upstream got the real key in the right header,
#      the dummy was stripped, and the path was forwarded as-is.
# ---------------------------------------------------------------------


# Bearer-auth providers — 8 OpenAI-compatible aggregators all use
# ``Authorization: Bearer <key>``. Parameterised so a future provider
# with the same shape adds one row, not a whole new class.
_BEARER_PROVIDERS = [
    # (provider name, path tail, expected creds key, dummy header)
    ("mistral",    "v1/chat/completions",    "mistral-real-NOT-LEAKED"),
    ("groq",       "openai/v1/chat/completions", "gsk-groq-real-NOT-LEAKED"),
    ("together",   "v1/chat/completions",    "together-real-NOT-LEAKED"),
    ("openrouter", "api/v1/chat/completions", "sk-or-real-NOT-LEAKED"),
    ("fireworks",  "inference/v1/chat/completions", "fw-fireworks-real-NOT-LEAKED"),
    ("deepinfra",  "v1/openai/chat/completions", "deepinfra-real-NOT-LEAKED"),
    ("perplexity", "chat/completions",       "pplx-perplexity-real-NOT-LEAKED"),
    ("cohere",     "v1/chat",                "cohere-real-NOT-LEAKED"),
]


@pytest.mark.parametrize("provider,path_tail,expected_key", _BEARER_PROVIDERS)
def test_bearer_provider_authorization_injected(
    all_providers_creds, tmp_path, provider, path_tail, expected_key,
):
    """Bearer-auth aggregator: ``Authorization: Bearer <real>`` lands
    upstream; worker's dummy ``Authorization`` is stripped."""
    upstream = _CaptiveUpstream()
    d = _setup_with_provider_redirected(
        all_providers_creds, tmp_path, provider, upstream.base_url,
    )
    try:
        _, fd = d.allocate_worker(label=f"{provider}-test")
        token = os.read(fd, 64).decode().strip(); os.close(fd)
        _post_via_dispatcher(
            d, token, f"http://_/{provider}/{path_tail}",
            b'{"model":"x","messages":[]}',
            {"Authorization": "Bearer dummy-stripped"},
        )
        sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
        assert sent.get("authorization") == f"Bearer {expected_key}", (
            f"{provider}: expected real key in Authorization, got "
            f"{sent.get('authorization')!r}"
        )
        assert sent.get("authorization") != "Bearer dummy-stripped"
        # Path forwarded verbatim under the path_tail.
        assert upstream.captured["path"] == f"/{path_tail}"
        assert "x-raptor-token" not in sent
    finally:
        upstream.shutdown()
        d.shutdown()


class TestReplicateProvider:

    def test_token_prefix_injected_dummy_stripped(
        self, all_providers_creds, tmp_path,
    ):
        """Replicate uses ``Authorization: Token <key>`` (not Bearer).
        Dispatcher rule encodes that prefix; verify the upstream
        sees ``Token`` not ``Bearer``."""
        upstream = _CaptiveUpstream()
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, "replicate", upstream.base_url,
        )
        try:
            _, fd = d.allocate_worker(label="replicate-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            _post_via_dispatcher(
                d, token, "http://_/replicate/v1/predictions",
                b'{"version":"x","input":{}}',
                {"Authorization": "Token dummy-stripped"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("authorization") == "Token r8-replicate-real-NOT-LEAKED"
            assert sent.get("authorization") != "Token dummy-stripped"
            # Crucially, NOT a Bearer prefix:
            assert not sent.get("authorization", "").startswith("Bearer ")
            assert upstream.captured["path"] == "/v1/predictions"
        finally:
            upstream.shutdown()
            d.shutdown()


class TestAzureOpenAIProvider:

    def test_api_key_header_injected_dummy_stripped(
        self, all_providers_creds, tmp_path,
    ):
        """Azure OpenAI uses ``api-key`` header (not Authorization).
        Worker's dummy ``api-key`` is stripped; dispatcher injects
        the real one."""
        upstream = _CaptiveUpstream()
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, "azure_openai", upstream.base_url,
        )
        try:
            _, fd = d.allocate_worker(label="azure-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            _post_via_dispatcher(
                d, token,
                "http://_/azure_openai/openai/deployments/gpt-5/chat/completions"
                "?api-version=2024-02-15-preview",
                b'{"messages":[]}',
                {"api-key": "dummy-stripped"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("api-key") == "azure-real-NOT-LEAKED"
            assert sent.get("api-key") != "dummy-stripped"
            # No Bearer auth — Azure doesn't use it.
            assert "authorization" not in sent
        finally:
            upstream.shutdown()
            d.shutdown()


class TestAzureOpenAIWithoutEndpoint:

    def test_unconfigured_endpoint_uses_invalid_sentinel(self, tmp_path):
        """When ``AZURE_OPENAI_ENDPOINT`` is unset, the rule's
        upstream is the documented sentinel — operator gets a
        connect-failure rather than the dispatcher silently routing
        somewhere unexpected."""
        from core.llm.dispatcher.auth import build_rules
        creds = CredentialStore.__new__(CredentialStore)
        creds._keys = {
            "azure_openai": "key-but-no-endpoint",
            "azure_openai_endpoint": None,
        }
        rules = build_rules(creds)
        assert rules["azure_openai"].upstream_base_url == (
            "https://azure-openai-not-configured.invalid"
        )


class TestNewProvidersUnconfiguredKeyReturns503:
    """Every aggregator must surface a clean 503 when its key is
    unset — same UX as the original three. Pinned per provider so
    a future build_rules edit that drops a 503 path gets caught."""

    @pytest.mark.parametrize(
        "provider,path",
        [
            ("mistral",      "/mistral/v1/chat/completions"),
            ("groq",         "/groq/openai/v1/chat/completions"),
            ("together",     "/together/v1/chat/completions"),
            ("openrouter",   "/openrouter/api/v1/chat/completions"),
            ("fireworks",    "/fireworks/inference/v1/chat/completions"),
            ("deepinfra",    "/deepinfra/v1/openai/chat/completions"),
            ("perplexity",   "/perplexity/chat/completions"),
            ("cohere",       "/cohere/v1/chat"),
            ("replicate",    "/replicate/v1/predictions"),
            ("azure_openai", "/azure_openai/openai/deployments/x/chat/completions"),
        ],
    )
    def test_unconfigured_provider_returns_503(self, tmp_path, provider, path):
        creds = CredentialStore.__new__(CredentialStore)
        # All keys absent — every provider should 503.
        creds._keys = {p: None for p in [
            "anthropic", "openai", "gemini",
            "mistral", "groq", "together", "openrouter",
            "fireworks", "deepinfra", "perplexity",
            "cohere", "replicate",
            "azure_openai", "azure_openai_endpoint",
        ]}
        d = LLMDispatcher(
            run_id=f"unconf-{provider}", creds=creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=5,
        )
        try:
            _, fd = d.allocate_worker(label="unconf-test")
            token = os.read(fd, 64).decode().strip(); os.close(fd)
            r = _post_via_dispatcher(d, token, f"http://_{path}", b'{}', {})
            assert r.status_code == 503, (
                f"{provider}: expected 503 with key unset, got "
                f"{r.status_code} {r.text!r}"
            )
            assert provider in r.text
        finally:
            d.shutdown()


class TestCredentialStoreReadsAggregatorEnvs:
    """Real CredentialStore() — verify every aggregator key is
    read at init time and the env vars are erased afterwards."""

    def test_all_new_keys_read_then_erased(self, monkeypatch):
        env_to_set = {
            "MISTRAL_API_KEY":    "mistral-test",
            "GROQ_API_KEY":       "groq-test",
            "TOGETHER_API_KEY":   "together-test",
            "OPENROUTER_API_KEY": "openrouter-test",
            "FIREWORKS_API_KEY":  "fireworks-test",
            "DEEPINFRA_API_KEY":  "deepinfra-test",
            "PERPLEXITY_API_KEY": "perplexity-test",
            "COHERE_API_KEY":     "cohere-test",
            "REPLICATE_API_TOKEN": "replicate-test",
            "AZURE_OPENAI_API_KEY": "azure-test",
            "AZURE_OPENAI_ENDPOINT": "https://example-azure.invalid",
        }
        for k, v in env_to_set.items():
            monkeypatch.setenv(k, v)
        creds = CredentialStore()
        # Each key landed in the store under the expected name.
        assert creds.get("mistral") == "mistral-test"
        assert creds.get("groq") == "groq-test"
        assert creds.get("together") == "together-test"
        assert creds.get("openrouter") == "openrouter-test"
        assert creds.get("fireworks") == "fireworks-test"
        assert creds.get("deepinfra") == "deepinfra-test"
        assert creds.get("perplexity") == "perplexity-test"
        assert creds.get("cohere") == "cohere-test"
        assert creds.get("replicate") == "replicate-test"
        assert creds.get("azure_openai") == "azure-test"
        assert creds.get("azure_openai_endpoint") == "https://example-azure.invalid"
        # Each env var was erased from os.environ as part of read.
        for k in env_to_set:
            assert os.environ.get(k) is None, (
                f"{k} not erased from environ — leak surface"
            )
