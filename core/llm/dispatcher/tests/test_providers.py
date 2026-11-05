"""Per-provider auth-injection tests.

The dispatcher infrastructure is tested in ``test_dispatcher.py``
against the Anthropic rule. Here we drive the same infrastructure
against OpenAI and Gemini paths, asserting each provider's
auth-header shape lands correctly on the upstream and the worker's
dummy header is stripped.
"""

from __future__ import annotations

from contextlib import ExitStack

import os
import http.server

from packages.web.tests import http_server as http_support

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import LLMDispatcher, _TOKEN_HEADER
from core.llm.model_brokers import MODEL_BROKERS


@pytest.fixture
def all_providers_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "anthropic-real-NOT-LEAKED",
        "openai":    "sk-openai-real-NOT-LEAKED",
        "gemini":    "AIza-gemini-real-NOT-LEAKED",
        "cohere": "cohere-real-NOT-LEAKED",
        "mistral": "mistral-real-NOT-LEAKED",
        # Cloud gateways
        "azure_openai":          "azure-real-NOT-LEAKED",
        "azure_openai_endpoint": "https://example-azure.invalid",
    }
    # Distinct keys expose accidental cross-broker credential injection.
    creds._keys.update({b.name: f"{b.name}-registry-test-key" for b in MODEL_BROKERS})
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
        with ExitStack() as cleanup:
            self._thread = http_support.start_http_server(self._server, cleanup.callback)
            self.host, self.port = self._server.server_address
            self._cleanup = cleanup.pop_all()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def shutdown(self):
        self._cleanup.close()


@pytest.mark.upstream_forward
@pytest.mark.parametrize("broker", MODEL_BROKERS, ids=lambda b: b.name)
def test_registry_broker_roundtrip(all_providers_creds, tmp_path, broker):
    """New JSON rows automatically exercise the actual SDK/dispatcher boundary."""
    from core.llm.dispatcher.client import make_broker_client

    with ExitStack() as cleanup:
        upstream = _CaptiveUpstream()
        cleanup.callback(upstream.shutdown)
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, broker.name, upstream.base_url,
        )
        cleanup.callback(d.shutdown)
        token = _worker_token(d, label=f'registry-{broker.name}')
        if broker.protocol == "openai":
            with make_broker_client(broker.name, socket_path=str(d.socket_path),
                                    token=token, timeout=5) as client:
                client.chat.completions.create(
                    model="example-model", messages=[{"role": "user", "content": "test"}],
                )
            assert upstream.captured["path"] == broker.api_path + "/chat/completions"
        else:
            response = _post_via_dispatcher(
                d, token, f"http://_/{broker.name}{broker.api_path}/predictions",
                b'{"model":"example-model"}', {"Authorization": "worker-dummy"},
            )
            assert response.status_code == 200
            assert upstream.captured["path"] == broker.api_path + "/predictions"
        headers = {k.lower(): v for k, v in upstream.captured["headers"].items()}
        assert headers["authorization"] == (
            f"{broker.auth_scheme} {all_providers_creds.get(broker.name)}"
        )
        assert _TOKEN_HEADER.lower() not in headers
        assert "dummy-not-used" not in str(headers)


def _setup_with_provider_redirected(creds, tmp_path, provider: str, base_url: str):
    """Build a dispatcher and rewrite the chosen provider's
    upstream_base_url to point at the captive HTTP server."""
    try:
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
    except BaseException:
        d.shutdown()
        raise
    return d


def _worker_token(d, *, label):
    _, fd = d.allocate_worker(label=label)
    try:
        return os.read(fd, 64).decode().strip()
    finally:
        os.close(fd)


def _post_via_dispatcher(d: LLMDispatcher, token: str, path: str, body: bytes,
                         dummy_headers: dict[str, str]) -> httpx.Response:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    with httpx.Client(transport=transport, timeout=10.0) as c:
        return c.post(path, content=body, headers={
            _TOKEN_HEADER: token,
            **dummy_headers,
        })


@pytest.mark.upstream_forward
class TestAnthropicProvider:

    def test_x_api_key_injected_dummy_stripped(self, all_providers_creds, tmp_path):
        with ExitStack() as cleanup:
            upstream = _CaptiveUpstream()
            cleanup.callback(upstream.shutdown)
            d = _setup_with_provider_redirected(
                all_providers_creds, tmp_path, "anthropic", upstream.base_url,
            )
            cleanup.callback(d.shutdown)
            token = _worker_token(d, label='anthropic-test')
            _post_via_dispatcher(
                d, token, "http://_/anthropic/v1/messages",
                b'{"x":1}',
                {"x-api-key": "dummy-stripped-please"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("x-api-key") == "anthropic-real-NOT-LEAKED"
            assert sent.get("anthropic-version") == "2023-06-01"
            assert "x-raptor-token" not in sent

    def test_caller_anthropic_version_honoured(
        self, all_providers_creds, tmp_path,
    ):
        """Claude Code negotiates anthropic-version per request; the
        static rule's injected default must not clobber a
        worker-supplied value (the Bedrock leg already honours it —
        sibling parity). The credential header still always wins."""
        with ExitStack() as cleanup:
            upstream = _CaptiveUpstream()
            cleanup.callback(upstream.shutdown)
            d = _setup_with_provider_redirected(
                all_providers_creds, tmp_path, "anthropic", upstream.base_url,
            )
            cleanup.callback(d.shutdown)
            token = _worker_token(d, label='anthropic-version-test')
            _post_via_dispatcher(
                d, token, "http://_/anthropic/v1/messages",
                b'{"x":1}',
                {"x-api-key": "dummy-stripped-please",
                 "anthropic-version": "2024-10-22"},
            )
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("anthropic-version") == "2024-10-22"
            assert sent.get("x-api-key") == "anthropic-real-NOT-LEAKED"


@pytest.mark.upstream_forward
class TestOpenAIProvider:

    def test_authorization_bearer_injected(self, all_providers_creds, tmp_path):
        with ExitStack() as cleanup:
            upstream = _CaptiveUpstream()
            cleanup.callback(upstream.shutdown)
            d = _setup_with_provider_redirected(
                all_providers_creds, tmp_path, "openai", upstream.base_url,
            )
            cleanup.callback(d.shutdown)
            token = _worker_token(d, label='openai-test')
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


@pytest.mark.upstream_forward
class TestGeminiProvider:

    def test_x_goog_api_key_injected_dummy_stripped(self, all_providers_creds, tmp_path):
        with ExitStack() as cleanup:
            upstream = _CaptiveUpstream()
            cleanup.callback(upstream.shutdown)
            d = _setup_with_provider_redirected(
                all_providers_creds, tmp_path, "gemini", upstream.base_url,
            )
            cleanup.callback(d.shutdown)
            token = _worker_token(d, label='gemini-test')
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
            token = _worker_token(d, label='unconf-test')
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
            token = _worker_token(d, label='unknown-test')
            r = _post_via_dispatcher(
                d, token, "http://_/unknown-vendor/v1/things",
                b'{}', {},
            )
            assert r.status_code == 404
            assert "unknown" in r.text.lower()
        finally:
            d.shutdown()


# ---------------------------------------------------------------------
# Native Bearer providers; broker forwarding is generated from the catalog.
# ---------------------------------------------------------------------

_BEARER_PROVIDERS = [
    ("cohere", "v1/chat", "cohere-real-NOT-LEAKED"),
    ("mistral", "v1/chat/completions", "mistral-real-NOT-LEAKED"),
]


@pytest.mark.parametrize("provider,path_tail,expected_key", _BEARER_PROVIDERS)
@pytest.mark.upstream_forward
def test_bearer_provider_authorization_injected(
    all_providers_creds, tmp_path, provider, path_tail, expected_key,
):
    """Bearer-auth aggregator: ``Authorization: Bearer <real>`` lands
    upstream; worker's dummy ``Authorization`` is stripped."""
    with ExitStack() as cleanup:
        upstream = _CaptiveUpstream()
        cleanup.callback(upstream.shutdown)
        d = _setup_with_provider_redirected(
            all_providers_creds, tmp_path, provider, upstream.base_url,
        )
        cleanup.callback(d.shutdown)
        token = _worker_token(d, label=f'{provider}-test')
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


@pytest.mark.upstream_forward
class TestAzureOpenAIProvider:

    def test_api_key_header_injected_dummy_stripped(
        self, all_providers_creds, tmp_path,
    ):
        """Azure OpenAI uses ``api-key`` header (not Authorization).
        Worker's dummy ``api-key`` is stripped; dispatcher injects
        the real one."""
        with ExitStack() as cleanup:
            upstream = _CaptiveUpstream()
            cleanup.callback(upstream.shutdown)
            d = _setup_with_provider_redirected(
                all_providers_creds, tmp_path, "azure_openai", upstream.base_url,
            )
            cleanup.callback(d.shutdown)
            token = _worker_token(d, label='azure-test')
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


def _keyless_store() -> CredentialStore:
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {}
    return creds


def _rule_names() -> list[str]:
    from core.llm.dispatcher.auth import build_rules
    return sorted(build_rules(_keyless_store()))


class TestRuleTableParity:
    """The path-prefix routing map (server.py) and the auth rules
    table (auth.py:build_rules) are hand-maintained in different
    modules. Both drift directions fail closed (404 unknown path /
    503 unconfigured), so drift is silent availability loss — and a
    provider added to both tables used to get zero 503 coverage
    because the 503 test was a third hand-typed list. One parity pin
    closes the pair; the 503 test below derives from the rules table."""

    def test_prefix_map_matches_rules_table(self):
        from core.llm.dispatcher.server import _PROVIDER_FROM_PATH_PREFIX
        assert set(_PROVIDER_FROM_PATH_PREFIX.values()) == set(_rule_names())
        for prefix, name in _PROVIDER_FROM_PATH_PREFIX.items():
            assert prefix == f"/{name}/", (
                f"prefix {prefix!r} does not follow the /<provider>/ "
                f"shape for {name!r}"
            )


class TestNewProvidersUnconfiguredKeyReturns503:
    """Every provider must surface a clean 503 when its key is unset.
    Parametrised over the rules table itself so a provider added to
    production gets this pin automatically. Bedrock is excluded: its
    unconfigured path (botocore/AWS-credential resolution) has its own
    dedicated tests."""

    @pytest.mark.parametrize(
        "provider",
        [n for n in _rule_names() if n != "bedrock"],
    )
    def test_unconfigured_provider_returns_503(self, tmp_path, provider):
        # Any path under the provider prefix routes to the rule; the
        # 503 fires on the configured-check before the path suffix is
        # ever consulted.
        path = f"/{provider}/v1/chat/completions"
        creds = _keyless_store()
        d = LLMDispatcher(
            run_id=f"unconf-{provider}", creds=creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=5,
        )
        try:
            token = _worker_token(d, label='unconf-test')
            r = _post_via_dispatcher(d, token, f"http://_{path}", b'{}', {})
            assert r.status_code == 503, (
                f"{provider}: expected 503 with key unset, got "
                f"{r.status_code} {r.text!r}"
            )
            assert provider in r.text
        finally:
            d.shutdown()


class TestCredentialStoreReadsAggregatorEnvs:
    """Native env-direct SDK credentials stay; broker credentials are erased."""

    def test_native_keys_kept_and_broker_keys_erased(self, monkeypatch):
        env_to_set = {
            **{broker.api_key_env: f"{broker.name}-test" for broker in MODEL_BROKERS},
            "COHERE_API_KEY": "cohere-test",
            "MISTRAL_API_KEY": "mistral-test",
            "AZURE_OPENAI_API_KEY": "azure-test",
            "AZURE_OPENAI_ENDPOINT": "https://example-azure.invalid",
        }
        for k, v in env_to_set.items():
            monkeypatch.setenv(k, v)
        creds = CredentialStore()
        for broker in MODEL_BROKERS:
            assert creds.get(broker.name) == f"{broker.name}-test"
        for provider in ("cohere", "mistral", "azure_openai"):
            assert creds.get(provider) == env_to_set[f"{provider.upper()}_API_KEY"]
        assert creds.get("azure_openai_endpoint") == env_to_set["AZURE_OPENAI_ENDPOINT"]
        # Broker keys are parent-only; legacy native SDK keys stay available.
        broker_keys = {broker.api_key_env for broker in MODEL_BROKERS}
        for k, v in env_to_set.items():
            if k in broker_keys:
                assert k not in os.environ
            else:
                assert os.environ.get(k) == v

    def test_kept_keys_warn_once_by_name(self, monkeypatch, caplog):
        import logging

        monkeypatch.setenv("MISTRAL_API_KEY", "mistral-test-value")
        with caplog.at_level(logging.WARNING):
            CredentialStore()
        kept_warnings = [
            m for m in caplog.messages if "MISTRAL_API_KEY" in m
        ]
        assert kept_warnings, "no warning naming the kept key"
        # Names only — never the value.
        assert all("mistral-test-value" not in m for m in kept_warnings)

    def test_routable_provider_keys_still_erased(self, monkeypatch):
        # Opposite direction: providers the worker-side factories DO
        # route through the dispatcher (anthropic/openai/gemini/AWS)
        # keep the read-and-erase isolation.
        for var in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
        ):
            monkeypatch.setenv(var, f"{var.lower()}-test")
        creds = CredentialStore()
        assert creds.get("anthropic") == "anthropic_api_key-test"
        assert creds.get("openai") == "openai_api_key-test"
        assert creds.get("gemini") == "gemini_api_key-test"
        for var in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
        ):
            assert os.environ.get(var) is None, (
                f"{var} not erased — dispatcher-routable keys must "
                f"not linger in the environ"
            )
