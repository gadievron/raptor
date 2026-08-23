"""Fail-loud guard: provider-shaped model ids on the wrong transport.

The observed failure: a standalone audit run whose Bedrock entry could
not get a dispatcher route fell back to claudecode/session-default, and
`claude -p --model us.anthropic...` on a non-Bedrock CLI shipped the
Bedrock-shaped id to the direct Anthropic API — a bare HTTP 400 with
no routing context.  The guard raises at provider CONSTRUCTION with an
actionable message naming the misroute and the config remedy; no
request is ever built, no subprocess spawned, no network touched.

Also pins the three-route contract: the guard must ONLY trip on
cross-shaped ids — legitimate claudecode ids (bare catalog names,
``session-default``, aliases, Vertex ids) and Bedrock ids on a
Bedrock-backed CLI pass untouched, so the fallback ORDER itself is
preserved.
"""

from __future__ import annotations

import pytest

from core.llm.config import ModelConfig


@pytest.fixture(autouse=True)
def _neutral_cc_env(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_USE_MANTLE", raising=False)


# ---------------------------------------------------------------------------
# Shape predicate
# ---------------------------------------------------------------------------

class TestBedrockShapedModelId:

    @pytest.mark.parametrize("model_id", [
        "us.anthropic.claude-opus-4-8-v1:0",
        "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "global.anthropic.claude-haiku-4-5",
        "apac.amazon.nova-pro-v1:0",   # vendor without a Family mapping
        "anthropic.claude-opus-4-8",   # bare Mantle-surface id
        "meta.llama3-70b-instruct-v1:0",
        "mistral.mistral-large-2402-v1:0",
        "cohere.command-r-plus-v1:0",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-8",
    ])
    def test_shaped(self, model_id):
        from core.llm.bedrock_prefixes import bedrock_shaped_model_id
        assert bedrock_shaped_model_id(model_id)

    @pytest.mark.parametrize("model_id", [
        "claude-opus-4-8",
        "claude-sonnet-4-5-20250929",
        "session-default",             # claudecode sentinel
        "opus",                        # shorthand alias
        "sonnet[1m]",
        "claude-opus-4@20250514",      # Vertex id shape
        "gpt-5",
        "gemini-2.5-pro",
        "",
    ])
    def test_not_shaped(self, model_id):
        from core.llm.bedrock_prefixes import bedrock_shaped_model_id
        assert not bedrock_shaped_model_id(model_id)


# ---------------------------------------------------------------------------
# claudecode transport
# ---------------------------------------------------------------------------

def _cc_config(model_name: str, provider: str = "claudecode") -> ModelConfig:
    return ModelConfig(
        provider=provider, model_name=model_name, api_key=None,
        max_tokens=1024, max_context=32000,
    )


class TestClaudecodeGuard:

    def test_evidence_shape_bedrock_id_on_direct_api_cli(self):
        """The exact failure from the field: Bedrock-shaped id reaching
        `claude -p` on a non-Bedrock CLI → clear error, no call."""
        from core.llm.providers import (
            ModelTransportMismatchError,
            create_provider,
        )
        with pytest.raises(ModelTransportMismatchError) as exc:
            create_provider(_cc_config("us.anthropic.claude-opus-4-8-v1:0"))
        msg = str(exc.value)
        assert "us.anthropic.claude-opus-4-8-v1:0" in msg
        assert "Bedrock-shaped" in msg
        assert "claudecode" in msg
        # The remedies must be actionable config statements.
        assert '"provider": "bedrock"' in msg
        assert "CLAUDE_CODE_USE_BEDROCK" in msg

    def test_resumable_transport_guarded_too(self):
        from core.llm.providers import (
            ModelTransportMismatchError,
            create_provider,
        )
        with pytest.raises(ModelTransportMismatchError):
            create_provider(_cc_config(
                "anthropic.claude-opus-4-8", provider="claudecode-resumable",
            ))

    def test_no_network_or_subprocess(self, monkeypatch):
        """Construction-time raise: the transport must never be
        invoked for a misrouted id."""
        import core.llm.cc_adapter as cc_adapter
        from core.llm.providers import (
            ModelTransportMismatchError,
            create_provider,
        )

        def _explode(*a, **k):  # pragma: no cover — must not run
            raise AssertionError("transport invoked despite misroute")

        monkeypatch.setattr(cc_adapter, "run_cc_streaming", _explode,
                            raising=False)
        monkeypatch.setattr(cc_adapter, "build_cc_command", _explode)
        with pytest.raises(ModelTransportMismatchError):
            create_provider(_cc_config("us.anthropic.claude-opus-4-8-v1:0"))

    def test_bedrock_backed_cli_serves_bedrock_ids(self, monkeypatch):
        """CLAUDE_CODE_USE_BEDROCK set → the CLI serves Bedrock ids
        natively; the guard must not trip."""
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        from core.llm.providers import create_provider
        p = create_provider(_cc_config("us.anthropic.claude-opus-4-8-v1:0"))
        assert p is not None

    @pytest.mark.parametrize("model_name", [
        "session-default",
        "claude-opus-4-8",
        "opus",
        "claude-opus-4@20250514",
    ])
    def test_legitimate_claudecode_ids_pass(self, model_name):
        """Fallback-order preservation: legit claudecode configs
        construct exactly as before — the guard is invisible to them."""
        from core.llm.providers import create_provider
        p = create_provider(_cc_config(model_name))
        assert p is not None

    def test_guard_error_is_non_retryable(self):
        """The fallback chain must move on immediately — burning
        max_retries on a deterministic misroute helps nobody."""
        from core.llm.client import _is_retryable_error
        from core.llm.providers import (
            ModelTransportMismatchError,
            create_provider,
        )
        with pytest.raises(ModelTransportMismatchError) as exc:
            create_provider(_cc_config("anthropic.claude-opus-4-8"))
        assert not _is_retryable_error(exc.value)


# ---------------------------------------------------------------------------
# direct Anthropic API transport
# ---------------------------------------------------------------------------

class TestAnthropicDirectGuard:

    def test_bedrock_id_on_direct_api_fails_loud(self):
        from core.llm.providers import (
            ModelTransportMismatchError,
            create_provider,
        )
        with pytest.raises(ModelTransportMismatchError) as exc:
            create_provider(ModelConfig(
                provider="anthropic",
                model_name="us.anthropic.claude-opus-4-8-v1:0",
                api_key="sk-ant-test",
                max_tokens=1024, max_context=32000,
            ))
        msg = str(exc.value)
        assert "direct Anthropic API" in msg
        assert '"provider": "bedrock"' in msg

    def test_custom_gateway_exempt(self):
        """Operator-supplied api_base is their own gateway contract —
        Bedrock-shaped ids may be exactly what it serves."""
        from core.llm.providers import create_provider
        p = create_provider(ModelConfig(
            provider="anthropic",
            model_name="anthropic.claude-opus-4-8",
            api_key="gw-key",
            api_base="https://gateway.example/v1",
            max_tokens=1024, max_context=32000,
        ))
        assert p is not None

    def test_bare_ids_unaffected(self):
        from core.llm.providers import create_provider
        p = create_provider(ModelConfig(
            provider="anthropic",
            model_name="claude-opus-4-8",
            api_key="sk-ant-test",
            max_tokens=1024, max_context=32000,
        ))
        assert p is not None

    def test_bedrock_provider_route_not_guarded(self, monkeypatch):
        """provider="bedrock" reuses the AnthropicProvider class with a
        dispatcher-routed client — Bedrock ids are its native
        vocabulary and must construct with a route present."""
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/route.sock")

        import core.llm.dispatcher.client as dclient
        from core.llm.providers import create_provider

        anthropic = pytest.importorskip("anthropic")
        # Real SDK client instances (offline at construction) — the
        # bedrock branch feeds its client into instructor, which
        # type-checks it.
        sentinel = anthropic.Anthropic(api_key="stub-route")
        monkeypatch.setattr(
            dclient, "make_bedrock_client", lambda **k: sentinel,
        )
        # AnthropicProvider first builds the dispatcher-routed
        # anthropic client (route present), then the bedrock branch
        # swaps it — stub both; neither touches the fake socket.
        monkeypatch.setattr(
            dclient, "make_anthropic_client",
            lambda **k: anthropic.Anthropic(api_key="stub-route"),
        )
        p = create_provider(ModelConfig(
            provider="bedrock",
            model_name="us.anthropic.claude-opus-4-8-v1:0",
            api_key=None,
            max_tokens=1024, max_context=32000,
        ))
        assert p.client is sentinel


# ---------------------------------------------------------------------------
# client-level: the misroute surfaces, no upstream call
# ---------------------------------------------------------------------------

class TestClientLevelMisroute:

    def test_generate_surfaces_misroute_without_any_call(self, monkeypatch):
        """End-to-end evidence shape at the LLMClient layer: the final
        error names the misroute + remedy, and the transport is never
        invoked (no subprocess, no network)."""
        import core.llm.cc_adapter as cc_adapter
        from core.llm.client import LLMClient
        from core.llm.config import LLMConfig

        def _explode(*a, **k):  # pragma: no cover — must not run
            raise AssertionError("transport invoked despite misroute")

        monkeypatch.setattr(cc_adapter, "run_cc_streaming", _explode,
                            raising=False)

        cfg = LLMConfig(
            primary_model=_cc_config("us.anthropic.claude-opus-4-8-v1:0"),
            fallback_models=[],
        )
        client = LLMClient(config=cfg)
        client.config.enable_cache = False
        with pytest.raises(RuntimeError) as exc:
            client.generate("ping")
        assert "Bedrock-shaped" in str(exc.value)
