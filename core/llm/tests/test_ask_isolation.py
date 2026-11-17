"""Offline ask bootstrap, selected-account injection and compatibility refusals."""

from __future__ import annotations

import http.server
import json
import logging
import os
import sys
import threading
import importlib.machinery
import importlib.util
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from core.llm import ask_isolation
from core.llm.ask_isolation import IsolatedAskError
from core.llm.config import ModelConfig
from core.security.credential_env import ANTHROPIC_FIRST_PARTY_AUTH_VARS


@pytest.fixture
def native_setup(monkeypatch):
    from core.llm import detection

    monkeypatch.setattr(detection, "_sdk_available", lambda name: True)
    for name in list(os.environ):
        if name.startswith("GOOGLE_"):
            monkeypatch.delenv(name, raising=False)
    for name in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_OAUTH_TOKEN",
                 "ANTHROPIC_BASE_URL", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GEMINI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("provider,header", [("anthropic", "x-api-key"), ("gemini", "x-goog-api-key")])
def test_rule_pins_selected_entry_account(native_setup, monkeypatch, provider, header):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-ambient-key")
    monkeypatch.setenv("GEMINI_API_KEY", "unrelated-ambient-key")
    model = ModelConfig(provider=provider, model_name="fixture-model", api_key="selected-account")
    rule = ask_isolation._rule_for(model)
    model.api_key = "changed-after-bootstrap"
    assert rule.inject_headers()[header] == "selected-account"


@pytest.mark.parametrize("change", [
    {"provider": "openai"}, {"api_key": None}, {"enabled": False},
    {"api_base": "https://custom.example.test/v1"},
], ids=["other-provider", "missing-key", "disabled", "custom-endpoint"])
def test_unsupported_setups_do_not_spawn_or_fall_back(native_setup, monkeypatch, change):
    def no_spawn(*args, **kwargs):
        pytest.fail("unsupported setup must be refused before spawn")

    monkeypatch.setattr(ask_isolation, "spawn_worker", no_spawn)
    config = ModelConfig(provider="anthropic", model_name="fixture-model", api_key="selected-account")
    with pytest.raises(IsolatedAskError):
        ask_isolation.run_isolated_ask(replace(config, **change), "test", None)


def test_missing_native_sdk_is_not_an_openai_compatibility_fallback(monkeypatch):
    from core.llm import detection

    monkeypatch.setattr(detection, "_sdk_available", lambda name: False)
    config = ModelConfig(provider="gemini", model_name="fixture-model", api_key="selected-account")
    with pytest.raises(IsolatedAskError, match="native SDK"):
        ask_isolation.run_isolated_ask(config, "test", None)


def test_additional_google_setup_does_not_silently_change_backend(native_setup, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "fixture-project")
    model = ModelConfig(provider="gemini", model_name="fixture-model", api_key="selected-account")
    with pytest.raises(IsolatedAskError, match="Additional Google SDK"):
        ask_isolation.run_isolated_ask(model, "test", None)


@pytest.mark.parametrize("name", [name for name in ANTHROPIC_FIRST_PARTY_AUTH_VARS
                                  if name != "ANTHROPIC_API_KEY"])
def test_alternate_anthropic_auth_requires_compatibility(native_setup, monkeypatch, name):
    monkeypatch.setenv(name, "fixture-alternate-auth")
    model = ModelConfig(provider="anthropic", model_name="fixture-model", api_key="selected-account")
    with pytest.raises(IsolatedAskError, match="Custom Anthropic authentication"):
        ask_isolation._rule_for(model)


def test_worker_response_identity_and_size_are_checked():
    model = ModelConfig(provider="gemini", model_name="fixture-model")
    data = {"content": "answer", "model": model.model_name, "provider": model.provider,
            "tokens_used": 1, "cost": 0}
    assert ask_isolation.decode_ask_response(json.dumps(data).encode(), model).content == "answer"
    for change in [{"provider": "anthropic"}, {"cost": float("nan")},
                   {"tokens_used": True}, {"api_key": "untrusted-extra"}]:
        with pytest.raises(IsolatedAskError):
            ask_isolation.decode_ask_response(json.dumps(data | change).encode(), model)


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
@pytest.mark.parametrize("timeout", [120, 0.125])
def test_keyless_setup_preflight_does_not_start_dispatcher(native_setup, monkeypatch, provider, timeout):
    def no_dispatch(*args, **kwargs):
        pytest.fail("setup eligibility started a dispatcher or worker")

    monkeypatch.setattr(ask_isolation, "LLMDispatcher", no_dispatch)
    monkeypatch.setattr(ask_isolation, "spawn_worker", no_dispatch)
    selected = ModelConfig(provider=provider, model_name="fixture-model", api_key="parent-only", timeout=timeout)
    assert ask_isolation.supports_isolated_ask(selected)


@pytest.mark.parametrize("change", [
    {"provider": "openai"}, {"provider": "bedrock"}, {"provider": "claudecode"},
    {"api_key": None}, {"enabled": False}, {"api_base": "https://custom.example.test/v1"},
    {"model_name": "models/fixture-model"}, {"timeout": 0}, {"timeout": None},
    {"timeout": float("inf")}, {"max_context": 0},
], ids=["openai", "bedrock", "claudecode", "no-key", "disabled", "custom-endpoint",
        "model-path", "no-timeout", "null-timeout", "infinite-timeout", "invalid-context"])
def test_incompatible_setup_is_classified_before_routing(native_setup, change):
    selected = ModelConfig(provider="anthropic", model_name="fixture-model", api_key="parent-only")
    assert not ask_isolation.supports_isolated_ask(replace(selected, **change))


def test_missing_sdk_keeps_compatibility_routing(monkeypatch):
    from core.llm import detection

    monkeypatch.setattr(detection, "_sdk_available", lambda name: False)
    selected = ModelConfig(provider="gemini", model_name="fixture-model", api_key="parent-only")
    assert not ask_isolation.supports_isolated_ask(selected)


def test_non_posix_setup_keeps_compatibility_routing(monkeypatch):
    monkeypatch.setattr(ask_isolation, "os", SimpleNamespace(name="nt"))
    selected = ModelConfig(provider="gemini", model_name="fixture-model", api_key="parent-only")
    assert not ask_isolation.supports_isolated_ask(selected)


def _run_ask_cli(monkeypatch, *args):
    """Run the actual CLI with owned import, environment and logging state."""
    from core.testing.logging_state import isolated_cli_logging

    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(sys, "argv", ["raptor-llm-ask", *args])
    script = Path(__file__).resolve().parents[3] / "libexec" / "raptor-llm-ask"
    loader = importlib.machinery.SourceFileLoader("keyless_ask_test_cli", str(script))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    keys = ("RAPTOR_DIR", "RAPTOR_LLM_QUIET")
    missing = object()
    environment = {key: os.environ.get(key, missing) for key in keys}
    names = ("raptor", "httpx", "httpcore")
    loggers = [logging.getLogger(name) for name in names]
    levels = {logger: logger.level for logger in loggers}
    handler_levels = {handler: handler.level for logger in loggers for handler in logger.handlers}
    with ExitStack() as stack:
        stack.enter_context(patch.object(sys, "path", sys.path.copy()))
        state = stack.enter_context(pytest.MonkeyPatch.context())
        for key in keys:
            present = key in os.environ
            state.setenv(key, os.environ.get(key, ""))
            if not present:
                state.delenv(key)
        stack.enter_context(isolated_cli_logging(logger_names=names))
        for handler, level in handler_levels.items():
            stack.callback(handler.setLevel, level)
        loader.exec_module(module)
        result = module.main()
    assert {key: os.environ.get(key, missing) for key in keys} == environment
    assert {logger: logger.level for logger in loggers} == levels
    assert {handler: handler.level for handler in handler_levels} == handler_levels
    return result


def _stub_ask_setup(monkeypatch, selected):
    from core.llm import config as config_module, transcript
    from core.llm.config import LLMConfig
    from core.llm.dispatcher import lifecycle
    from core.llm.providers import LLMResponse

    config = LLMConfig(primary_model=selected, fallback_models=[], specialized_models={}, enable_caching=False)
    response = LLMResponse("answer\x1b[2J", selected.model_name, selected.provider, 1, 0, "stop")
    parent = SimpleNamespace(config=config, generate=Mock(return_value=response),
                             generate_structured=Mock(return_value=SimpleNamespace(
                                 result={"answer": "structured"}, model=selected.model_name, cost=0)))
    builder = Mock(return_value=parent)
    worker = Mock(return_value=response)
    route = Mock()
    monkeypatch.setattr(config_module, "LLMConfig", lambda **kwargs: config)
    monkeypatch.setattr(transcript, "build_llm_client", builder)
    monkeypatch.setattr(ask_isolation, "run_isolated_ask", worker)
    monkeypatch.setattr(lifecycle, "ensure_route_for_model_configs", route)
    return parent, builder, worker, route


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
@pytest.mark.parametrize("explicit_model", [False, True], ids=["default-model", "explicit-model"])
def test_cli_automatically_uses_worker_and_keeps_terminal_sanitisation(
    native_setup, monkeypatch, capsys, provider, explicit_model,
):
    selected = ModelConfig(provider=provider, model_name="fixture-model", api_key="parent-only")
    parent, builder, worker, route = _stub_ask_setup(monkeypatch, selected)
    args = ["--model", selected.model_name] if explicit_model else []
    assert _run_ask_cli(monkeypatch, *args, "test prompt") == 0
    worker.assert_called_once_with(selected, "test prompt", None, max_tokens=4096, temperature=None)
    builder.assert_not_called()
    parent.generate.assert_not_called()
    route.assert_not_called()
    assert "\x1b" not in capsys.readouterr().out


@pytest.mark.parametrize("change", [
    {"provider": "openai"}, {"provider": "bedrock"},
    {"api_base": "https://custom.example.test/v1"}, {"timeout": 0},
], ids=["other-provider", "cloud-provider", "custom-endpoint", "unbounded-timeout"])
def test_cli_unsupported_setup_keeps_existing_provider_path(native_setup, monkeypatch, change):
    selected = replace(ModelConfig(provider="anthropic", model_name="fixture-model", api_key="parent-only"), **change)
    parent, builder, worker, route = _stub_ask_setup(monkeypatch, selected)
    assert _run_ask_cli(monkeypatch, "test prompt") == 0
    builder.assert_called_once_with(parent.config)
    parent.generate.assert_called_once_with("test prompt", system_prompt=None, model_config=selected, max_tokens=4096)
    route.assert_called_once_with([selected], label="raptor-llm-ask")
    worker.assert_not_called()


@pytest.mark.parametrize("provider,env_name", [
    ("anthropic", "CLAUDE_CODE_OAUTH_TOKEN"), ("gemini", "GOOGLE_CLOUD_PROJECT"),
])
def test_cli_alternate_setup_keeps_existing_provider_path(native_setup, monkeypatch, provider, env_name):
    selected = ModelConfig(provider=provider, model_name="fixture-model", api_key="parent-only")
    parent, builder, worker, _route = _stub_ask_setup(monkeypatch, selected)
    monkeypatch.setenv(env_name, "fixture-alternate-setup")
    assert _run_ask_cli(monkeypatch, "test prompt") == 0
    builder.assert_called_once_with(parent.config)
    parent.generate.assert_called_once()
    worker.assert_not_called()


def test_cli_worker_failure_never_constructs_direct_client(native_setup, monkeypatch, capsys):
    selected = ModelConfig(provider="gemini", model_name="fixture-model", api_key="parent-only")
    parent, builder, worker, route = _stub_ask_setup(monkeypatch, selected)
    worker.side_effect = IsolatedAskError("proxy unavailable")
    assert _run_ask_cli(monkeypatch, "test prompt") == 1
    worker.assert_called_once()
    builder.assert_not_called()
    parent.generate.assert_not_called()
    route.assert_not_called()
    assert "proxy unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("mode", ["record", "replay"])
def test_cli_transcript_mode_reaches_worker_without_parent_client(native_setup, monkeypatch, tmp_path, mode):
    selected = ModelConfig(provider="gemini", model_name="fixture-model", api_key="parent-only")
    parent, builder, worker, _route = _stub_ask_setup(monkeypatch, selected)
    monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"{mode}:{tmp_path / 'transcript.jsonl'}")
    assert _run_ask_cli(monkeypatch, "test prompt") == 0
    worker.assert_called_once()
    builder.assert_not_called()
    parent.generate.assert_not_called()


def test_cli_preflight_error_is_not_a_compatibility_fallback(native_setup, monkeypatch):
    selected = ModelConfig(provider="gemini", model_name="fixture-model", api_key="parent-only")
    parent, builder, worker, route = _stub_ask_setup(monkeypatch, selected)
    monkeypatch.setattr(ask_isolation, "supports_isolated_ask", Mock(side_effect=RuntimeError("setup failed")))
    assert _run_ask_cli(monkeypatch, "test prompt") == 1
    builder.assert_not_called()
    parent.generate.assert_not_called()
    worker.assert_not_called()
    route.assert_not_called()


def test_cli_zero_token_override_uses_configured_limit(native_setup, monkeypatch):
    selected = ModelConfig(provider="gemini", model_name="fixture-model", api_key="parent-only", max_tokens=768)
    _parent, _builder, worker, _route = _stub_ask_setup(monkeypatch, selected)
    assert _run_ask_cli(monkeypatch, "--max-tokens", "0", "test prompt") == 0
    worker.assert_called_once_with(selected, "test prompt", None, max_tokens=768, temperature=None)


def test_cli_structured_output_keeps_existing_provider_path(native_setup, monkeypatch, tmp_path):
    selected = ModelConfig(provider="anthropic", model_name="fixture-model", api_key="parent-only")
    parent, builder, worker, _route = _stub_ask_setup(monkeypatch, selected)
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"type": "object", "properties": {"answer": {"type": "string"}}}))
    assert _run_ask_cli(monkeypatch, "--json-schema", str(schema), "test prompt") == 0
    builder.assert_called_once_with(parent.config)
    parent.generate_structured.assert_called_once()
    worker.assert_not_called()


def test_cli_primary_probe_never_selects_request_route(native_setup, monkeypatch, capsys):
    selected = ModelConfig(provider="anthropic", model_name="fixture-model", api_key="parent-only")
    _parent, builder, worker, route = _stub_ask_setup(monkeypatch, selected)
    eligibility = Mock(side_effect=AssertionError("probe selected a route"))
    monkeypatch.setattr(ask_isolation, "supports_isolated_ask", eligibility)
    assert _run_ask_cli(monkeypatch, "--show-primary") == 0
    assert capsys.readouterr().out == "anthropic/fixture-model\n"
    eligibility.assert_not_called()
    builder.assert_not_called()
    worker.assert_not_called()
    route.assert_not_called()


def test_cli_temporary_worker_flag_is_removed(monkeypatch):
    with pytest.raises(SystemExit) as error:
        _run_ask_cli(monkeypatch, "--keyless-worker", "test prompt")
    assert error.value.code == 2


# A provider-seam test adapter, not a fake native SDK. It makes a real proxy
# request in a fresh worker, keeping credentials in the trusted parent. The
# audit hook proves worker bootstrap/client generation never open models.json.
_AUDITED_BOOTSTRAP = r'''
import os, sys
def audit(event, args):
    if event == "open" and isinstance(args[0], (str, bytes)):
        name = os.fsdecode(args[0])
        if name.endswith("models.json"):
            raise AssertionError("worker opened model credentials")
sys.addaudithook(audit)
from core.config import RaptorConfig
assert not (set(RaptorConfig.LLM_API_KEY_VARS) & set(os.environ))
assert "RAPTOR_CONFIG" not in os.environ
'''

_WORKER = _AUDITED_BOOTSTRAP + r'''
from core.llm import client, detection
detection._sdk_available = lambda name: True
def no_discovery(*args, **kwargs):
    raise AssertionError("worker attempted model/setup discovery")
detection.detect_llm_availability = no_discovery
from core.llm.providers import LLMProvider, LLMResponse
class Provider(LLMProvider):
    def generate(self, prompt, system_prompt=None, **kwargs):
        from core.llm.dispatcher.client import read_token, _make_httpx_client
        assert self.config.api_key is None and self.config.api_base is None
        assert os.environ["RAPTOR_LLM_TOKEN_RENEW"] == "0"
        path = "/v1/messages" if self.config.provider == "anthropic" else "/v1beta/models/fixture-model:generateContent"
        with _make_httpx_client(os.environ["RAPTOR_LLM_SOCKET"], read_token(), timeout=10) as http:
            response = http.post("http://_/" + self.config.provider + path,
                headers={"Authorization": "Bearer dummy"},
                json={"model": self.config.model_name, "prompt": prompt})
            response.raise_for_status()
        return LLMResponse("worker-ok", self.config.model_name, self.config.provider, 1, 0, "stop")
    def generate_structured(self, *args, **kwargs):
        raise AssertionError("unexpected structured call")
client.create_provider = Provider
from core.llm.ask_worker import main
raise SystemExit(main())
'''

_NATIVE_WORKER = _AUDITED_BOOTSTRAP + r'''
from core.llm import detection
def no_discovery(*args, **kwargs):
    raise AssertionError("native worker attempted model/setup discovery")
detection.detect_llm_availability = no_discovery
from core.llm.ask_worker import main
raise SystemExit(main())
'''


@pytest.mark.integration
@pytest.mark.parametrize("provider,header", [("anthropic", "x-api-key"), ("gemini", "x-goog-api-key")])
@pytest.mark.parametrize("native_sdk", [False, True], ids=["provider-seam", "native-sdk"])
@pytest.mark.parametrize("via_cli", [False, True], ids=["bootstrap", "default-cli"])
def test_fresh_worker_has_no_keys_or_config_reads_and_parent_injects_auth(
    native_setup, monkeypatch, tmp_path, capsys, provider, header, native_sdk, via_cli,
):
    if native_sdk:
        pytest.importorskip("anthropic" if provider == "anthropic" else "google.genai")
    observed = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            observed.append(dict(self.headers))
            if native_sdk and provider == "anthropic":
                payload = {
                    "id": "msg_fixture", "type": "message", "role": "assistant",
                    "model": "fixture-model", "content": [{"type": "text", "text": "worker-ok"}],
                    "stop_reason": "end_turn", "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            elif native_sdk:
                payload = {
                    "candidates": [{"content": {"parts": [{"text": "worker-ok"}], "role": "model"},
                                    "finishReason": "STOP"}],
                    "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1,
                                      "totalTokenCount": 2},
                    "modelVersion": "fixture-model",
                }
            else:
                payload = {"ok": True}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    original_rule = ask_isolation._rule_for
    original_spawn = ask_isolation.spawn_worker

    def captive_rule(model):
        return replace(original_rule(model), upstream_base_url=f"http://127.0.0.1:{server.server_port}")

    def test_worker(dispatcher, command, **kwargs):
        program = _NATIVE_WORKER if native_sdk else _WORKER
        return original_spawn(dispatcher, [sys.executable, "-c", program, command[-1]], **kwargs)

    monkeypatch.setattr(ask_isolation, "_rule_for", captive_rule)
    monkeypatch.setattr(ask_isolation, "spawn_worker", test_worker)
    monkeypatch.setenv("RAPTOR_CONFIG", str(tmp_path / "models.json"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-ambient-key")
    monkeypatch.setenv("GEMINI_API_KEY", "unrelated-ambient-key")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    config = ModelConfig(provider=provider, model_name="fixture-model", api_key="selected-account", timeout=10)
    try:
        if via_cli:
            from core.llm import config as config_module
            from core.llm.config import LLMConfig

            setup = LLMConfig(primary_model=config, fallback_models=[], specialized_models={})
            monkeypatch.setattr(config_module, "LLMConfig", lambda **kwargs: setup)
            assert _run_ask_cli(monkeypatch, "test prompt") == 0
            assert capsys.readouterr().out == "worker-ok\n"
        else:
            response = ask_isolation.run_isolated_ask(config, "test prompt", None)
            assert response.content == "worker-ok"
        assert len(observed) == 1
        headers = {name.lower(): value for name, value in observed[0].items()}
        assert headers[header] == "selected-account"
        assert "authorization" not in headers
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
