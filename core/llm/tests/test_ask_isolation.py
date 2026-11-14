"""Offline ask bootstrap, selected-account injection and compatibility refusals."""

from __future__ import annotations

import http.server
import json
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


@pytest.fixture
def native_setup(monkeypatch):
    from core.llm import detection

    monkeypatch.setattr(detection, "_sdk_available", lambda name: True)
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


def test_worker_response_identity_and_size_are_checked():
    model = ModelConfig(provider="gemini", model_name="fixture-model")
    data = {"content": "answer", "model": model.model_name, "provider": model.provider,
            "tokens_used": 1, "cost": 0}
    assert ask_isolation.decode_ask_response(json.dumps(data).encode(), model).content == "answer"
    for change in [{"provider": "anthropic"}, {"cost": float("nan")},
                   {"tokens_used": True}, {"api_key": "untrusted-extra"}]:
        with pytest.raises(IsolatedAskError):
            ask_isolation.decode_ask_response(json.dumps(data | change).encode(), model)


def test_cli_keyless_switch_uses_worker_and_keeps_terminal_sanitisation(monkeypatch, capsys):
    from core.llm import client as client_module
    from core.llm.config import LLMConfig
    from core.llm.providers import LLMResponse
    from core.testing.logging_state import isolated_cli_logging

    selected = ModelConfig(provider="anthropic", model_name="fixture-model", api_key="parent-only")
    config = LLMConfig(primary_model=selected, fallback_models=[], enable_caching=False)
    parent = SimpleNamespace(config=config, generate=Mock(side_effect=AssertionError("direct call")))
    worker = Mock(return_value=LLMResponse("answer\x1b[2J", selected.model_name, selected.provider, 1, 0, "stop"))
    monkeypatch.setattr(client_module, "LLMClient", lambda: parent)
    monkeypatch.setattr(ask_isolation, "run_isolated_ask", worker)
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.delenv("RAPTOR_LLM_QUIET", raising=False)
    monkeypatch.setattr(sys, "argv", ["raptor-llm-ask", "--keyless-worker", "test prompt"])
    script = Path(__file__).resolve().parents[3] / "libexec" / "raptor-llm-ask"
    loader = importlib.machinery.SourceFileLoader("keyless_ask_test_cli", str(script))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    with ExitStack() as stack:
        stack.enter_context(patch.object(sys, "path", sys.path.copy()))
        stack.enter_context(isolated_cli_logging())
        loader.exec_module(module)
        assert module.main() == 0
    worker.assert_called_once_with(selected, "test prompt", None, max_tokens=4096, temperature=None)
    parent.generate.assert_not_called()
    assert "\x1b" not in capsys.readouterr().out


# A provider-seam test adapter, not a fake native SDK. It makes a real proxy
# request in a fresh worker, keeping credentials in the trusted parent. The
# audit hook proves worker bootstrap/client generation never open models.json.
_WORKER = r'''
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


@pytest.mark.integration
@pytest.mark.parametrize("provider,header", [("anthropic", "x-api-key"), ("gemini", "x-goog-api-key")])
def test_fresh_worker_has_no_keys_or_config_reads_and_parent_injects_auth(
    native_setup, monkeypatch, tmp_path, provider, header,
):
    observed = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            observed.append(dict(self.headers))
            body = b'{"ok":true}'
            self.send_response(200)
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
        return original_spawn(dispatcher, [sys.executable, "-c", _WORKER, command[-1]], **kwargs)

    monkeypatch.setattr(ask_isolation, "_rule_for", captive_rule)
    monkeypatch.setattr(ask_isolation, "spawn_worker", test_worker)
    monkeypatch.setenv("RAPTOR_CONFIG", str(tmp_path / "models.json"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-ambient-key")
    monkeypatch.setenv("GEMINI_API_KEY", "unrelated-ambient-key")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    config = ModelConfig(provider=provider, model_name="fixture-model", api_key="selected-account", timeout=10)
    try:
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
