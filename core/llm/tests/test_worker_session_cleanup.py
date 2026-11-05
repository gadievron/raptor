"""In-process worker fixtures restore token state and own unread descriptors."""

import errno
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from core.llm.dispatcher import client
from core.llm import providers
from core.llm.tests import test_dispatcher_integration as module


_SITES = [
    (
        "TestProviderRouteSelection",
        "test_anthropic_provider_uses_dispatcher_when_socket_set",
    ),
    (
        "TestProviderRouteSelection",
        "test_openai_provider_uses_dispatcher_when_socket_set",
    ),
    (
        "TestProviderRouteSelection",
        "test_openai_compat_does_NOT_use_dispatcher_for_ollama",
    ),
    (
        "TestProviderRouteSelection",
        "test_gemini_provider_uses_dispatcher_when_socket_set",
    ),
    (
        "TestGrandchildRelay",
        "test_relay_for_grandchild_returns_inheritable_fd_with_token",
    ),
]
_CASES = [
    (stage, error)
    for stage in ("unread-error", "read-error", "env-error")
    for error in (OSError, KeyboardInterrupt)
]
_CASES += [("normal", None), ("reuse", None)]


def _identity(fd):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return None
        raise
    return stat.st_dev, stat.st_ino


@pytest.mark.parametrize("owner,name", _SITES)
@pytest.mark.parametrize("stage,error", _CASES)
@pytest.mark.parametrize("previous_env", ["present", "absent"])
def test_worker_scope_releases_unread_token_and_restores_state(
    owner, name, stage, error, previous_env, tmp_path, monkeypatch
):
    borrowed = tempfile.TemporaryFile()
    read_fd, write_fd = os.pipe()
    pipe_identity = _identity(read_fd)
    borrowed_identity = _identity(borrowed.fileno())
    os.write(write_fd, b"fixture-worker-token")
    os.close(write_fd)
    transport = httpx.HTTPTransport()
    failure = error("injected worker setup failure") if error else None
    allocated = []
    replacement = []
    sentinel = "previous-cached-token"
    real_get = client._get_or_read_token
    real_relay = client.relay_for_grandchild
    real_setenv = pytest.MonkeyPatch.setenv

    def allocate(**kwargs):
        allocated.append(read_fd)
        return "unused", read_fd

    dispatcher = SimpleNamespace(
        socket_path=tmp_path / "inert.sock",
        allocate_worker=allocate,
        shutdown=Mock(),
    )
    upstream = SimpleNamespace(shutdown=Mock())

    def reuse_number():
        os.dup2(borrowed.fileno(), read_fd)
        replacement.append(read_fd)

    def provider(config):
        if stage == "unread-error":
            raise failure
        if stage in ("read-error", "reuse") or config.provider != "ollama":
            assert real_get() == "fixture-worker-token"
        if stage == "read-error":
            raise failure
        if stage == "reuse":
            reuse_number()
        base_url = {
            "anthropic": "http://_/anthropic",
            "openai": "http://_/openai",
            "ollama": "http://localhost:11434/v1",
        }.get(config.provider, "http://_/gemini")
        return SimpleNamespace(
            client=SimpleNamespace(
                base_url=base_url,
                _client=SimpleNamespace(_transport=transport),
                _api_client=SimpleNamespace(
                    _http_options=SimpleNamespace(base_url=base_url)
                ),
            )
        )

    def get():
        if stage == "unread-error":
            raise failure
        return real_get()

    def relay():
        if stage == "read-error":
            raise failure
        if stage == "reuse":
            reuse_number()
        return real_relay()

    def setenv(patcher, key, value, *args, **kwargs):
        real_setenv(patcher, key, value, *args, **kwargs)
        if stage == "env-error" and key == "RAPTOR_LLM_TOKEN_FD":
            raise failure

    try:
        with monkeypatch.context() as patcher:
            for key in ("RAPTOR_LLM_SOCKET", "RAPTOR_LLM_TOKEN_FD"):
                if previous_env == "present":
                    patcher.setenv(key, "previous-" + key)
                else:
                    patcher.delenv(key, raising=False)
            expected_env = {
                key: os.environ.get(key)
                for key in ("RAPTOR_LLM_SOCKET", "RAPTOR_LLM_TOKEN_FD")
            }
            patcher.setattr(client, "_cached_token", sentinel)
            patcher.setattr(module, "_CaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(module, "_wired_dispatcher", Mock(return_value=dispatcher))
            patcher.setattr(module, "LLMDispatcher", Mock(return_value=dispatcher))
            patcher.setattr(module.pytest, "importorskip", lambda *args, **kwargs: None)
            patcher.setattr(client, "_get_or_read_token", get)
            patcher.setattr(client, "relay_for_grandchild", relay)
            patcher.setattr(pytest.MonkeyPatch, "setenv", setenv)
            for cls in (
                "AnthropicProvider",
                "OpenAICompatibleProvider",
                "GeminiProvider",
            ):
                patcher.setattr(providers, cls, provider)
            invoke = getattr(getattr(module, owner)(), name)
            if error:
                with pytest.raises(error, match="injected worker setup failure"):
                    invoke(None, tmp_path, patcher)
            else:
                invoke(None, tmp_path, patcher)
            assert allocated == [read_fd]
            assert _identity(read_fd) != pipe_identity, (
                "worker scope left its unread token open"
            )
            if stage == "reuse":
                assert replacement == [read_fd]
                assert _identity(read_fd) == borrowed_identity, (
                    "cleanup closed a descriptor reused by another owner"
                )
            assert client._cached_token == sentinel, (
                "worker scope leaked its cached token"
            )
            assert {key: os.environ.get(key) for key in expected_env} == expected_env, (
                "worker scope leaked its environment"
            )
            dispatcher.shutdown.assert_called_once()
    finally:
        if _identity(read_fd) in (pipe_identity, borrowed_identity):
            os.close(read_fd)
        borrowed.close()
        transport.close()
