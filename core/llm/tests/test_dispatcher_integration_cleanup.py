"""Integration fixtures release acquired resources on setup and teardown errors."""

import socket
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.llm.tests import test_dispatcher_integration as module
from packages.web.tests import http_server as support


_CALLERS = [
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
    ("TestGrandchildRelay", "test_grandchild_subprocess_uses_relayed_session"),
    (
        "TestEndToEndCredentialIsolationThroughProviders",
        "test_subprocess_via_anthropic_provider_no_env_key",
    ),
]


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("stage", ["lookup", "upstream", "rule", "assignment", "none"])
def test_wired_dispatcher_rolls_back_partial_setup(error, stage, tmp_path, monkeypatch):
    owned = socket.socket()
    failure = error("injected wire failure")
    original = SimpleNamespace(
        name="anthropic", inject_headers={}, strip_request_headers=()
    )

    class Rules(dict):
        def __getitem__(self, key):
            if stage == "lookup":
                raise failure
            return original

        def __setitem__(self, key, value):
            if stage == "assignment":
                raise failure
            super().__setitem__(key, value)

    class Upstream:
        @property
        def base_url(self):
            if stage == "upstream":
                raise failure
            return "http://127.0.0.1:1"

    dispatcher = SimpleNamespace(_rules=Rules(), shutdown=Mock(side_effect=owned.close))
    monkeypatch.setattr(module, "LLMDispatcher", Mock(return_value=dispatcher))
    monkeypatch.setattr(
        module, "ProviderRule", Mock(side_effect=failure if stage == "rule" else None)
    )
    try:
        if stage == "none":
            assert (
                module._wired_dispatcher(None, tmp_path, "anthropic", Upstream())
                is dispatcher
            )
            assert owned.fileno() != -1
            dispatcher.shutdown()
        else:
            with pytest.raises(error, match="injected wire failure"):
                module._wired_dispatcher(None, tmp_path, "anthropic", Upstream())
            assert owned.fileno() == -1, "partial setup left the dispatcher open"
        dispatcher.shutdown.assert_called_once()
    finally:
        owned.close()


@pytest.mark.parametrize("owner,name", _CALLERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("stage", ["wire", "upstream-shutdown"])
def test_captive_callers_release_all_acquired_owners(
    owner, name, error, stage, tmp_path, monkeypatch
):
    upstream_socket, dispatcher_socket = socket.socket(), socket.socket()
    failure = error("injected caller failure")

    def fail_body(*args, **kwargs):
        raise RuntimeError("inert test body")

    def shutdown_upstream():
        upstream_socket.close()
        if stage == "upstream-shutdown":
            raise failure

    upstream = SimpleNamespace(shutdown=Mock(side_effect=shutdown_upstream))
    dispatcher = SimpleNamespace(
        shutdown=Mock(side_effect=dispatcher_socket.close),
        allocate_worker=fail_body,
    )
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_CaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(
                module,
                "_wired_dispatcher",
                Mock(
                    side_effect=failure if stage == "wire" else None,
                    return_value=dispatcher,
                ),
            )
            # Subprocess callers stop at their first source-file write. No
            # SDK request, process, or credential-bearing dispatcher is created.
            patcher.setattr(Path, "write_text", fail_body)
            patcher.setattr(module.pytest, "importorskip", lambda *args, **kwargs: None)
            args = [None, tmp_path]
            if owner == "TestProviderRouteSelection":
                args.append(patcher)
            with pytest.raises(error, match="injected caller failure"):
                getattr(getattr(module, owner)(), name)(*args)
        assert upstream_socket.fileno() == -1, (
            "caller leaked upstream during wire failure"
        )
        assert upstream.shutdown.call_count == 1
        if stage != "wire":
            assert dispatcher_socket.fileno() == -1, (
                "upstream teardown skipped dispatcher cleanup"
            )
            dispatcher.shutdown.assert_called_once()
    finally:
        upstream_socket.close()
        dispatcher_socket.close()


@pytest.mark.parametrize(
    "owner,name",
    [
        ("TestPhaseBChainE2E", "test_full_chain_no_api_keys_anywhere"),
        ("TestPhaseBChainE2EGemini", "test_full_chain_gemini_no_api_keys_anywhere"),
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("stage", ["construct", "rule"])
def test_inline_chain_setup_releases_http_server(
    owner, name, error, stage, tmp_path, monkeypatch
):
    servers, threads = [], []
    real_server, real_thread = module.http.server.HTTPServer, threading.Thread
    owned = socket.socket()
    failure = error("injected inline setup failure")
    original = SimpleNamespace(
        name="fixture", inject_headers={}, strip_request_headers=()
    )
    dispatcher = SimpleNamespace(
        _rules={"anthropic": original, "gemini": original},
        shutdown=Mock(side_effect=owned.close),
    )

    def server(*args, **kwargs):
        instance = real_server(*args, **kwargs)
        servers.append(instance)
        return instance

    def thread(*args, **kwargs):
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        return instance

    proxy = SimpleNamespace(**(vars(threading) | {"Thread": thread}))
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module.http.server, "HTTPServer", server)
            patcher.setattr(module, "threading", proxy)
            patcher.setattr(support, "threading", proxy)
            patcher.setattr(
                module,
                "LLMDispatcher",
                Mock(
                    side_effect=failure if stage == "construct" else None,
                    return_value=dispatcher,
                ),
            )
            patcher.setattr(module, "ProviderRule", Mock(side_effect=failure))
            patcher.setattr(module.pytest, "importorskip", lambda *args, **kwargs: None)
            with pytest.raises(error, match="injected inline setup failure"):
                getattr(getattr(module, owner)(), name)(None, tmp_path)
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "inline setup leaked its HTTP listener"
        assert all(not thread.is_alive() for thread in threads)
        if stage == "rule":
            assert owned.fileno() == -1
            dispatcher.shutdown.assert_called_once()
    finally:
        for server in servers:
            if any(thread.is_alive() for thread in threads):
                server.shutdown()
            server.server_close()
        for thread in threads:
            if thread.ident is not None:
                thread.join(5)
        owned.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("stage", ["construct", "start", "after-start", "shutdown"])
def test_captive_http_lifecycle_retires_listener_and_thread(error, stage, monkeypatch):
    servers, threads = [], []
    real_server, real_thread = module.http.server.HTTPServer, threading.Thread
    failure = error("injected HTTP lifecycle failure")
    serving = threading.Event()

    def server(*args, **kwargs):
        instance = real_server(*args, **kwargs)
        instance.service_actions = serving.set
        servers.append(instance)
        if stage == "shutdown":
            shutdown = instance.shutdown

            def fail_shutdown():
                shutdown()
                raise failure

            instance.shutdown = fail_shutdown
        return instance

    def thread(*args, **kwargs):
        if stage == "construct":
            raise failure
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        start = instance.start

        def fail_start():
            if stage == "after-start":
                start()
                assert serving.wait(3), "HTTP loop did not become ready"
            raise failure

        if stage in ("start", "after-start"):
            instance.start = fail_start
        return instance

    proxy = SimpleNamespace(**(vars(threading) | {"Thread": thread}))
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module.http.server, "HTTPServer", server)
            patcher.setattr(module, "threading", proxy)
            patcher.setattr(support, "threading", proxy)
            with pytest.raises(error, match="injected HTTP lifecycle failure"):
                upstream = module._CaptiveUpstream()
                upstream.shutdown()
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "HTTP lifecycle leaked its listener"
        assert all(not thread.is_alive() for thread in threads)
    finally:
        for server in servers:
            if any(thread.is_alive() for thread in threads):
                # Bypass the injected shutdown failure for independent cleanup.
                real_server.shutdown(server)
            server.server_close()
        for thread in threads:
            if thread.ident is not None:
                thread.join(5)
