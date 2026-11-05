"""Dispatcher test setup owns every upstream and dispatcher it acquires."""

import ast
import copy
import http.server
import inspect
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.llm.dispatcher import auth
from core.llm.dispatcher.tests import test_dispatcher as module
from packages.web.tests import http_server as support

_CALLERS = [
    (
        "TestLayer3TokenAuth",
        "test_request_with_valid_token_passes_token_check",
        "_socket_path, fd = dispatcher.allocate_worker(label='test-l3')",
        True,
    ),
    (
        "TestLayer4TokenLifecycle",
        "test_token_budget_exhaustion",
        "_socket_path, fd = d.allocate_worker(label='budget-test')",
        False,
    ),
    (
        "TestLayer4TokenLifecycle",
        "test_client_auth_renews_proactively",
        "token = self._mint_worker_token(d)",
        False,
    ),
    (
        "TestLayer4TokenLifecycle",
        "test_client_renewal_outlives_original_ttl",
        "token = self._mint_worker_token(d)",
        False,
    ),
    (
        "TestE2ECredentialIsolation",
        "test_e2e_credentials_injected_dummy_stripped",
        "_, fd = d.allocate_worker(label='e2e')",
        False,
    ),
    (
        "TestE2ECredentialIsolation",
        "test_e2e_audit_records_dispatch_without_body",
        "_, fd = d.allocate_worker(label='audit-e2e')",
        False,
    ),
    (
        "TestRealAnthropicSDKThroughDispatcher",
        "test_real_anthropic_sdk_call_succeeds",
        "_socket_path, fd = d.allocate_worker(label='sdk-e2e')",
        False,
    ),
    (
        "TestSubprocessE2E",
        "test_subprocess_uses_dispatcher_with_no_keys_in_env",
        "worker_src = tmp_path / 'worker.py'",
        False,
    ),
    (
        "TestChildPlaneSocket",
        "test_child_token_dispatches_on_child_plane",
        "from core.llm.dispatcher.usage_scan_jail import get_usage_scan_jail",
        False,
    ),
    (
        "TestE2EResponseEncodingPreserved",
        "test_gzipped_upstream_body_decompresses_at_worker",
        "_, fd = d.allocate_worker(label='gzip-e2e')",
        False,
    ),
]
_HELPERS = [
    "TestE2ECredentialIsolation",
    "TestRealAnthropicSDKThroughDispatcher",
    "TestE2EResponseEncodingPreserved",
]


def _owners(stage, failure):
    sockets = [socket.socket(), socket.socket()]
    rule = auth.ProviderRule(
        name="anthropic",
        upstream_base_url="http://127.0.0.1:1",
        inject_headers=lambda: {},
        strip_request_headers=(),
    )

    class Rules(dict):
        def __getitem__(self, name):
            if stage == "lookup":
                raise failure
            return super().__getitem__(name)

    def stop_upstream():
        sockets[0].close()
        if stage == "up-close":
            raise failure

    upstream = SimpleNamespace(
        base_url="http://127.0.0.1:1",
        shutdown=Mock(side_effect=stop_upstream),
        _server=SimpleNamespace(RequestHandlerClass=SimpleNamespace()),
    )
    dispatcher = SimpleNamespace(
        _rules=Rules(anthropic=rule), shutdown=Mock(side_effect=sockets[1].close)
    )
    return sockets, upstream, dispatcher


def _body_failure_function(owner, name, anchor, failure):
    # Execute the real ownership envelope, stopping at the original first
    # payload statement. No request, token allocation, subprocess, or
    # confinement-worker startup from that payload can run.
    tree = ast.parse(Path(module.__file__).read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == owner)
    function = copy.deepcopy(
        next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    )
    target = ast.dump(ast.parse(anchor).body[0], include_attributes=False)
    replaced = []

    class StopPayload(ast.NodeTransformer):
        def visit(self, node):
            if (
                isinstance(node, ast.stmt)
                and ast.dump(node, include_attributes=False) == target
            ):
                replaced.append(True)
                return ast.copy_location(
                    ast.Raise(exc=ast.Name(id="_owned_failure", ctx=ast.Load())), node
                )
            return super().visit(node)

    function = StopPayload().visit(function)
    assert replaced == [True], "payload boundary changed; review its ownership check"
    function.decorator_list = []
    envelope = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = dict(vars(module), _owned_failure=failure)
    exec(compile(envelope, str(module.__file__), "exec"), namespace)
    return namespace[name]


@pytest.mark.parametrize("owner,name,anchor,borrowed_dispatcher", _CALLERS)
@pytest.mark.parametrize("stage", ["lookup", "body", "up-close"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_caller_setup_and_teardown_release_owned_resources(
    owner, name, anchor, borrowed_dispatcher, stage, error, tmp_path, monkeypatch
):
    failure = error("injected ownership failure")
    sockets, upstream, dispatcher = _owners(stage, failure)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_CaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(module, "_GzipCaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(module, "LLMDispatcher", Mock(return_value=dispatcher))
            patcher.setattr(module.pytest, "importorskip", lambda *args, **kwargs: None)
            invoke = _body_failure_function(owner, name, anchor, failure)
            values = {
                "self": getattr(module, owner)(),
                "fake_creds": None,
                "tmp_path": tmp_path,
                "dispatcher": dispatcher,
                "monkeypatch": patcher,
            }
            with pytest.raises(error, match="injected ownership failure"):
                invoke(
                    **{key: values[key] for key in inspect.signature(invoke).parameters}
                )
        assert sockets[0].fileno() == -1, "caller leaked its upstream"
        upstream.shutdown.assert_called_once()
        if not borrowed_dispatcher:
            assert sockets[1].fileno() == -1, "caller leaked its dispatcher"
            dispatcher.shutdown.assert_called_once()
        else:
            assert sockets[1].fileno() != -1
            dispatcher.shutdown.assert_not_called()
    finally:
        for owned in sockets:
            owned.close()


@pytest.mark.parametrize("owner", _HELPERS)
@pytest.mark.parametrize("stage", ["construct", "lookup", "rule", "none"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_setup_helper_rolls_back_until_ownership_transfer(
    owner, stage, error, tmp_path, monkeypatch
):
    failure = error("injected helper failure")
    sockets, upstream, dispatcher = _owners(stage, failure)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_CaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(module, "_GzipCaptiveUpstream", Mock(return_value=upstream))
            patcher.setattr(
                module,
                "LLMDispatcher",
                Mock(
                    side_effect=failure if stage == "construct" else None,
                    return_value=dispatcher,
                ),
            )
            if stage == "rule":
                patcher.setattr(auth, "ProviderRule", Mock(side_effect=failure))
            args = [None, tmp_path]
            if owner == "TestE2EResponseEncodingPreserved":
                args.append(b"fixture")
            if stage == "none":
                assert getattr(module, owner)()._setup(*args) == (dispatcher, upstream)
                assert all(owned.fileno() != -1 for owned in sockets)
                dispatcher.shutdown.assert_not_called()
                upstream.shutdown.assert_not_called()
            else:
                with pytest.raises(error, match="injected helper failure"):
                    getattr(module, owner)()._setup(*args)
                assert sockets[0].fileno() == -1, "helper leaked its upstream"
                upstream.shutdown.assert_called_once()
                if stage != "construct":
                    assert sockets[1].fileno() == -1, "helper leaked its dispatcher"
                    dispatcher.shutdown.assert_called_once()
    finally:
        for owned in sockets:
            owned.close()


@pytest.mark.parametrize("owner", ["_CaptiveUpstream", "_GzipCaptiveUpstream"])
@pytest.mark.parametrize("stage", ["construct", "start", "after-start", "shutdown"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_captive_http_failure_retires_serving_thread_and_listener(
    owner, stage, error, monkeypatch
):
    servers, threads = [], []
    real_server, real_thread = http.server.HTTPServer, threading.Thread
    ready = threading.Event()
    failure = error("injected captive HTTP failure")

    def server(*args, **kwargs):
        instance = real_server(*args, **kwargs)
        servers.append(instance)
        instance.service_actions = ready.set
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
                assert ready.wait(3), "captive serving loop did not start"
            raise failure

        if stage in ("start", "after-start"):
            instance.start = fail_start
        return instance

    proxy = SimpleNamespace(**(vars(threading) | {"Thread": thread}))
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(http.server, "HTTPServer", server)
            patcher.setattr(module, "threading", proxy)
            patcher.setattr(support, "threading", proxy)
            with pytest.raises(error, match="injected captive HTTP failure"):
                upstream = (
                    getattr(module, owner)(b"fixture")
                    if owner == "_GzipCaptiveUpstream"
                    else getattr(module, owner)()
                )
                upstream.shutdown()
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "captive HTTP leaked its listener"
        assert all(not worker.is_alive() for worker in threads), (
            "captive HTTP leaked its serving thread"
        )
    finally:
        for instance in servers:
            if any(worker.is_alive() for worker in threads):
                real_server.shutdown(instance)
            instance.server_close()
        for worker in threads:
            if worker.ident is not None:
                worker.join(5)
