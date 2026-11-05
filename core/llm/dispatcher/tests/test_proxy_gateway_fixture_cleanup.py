"""Proxy and gateway fixtures own setup resources before their payload runs."""

import ast
import copy
import errno
import http.server
import os
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from core.llm.dispatcher import client, server as dispatcher_server
from core.llm.dispatcher.auth import ProviderRule
from core.llm.dispatcher.tests import test_cc_proxy_integration as cc
from packages.openant.tests import test_gateway_staging as gateway


def _identity(fd):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return None
        raise
    return stat.st_dev, stat.st_ino


def _without_payload(module, name, payload):
    function = copy.deepcopy(
        next(
            n
            for n in ast.walk(ast.parse(Path(module.__file__).read_text()))
            if isinstance(n, ast.FunctionDef) and n.name == name
        )
    )
    matched = []

    class StopPayload(ast.NodeTransformer):
        def visit(self, node):
            match = isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name)
                and t.id
                in ("port" if name.startswith("test_real_claude") else "gateway",)
                for t in node.targets
            )
            if name == "_probe":
                match = isinstance(node, ast.With) and any(
                    isinstance(item.context_expr, ast.Call)
                    and isinstance(item.context_expr.func, ast.Attribute)
                    and item.context_expr.func.attr == "TemporaryDirectory"
                    for item in node.items
                )
            if match:
                matched.append(True)
                return ast.copy_location(
                    ast.Expr(
                        value=ast.Call(
                            func=ast.Name(id="_owned_payload", ctx=ast.Load()),
                            args=[],
                            keywords=[],
                        )
                    ),
                    node,
                )
            return super().visit(node)

    function = StopPayload().visit(function)
    assert matched == [True], "payload boundary changed; review the ownership check"
    function.decorator_list = []
    namespace = dict(vars(module), _owned_payload=payload)
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
            str(module.__file__),
            "exec",
        ),
        namespace,
    )
    return namespace[name]


@pytest.mark.parametrize("stage", ["construct", "body", "up-close", "close-d"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_cli_fixture_owns_both_resources_before_payload(
    stage, error, tmp_path, monkeypatch
):
    owned = [socket.socket(), socket.socket()]
    failure = error("owned CLI fixture failure")

    def stop(index, fault):
        owned[index].close()
        if stage == fault:
            raise failure

    upstream = SimpleNamespace(
        base_url="http://127.0.0.1:1",
        shutdown=Mock(side_effect=lambda: stop(0, "up-close")),
    )
    dispatcher = SimpleNamespace(shutdown=Mock(side_effect=lambda: stop(1, "close-d")))

    def payload():
        raise failure

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(cc, "_FakeMantle", Mock(return_value=upstream))
            patcher.setattr(
                cc,
                "LLMDispatcher",
                Mock(
                    side_effect=failure if stage == "construct" else None,
                    return_value=dispatcher,
                ),
            )
            with pytest.raises(error, match="owned CLI fixture failure"):
                _without_payload(
                    cc,
                    "test_real_claude_cli_round_trip_through_credential_proxy",
                    payload,
                )(tmp_path, patcher)
        assert owned[0].fileno() == -1, "CLI fixture left its upstream open"
        upstream.shutdown.assert_called_once()
        if stage != "construct":
            assert owned[1].fileno() == -1, "CLI fixture left its dispatcher open"
            dispatcher.shutdown.assert_called_once()
    finally:
        for item in owned:
            item.close()


@pytest.mark.parametrize(
    "stage",
    [
        "construct",
        "lookup",
        "allocate",
        "stat",
        "body",
        "reuse",
        "close-d",
        "close-http",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_gateway_fixture_retires_resources_and_unread_token(
    stage, error, tmp_path, monkeypatch
):
    failure = error("owned gateway fixture failure")
    servers, workers, allocated, audit_dirs = [], [], [], []
    real_server, real_thread = http.server.HTTPServer, threading.Thread
    borrowed = tempfile.TemporaryFile()
    read_fd, write_fd = os.pipe()
    pipe_identity, borrowed_identity = _identity(read_fd), _identity(borrowed.fileno())
    os.write(write_fd, b"fixture-gateway-token")
    os.close(write_fd)
    dispatcher_socket = socket.socket()
    rule = ProviderRule(
        name="anthropic",
        upstream_base_url="http://127.0.0.1:1",
        inject_headers=lambda: {},
        strip_request_headers=(),
    )

    class Rules(dict):
        def __getitem__(self, key):
            if stage == "lookup":
                raise failure
            return super().__getitem__(key)

    def stop_dispatcher():
        assert all(directory.exists() for directory in audit_dirs), (
            "dispatcher cleanup ran after temporary-directory removal"
        )
        dispatcher_socket.close()
        if stage == "close-d":
            raise failure

    def allocate(**kwargs):
        if stage == "allocate":
            raise failure
        allocated.append(read_fd)
        return "inert.sock", read_fd

    dispatcher = SimpleNamespace(
        _rules=Rules(anthropic=rule),
        allocate_worker=allocate,
        shutdown=Mock(side_effect=stop_dispatcher),
    )

    def construct(**kwargs):
        if stage == "construct":
            raise failure
        audit_dirs.append(Path(kwargs["audit_path"]).parent)
        return dispatcher

    def server(*args, **kwargs):
        instance = real_server(*args, **kwargs)
        servers.append(instance)
        if stage == "close-http":
            shutdown = instance.shutdown

            def fail_shutdown():
                shutdown()
                raise failure

            instance.shutdown = fail_shutdown
        return instance

    def thread(*args, **kwargs):
        instance = real_thread(*args, **kwargs)
        workers.append(instance)
        return instance

    def stat(fd):
        if stage == "stat" and fd == read_fd:
            raise failure
        return os.fstat(fd)

    def payload():
        if stage == "reuse":
            assert client._get_or_read_token() == "fixture-gateway-token"
            os.dup2(borrowed.fileno(), read_fd)
        raise failure

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(client, "_cached_token", "previous-cached-token")
            patcher.setattr(dispatcher_server, "LLMDispatcher", construct)
            patcher.setattr(http.server, "HTTPServer", server)
            patcher.setattr(threading, "Thread", thread)
            patcher.setattr(
                gateway, "os", SimpleNamespace(**(vars(os) | {"fstat": stat}))
            )
            with pytest.raises(error, match="owned gateway fixture failure"):
                _without_payload(
                    gateway,
                    "test_staged_credentials_round_trip_then_die_at_settlement",
                    payload,
                )(gateway.TestGatewayAgainstRealDispatcher())
            assert client._cached_token == "previous-cached-token"
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "gateway fixture left its HTTP listener open"
        assert all(not worker.is_alive() for worker in workers)
        if stage != "construct":
            assert dispatcher_socket.fileno() == -1, (
                "gateway fixture left its dispatcher open"
            )
            dispatcher.shutdown.assert_called_once()
        if allocated:
            assert _identity(read_fd) != pipe_identity, (
                "gateway fixture left its unread token open"
            )
        if stage == "reuse":
            assert _identity(read_fd) == borrowed_identity, (
                "token cleanup closed a reused descriptor"
            )
    finally:
        for instance in servers:
            if any(worker.is_alive() for worker in workers):
                real_server.shutdown(instance)
            instance.server_close()
        for worker in workers:
            if worker.ident is not None:
                real_thread.join(worker, timeout=5)
        dispatcher_socket.close()
        if _identity(read_fd) in (pipe_identity, borrowed_identity):
            os.close(read_fd)
        borrowed.close()


@pytest.mark.parametrize("kind", ["mantle", "probe"])
@pytest.mark.parametrize("stage", ["construct", "start", "after-start", "shutdown"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_proxy_http_startup_and_shutdown_own_listener_and_thread(
    kind, stage, error, monkeypatch
):
    servers, workers = [], []
    real_server, real_thread = (
        http.server.ThreadingHTTPServer if kind == "mantle" else http.server.HTTPServer,
        threading.Thread,
    )
    ready = threading.Event()
    failure = error("owned proxy HTTP failure")

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
        workers.append(instance)
        start = instance.start

        def fail_start():
            if stage == "after-start":
                start()
                assert ready.wait(3), "owned HTTP server did not initialize"
            raise failure

        if stage in ("start", "after-start"):
            instance.start = fail_start
        return instance

    def payload():
        raise failure

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                http.server,
                "ThreadingHTTPServer" if kind == "mantle" else "HTTPServer",
                server,
            )
            patcher.setattr(threading, "Thread", thread)
            with pytest.raises(error, match="owned proxy HTTP failure"):
                if kind == "mantle":
                    cc._FakeMantle().shutdown()
                else:
                    _without_payload(gateway, "_probe", payload)(
                        gateway.TestLoopbackReachableFromSandboxLane()
                    )
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "proxy fixture left its listener open"
        assert all(not worker.is_alive() for worker in workers), (
            "proxy fixture left its serving thread running"
        )
    finally:
        for instance in servers:
            if any(worker.is_alive() for worker in workers):
                real_server.shutdown(instance)
            instance.server_close()
        for worker in workers:
            if worker.ident is not None:
                real_thread.join(worker, timeout=5)


@pytest.mark.parametrize("streaming", [False, True])
def test_fake_mantle_wire_response_remains_compatible(streaming):
    upstream = cc._FakeMantle()
    try:
        with httpx.Client(trust_env=False, timeout=3) as session:
            result = session.post(
                upstream.base_url + "/anthropic/v1/messages",
                json={"stream": streaming},
                headers={"Authorization": "Bearer fixture-only"},
            )
        assert result.status_code == 200
        assert upstream.messages_hits == 1
        assert upstream.captured_headers[0]["Authorization"] == "Bearer fixture-only"
        if streaming:
            assert result.content == cc._sse_reply("PROOF-SMOKE-OK")
        else:
            assert result.json()["content"][0]["text"] == "PROOF-SMOKE-OK"
    finally:
        upstream.shutdown()
