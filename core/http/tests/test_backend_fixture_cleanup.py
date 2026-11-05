"""HTTP backend fixtures retire listeners after TLS, startup and teardown errors."""

import ast
import copy
import http.server
from pathlib import Path
import sys
import threading
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

import core.sandbox
from core.sandbox import proxy
from core.http.tests import test_egress_backend as egress
from core.http.tests import test_urllib_backend as direct


_CASES = [
    (kind, stage)
    for kind in ("redirect", "egress")
    for stage in ("construct", "start", "after-start", "body", "shutdown")
]
_CASES += [("egress", stage) for stage in ("context", "cert", "wrap", "reset")]


def _stop_before_payload(module, name, failure):
    tree = ast.parse(Path(module.__file__).read_text())
    fn = copy.deepcopy(
        next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == name
        )
    )
    replaced = []

    class StopPayload(ast.NodeTransformer):
        def visit(self, node):
            match = (
                isinstance(node, ast.For)
                and isinstance(node.target, ast.Name)
                and node.target.id == "name"
                if module is egress
                else isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id == "port" for t in node.targets
                )
            )
            if match:
                replaced.append(True)
                return ast.copy_location(
                    ast.Raise(exc=ast.Name(id="_owned_failure", ctx=ast.Load())), node
                )
            return super().visit(node)

    fn = StopPayload().visit(fn)
    assert replaced == [True], (
        "payload boundary changed; review fixture ownership check"
    )
    fn.decorator_list = []
    namespace = dict(vars(module), _owned_failure=failure)
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
            module.__file__,
            "exec",
        ),
        namespace,
    )
    return namespace[name]


@pytest.mark.parametrize("kind,stage", _CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_http_fixture_failure_retires_listener_and_worker(
    kind, stage, error, tmp_path, monkeypatch
):
    failure = error("owned HTTP backend failure")
    servers, workers = [], []
    real_server, real_thread = http.server.ThreadingHTTPServer, threading.Thread
    ready = threading.Event()
    sandbox = ModuleType("core.sandbox._macos_spawn")
    sandbox.run_sandboxed = Mock(
        side_effect=AssertionError("sandbox payload must not execute")
    )
    openssl = Mock()
    reset = Mock(side_effect=failure if stage == "reset" else None)
    module = direct if kind == "redirect" else egress
    name = (
        "test_302_not_followed_against_real_server"
        if kind == "redirect"
        else "test_real_seatbelt_child_uses_parent_proxy_allowlist"
    )
    owner = (
        direct.TestFollowRedirects()
        if kind == "redirect"
        else egress.TestSeatbeltParentProxy()
    )

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
                assert ready.wait(3), "owned HTTP loop did not start"
            raise failure

        if stage in ("start", "after-start"):
            instance.start = fail_start
        return instance

    def context(*args):
        if stage == "context":
            raise failure

        def load(**kwargs):
            if stage == "cert":
                raise failure

        def wrap(sock, **kwargs):
            if stage == "wrap":
                raise failure
            return sock

        return SimpleNamespace(load_cert_chain=load, wrap_socket=wrap)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(http.server, "ThreadingHTTPServer", server)
            patcher.setattr(threading, "Thread", thread)
            if kind == "egress":
                patcher.setattr(egress, "ThreadingHTTPServer", server)
                patcher.setattr(
                    egress,
                    "ssl",
                    SimpleNamespace(**(vars(egress.ssl) | {"SSLContext": context})),
                )
                patcher.setattr(
                    egress,
                    "subprocess",
                    SimpleNamespace(**(vars(egress.subprocess) | {"run": openssl})),
                )
                patcher.setitem(sys.modules, "core.sandbox._macos_spawn", sandbox)
                patcher.setattr(core.sandbox, "_macos_spawn", sandbox, raising=False)
                patcher.setattr(proxy, "_reset_for_tests", reset)
            invoke = _stop_before_payload(module, name, failure)
            with pytest.raises(error, match="owned HTTP backend failure"):
                if kind == "redirect":
                    invoke(owner, patcher)
                else:
                    invoke(owner, tmp_path, patcher)
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "backend fixture left its listener open"
        assert all(not worker.is_alive() for worker in workers), (
            "backend fixture left its serving thread running"
        )
        sandbox.run_sandboxed.assert_not_called()
        if kind == "egress":
            openssl.assert_called_once()
    finally:
        for instance in servers:
            if any(worker.is_alive() for worker in workers):
                real_server.shutdown(instance)
            instance.server_close()
        for worker in workers:
            if worker.ident is not None:
                real_thread.join(worker, timeout=5)
