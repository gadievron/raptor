"""Remaining dispatcher fixtures own acquired servers, dispatchers and clients."""

import ast
import copy
import http.server
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.llm.dispatcher import auth
from core.llm.dispatcher.tests import test_child_path_allowlist as paths
from core.llm.dispatcher.tests import test_child_tokens as tokens
from core.llm.dispatcher.tests import test_handler_hardening as handler
from core.llm.dispatcher.tests import test_upstream_stale_retry as stale
from packages.web.tests import http_server as support


def _owners(stage, failure):
    owned = [socket.socket() for _ in range(3)]
    rule = auth.ProviderRule(
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

    def close(index, fault):
        def stop():
            owned[index].close()
            if stage == fault:
                raise failure

        return Mock(side_effect=stop)

    upstream = SimpleNamespace(
        base_url="http://127.0.0.1:1", shutdown=close(0, "up-close")
    )
    dispatcher = SimpleNamespace(
        _rules=Rules(anthropic=rule), shutdown=close(1, "close-d")
    )
    client = SimpleNamespace(close=close(2, "client-close"))
    return owned, upstream, dispatcher, client


@pytest.mark.parametrize("stage", ["construct", "lookup", "yield", "close-d", "none"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_child_path_fixture_retires_resources_on_every_exit(
    stage, error, tmp_path, monkeypatch
):
    failure = error("owned fixture failure")
    owned, upstream, dispatcher, client = _owners(stage, failure)
    generator = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(tokens, "_Upstream", Mock(return_value=upstream))
            patcher.setattr(
                paths,
                "LLMDispatcher",
                Mock(
                    side_effect=failure if stage == "construct" else None,
                    return_value=dispatcher,
                ),
            )
            generator = paths.dispatcher.__wrapped__(None, tmp_path)
            if stage in ("construct", "lookup"):
                with pytest.raises(error, match="owned fixture failure"):
                    next(generator)
            else:
                assert next(generator) == (dispatcher, upstream)
                assert all(item.fileno() >= 0 for item in owned)
                if stage == "none":
                    generator.close()
                else:
                    with pytest.raises(error, match="owned fixture failure"):
                        generator.throw(
                            failure
                        ) if stage == "yield" else generator.close()
        assert owned[0].fileno() == -1, "fixture left its upstream open"
        upstream.shutdown.assert_called_once()
        if stage != "construct":
            assert owned[1].fileno() == -1, "fixture left its dispatcher open"
            dispatcher.shutdown.assert_called_once()
    finally:
        if generator is not None:
            generator.close()
        for item in owned:
            item.close()


_CASES = [
    (kind, stage)
    for kind in ("handler", "stale")
    for stage in ("construct", "lookup", "body", "up-close")
]
_CASES += [("stale", stage) for stage in ("client-construct", "client-close")]


def _caller(module, name, anchor, failure):
    tree = ast.parse(Path(module.__file__).read_text())
    function = copy.deepcopy(
        next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == name
        )
    )
    target = ast.dump(ast.parse(anchor).body[0], include_attributes=False)
    matched = []

    class StopPayload(ast.NodeTransformer):
        def visit(self, node):
            if (
                isinstance(node, ast.stmt)
                and ast.dump(node, include_attributes=False) == target
            ):
                matched.append(True)
                return ast.copy_location(
                    ast.Raise(exc=ast.Name(id="_owned_failure", ctx=ast.Load())), node
                )
            return super().visit(node)

    function = StopPayload().visit(function)
    assert matched == [True], "payload boundary changed; review the ownership check"
    function.decorator_list = []
    namespace = dict(vars(module), _owned_failure=failure)
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
            str(module.__file__),
            "exec",
        ),
        namespace,
    )
    return namespace[name]


@pytest.mark.parametrize("kind,stage", _CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_remaining_callers_release_every_acquired_owner(
    kind, stage, error, tmp_path, monkeypatch
):
    failure = error("owned caller failure")
    owned, upstream, dispatcher, client = _owners(stage, failure)
    module = handler if kind == "handler" else stale
    name = (
        "test_stalled_reader_aborts_books_and_releases"
        if kind == "handler"
        else "test_oneshot_failure_never_strikes_twice"
    )
    anchor = (
        "token, _info = d.allocate_child('cc-stall', budget_usd=50.0)"
        if kind == "handler"
        else "token = _worker_token(d)"
    )
    owner = (
        handler.TestClientLegWriteTimeout()
        if kind == "handler"
        else stale.TestStaleRetryShardEvidence()
    )
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "_SlowDrainUpstream" if kind == "handler" else "MockUpstream",
                Mock(return_value=upstream),
            )
            patcher.setattr(
                module,
                "LLMDispatcher",
                Mock(
                    side_effect=failure if stage == "construct" else None,
                    return_value=dispatcher,
                ),
            )
            if kind == "stale":
                patcher.setattr(
                    module,
                    "httpx",
                    SimpleNamespace(
                        **(
                            vars(module.httpx)
                            | {
                                "Client": Mock(
                                    side_effect=failure
                                    if stage == "client-construct"
                                    else None,
                                    return_value=client,
                                )
                            }
                        )
                    ),
                )
            with pytest.raises(error, match="owned caller failure"):
                _caller(module, name, anchor, failure)(owner, None, tmp_path, patcher)
        assert owned[0].fileno() == -1, "caller left its upstream open"
        upstream.shutdown.assert_called_once()
        if stage != "construct":
            assert owned[1].fileno() == -1, "caller left its dispatcher open"
            dispatcher.shutdown.assert_called_once()
        if kind == "stale" and stage in ("body", "up-close", "client-close"):
            assert owned[2].fileno() == -1, "caller left its one-shot client open"
            client.close.assert_called_once()
    finally:
        for item in owned:
            item.close()


_HTTP_CASES = [
    (module, name, stage)
    for module, name in [
        (tokens, "_Upstream"),
        (tokens, "_GatedUpstream"),
        (handler, "_SlowDrainUpstream"),
    ]
    for stage in ("construct", "start", "after-start", "shutdown")
]
_HTTP_CASES.append((tokens, "_GatedUpstream", "release"))


@pytest.mark.parametrize("module,name,stage", _HTTP_CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_remaining_http_helpers_release_listener_and_worker(
    module, name, stage, error, monkeypatch
):
    servers, workers = [], []
    real_server, real_thread = http.server.HTTPServer, threading.Thread
    ready = threading.Event()
    failure = error("owned HTTP failure")

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

    proxy = SimpleNamespace(**(vars(threading) | {"Thread": thread}))
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(http.server, "HTTPServer", server)
            if hasattr(module, "threading"):
                patcher.setattr(module, "threading", proxy)
            patcher.setattr(support, "threading", proxy)
            with pytest.raises(error, match="owned HTTP failure"):
                upstream = (
                    getattr(module, name)("json")
                    if name == "_Upstream"
                    else getattr(module, name)()
                )
                if stage == "release":
                    release = upstream.release.set

                    def fail_release():
                        release()
                        raise failure

                    patcher.setattr(upstream.release, "set", fail_release)
                upstream.shutdown()
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "HTTP fixture left its listener open"
        assert all(not worker.is_alive() for worker in workers), (
            "HTTP fixture left its serving thread running"
        )
    finally:
        for instance in servers:
            if any(worker.is_alive() for worker in workers):
                real_server.shutdown(instance)
            instance.server_close()
        for worker in workers:
            if worker.ident is not None:
                worker.join(5)
