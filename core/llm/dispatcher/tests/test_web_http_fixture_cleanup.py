"""HTTP fixture ownership before yield and after normal teardown."""

from contextlib import contextmanager
import http.server
import importlib
import threading

import pytest

_CASES = [
    ("packages.web.tests.test_client_hardening", "_server", "context", "handler"),
    ("packages.web.tests.test_client_scope", "_server", "context", "none"),
    ("packages.web.tests.test_check_containment", "_listener", "context", "handler"),
    ("packages.web.tests.test_scanner_fake_target", "_fake_target", "context", "none"),
    ("packages.web.tests.test_fuzz_scoping", "_fake_target", "context", "none"),
    ("packages.web.tests.test_nuclei_live", "fixture_server", "fixture", "none"),
    ("packages.web.tests.test_ffuf_live", "fixture_server", "fixture", "none"),
    ("core.llm.dispatcher.tests.test_bedrock_signing", "upstream", "fixture", "none"),
]


@pytest.mark.parametrize(
    "module_name,name,kind,argument", _CASES, ids=[f"{m}.{n}" for m, n, _, _ in _CASES]
)
@pytest.mark.parametrize("fault", ["construction", "start", "after-start", "none"])
def test_http_fixture_owns_listener(
    module_name,
    name,
    kind,
    argument,
    fault,
    monkeypatch,
):
    module = importlib.import_module(module_name)
    servers = []
    threads = []
    real_thread = threading.Thread
    real_http = http.server.HTTPServer
    real_threading_http = http.server.ThreadingHTTPServer

    def recording(factory):
        def create(*args, **kwargs):
            server = factory(*args, **kwargs)
            servers.append(server)
            return server

        return create

    class StartFailure(real_thread):
        def start(self):
            if fault == "after-start":
                ready = threading.Event()
                server = self._target.__self__
                action = server.service_actions

                def observe():
                    action()
                    ready.set()

                server.service_actions = observe
                super().start()
                assert ready.wait(3), "HTTP serving loop did not start"
            raise RuntimeError("injected HTTP thread start failure")

    def thread(*args, **kwargs):
        if fault == "construction":
            raise RuntimeError("injected HTTP thread construction failure")
        cls = StartFailure if fault in ("start", "after-start") else real_thread
        instance = cls(*args, **kwargs)
        threads.append(instance)
        return instance

    function = getattr(module, name)
    if kind == "fixture":
        function = contextmanager(function.__wrapped__)
    args = ()
    if argument == "handler":
        args = (getattr(module, "_Handler", http.server.BaseHTTPRequestHandler),)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(http.server, "HTTPServer", recording(real_http))
            patcher.setattr(
                http.server, "ThreadingHTTPServer", recording(real_threading_http)
            )
            for attr, factory in (
                ("HTTPServer", real_http),
                ("ThreadingHTTPServer", real_threading_http),
            ):
                if hasattr(module, attr):
                    patcher.setattr(module, attr, recording(factory))
            patcher.setattr(threading, "Thread", thread)
            if fault == "none":
                with function(*args):
                    assert len(servers) == 1
                    assert servers[0].socket.fileno() >= 0
            else:
                with pytest.raises(
                    RuntimeError, match="injected HTTP thread .* failure"
                ):
                    with function(*args):
                        pytest.fail("fixture returned despite startup failure")
        assert len(servers) == 1
        assert servers[0].socket.fileno() == -1, "fixture left its listener open"
        assert all(not t.is_alive() for t in threads), "fixture left its thread running"
    finally:
        # Independent cleanup contains every red case, including before yield.
        if any(t.ident is not None for t in threads):
            for server in servers:
                server.shutdown()
        for server in servers:
            server.server_close()
        for t in threads:
            if t.ident is not None:
                t.join(timeout=5)
