"""HTTP fixture cleanup must continue after body or teardown failures."""

from contextlib import contextmanager
import importlib
import socketserver
import threading
from types import SimpleNamespace

import pytest

from core.testing.module_bindings import patch_module_attribute
from packages.web.tests import http_server as http_support

from core.llm.dispatcher.tests.test_web_http_fixture_cleanup import _CASES


@contextmanager
def _record_servers(monkeypatch, fault):
    servers, threads, joined = [], [], []
    shutdowns, closes = {}, {}
    real_init = socketserver.TCPServer.__init__
    real_thread = threading.Thread
    real_join = threading.Thread.join

    def initialize(server, *args, **kwargs):
        real_init(server, *args, **kwargs)
        servers.append(server)
        shutdowns[server] = server.shutdown
        closes[server] = server.server_close

        def shutdown():
            shutdowns[server]()
            if fault == "shutdown":
                raise OSError("injected shutdown failure")

        def close():
            closes[server]()
            if fault == "close":
                raise OSError("injected close failure")

        server.shutdown = shutdown
        server.server_close = close

    def thread(*args, **kwargs):
        if fault == "construction":
            raise OSError("injected thread construction failure")
        instance = real_thread(*args, **kwargs)
        threads.append(instance)

        def join(*args, **kwargs):
            joined.append(instance)
            return real_join(instance, *args, **kwargs)

        instance.join = join
        if fault == "start":

            def start():
                raise OSError("injected thread start failure")

            instance.start = start
        return instance

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(socketserver.TCPServer, "__init__", initialize)
            patch_module_attribute(patcher, http_support, "threading", "Thread", thread)
            yield servers, threads, joined
    finally:
        # Independent retirement also contains failures of the code under test.
        if any(t.ident is not None for t in threads):
            for server in servers:
                shutdowns[server]()
        for server in servers:
            closes[server]()
        for instance in threads:
            if instance.ident is not None:
                real_join(instance, timeout=5)


def _assert_retired(servers, threads, joined):
    assert len(servers) == 1
    assert servers[0].socket.fileno() == -1, "fixture left its listener open"
    assert all(not t.is_alive() for t in threads), "fixture left a serving thread"
    assert all(t in joined for t in threads if t.ident is not None), (
        "fixture skipped joining its serving thread"
    )


@pytest.mark.parametrize("module_name,name,kind,argument", _CASES)
@pytest.mark.parametrize("fault", ["shutdown", "close", "body", "none"])
def test_context_server_unwinds_all_cleanup(
    module_name, name, kind, argument, fault, monkeypatch
):
    import http.server

    module = importlib.import_module(module_name)
    function = getattr(module, name)
    if kind == "fixture":
        function = contextmanager(function.__wrapped__)
    args = (
        (getattr(module, "_Handler", http.server.BaseHTTPRequestHandler),)
        if argument == "handler"
        else ()
    )
    with _record_servers(monkeypatch, fault) as (servers, threads, joined):

        def exercise():
            with function(*args):
                assert servers[0].socket.fileno() >= 0
                if fault == "body":
                    raise OSError("injected body failure")

        if fault == "none":
            exercise()
        else:
            with pytest.raises(OSError, match=f"injected {fault} failure"):
                exercise()
        _assert_retired(servers, threads, joined)


_INLINE = [
    (kind, fault)
    for kind in ("browser", "drip")
    for fault in ("construction", "start", "shutdown", "close", "body", "none")
]
_INLINE += [("browser", "late-setup")]


@pytest.mark.parametrize("kind,fault", _INLINE)
def test_inline_server_owns_setup_and_teardown(kind, fault, tmp_path, monkeypatch):
    clients = []

    class Client:
        def __init__(self, base, **kwargs):
            self.base = base
            self.closed = False
            clients.append(self)
            self._browser = SimpleNamespace(
                new_browser_cdp_session=lambda: SimpleNamespace(
                    send=lambda _: {"arguments": ["--no-sandbox"]}
                )
            )

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def close(self):
            self.closed = True

        def get(self, path):
            if fault == "body":
                raise OSError("injected body failure")
            return SimpleNamespace(status_code=200, content=b"y")

        def render(self, path):
            self.get(path)
            return SimpleNamespace(links=[self.base + "/owned-js"])

    def delenv(*args, **kwargs):
        if fault == "late-setup":
            raise OSError("injected late-setup failure")
        monkeypatch.delenv(*args, **kwargs)

    with _record_servers(monkeypatch, fault) as (servers, threads, joined):
        with monkeypatch.context() as patcher:
            if kind == "browser":
                from packages.web import browser
                from packages.web.tests import test_browser_sandbox_native as module

                real_importorskip = pytest.importorskip
                patcher.setattr(
                    pytest,
                    "importorskip",
                    lambda name, **kwargs: (
                        SimpleNamespace()
                        if name == "playwright.sync_api"
                        else real_importorskip(name, **kwargs)
                    ),
                )
                patcher.setattr(browser, "BrowserEngine", Client)
                invoke = lambda: (
                    module.test_real_browser_javascript_and_explicit_inner_policy(
                        tmp_path,
                        SimpleNamespace(delenv=delenv),
                        True,
                        lambda *args: None,
                    )
                )
            else:
                from packages.web.tests import test_client_hardening as module

                patcher.setattr(module, "WebClient", Client)
                invoke = lambda: (
                    module.test_drip_fed_body_is_cut_at_the_wall_clock_deadline(
                        monkeypatch
                    )
                )
            if fault == "none":
                invoke()
            else:
                with pytest.raises(OSError, match="injected .* failure"):
                    invoke()
        _assert_retired(servers, threads, joined)
        assert all(c.closed for c in clients), "fixture left its client open"
