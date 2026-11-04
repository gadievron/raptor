"""HTTP fixture cleanup survives registration and partial-start failures."""

from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packages.web.tests import http_server as module


@pytest.mark.parametrize(
    "stage",
    [
        "first_before",
        "first_after",
        "second_before",
        "second_after",
        "start_before",
        "start_after",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_http_start_failure_releases_listener_and_thread(stage, error, monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    real_thread = threading.Thread
    workers = []
    ready = threading.Event()
    action = server.service_actions

    def observe():
        action()
        ready.set()

    server.service_actions = observe
    failure = error("injected HTTP setup failure")

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start = worker.start

        def started():
            if stage == "start_before":
                raise failure
            start()
            assert ready.wait(3), "HTTP serving loop did not start"
            if stage == "start_after":
                raise failure

        worker.start = started
        workers.append(worker)
        return worker

    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    count = 0
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            with pytest.raises(error, match="injected HTTP setup failure"):
                with ExitStack() as cleanup:

                    def register(callback, *args):
                        nonlocal count
                        count += 1
                        label = "first" if count == 1 else "second"
                        if stage == label + "_before":
                            raise failure
                        cleanup.callback(callback, *args)
                        if stage == label + "_after":
                            raise failure

                    module.start_http_server(server, register)
        assert server.socket.fileno() == -1, "HTTP setup left listener open"
        assert all(not worker.is_alive() for worker in workers), (
            "HTTP setup abandoned serving thread"
        )
    finally:
        if any(worker.ident is not None for worker in workers):
            server.shutdown()
        server.server_close()
        for worker in workers:
            if worker.ident is not None:
                real_thread.join(worker, 3)


def test_unstarted_cleanup_does_not_call_blocking_shutdown():
    server = Mock()
    server.shutdown.side_effect = AssertionError(
        "shutdown before serve_forever would block"
    )
    worker = threading.Thread(target=lambda: None)
    module._stop_serving(server, worker)
    server.shutdown.assert_not_called()
    assert worker.ident is None


def test_native_http_request_and_cleanup_complete():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"owned")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = None
    try:
        with ExitStack() as cleanup:
            worker = module.start_http_server(server, cleanup.callback)
            client = http.client.HTTPConnection(*server.server_address, timeout=2)
            cleanup.callback(client.close)
            client.request("GET", "/")
            response = client.getresponse()
            assert response.status == 200
            assert response.read() == b"owned"
        assert not worker.is_alive()
        assert server.socket.fileno() == -1
    finally:
        if worker is not None and worker.ident is not None:
            server.shutdown()
            worker.join(3)
        server.server_close()
