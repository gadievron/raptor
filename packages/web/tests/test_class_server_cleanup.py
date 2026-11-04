"""Class and instance cleanups own HTTP servers across partial setup."""

import http.server
import importlib
import threading
import unittest

import pytest

_CASES = [
    ("browser", "TestBrowserEngineLive", "construction", 1),
    ("browser", "TestBrowserEngineLive", "start", 1),
    ("browser", "TestBrowserEngineLive", "none", 1),
    ("browser", "TestBrowserEngineLive", "shutdown", 1),
    ("browser", "TestOriginGateHardening", "bind", 2),
    ("browser", "TestOriginGateHardening", "construction", 1),
    ("browser", "TestOriginGateHardening", "construction", 2),
    ("browser", "TestOriginGateHardening", "start", 1),
    ("browser", "TestOriginGateHardening", "start", 2),
    ("browser", "TestOriginGateHardening", "none", 1),
    ("browser", "TestOriginGateHardening", "shutdown", 1),
    ("browser", "TestOriginGateHardening", "shutdown", 2),
    ("oob", "TestCanaryReplacesTheOriginalParameter", "construction", 1),
    ("oob", "TestCanaryReplacesTheOriginalParameter", "start", 1),
    ("oob", "TestCanaryReplacesTheOriginalParameter", "none", 1),
    ("oob", "TestCanaryReplacesTheOriginalParameter", "shutdown", 1),
]


@pytest.mark.parametrize("kind,class_name,fault,position", _CASES)
def test_partial_setup_and_teardown_release_all_servers(
    kind,
    class_name,
    fault,
    position,
    monkeypatch,
):
    name = "test_browser_live" if kind == "browser" else "test_oob"
    module = importlib.import_module(f"packages.web.tests.{name}")
    base = getattr(module, class_name)
    servers = []
    threads = []
    shutdowns = {}
    real_server = http.server.ThreadingHTTPServer
    real_thread = threading.Thread

    def server(*args, **kwargs):
        number = len(servers) + 1
        if fault == "bind" and number == position:
            raise OSError("injected server bind failure")
        instance = real_server(*args, **kwargs)
        servers.append(instance)
        shutdowns[instance] = instance.shutdown
        if fault == "shutdown" and number == position:

            def fail_shutdown():
                shutdowns[instance]()
                raise RuntimeError("injected server shutdown failure")

            instance.shutdown = fail_shutdown
        return instance

    def thread(*args, **kwargs):
        number = len(threads) + 1
        if fault == "construction" and number == position:
            raise RuntimeError("injected thread construction failure")
        instance = real_thread(*args, **kwargs)
        threads.append((instance, kwargs["target"].__self__))
        if fault == "start" and number == position:

            def fail_start():
                raise RuntimeError("injected thread start failure")

            instance.start = fail_start
        return instance

    def owned_test(self):
        if kind == "oob":
            self._serve_first_param_wins()
        assert servers and all(s.socket.fileno() >= 0 for s in servers)

    controlled = type(
        "OwnedFixture",
        (base,),
        {
            "__module__": __name__,
            "test_owned_fixture": owned_test,
        },
    )
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(http.server, "ThreadingHTTPServer", server)
            if hasattr(module, "ThreadingHTTPServer"):
                patcher.setattr(module, "ThreadingHTTPServer", server)
            patcher.setattr(threading, "Thread", thread)
            result = unittest.TestResult()
            unittest.TestSuite([controlled("test_owned_fixture")]).run(result)
        assert not result.failures
        if fault == "none":
            assert not result.errors
            assert result.testsRun == 1
        else:
            assert len(result.errors) == 1
            assert "injected" in result.errors[0][1]
        assert servers
        assert all(s.socket.fileno() == -1 for s in servers), (
            "fixture left listeners open"
        )
        assert all(not t.is_alive() for t, _ in threads), (
            "fixture left serving threads running"
        )
    finally:
        # Safely retire only servers whose loops really started; shutdown() on
        # a constructed-but-unstarted server would block indefinitely.
        for t, instance in threads:
            if t.ident is not None:
                shutdowns[instance]()
        for instance in servers:
            instance.server_close()
        for t, _ in threads:
            if t.ident is not None:
                t.join(timeout=5)
