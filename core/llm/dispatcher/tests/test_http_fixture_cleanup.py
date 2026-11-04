"""Captive HTTP helpers release listeners when serving-thread setup fails."""

import http.server
import importlib
import threading
from types import SimpleNamespace

import pytest


_CASES = [
    ("test_body_limits", "_Upstream", ()),
    ("test_cc_proxy_integration", "_FakeMantle", ()),
    ("test_child_ledger_vetoed_death", "_AbortSSEUpstream", ()),
    ("test_child_tokens", "_Upstream", ()),
    ("test_child_tokens", "_GatedUpstream", ()),
    ("test_dispatcher", "_CaptiveUpstream", ()),
    ("test_dispatcher", "_GzipCaptiveUpstream", (b"{}",)),
    ("test_handler_hardening", "_SlowDrainUpstream", ()),
    ("test_providers", "_CaptiveUpstream", ()),
    ("test_upstream_state_header", "_CannedUpstream", ()),
    ("test_usage_scan_integrity", "_EchoUpstream", ()),
    ("test_usage_scan_seam", "_EchoUpstream", ()),
]


@pytest.mark.parametrize(
    "module_name,class_name,args",
    _CASES,
    ids=[f"{module}.{name}" for module, name, _ in _CASES],
)
@pytest.mark.parametrize("fault", ["construction", "start"])
def test_http_helper_failed_startup_closes_listener(
    module_name,
    class_name,
    args,
    fault,
    monkeypatch,
):
    module = importlib.import_module(f"core.llm.dispatcher.tests.{module_name}")
    servers = []
    real_http = http.server.HTTPServer
    real_threading_http = http.server.ThreadingHTTPServer

    def recording(factory):
        def create(*args, **kwargs):
            server = factory(*args, **kwargs)
            servers.append(server)
            return server

        return create

    class StartFailure(threading.Thread):
        def start(self):
            raise RuntimeError("injected serving-thread start failure")

    def thread(*args, **kwargs):
        if fault == "construction":
            raise RuntimeError("injected serving-thread construction failure")
        return StartFailure(*args, **kwargs)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(http.server, "HTTPServer", recording(real_http))
            patcher.setattr(
                http.server, "ThreadingHTTPServer", recording(real_threading_http)
            )
            patcher.setattr(
                module,
                "threading",
                SimpleNamespace(
                    **(vars(threading) | {"Thread": thread}),
                ),
            )
            with pytest.raises(
                RuntimeError, match="injected serving-thread .* failure"
            ):
                getattr(module, class_name)(*args)
        assert len(servers) == 1
        assert servers[0].socket.fileno() == -1, "failed startup left its listener open"
    finally:
        # No serving thread started: shutdown() would block on these paths.
        for server in servers:
            server.server_close()
