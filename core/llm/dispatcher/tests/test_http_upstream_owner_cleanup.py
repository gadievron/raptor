"""Captive HTTP upstreams own listeners and started threads on every failure."""

from contextlib import ExitStack
import http.server
import importlib
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packages.web.tests import http_server as support


_UPSTREAMS = [
    ("test_providers", "_CaptiveUpstream", (), 5),
    ("test_relay_limits", "_Upstream", ("firehose",), 2),
    ("test_child_ledger_vetoed_death", "_AbortSSEUpstream", (), 5),
    ("test_usage_scan_integrity", "_EchoUpstream", (), 5),
    ("test_upstream_state_header", "_CannedUpstream", (), 5),
    ("test_body_limits", "_Upstream", (), 5),
    ("test_usage_scan_seam", "_EchoUpstream", (), 5),
]


@pytest.mark.parametrize("module_name,name,args,join_timeout", _UPSTREAMS)
@pytest.mark.parametrize("stage", ["construct", "start", "after-start", "shutdown"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_upstream_failure_releases_listener_and_serving_thread(
    module_name, name, args, join_timeout, stage, error, monkeypatch
):
    module = importlib.import_module("core.llm.dispatcher.tests." + module_name)
    servers, workers, joins = [], [], []
    real_server, real_thread = http.server.HTTPServer, threading.Thread
    ready = threading.Event()
    failure = error("owned upstream lifecycle failure")

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
        start, join = instance.start, instance.join

        def join_worker(*args, **kwargs):
            joins.append((args, kwargs))
            return join(*args, **kwargs)

        def fail_start():
            if stage == "after-start":
                start()
                assert ready.wait(3), "owned serving loop did not initialize"
            raise failure

        instance.join = join_worker
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
            with pytest.raises(error, match="owned upstream lifecycle failure"):
                upstream = getattr(module, name)(*args)
                upstream.shutdown()
        assert len(servers) == 1
        assert servers[0].fileno() == -1, "upstream left its HTTP listener open"
        assert all(not worker.is_alive() for worker in workers), (
            "upstream left its serving thread running"
        )
        if stage in ("after-start", "shutdown"):
            assert joins == [((), {"timeout": join_timeout})], (
                "upstream changed its join bound or skipped joining"
            )
    finally:
        for instance in servers:
            if any(worker.is_alive() for worker in workers):
                real_server.shutdown(instance)
            instance.server_close()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=5)


@pytest.mark.parametrize("join_timeout", [None, 2])
def test_shared_http_owner_preserves_default_and_custom_join_bound(
    join_timeout, monkeypatch
):
    server = SimpleNamespace(
        serve_forever=lambda: None, shutdown=Mock(), server_close=Mock()
    )
    worker = SimpleNamespace(
        ident=1, start=Mock(), join=Mock(), is_alive=Mock(return_value=False)
    )
    monkeypatch.setattr(
        support, "threading", SimpleNamespace(Thread=Mock(return_value=worker))
    )
    options = {} if join_timeout is None else {"join_timeout": join_timeout}
    with ExitStack() as cleanup:
        assert support.start_http_server(server, cleanup.callback, **options) is worker
    worker.start.assert_called_once()
    worker.join.assert_called_once_with(
        timeout=5 if join_timeout is None else join_timeout
    )
    server.shutdown.assert_called_once()
    server.server_close.assert_called_once()
