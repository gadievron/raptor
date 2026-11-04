"""Broker fixtures own listeners even before their serving threads start."""

import contextlib
import importlib
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace

import pytest

_SITES = ("fixture", "idle", "lease", "replacement")
_CASES = [(site, fault, 1) for site in _SITES for fault in ("construction", "start")]
_CASES += [("replacement", fault, 2) for fault in ("construction", "start")]
_CASES += [(site, fault, 1) for site in _SITES[:3] for fault in ("event", "early-exit")]
_CASES += [("lease", "graph-write", 1)]


@pytest.mark.skipif(os.name != "posix", reason="owned AF_UNIX controller fixtures")
@pytest.mark.parametrize("site,fault,position", _CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_controller_setup_failure_retires_listener_and_services(
    site, fault, position, error, monkeypatch, request
):
    from packages.joern.tests import test_broker as module

    support = None
    with contextlib.suppress(ModuleNotFoundError):
        support = importlib.import_module("packages.joern.tests.broker_server")
    owners, threads, closed = [], [], []
    real_controller = module.broker.Controller
    real_thread, real_event = threading.Thread, threading.Event
    real_write = Path.write_bytes

    def fail(*args, **kwargs):
        raise error("injected controller setup failure")

    def controller(*args, **kwargs):
        owner = real_controller(*args, **kwargs)
        owners.append(owner)
        close = owner.services.close

        def close_services():
            closed.append(owner)
            close()

        owner.services.close = close_services
        if fault == "early-exit":
            # Simulate a serving loop that exits before its normal cleanup.
            # Only fixture ownership is under test; no JVM is launched.
            owner.serve = lambda **kwargs: None
        return owner

    def thread(*args, **kwargs):
        target = kwargs.get("target")
        if not any(target == owner.serve for owner in owners):
            return real_thread(*args, **kwargs)
        if fault == "construction" and len(owners) == position:
            return fail()
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        if fault == "start" and len(owners) == position:
            instance.start = fail
        return instance

    def event():
        if owners and fault == "event":
            return fail()
        instance = real_event()
        if owners and fault == "early-exit":
            instance.wait = fail
        return instance

    def write(path, data):
        if fault == "graph-write" and path.name == "graph.bin":
            return fail()
        return real_write(path, data)

    proxy = SimpleNamespace(**(vars(threading) | {"Thread": thread, "Event": event}))
    with tempfile.TemporaryDirectory(
        prefix="raptor-broker-startup-", dir="/tmp"
    ) as raw:
        root = Path(raw)
        fixture = None
        try:
            module.prereqs.reset_path_cache()
            with monkeypatch.context() as patcher:
                patcher.setattr(module.broker, "Controller", controller)
                patcher.setattr(module, "threading", proxy)
                if support is not None:
                    patcher.setattr(support, "threading", proxy)
                patcher.setattr(Path, "write_bytes", write)
                if site == "fixture":
                    fixture = module.controller.__wrapped__(root, request)
                    invoke = lambda: next(fixture)
                elif site == "idle":
                    invoke = lambda: (
                        module.test_controller_production_idle_deadline_closes_socket_and_services(
                            root
                        )
                    )
                elif site == "lease":
                    invoke = lambda: (
                        module.test_idle_deadline_does_not_expire_a_live_lease(root)
                    )
                else:
                    invoke = lambda: (
                        module.test_old_controller_cleanup_cannot_remove_concurrent_discovery_record(
                            root, monkeypatch
                        )
                    )
                with pytest.raises(error, match="injected controller setup failure"):
                    invoke()
            assert len(owners) == position
            assert all(owner.listener.fileno() == -1 for owner in owners), (
                "setup left a controller listener open"
            )
            assert all(closed.count(owner) == 1 for owner in owners), (
                "setup did not close controller services exactly once"
            )
            assert all(not thread.is_alive() for thread in threads), (
                "setup left a controller thread running"
            )
        finally:
            # Independent cleanup contains old-code failures without joining
            # threads that were constructed but never successfully started.
            for owner in owners:
                owner.stopping.set()
            for instance in threads:
                if instance.ident is not None:
                    instance.join(5)
            for owner in owners:
                owner.listener.close()
                owner.services.close()
            if fixture is not None:
                fixture.close()
            module.prereqs.reset_path_cache()


@pytest.mark.skipif(os.name != "posix", reason="owned AF_UNIX controller fixtures")
@pytest.mark.parametrize(
    "name",
    [
        "test_macos_peer_pid_reuse_does_not_reuse_controller",
        "test_peer_cgroup_namespace_is_checked_even_with_same_cgroup_path",
        "test_changing_peer_context_is_refused",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_peer_setup_failure_retires_controller(name, error, tmp_path, monkeypatch):
    from unittest import mock
    from packages.joern.tests import test_broker as module

    owners, closed = [], []
    real_controller = module.broker.Controller

    def controller(*args, **kwargs):
        owner = real_controller(*args, **kwargs)
        owners.append(owner)
        close = owner.services.close

        def close_services():
            closed.append(owner)
            close()

        owner.services.close = close_services
        return owner

    def fail(*args, **kwargs):
        raise error("injected peer setup failure")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module.broker, "Controller", controller)
            patcher.setattr(mock, "Mock", fail)
            with pytest.raises(error, match="injected peer setup failure"):
                getattr(module, name)(tmp_path, patcher)
        assert len(owners) == 1
        assert owners[0].listener.fileno() == -1, "peer setup left its listener open"
        assert closed == owners, "peer setup left controller services unclosed"
    finally:
        for owner in owners:
            owner.listener.close()
            owner.services.close()
