"""Failure injection at test resource acquisition and readiness boundaries."""

import contextlib
import importlib
import os
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(
    "name",
    [
        "test_two_clients_share_worker_and_releasing_creator_preserves_other",
        "test_cancelled_request_leaves_other_lease_usable",
        "test_killed_client_releases_only_its_lease",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_broker_lease_survives_later_setup_failure(name, error, tmp_path, monkeypatch):
    from packages.joern.tests import test_broker as module

    handle = (tmp_path / "owned-lease").open("w")
    calls = []

    def fail(*args, **kwargs):
        raise error("injected later acquisition")

    def acquire(*args):
        calls.append(None)
        if len(calls) > 1:
            return fail()
        return SimpleNamespace(close=handle.close)

    owner = SimpleNamespace(root=tmp_path, token="owned-token")
    graph = SimpleNamespace(path=tmp_path, target=tmp_path)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_lease", acquire)
            if "killed_client" in name:
                patcher.setattr(subprocess, "Popen", fail)
            with pytest.raises(error, match="injected later acquisition"):
                getattr(module, name)(
                    (owner, graph, []),
                    **({"tmp_path": tmp_path} if "killed_client" in name else {}),
                )
        assert handle.closed, "earlier lease survived failed acquisition"
    finally:
        handle.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_broker_socket_owned_before_connect(error, tmp_path, monkeypatch):
    from packages.joern.tests import test_broker as module

    connection = socket.socket(socket.AF_UNIX)

    class Connection:
        def connect(self, address):
            raise error("injected connect")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            connection.close()

    @contextlib.contextmanager
    def address(root):
        yield str(tmp_path / "unused.sock")

    owner = SimpleNamespace(root=tmp_path)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "socket",
                SimpleNamespace(
                    AF_UNIX=socket.AF_UNIX, socket=lambda *args: Connection()
                ),
            )
            patcher.setattr(module.broker, "_address", address)
            with pytest.raises(error, match="injected connect"):
                module.test_unauthenticated_connection_cannot_acquire_worker(
                    (owner, None, [])
                )
        assert connection.fileno() == -1, "connect failure left the socket open"
    finally:
        connection.close()


@pytest.mark.skipif(os.name != "posix", reason="owned child process fixtures")
@pytest.mark.parametrize(
    "case",
    ["scratch-second", "scratch-read", "cache", "stress", "broker-read", "peer-owner"],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_process_setup_failure_reaps_and_closes(case, error, tmp_path, monkeypatch):
    modules = {
        "scratch": "core.security.tests.test_launch_scratch",
        "cache": "packages.sca.tests.test_cache_budget",
        "stress": "packages.sca.calibration.tests.test_stress_remeasure",
        "broker": "packages.joern.tests.test_broker",
        "peer": "packages.joern.tests.test_broker",
    }
    module = importlib.import_module(modules[case.split("-")[0]])
    children = []
    real_popen = subprocess.Popen
    lease = (tmp_path / "remaining-lease").open("w")

    def fail(*args, **kwargs):
        raise error("injected setup boundary")

    class ReadFailure:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def readline(self, *args):
            return fail()

    def popen(command, **options):
        if case == "scratch-second" and children:
            return fail()
        # Exercise cleanup using only this inert child, never the original
        # CLI, broker, scan, or security probe program supplied by the test.
        process = real_popen(
            [
                sys.executable,
                "-I",
                "-u",
                "-c",
                "import time; print('ready', flush=True); time.sleep(60)",
            ],
            **(options | {"env": dict(os.environ)}),
        )
        children.append(process)
        if case not in ("scratch-second", "peer-owner"):
            process.stdout = ReadFailure(process.stdout)
        return process

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(subprocess, "Popen", popen)
            if case.startswith("scratch"):
                invoke = lambda: (
                    module.test_parallel_instances_keep_operator_base_and_separate_child_contexts(
                        tmp_path
                    )
                )
            elif case == "cache":
                invoke = lambda: module.test_cross_process_scan_lease(tmp_path)
            elif case == "stress":
                invoke = lambda: (
                    module.test_sigterm_prints_in_flight_and_partial_summary(tmp_path)
                )
            elif case == "broker-read":
                patcher.setattr(
                    module, "_lease", lambda *args: SimpleNamespace(close=lease.close)
                )
                owner = SimpleNamespace(root=tmp_path, token="owned-token")
                graph = SimpleNamespace(path=tmp_path, target=tmp_path)
                invoke = lambda: module.test_killed_client_releases_only_its_lease(
                    (owner, graph, []), tmp_path
                )
            else:
                patcher.setattr(module.broker, "Controller", fail)
                invoke = lambda: (
                    module.test_peer_exit_during_context_check_does_not_read_recycled_pid_paths(
                        tmp_path, monkeypatch
                    )
                )
            with pytest.raises(error, match="injected setup boundary"):
                invoke()
        assert len(children) == (2 if case == "scratch-read" else 1)
        assert all(child.returncode is not None for child in children), (
            "setup failure did not reap the owned child"
        )
        assert all(
            s is None or s.closed
            for child in children
            for s in (child.stdin, child.stdout, child.stderr)
        ), "setup failure left child pipes open"
        if case == "broker-read":
            assert lease.closed
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
        lease.close()
