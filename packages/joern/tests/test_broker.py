"""Real local sockets and client death, with a controlled JVM substitute."""

from contextlib import ExitStack
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from core.testing.processes import reap_on_exit

from packages.joern import broker, prereqs
from packages.joern.models import JoernCPG
from packages.joern.services import GraphServices
from packages.joern.tests.broker_server import controller_server
from packages.joern.tests.test_graph_services import Worker
from packages.joern.tunables import JoernTunables


@pytest.fixture
def tmp_path():
    # Exercise the pathname transport on macOS rather than its path-length
    # refusal. Deliberate overlong-path tests construct their own paths.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="raptor-pytest-joern-", dir="/tmp") as raw:
        yield Path(raw).resolve()


@pytest.fixture(autouse=True)
def _fresh_toolchain_paths(monkeypatch):
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(prereqs, {"_resolved_joern": None, "_joern_resolved": False,
        "_resolved_joern_parse": None, "_joern_parse_resolved": False,
        "_resolved_java": None, "_java_resolved": False}):
        try:
            yield
        finally:
            monkeypatch.undo()


@pytest.fixture
def controller(tmp_path, request):
    import os
    import tempfile
    # This fixture is imported by test_lifecycle too, where this module's
    # tmp_path override is not in scope. Own the short socket root here.
    directory = tempfile.TemporaryDirectory(prefix="raptor-pytest-broker-", dir="/tmp")
    request.addfinalizer(directory.cleanup)
    root = Path(directory.name).resolve() / "runtime"
    assert len(os.fsencode(root / "rpc.sock")) <= 100
    root.mkdir(mode=0o700)
    workers = []

    def factory(*a, **kw):
        worker = Worker()
        workers.append(worker)
        return worker

    pool = GraphServices(root / "graphs", factory=factory)
    owner = broker.Controller(root, "fixture-token", services=pool)
    with controller_server(owner) as start_server:
        ready = threading.Event()
        original = owner.start

        def start():
            original()
            ready.set()

        owner.start = start
        start_server(idle_seconds=60)
        try:
            assert ready.wait(2)
            graph_path = tmp_path / "graph.bin"
            graph_path.write_bytes(b"graph")
            yield owner, JoernCPG(graph_path, tmp_path), workers
        finally:
            for worker in workers:
                worker.proceed.set()


@pytest.mark.parametrize("fault", ["readiness", "graph-write"])
def test_controller_setup_failure_stops_server(tmp_path, monkeypatch, request, fault):
    from types import SimpleNamespace
    from packages.joern.tests import broker_server

    threads = []
    owners = []
    real_thread = threading.Thread
    ready = threading.Event()
    real_write = Path.write_bytes

    def make_thread(*args, **kwargs):
        owners.append(kwargs["target"].__self__)
        thread = real_thread(*args, **kwargs)
        threads.append(thread)
        return thread

    def wait(timeout):
        assert ready.wait(timeout), "controlled server did not start"
        if fault == "readiness":
            raise TimeoutError("injected readiness failure")
        return True

    def write(path, data):
        if path.name == "graph.bin" and fault == "graph-write":
            raise OSError("injected graph-write failure")
        return real_write(path, data)

    module = sys.modules[__name__]
    fixture = controller.__wrapped__(tmp_path, request)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", SimpleNamespace(
                Thread=make_thread,
                Event=lambda: SimpleNamespace(set=ready.set, wait=wait),
            ))
            patcher.setattr(broker_server, "threading", module.threading)
            patcher.setattr(Path, "write_bytes", write)
            with pytest.raises(OSError, match="injected .* failure"):
                next(fixture)
        assert len(threads) == 1
        assert not threads[0].is_alive(), "failed setup left its server thread running"
        assert owners[0].stopping.is_set()
    finally:
        # Reclaim the controlled server even when the regression assertion fails.
        for owner in owners:
            owner.stopping.set()
        for thread in threads:
            thread.join(5)
        fixture.close()


def _lease(owner, graph):
    return broker.BrokerLease.acquire(owner.root, owner.token, graph, JoernTunables())


def test_two_clients_share_worker_and_releasing_creator_preserves_other(controller):
    owner, graph, workers = controller
    with ExitStack() as cleanup:
        first = _lease(owner, graph)
        cleanup.callback(first.close)
        second = _lease(owner, graph)
        cleanup.callback(second.close)
        assert len(workers) == 1
        first.close()
        assert second.query("query").ok
        assert workers[0].stops == 0
        second.close()
        assert workers[0].stopped.wait(2)
        assert workers[0].stops == 1


@pytest.mark.skipif(sys.platform != "linux", reason="cross-process reuse requires comparable Linux confinement contexts")
def test_killed_client_releases_only_its_lease(controller, tmp_path):
    owner, graph, workers = controller
    program = '''
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from packages.joern.broker import BrokerLease
from packages.joern.models import JoernCPG
from packages.joern.tunables import JoernTunables
data = json.loads(sys.stdin.readline())
try:
    lease = BrokerLease.acquire(Path(data['root']), data['token'],
        JoernCPG(Path(data['graph']), Path(data['target'])), JoernTunables())
except BaseException as exc:
    print(f'acquire failed: {exc}', file=sys.stderr, flush=True)
    raise
print('leased', flush=True)
sys.stdin.readline()
os._exit(0)
'''
    with ExitStack() as cleanup:
        remaining = _lease(owner, graph)
        cleanup.callback(remaining.close)
        process = subprocess.Popen([sys.executable, "-I", "-c", program,
                                    str(Path(__file__).resolve().parents[3])],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        cleanup.enter_context(reap_on_exit(process))
        process.stdin.write(json.dumps({"root": str(owner.root), "token": owner.token,
                                       "graph": str(graph.path), "target": str(graph.target)}) + "\n")
        process.stdin.flush()
        line = process.stdout.readline().strip()
        if line != "leased":
            # EOF on stdout can precede waitpid observing the exit.
            # Reap the child before deciding whether stderr is available.
            try:
                _, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate(timeout=3)
            rc = process.returncode
            pytest.fail(
                f"child did not acquire lease: stdout={line!r}, "
                f"returncode={rc}, stderr:\n{stderr}"
            )
        process.kill()
        process.wait(timeout=3)
        assert remaining.query("query").ok
        assert len(workers) == 1 and workers[0].stops == 0
    assert workers[0].stopped.wait(2)


def test_unauthenticated_connection_cannot_acquire_worker(controller):
    owner, graph, workers = controller
    with socket.socket(socket.AF_UNIX) as connection:
        with broker._address(owner.root) as address:
            connection.connect(address)
        broker._send(connection, {"token": "wrong"})
        with pytest.raises(EOFError):
            broker._receive(connection, limit=8192, deadline=time.monotonic() + 1)
    assert not workers


def test_oversized_request_is_refused_before_reading_body(controller):
    owner, graph, workers = controller
    with broker._connect(owner.root, owner.token) as connection:
        connection.sendall(struct.pack("!I", broker._REQUEST_MAX + 1))
        with pytest.raises(EOFError):
            broker._receive(connection, limit=8192, deadline=time.monotonic() + 1)
    assert not workers


def test_partial_frame_has_absolute_deadline():
    first, second = socket.socketpair()
    with first, second:
        first.sendall(struct.pack("!I", 100) + b"{")
        with pytest.raises(TimeoutError):
            broker._receive(second, limit=8192, deadline=time.monotonic() + 0.01)


def test_cancelled_request_leaves_other_lease_usable(controller):
    owner, graph, workers = controller
    with ExitStack() as cleanup:
        first = _lease(owner, graph)
        cleanup.callback(first.close)
        second = _lease(owner, graph)
        cleanup.callback(second.close)
        worker = workers[0]
        worker.proceed.clear()
        try:
            result = first.query("query", cancel_check=lambda: True)
            assert "cancel" in result.errors[0]
            worker.proceed.set()
            if not second.status()["ready"]:
                assert second.recover()["ready"]
            assert second.query("next query").ok
        finally:
            worker.proceed.set()


def test_explicit_release_acknowledges_last_worker_teardown(controller):
    owner, graph, workers = controller
    lease = _lease(owner, graph)
    assert lease.close()
    assert workers[0].stops == 1
    assert not workers[0].path.exists()
    assert lease.close()


def test_macos_peer_pid_reuse_does_not_reuse_controller(tmp_path, monkeypatch):
    from unittest.mock import Mock
    monkeypatch.setattr(broker.sys, "platform", "darwin")
    owner = broker.Controller(tmp_path, "token", owner_pid=321, owner_birth=1234)
    with controller_server(owner):
        connection = Mock(spec=socket.socket)
        monkeypatch.setattr(broker, "_darwin_peer_uid", lambda connection: __import__('os').geteuid())
        connection.getsockopt.return_value = struct.pack("i", 321)
        monkeypatch.setattr(broker, "_pid_starttime", lambda pid: 1234)
        assert owner._peer_allowed(connection)
        monkeypatch.setattr(broker, "_pid_starttime", lambda pid: 5678)
        assert not owner._peer_allowed(connection)
        monkeypatch.setattr(broker, "_pid_starttime", lambda pid: 1234)
        monkeypatch.setattr(broker, "_darwin_peer_uid", lambda connection: __import__('os').geteuid() + 1)
        assert not owner._peer_allowed(connection)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux namespace identities")
def test_peer_cgroup_namespace_is_checked_even_with_same_cgroup_path(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    from unittest.mock import Mock
    owner = broker.Controller(tmp_path, "token")
    with controller_server(owner):
        connection = Mock()
        connection.getsockopt.return_value = struct.pack("3i", os.getpid(), os.geteuid(), 0)
        original = os.stat
        sampled_peer = False
        def stat(path, **kwargs):
            nonlocal sampled_peer
            result = original(path, **kwargs)
            if path == "ns/cgroup" and not sampled_peer:
                sampled_peer = True
                return SimpleNamespace(st_ino=result.st_ino + 1)
            return result
        monkeypatch.setattr(os, "stat", stat)
        assert not owner._peer_allowed(connection)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux user namespaces")
def test_root_mappings_do_not_share_a_uid_only_discovery_family(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(broker.os, "geteuid", lambda: 0)
    original = Path.stat
    inode = [101]
    def stat(path, **kwargs):
        if str(path) == "/proc/self/ns/user":
            return SimpleNamespace(st_ino=inode[0])
        return original(path, **kwargs)
    monkeypatch.setattr(Path, "stat", stat)
    first = broker._runtime_family(tmp_path)
    inode[0] = 202
    assert broker._runtime_family(tmp_path) != first


def test_discovery_separates_toolchain_upgrades(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, "toolchain_identity", lambda: "runtime-a")
    first = broker._discovery_key(tmp_path)
    monkeypatch.setattr(broker, "toolchain_identity", lambda: "runtime-b")
    assert broker._discovery_key(tmp_path) != first


def test_client_cannot_bind_to_a_different_controller_toolchain(controller):
    owner, graph, workers = controller
    with broker._connect(owner.root, owner.token) as connection:
        broker._send(connection, {"op": "acquire", "toolchain": "different runtime"})
        reply = broker._receive(connection, limit=8192, deadline=time.monotonic() + 2)
    assert "toolchain differs" in reply["error"]
    assert not workers


class IdleClock:
    """Advance only controller idleness; socket and test deadlines stay real."""
    def __init__(self):
        self.value = 0.0
        self.sampled = threading.Condition()
        self.last_sample = None
        self.sample_counts = {}

    def __call__(self):
        with self.sampled:
            self.last_sample = self.value
            self.sample_counts[self.value] = self.sample_counts.get(self.value, 0) + 1
            self.sampled.notify_all()
            return self.value

    def advance_to(self, value):
        with self.sampled:
            self.value = value

    def wait_for_sample(self, value, count=1):
        with self.sampled:
            assert self.sampled.wait_for(lambda: self.sample_counts.get(value, 0) >= count, timeout=2)


def test_controller_production_idle_deadline_closes_socket_and_services(tmp_path):
    from unittest.mock import Mock
    clock = IdleClock()
    services = Mock()
    owner = broker.Controller(tmp_path, "token", services=services, clock=clock)
    with controller_server(owner) as start_server:
        ready = threading.Event()
        original_start = owner.start
        def start():
            original_start()
            ready.set()
        owner.start = start
        thread = start_server()
        assert ready.wait(2)
        clock.advance_to(broker._CONTROLLER_IDLE_SECONDS - 0.01)
        # A second sample proves the first idle decision continued serving;
        # merely observing the clock read could race the teardown decision.
        clock.wait_for_sample(broker._CONTROLLER_IDLE_SECONDS - 0.01, count=2)
        assert thread.is_alive()
        services.close.assert_not_called()
        clock.advance_to(broker._CONTROLLER_IDLE_SECONDS + 0.01)
        thread.join(2)
        assert not thread.is_alive()
        services.close.assert_called_once_with()
        assert not (tmp_path / "rpc.sock").exists()
        assert owner.listener.fileno() == -1


@pytest.mark.skipif(sys.platform != "linux", reason="Linux procfs peer identity")
def test_changing_peer_context_is_refused(tmp_path, monkeypatch):
    import os
    from unittest.mock import Mock
    owner = broker.Controller(tmp_path, "token")
    with controller_server(owner):
        connection = Mock()
        connection.getsockopt.return_value = struct.pack("3i", os.getpid(), os.geteuid(), 0)
        contexts = iter([("namespaces", b"before"), ("namespaces", b"before"),
                         ("namespaces", b"after")])
        monkeypatch.setattr(broker, "_kernel_context", lambda directory: next(contexts))
        assert not owner._peer_allowed(connection)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux procfs peer identity")
def test_peer_exit_during_context_check_does_not_read_recycled_pid_paths(tmp_path, monkeypatch):
    import os
    from unittest.mock import Mock
    with ExitStack() as cleanup:
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        cleanup.enter_context(reap_on_exit(process))
        owner = broker.Controller(tmp_path, "token")
        cleanup.callback(owner.listener.close)
        connection = Mock()
        connection.getsockopt.return_value = struct.pack("3i", process.pid, os.geteuid(), 0)
        original = broker._kernel_context
        sampled = False
        def sample(directory):
            nonlocal sampled
            context = original(directory)
            if not sampled:
                sampled = True
                process.kill()
                process.wait(timeout=2)
            return context
        monkeypatch.setattr(broker, "_kernel_context", sample)
        assert not owner._peer_allowed(connection)
        assert sampled


def test_old_controller_cleanup_cannot_remove_concurrent_discovery_record(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    with ExitStack() as controllers:
        owners = []
        threads = []
        new_boot = threading.Event()
        allow_boot = threading.Event()
        cleanup_waiting = threading.Event()
        real_lock = broker.sidecar_flock

        class Process:
            def __init__(self, thread):
                self.thread = thread
            def poll(self):
                return None if self.thread.is_alive() else 0

        def launch(root, environment):
            if owners:
                new_boot.set()
                assert allow_boot.wait(3), "replacement bootstrap not released"
            record = broker._record(root / "controller.json")
            owner = broker.Controller(root, record["token"], owner_pid=record["owner_pid"],
                                      owner_birth=record["owner_birth"])
            start_server = controllers.enter_context(controller_server(owner))
            owners.append(owner)
            thread = start_server(idle_seconds=60)
            threads.append(thread)
            return Process(thread)

        @contextmanager
        def observed_lock(path, **kwargs):
            if kwargs.get("subject") == "Joern controller cleanup":
                cleanup_waiting.set()
            with real_lock(path, **kwargs):
                yield

        monkeypatch.setattr(broker, "_start_controller", launch)
        monkeypatch.setattr(broker, "sidecar_flock", observed_lock)
        try:
            old_root, _ = broker.discover(tmp_path)
            old_record = broker._record(old_root / "controller.json")
            owners[0].stopping.set()
            threads[0].join(2)
            assert not threads[0].is_alive()
            with ThreadPoolExecutor(max_workers=2) as executor:
                replacement = executor.submit(broker.discover, tmp_path)
                try:
                    assert new_boot.wait(2)
                    cleanup = executor.submit(broker._cleanup_controller, old_root, old_record)
                    assert cleanup_waiting.wait(2)
                finally:
                    allow_boot.set()
                new_root, token = replacement.result(timeout=4)
                cleanup.result(timeout=4)
            assert new_root != old_root and not old_root.exists()
            registry = Path(broker._record(new_root / "controller.json")["registry"])
            assert broker._record(registry / "current.json")["root"] == str(new_root)
            with broker._connect(new_root, token):
                pass
            assert broker.discover(tmp_path) == (new_root, token)
            assert len(owners) == 2
        finally:
            allow_boot.set()
            for owner in owners:
                owner.stopping.set()


def test_idle_deadline_does_not_expire_a_live_lease(tmp_path):
    workers = []
    def factory(*args, **kwargs):
        worker = Worker()
        workers.append(worker)
        return worker
    owner = broker.Controller(tmp_path, "token", services=GraphServices(tmp_path / "graphs", factory=factory))
    with controller_server(owner) as start_server:
        ready = threading.Event()
        start_original = owner.start
        def start():
            start_original()
            ready.set()
        owner.start = start
        graph_path = tmp_path / "graph.bin"
        graph_path.write_bytes(b"graph")
        thread = start_server(idle_seconds=0.01)
        lease = None
        try:
            assert ready.wait(2)
            lease = _lease(owner, JoernCPG(graph_path, tmp_path))
            # Real quiet interval exceeds the listener's 200ms idle poll.
            assert not owner.stopping.wait(0.3)
            assert thread.is_alive()
            assert lease.query("still held").ok
            assert lease.close()
            lease = None
            thread.join(2)
            assert not thread.is_alive()
            assert workers[0].stops == 1
        finally:
            if lease is not None:
                lease.close()


def test_controller_bootstrap_preserves_resolved_jdk_selection(tmp_path, monkeypatch):
    from packages.joern import prereqs
    from packages.joern.tests.test_prereqs import _mac_jdk
    root, java = _mac_jdk(tmp_path)
    monkeypatch.setattr(prereqs, "_java_path", lambda: str(java))
    captured = []
    def launch(directory, environment):
        captured.append(environment)
        raise RuntimeError("bootstrap captured")
    monkeypatch.setattr(broker, "_start_controller", launch)
    with pytest.raises(RuntimeError, match="bootstrap captured"):
        broker.discover(tmp_path)
    assert len(captured) == 1
    assert captured[0]["JAVA_HOME"] == str(root)


def test_macos_socket_root_avoids_nested_discovery_prefix(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(broker, "sys", SimpleNamespace(platform="darwin", executable=sys.executable))
    monkeypatch.setattr(broker, "_discovery_key", lambda base: "a" * 12)
    captured = []
    def launch(root, environment):
        captured.append(root)
        config = broker._record(root / "controller.json")
        assert Path(config["registry"]) == tmp_path / f"rj{__import__('os').geteuid()}" / ("a" * 12)
        assert root.parent == tmp_path
        raise RuntimeError("bootstrap captured")
    monkeypatch.setattr(broker, "_start_controller", launch)
    with pytest.raises(RuntimeError, match="bootstrap captured"):
        broker.discover(tmp_path)
    assert len(captured) == 1
    root = captured[0]
    config = broker._record(root / "controller.json")
    registry = Path(config["registry"])
    from core.json import save_json
    save_json(registry / "current.json", config, mode=0o600)
    broker._cleanup_controller(root, config)
    assert not root.exists()
    assert not (registry / "current.json").exists()


def test_darwin_peer_uid_uses_native_descriptor_api(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    import ctypes
    connection = Mock(spec=socket.socket)
    connection.fileno.return_value = 123
    def native(descriptor, uid, gid):
        assert descriptor == 123
        ctypes.cast(uid, ctypes.POINTER(ctypes.c_uint32)).contents.value = 501
        ctypes.cast(gid, ctypes.POINTER(ctypes.c_uint32)).contents.value = 20
        return 0
    function = Mock(side_effect=native)
    def library(path, **kwargs):
        assert path == "/usr/lib/libSystem.B.dylib" and kwargs == {"use_errno": True}
        return SimpleNamespace(getpeereid=function)
    monkeypatch.setattr(broker.ctypes, "CDLL", library)
    assert broker._darwin_peer_uid(connection) == 501
    assert function.argtypes[0] is ctypes.c_int
    function.side_effect = lambda *args: -1
    monkeypatch.setattr(broker.ctypes, "get_errno", lambda: 9)
    with pytest.raises(OSError) as failure:
        broker._darwin_peer_uid(connection)
    assert failure.value.errno == 9


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS kernel peer identity")
def test_native_macos_controller_checks_real_socket_peer(tmp_path):
    import os
    birth = broker._pid_starttime(os.getpid())
    assert birth is not None, "kernel process birth unavailable"
    owner = broker.Controller(tmp_path, "fixture-token", owner_pid=os.getpid(), owner_birth=birth)
    try:
        first, second = socket.socketpair()
        with first, second:
            assert broker._darwin_peer_uid(first) == os.geteuid()
            assert owner._peer_allowed(first)
            owner.owner_birth = birth + 1
            assert not owner._peer_allowed(first)
            owner.owner_birth = birth
            owner.owner_pid = os.getpid() + 1
            assert not owner._peer_allowed(first)
    finally:
        owner.listener.close()
