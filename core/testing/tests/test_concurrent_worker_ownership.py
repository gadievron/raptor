"""Native concurrency tests retire owned workers even after partial startup."""

import importlib
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import ModuleType

import pytest

from core.testing.threads import retiring_threads


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('cleanup_fault', ['none', 'release', 'join'])
@pytest.mark.parametrize('count', [1, 3])
def test_group_retires_every_worker(finish, cleanup_fault, count):
    stop, borrowed_stop = threading.Event(), threading.Event()
    joined = []
    workers = []
    failure = RuntimeError('owned cleanup failure')
    body_error = KeyboardInterrupt('owned body interrupted') if finish == 'interrupt' else ValueError('owned body failed')
    borrowed = threading.Thread(target=borrowed_stop.wait)
    borrowed.start()

    class Worker(threading.Thread):
        def join(self, timeout=None):
            super().join(timeout)
            joined.append(self)
            if cleanup_fault == 'join' and self is workers[0]:
                raise failure

    def release():
        stop.set()
        if cleanup_fault == 'release':
            raise failure

    observed = None
    try:
        with retiring_threads(workers, release=release, timeout=2):
            for _ in range(count):
                worker = Worker(target=stop.wait)
                workers.append(worker)
                worker.start()
            if finish != 'normal':
                raise body_error
    except BaseException as error:
        observed = error
    finally:
        # Record the owner's result before this outer safety-net cleanup.
        retired = all(not worker.is_alive() for worker in workers)
        visited = set(joined)
        borrowed_alive = borrowed.is_alive()
        stop.set()
        for worker in workers:
            threading.Thread.join(worker, 2)
        borrowed_stop.set()
        borrowed.join(2)
    assert retired
    assert visited == set(workers)
    assert borrowed_alive
    assert observed is (failure if cleanup_fault != 'none' else None if finish == 'normal' else body_error)


def test_unstarted_workers_are_not_joined():
    worker = threading.Thread(target=lambda: None)
    released = []
    with retiring_threads([worker], release=lambda: released.append(True), timeout=1):
        pass
    assert released == [True]
    assert worker.ident is None


WORKERS = (
    ('test_parser_jail', 'TestConcurrency', 'test_parallel_parses_no_cross_talk'),
    ('test_proxy_observability', 'TestScanPermitContention', 'test_cross_thread_hammer_increments_stay_on_loop_thread'),
    ('test_proxy_perf', 'TestBufferSnapshot', 'test_concurrent_record_and_register'),
    ('test_proxy_record_unregister_race', 'TestRecordUnregisterRace', 'test_final_event_survives_concurrent_unregister'),
)
BRIDGES = (
    ('TestRunBridges', 'test_two_bridges_relay_to_their_own_upstreams'),
    ('TestRunBridges', 'test_single_bridge_wrapper_compatible'),
    ('TestRunBridges', 'test_dead_upstream_closes_client_not_relay'),
    ('TestForwarderBounds', 'test_pair_cap_refuses_excess_connections'),
    ('TestForwarderBounds', 'test_idle_pairs_are_swept'),
    ('TestForwarderBounds', 'test_stalled_peer_does_not_block_other_pairs'),
    ('TestForwarderBounds', 'test_eof_with_pending_bytes_still_delivers_the_tail'),
)


def _thread_view(monkeypatch, native, position, when):
    original = native.threading
    private = ModuleType(original.__name__)
    vars(private).update(vars(original))
    owned, events, joined = [], [], []
    failure = RuntimeError('injected native thread start failure')
    started = []

    class Worker(original.Thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owned.append(self)

        def start(self):
            started.append(self)
            fail = len(started) == position
            if fail and when == 'before':
                raise failure
            super().start()
            if fail:
                raise failure

        def join(self, timeout=None):
            super().join(timeout)
            joined.append(self)

    class Timer(original.Timer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owned.append(self)

        def start(self):
            started.append(self)
            if when == 'before':
                raise failure
            super().start()
            raise failure

        def join(self, timeout=None):
            super().join(timeout)
            joined.append(self)

    def event():
        value = original.Event()
        events.append(value)
        return value

    private.Thread, private.Event, private.Timer = Worker, event, Timer
    monkeypatch.setattr(native, 'threading', private)
    return owned, events, joined, failure


def _snapshot(owned, joined):
    return [(worker.ident is None or not worker.is_alive(), worker.ident is None or worker in joined)
            for worker in owned]


def _safety_cleanup(owned, events):
    for event in events:
        event.set()
    for worker in owned:
        if worker.ident is not None:
            threading.Thread.join(worker, 5)
            assert not worker.is_alive(), 'native regression worker survived safety cleanup'


@pytest.mark.parametrize('spec', WORKERS, ids=lambda row: row[0])
@pytest.mark.parametrize('when', ['before', 'after'])
@pytest.mark.parametrize('position', [1, 2])
def test_native_partial_worker_start_is_retired(spec, when, position, monkeypatch):
    from core.sandbox import parser_jail
    from core.sandbox.tests import test_parser_jail as parser_native
    from core.testing.proxy_scope import isolated_proxy_scope

    name, cls, method = spec
    native = importlib.import_module('core.sandbox.tests.' + name)
    # These are lifecycle faults, not confinement claims. Native suites still
    # start real confined workers; use the existing protocol peer here.
    monkeypatch.setattr(parser_jail, 'subprocess', parser_native._fake_subprocess(
        parser_native._READY_OK, parser_native._honest_responder,
    ))
    with isolated_proxy_scope():
        jail = parser_jail.ParserJail()
        jail.start()
        owned, events, joined, failure = _thread_view(monkeypatch, native, position, when)
        function = getattr(getattr(native, cls)(), method)
        kwargs = {key: value for key, value in {'fresh_jail': jail, 'reset_proxy': None, 'monkeypatch': monkeypatch}.items()
                  if key in inspect.signature(function).parameters}
        observed = []
        try:
            with pytest.raises(RuntimeError) as caught:
                function(**kwargs)
            assert caught.value is failure
        finally:
            observed = _snapshot(owned, joined)
            _safety_cleanup(owned, events)
            jail.stop()
        assert observed and all(stopped and visited for stopped, visited in observed)


@pytest.mark.parametrize('cls,method', BRIDGES, ids=[name for _, name in BRIDGES])
@pytest.mark.parametrize('when', ['before', 'after'])
def test_native_bridge_start_failure_retires_relay(cls, method, when, monkeypatch):
    from core.sandbox.tests import test_proxy_bridge_multi as native

    owned, events, joined, failure = _thread_view(monkeypatch, native, 1, when)
    patch = pytest.MonkeyPatch()
    generator = native._owned_backends.__wrapped__(patch)
    next(generator)
    function = getattr(getattr(native, cls)(), method)
    observed = []
    try:
        with TemporaryDirectory(prefix='rp-bridge-', dir='/tmp') as directory:
            kwargs = {key: value for key, value in {'short_sock_dir': Path(directory), 'monkeypatch': patch}.items()
                      if key in inspect.signature(function).parameters}
            with pytest.raises(RuntimeError) as caught:
                function(**kwargs)
            assert caught.value is failure
    finally:
        observed = _snapshot(owned, joined)
        _safety_cleanup(owned, events)
        generator.close()
        patch.undo()
    assert observed and all(stopped and visited for stopped, visited in observed)


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('count', [1, 2])
def test_backend_scope_closes_overwritten_owners(finish, count, monkeypatch, tmp_path):
    from core.sandbox.tests import test_proxy_bridge_multi as native

    patch = pytest.MonkeyPatch()
    generator = native._owned_backends.__wrapped__(patch)
    next(generator)
    servers = []
    try:
        with TemporaryDirectory(prefix='rp-backend-', dir='/tmp') as directory:
            for index in range(count):
                servers.append(native._unix_echo_server(str(Path(directory) / str(index)), b'owned:'))
            patch.setattr(native, 'SocketServer', object)
            if finish == 'error':
                raise RuntimeError('owned backend body failed')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned backend body interrupted')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[finish]
    finally:
        generator.close()
        observed = [(server._listener.fileno(), server._accept_thread.is_alive()) for server in servers]
        for server in servers:
            server.close()
        patch.undo()
    assert observed == [(-1, False)] * count


@pytest.mark.parametrize('stage', ['bind', 'listen'])
@pytest.mark.parametrize('failure', [OSError, RuntimeError, KeyboardInterrupt])
def test_listener_setup_failure_closes_socket(stage, failure, monkeypatch):
    from core.sandbox.tests import test_proxy_bridge_multi as native
    from types import SimpleNamespace
    import socket

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    error = failure('owned listener setup failed')

    class FailingListener:
        def bind(self, path):
            if stage == 'bind':
                raise error

        def listen(self, backlog):
            raise error

        def close(self):
            listener.close()

    monkeypatch.setattr(native, 'socket', SimpleNamespace(
        socket=lambda *args: FailingListener(), AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM,
    ))
    try:
        with pytest.raises(failure) as caught:
            native._unix_listener('/owned/listener')
        assert caught.value is error
        assert listener.fileno() == -1
    finally:
        listener.close()


@pytest.mark.parametrize('when', ['before', 'after'])
def test_native_delayed_closer_is_cancelled_and_joined(when, monkeypatch, caplog):
    from core.sandbox import parser_jail
    from core.sandbox.tests import test_parser_jail as parser_native
    from core.sandbox.tests import test_proxy_observability as native
    from core.testing.proxy_scope import isolated_proxy_scope

    monkeypatch.setattr(parser_jail, 'subprocess', parser_native._fake_subprocess(
        parser_native._READY_OK, parser_native._honest_responder,
    ))
    native.loopback_permitted.__wrapped__(monkeypatch)
    with isolated_proxy_scope():
        owned, events, joined, failure = _thread_view(monkeypatch, native, 1, when)
        try:
            with pytest.raises(RuntimeError) as caught:
                native.TestSummaryAndHeartbeat().test_summary_includes_drain_window_completions(
                    reset_proxy=None, loopback_permitted=True, caplog=caplog,
                )
            assert caught.value is failure
        finally:
            observed = _snapshot(owned, joined)
            for worker in owned:
                worker.cancel()
            _safety_cleanup(owned, events)
        assert observed and all(stopped and visited for stopped, visited in observed)


BACKEND_CASES = (('TestConnectionChurnCounters', 'test_accepted_denied_failed_counts_match_real_churn'), ('TestConnectionChurnCounters', 'test_eof_propagation_and_reset_teardown_counted'), ('TestTunnelGauge', 'test_peak_tracks_concurrency_and_survives_drain'), ('TestSummaryAndHeartbeat', 'test_summary_carries_the_run_facts'), ('TestSummaryAndHeartbeat', 'test_summary_includes_drain_window_completions'))


@pytest.mark.parametrize('cls,method', BACKEND_CASES, ids=[method for _, method in BACKEND_CASES])
@pytest.mark.parametrize('failure', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_proxy_startup_failure_closes_backend(cls, method, failure, monkeypatch, caplog):
    from core.sandbox import proxy
    from core.sandbox.tests import test_proxy_observability as native
    from core.testing.module_bindings import patch_module_attribute
    from core.testing.proxy_scope import isolated_proxy_scope

    original = native.SocketServer
    servers = []

    class TrackedServer(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            servers.append(self)

    monkeypatch.setattr(native, 'SocketServer', TrackedServer)
    error = failure('injected parser startup failure')

    def unavailable():
        raise error

    patch_module_attribute(monkeypatch, proxy, 'parser_jail', 'get_parser_jail', unavailable)
    body = pytest.MonkeyPatch()
    owner = native._owned_backends.__wrapped__(body)
    next(owner)
    try:
        with isolated_proxy_scope():
            function = getattr(getattr(native, cls)(), method)
            kwargs = {key: value for key, value in {'reset_proxy': None, 'loopback_permitted': True, 'caplog': caplog}.items()
                      if key in inspect.signature(function).parameters}
            with pytest.raises(failure) as caught:
                function(**kwargs)
            assert caught.value is error
    finally:
        owner.close()
        observed = [(server._listener.fileno(), server._accept_thread.is_alive()) for server in servers]
        for server in servers:
            server.close()
        body.undo()
    assert observed == [(-1, False)]


@pytest.mark.parametrize('stage', ['second-backend', 'port'])
@pytest.mark.parametrize('failure', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_bridge_setup_failure_closes_earlier_backends(stage, failure, monkeypatch):
    from core.sandbox.tests import test_proxy_bridge_multi as native

    original = native.SocketServer
    servers = []

    class TrackedServer(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            servers.append(self)

    monkeypatch.setattr(native, 'SocketServer', TrackedServer)
    error = failure('injected bridge setup failure')
    create = native._unix_echo_server
    calls = []

    def make(path, tag):
        calls.append(path)
        if len(calls) == 2:
            raise error
        return create(path, tag)

    def port():
        raise error

    monkeypatch.setattr(native, '_unix_echo_server' if stage == 'second-backend' else '_free_port',
                        make if stage == 'second-backend' else port)
    body = pytest.MonkeyPatch()
    owner = native._owned_backends.__wrapped__(body)
    next(owner)
    try:
        with TemporaryDirectory(prefix='rp-setup-', dir='/tmp') as directory:
            with pytest.raises(failure) as caught:
                native.TestRunBridges().test_two_bridges_relay_to_their_own_upstreams(Path(directory))
            assert caught.value is error
    finally:
        owner.close()
        observed = [(server._listener.fileno(), server._accept_thread.is_alive()) for server in servers]
        for server in servers:
            server.close()
        body.undo()
    assert observed == [(-1, False)] * (1 if stage == 'second-backend' else 2)


@pytest.mark.parametrize('index', [0, 1])
@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt])
def test_backend_cleanup_finishes_all_servers_before_restoring_caller(index, failure):
    from core.sandbox.tests import test_proxy_bridge_multi as native

    original = native.SocketServer
    with TemporaryDirectory(prefix='rp-close-', dir='/tmp') as directory:
        borrowed = native._unix_echo_server(str(Path(directory) / 'caller'), b'caller')
        body = pytest.MonkeyPatch()
        owner = native._owned_backends.__wrapped__(body)
        next(owner)
        servers = []
        error = failure('owned server close failed')

        def fail():
            raise error

        try:
            for i in range(2):
                servers.append(native._unix_echo_server(str(Path(directory) / str(i)), b'owned'))
            body.setattr(servers[index], 'close', fail)
            with pytest.raises(failure) as caught:
                owner.close()
            assert caught.value is error
            assert native.SocketServer is original
            assert borrowed._listener.fileno() >= 0 and borrowed._accept_thread.is_alive()
            assert all(server._listener.fileno() == -1 and not server._accept_thread.is_alive() for server in servers)
        finally:
            owner.close()
            body.undo()
            for server in servers:
                original.close(server)
            borrowed.close()
