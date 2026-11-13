"""The actual server fixture owns its real loop through partial thread starts."""

from contextlib import contextmanager
import builtins
import socketserver
import threading
from types import ModuleType
import pytest
import core.env.tests.test_verify_engine as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real_thread, real_server = threading.Thread, socketserver.TCPServer
    servers, threads, requests = [], [], []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Server(real_server):
        def __init__(self, *args, **kwargs):
            assert args[0] == ('127.0.0.1', 0)
            super().__init__(*args, **kwargs)
            self.ready = threading.Event()
            self.shutdowns = []
            servers.append(self)
        def service_actions(self):
            self.ready.set()
            return super().service_actions()
        def shutdown(self):
            self.shutdowns.append(True)
            assert self.ready.is_set(), 'shutdown must not wait for an unstarted server loop'
            return super().shutdown()
    class Thread(real_thread):
        def __init__(self, *args, **kwargs):
            self.native_target = kwargs['target']
            self.server = self.native_target.__self__
            assert self.native_target.__func__ is socketserver.BaseServer.serve_forever
            self.joins = []
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith('before-'):
                raise error('owned start failure')
            super().start()
            assert self.server.ready.wait(5), 'actual server loop did not reach service_actions'
            if phase.startswith('after-'):
                raise error('owned start failure')
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            return super().join(*args, **kwargs)
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            requests.append(True)
            raise AssertionError('no request traffic authorised by this fixture proof')
    private_server = ModuleType('socketserver')
    vars(private_server).update(vars(socketserver))
    private_server.TCPServer = Server
    private_threads = ModuleType('threading')
    vars(private_threads).update(vars(threading))
    private_threads.Thread = Thread
    importer = builtins.__import__
    def local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'socketserver' and level == 0:
            return private_server
        if name == 'threading' and level == 0:
            return private_threads
        return importer(name, globals, locals, fromlist, level)
    function = native._serve.__wrapped__
    view = module_function_view(native, bindings={'_owned_serve': function}, import_hook=local)
    assert view._owned_serve.__code__ is function.__code__
    try:
        yield lambda: contextmanager(view._owned_serve)(Handler), servers, threads, requests
    finally:
        for server in servers:
            if server.ready.is_set() and any(thread.is_alive() for thread in threads):
                socketserver.BaseServer.shutdown(server)
        for thread in threads:
            if thread.ident is not None:
                real_thread.join(thread, timeout=5)
                assert not thread.is_alive()
        for server in servers:
            real_server.server_close(server)


@pytest.mark.parametrize('phase', ['normal', 'before-error', 'before-interrupt', 'after-error', 'after-interrupt', 'body-error', 'body-interrupt'])
def test_actual_serve_fixture_retires_started_loop_on_every_body_exit(phase):
    real_thread, real_server = threading.Thread, socketserver.TCPServer
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(phase) as (serve, servers, threads, requests):
        if phase == 'normal':
            with serve() as yielded:
                assert yielded is servers[0]
                assert yielded.socket.fileno() >= 0
                assert threads[0].is_alive()
        else:
            with pytest.raises(error, match='owned .* failure'):
                with serve() as yielded:
                    assert phase.startswith('body-')
                    raise error('owned body failure')
        assert len(servers) == len(threads) == 1
        server, thread = servers[0], threads[0]
        assert server.socket.fileno() == -1
        assert not thread.is_alive()
        if phase.startswith('before-'):
            assert thread.ident is None and not thread.joins
            assert not server.ready.is_set() and not server.shutdowns
        else:
            assert thread.ident is not None and thread.joins
            assert server.ready.is_set() and server.shutdowns == [True]
        assert requests == []
        assert threading.Thread is real_thread
        assert socketserver.TCPServer is real_server
