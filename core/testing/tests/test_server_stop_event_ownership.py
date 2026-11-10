"""Stop notification failures retain ownership of server retirement."""

from contextlib import suppress
import socket, threading
import pytest
from core.sandbox.tests.socket_server import SocketServer


@pytest.mark.parametrize("secondary", [False, True])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("connected", [False, True])
def test_native_stop_interruption_retires_server(
    after, connected, secondary, monkeypatch
):
    listener = socket.socket()
    server = None
    client = None
    entered = threading.Event()

    def handler(conn):
        entered.set()
        with suppress(OSError):
            conn.recv(1)

    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        server = SocketServer(listener, handler)
        if connected:
            client = socket.create_connection(listener.getsockname(), timeout=2)
            assert entered.wait(2)
        setter = server._stop.set
        failure = KeyboardInterrupt("owned stop interruption")

        def interrupt():
            if after:
                setter()
            raise failure

        class ListenerView:
            def __getattr__(self, name):
                return getattr(listener, name)

            def shutdown(self, *args):
                return listener.shutdown(*args)

            def close(self):
                listener.close()
                if secondary:
                    raise RuntimeError("secondary listener close")

        with monkeypatch.context() as patch:
            patch.setattr(server, "_listener", ListenerView())
            patch.setattr(server._stop, "set", interrupt)
            with pytest.raises(KeyboardInterrupt) as caught:
                server.close()
            assert caught.value is failure
            assert listener.fileno() == -1
            assert not server._accept_thread.is_alive()
            assert not any(worker.is_alive() for worker in server._threads)
            assert not server._clients
    finally:
        if server is not None:
            server._stop.set()
            with suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
            server._accept_thread.join(2)
            with server._lock:
                clients = list(server._clients)
            for item in clients:
                with suppress(OSError):
                    item.shutdown(socket.SHUT_RDWR)
                item.close()
            for worker in server._threads:
                worker.join(2)
            assert not server._accept_thread.is_alive()
            assert not any(t.is_alive() for t in server._threads)
        if client is not None:
            client.close()
        listener.close()


def test_live_worker_error_keeps_precedence(monkeypatch):
    from core.testing.tests.test_socket_server_retirement import _model_server

    server, clients, workers = _model_server()
    failure = KeyboardInterrupt("stop notification")
    monkeypatch.setattr(server._stop, "set", lambda: (_ for _ in ()).throw(failure))
    workers[0].is_alive.return_value = True
    with pytest.raises(RuntimeError, match="threads did not stop"):
        server.close()
    server._listener.close.assert_called_once()
    server._accept_thread.join.assert_called_once_with(timeout=2)
    for client in clients:
        client.close.assert_called_once()
    for worker in workers:
        worker.join.assert_called_once_with(timeout=2)
