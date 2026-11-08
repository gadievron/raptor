"""Socket and serving-thread ownership for in-process test workers."""

from contextlib import ExitStack, contextmanager, suppress
import os
import socket
import threading


@contextmanager
def socket_worker_setup(fd):
    """Yield a duplicate and thread starter; transfer both only on success."""
    duplicate = os.dup(fd)
    try:
        owned = socket.socket(fileno=duplicate)
    except BaseException:
        with suppress(OSError):
            os.close(duplicate)
        raise
    thread = None

    def start_worker(target):
        nonlocal thread
        if thread is not None:
            raise RuntimeError("socket worker already started")
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    try:
        yield owned, start_worker
    except BaseException:
        try:
            if thread is not None and thread.ident is not None:
                # A started worker may be blocked in recv. shutdown wakes it;
                # close alone does not reliably interrupt another thread.
                try:
                    with suppress(OSError):
                        owned.shutdown(socket.SHUT_RDWR)
                finally:
                    thread.join(timeout=5)
                    if thread.is_alive():
                        raise RuntimeError("socket fixture worker did not stop")
        finally:
            owned.close()
        raise


@contextmanager
def isolated_socket_servers(owner, monkeypatch):
    """Close test-created backends before restoring the consumer's factory.

    SocketServer already cleans partially failed construction. Keep completed
    instances too, since later test setup can fail before its local finally.
    """
    from core.testing.module_state import isolated_module_state

    servers = []
    original = owner.SocketServer

    class OwnedServer(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            servers.append(self)

    def close(server):
        try:
            server.close()
        except BaseException:
            original.close(server)
            raise

    with isolated_module_state(owner, {"SocketServer": OwnedServer}):
        try:
            yield
        finally:
            with ExitStack() as cleanup:
                cleanup.callback(monkeypatch.undo)
                for server in servers:
                    cleanup.callback(close, server)
