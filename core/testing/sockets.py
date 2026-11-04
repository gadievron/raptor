"""Socket and serving-thread ownership for in-process test workers."""

from contextlib import contextmanager, suppress
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
                with suppress(OSError):
                    owned.shutdown(socket.SHUT_RDWR)
                thread.join(timeout=5)
                if thread.is_alive():
                    raise RuntimeError("socket fixture worker did not stop")
        finally:
            owned.close()
        raise
