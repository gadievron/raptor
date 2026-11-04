"""Test ownership for a controller before and after its serving thread starts."""

from contextlib import contextmanager
import threading


@contextmanager
def controller_server(owner):
    """Own an acquired controller; yield its one-shot serving-thread starter."""
    thread = None

    def start(**kwargs):
        nonlocal thread
        if thread is not None:
            raise RuntimeError("controller fixture already started")
        thread = threading.Thread(target=owner.serve, kwargs=kwargs)
        thread.start()
        return thread

    try:
        yield start
    finally:
        owner.stopping.set()
        try:
            if thread is not None and thread.ident is not None:
                thread.join(timeout=3)
                if thread.is_alive():
                    raise RuntimeError("controller fixture serving thread did not stop")
        finally:
            # Normal serve() teardown closes the listener and services. If
            # the thread never started or exited before that teardown, the
            # fixture still owns both resources. Avoid closing services a
            # second time after a normal serving-loop exit.
            if owner.listener.fileno() != -1:
                try:
                    owner.listener.close()
                finally:
                    owner.services.close()
