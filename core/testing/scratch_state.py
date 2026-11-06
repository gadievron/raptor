"""Own scratch ticker state without clearing a caller's live registrations."""

from contextlib import contextmanager
from threading import Event

from core.testing.module_state import isolated_module_state


@contextmanager
def isolated_scratch_keepalive():
    """Join the test's ticker before restoring inherited scratch state.

    Assert that resource owners released their pins; never hide leaks by
    clearing the registry. The independent undo scope survives test bodies
    that undo their own monkeypatch stack.
    """
    from core.run import scratch

    stop = Event()
    paths = set()
    with isolated_module_state(scratch, {
        "_keepalive_paths": paths,
        "_keepalive_thread": None,
        "_keepalive_loop": lambda: stop.wait(),
    }, lock=scratch._keepalive_lock):
        try:
            yield paths
        finally:
            stop.set()
            thread = scratch._keepalive_thread
            if thread is not None:
                thread.join(timeout=5)
                assert not thread.is_alive(), "owned scratch ticker did not stop"
            assert not paths, f"owner left scratch keepalives registered: {paths}"
