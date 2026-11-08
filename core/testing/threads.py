"""Explicit retirement of test-owned threads on every scope exit."""

from contextlib import ExitStack, contextmanager


def _join(worker, timeout):
    # start() can fail either before or after starting the native thread.
    if worker.ident is not None:
        worker.join(timeout=timeout)
        assert not worker.is_alive(), f"test-owned thread survived cleanup: {worker.name}"


@contextmanager
def retiring_threads(workers, *, release, timeout):
    """Release blocked workers, then join every started owned thread.

    Enter before the first start(). Register workers before starting them;
    a mutable list supports later construction. Attempt every join even when
    release or another join raises, and leave unstarted threads untouched.
    """
    try:
        yield
    finally:
        with ExitStack() as cleanup:
            for worker in reversed(tuple(workers)):
                cleanup.callback(_join, worker, timeout)
            cleanup.callback(release)
