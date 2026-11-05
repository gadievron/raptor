"""Exception-safe lifetimes for unittest module fixtures."""

from contextlib import ExitStack, contextmanager

import pytest


@contextmanager
def module_fixture_setup(namespace, names):
    """Keep successful setup alive until tearDownModule closes the owned stack.

    Snapshot fixture handles before setup writes them. A partial setup closes
    immediately; normal teardown attempts every resource callback before
    restoring the caller's original handles and any outer scope.
    """
    cleanup = ExitStack()
    try:
        patch = pytest.MonkeyPatch()
        cleanup.callback(patch.undo)
        for name in names:
            patch.setitem(namespace, name, namespace[name])
        patch.setitem(namespace, "_module_fixture_scope", cleanup)
        yield cleanup
    except BaseException:
        cleanup.close()
        raise


def start_module_patch(cleanup, patcher):
    """Register a real unittest patch before start can raise after taking effect."""
    def stop():
        try:
            patcher.stop()
        except BaseException:
            # Finish an interrupted stop through the original patch class, then
            # preserve the error while ExitStack attempts the other callbacks.
            type(patcher).stop(patcher)
            raise

    cleanup.callback(stop)
    return patcher.start()
