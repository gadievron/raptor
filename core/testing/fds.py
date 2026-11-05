"""Descriptor ownership and snapshots for tests."""

from contextlib import contextmanager, ExitStack
import os


@contextmanager
def preserved_fds(*fds):
    """Restore and close every snapshot, even if another cleanup raises."""
    with ExitStack() as cleanup:
        for fd in fds:
            saved = os.dup(fd)
            cleanup.callback(os.close, saved)
            cleanup.callback(os.dup2, saved, fd)
        yield


def read_and_close(fd: int, size: int) -> bytes:
    """Read bounded bytes, closing the owned descriptor on every exit."""
    try:
        return os.read(fd, size)
    finally:
        os.close(fd)
