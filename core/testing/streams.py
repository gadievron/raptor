"""Owned pipe streams for test fixtures with fallible setup."""

import os
from contextlib import ExitStack, contextmanager, suppress


def fdopen_owned(fd, *args, **kwargs):
    """Transfer a descriptor to a stream, closing it if adoption fails."""
    try:
        return os.fdopen(fd, *args, **kwargs)
    except BaseException:
        with suppress(OSError):
            os.close(fd)
        raise


@contextmanager
def pipe_streams():
    """Own both pipe ends throughout setup and attempt every close."""
    with ExitStack() as cleanup:
        read_fd, write_fd = os.pipe()
        try:
            reader = fdopen_owned(read_fd, "r")
        except BaseException:
            os.close(write_fd)
            raise
        cleanup.callback(reader.close)
        writer = fdopen_owned(write_fd, "wb", buffering=0)
        cleanup.callback(writer.close)
        yield reader, writer
