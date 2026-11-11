"""Owned pipe streams for test fixtures with fallible setup."""

import io
import os
from contextlib import ExitStack, contextmanager, suppress
from inspect import signature

from core.source.streams import adopt_fd


_FDOPEN_ARGUMENTS = signature(io.open)


def fdopen_owned(fd, *args, **kwargs):
    """Transfer a descriptor to a stream, closing it if adoption fails."""
    try:
        if not isinstance(fd, int):
            raise TypeError("invalid fd type (%s, expected integer)" % type(fd))
        options = dict(_FDOPEN_ARGUMENTS.bind(fd, *args, **kwargs).arguments)
    except BaseException:
        # Argument binding has not handed the descriptor to a native owner.
        with suppress(BaseException):
            os.close(fd)
        raise
    options.pop("file")
    mode = options.pop("mode", "r")
    # The adopter owns every later failure, including native construction
    # which may already have closed and recycled this descriptor number.
    return adopt_fd(fd, mode, os.close, **options)


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
