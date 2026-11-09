"""Ownership and error precedence for file and archive streams."""
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
import io
import os
from typing import IO, ContextManager, TypeVar

_T = TypeVar('_T')


def _stream_method(resource, name):
    # Special lookup uses the type's raw descriptor, bypassing instance
    # shadows while preserving static/class methods and callable mock slots.
    owner = type(resource)
    for base in owner.__mro__:
        if name in vars(base):
            method = vars(base)[name]
            bind = getattr(type(method), '__get__', None)
            return bind(method, resource, owner) if bind is not None else method
    raise TypeError('stream does not implement the context manager protocol')


@contextmanager
def preserving_stream_error(resource: ContextManager[_T]) -> Iterator[_T]:
    """Own a stream context without letting teardown replace a body exception.

    Successful work still requires successful teardown. With an active body
    error, invoke the original exit protocol once and preserve that error even
    if cleanup fails or returns a truthy value. This is for file/archive streams,
    not contexts whose purpose is to suppress exceptions or commit transactions.
    """
    # Match with-statement special-method lookup, including shadowed instances.
    enter = _stream_method(resource, '__enter__')
    exit_stream = _stream_method(resource, '__exit__')
    stream = enter()
    try:
        yield stream
    except BaseException as primary:
        try:
            exit_stream(type(primary), primary, primary.__traceback__)
        except BaseException as cleanup:
            try:
                primary.add_note(f'Secondary stream cleanup failure: {type(cleanup).__name__}')
            except BaseException:
                pass  # Diagnostic failure must not replace the operation error.
        raise
    else:
        exit_stream(None, None, None)


@contextmanager
def owned_fd(
    fd: int, *, close_fd: Callable[[int], None] | None = None,
) -> Iterator[int]:
    """Consume a raw descriptor, preserving an active operation error.

    Wrappers must borrow it with ``closefd=False``. A custom closer owns
    the consumer's I/O policy and must consume the descriptor exactly once.
    Without one, resolve this module's closer at cleanup time.
    """
    failed = False
    try:
        yield fd
    except BaseException:
        failed = True
        raise
    finally:
        try:
            (os.close if close_fd is None else close_fd)(fd)
        except BaseException:
            if not failed:
                raise


@contextmanager
def open_owned_fd(fd: int, mode: str, **kwargs) -> Iterator[IO]:
    """Consume an open descriptor through stream adoption and teardown.

    The wrapper borrows the descriptor internally, so a partially failed
    adoption cannot close it before this owner does. Stream and descriptor
    closure are independent; an active operation error keeps precedence.
    ``closefd`` is managed here and cannot be supplied by callers.
    """
    with owned_fd(fd):
        if "closefd" in kwargs:
            raise TypeError("open_owned_fd manages descriptor closure")
        stream = os.fdopen(fd, mode, closefd=False, **kwargs)
        with preserving_stream_error(closing(stream)) as owned:
            yield owned


def adopt_fd(fd: int, mode: str, close_fd: Callable[[int], None] | None = None, /, **kwargs) -> IO:
    """Consume a descriptor into a returned stream, including setup failure.

    Native fdopen may dispose of its FileIO before raising. Transfer through
    the standard opener protocol so its caller never retries that descriptor.
    Preserve fdopen's integer name and explicit borrowed-close behaviour.
    """
    transferred = False
    stream = None

    def take_descriptor(_path, _flags):
        nonlocal transferred
        transferred = True
        return fd

    try:
        closefd = kwargs.pop('closefd', True)
        if not closefd:
            # A borrowed native wrapper cannot dispose of the raw descriptor
            # on construction failure. Retain the historical caller option.
            stream = os.fdopen(fd, mode, closefd=False, **kwargs)
            transferred = True
            return stream
        # fdopen ignores an opener when its file argument is a descriptor.
        kwargs.pop('opener', None)
        stream = io.open('<owned-descriptor>', mode, opener=take_descriptor, **kwargs)
        raw = stream.buffer if isinstance(stream, io.TextIOWrapper) else stream
        if isinstance(raw, (io.BufferedReader, io.BufferedWriter, io.BufferedRandom)):
            raw = raw.raw
        if not isinstance(raw, io.FileIO):
            raise TypeError("native stream has no FileIO owner")
        raw.name = fd
        return stream
    except BaseException:
        if stream is not None:
            try:
                stream.close()
            except BaseException:
                pass
        if not transferred:
            try:
                (os.close if close_fd is None else close_fd)(fd)
            except BaseException:
                pass
        raise
