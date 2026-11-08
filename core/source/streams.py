"""Keep an IO failure primary when a file or archive context also fails to close."""
from collections.abc import Iterator
from contextlib import contextmanager
from typing import ContextManager, TypeVar

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
