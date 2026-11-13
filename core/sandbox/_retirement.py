"""Ordered parent cleanup shared by the native sandbox backends."""

from collections.abc import Callable
import contextlib
import sys


class _ActiveException:
    pass


_ACTIVE_EXCEPTION = _ActiveException()


def retire_parent_resources(
    *callbacks: Callable[[], object],
    primary_error: BaseException | None | _ActiveException = _ACTIVE_EXCEPTION,
) -> None:
    """Attempt every owner, preserving an active or explicitly owned failure.

    Explicit None identifies local success even inside a caller's except block.
    Omitting primary_error retains the active-exception behaviour for callers
    already retiring inside their own exception handler.
    """
    original = sys.exc_info()[1] if isinstance(primary_error, _ActiveException) else primary_error
    failures = []
    for callback in callbacks:
        try:
            callback()
        except BaseException as error:
            failures.append(error)
    if failures:
        primary = original if original is not None else failures.pop(0)
        for cleanup_error in failures:
            with contextlib.suppress(BaseException):
                primary.add_note("parent owner cleanup: " + type(cleanup_error).__name__)
        if original is None:
            raise primary

