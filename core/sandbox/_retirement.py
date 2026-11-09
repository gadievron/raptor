"""Ordered parent cleanup shared by the native sandbox backends."""

from collections.abc import Callable
import contextlib
import sys


def retire_parent_resources(*callbacks: Callable[[], object]) -> None:
    """Attempt every owner without replacing an operation already unwinding."""
    original = sys.exc_info()[1]
    failures = []
    for callback in callbacks:
        try:
            callback()
        except BaseException as error:
            failures.append(error)
    if failures:
        primary = original if original is not None else failures.pop(0)
        for error in failures:
            with contextlib.suppress(BaseException):
                primary.add_note("parent owner cleanup: " + type(error).__name__)
        if original is None:
            raise primary

