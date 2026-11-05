"""Scoped logging ownership for tests that call standalone CLIs in-process."""

from __future__ import annotations

import logging
from contextlib import ExitStack, contextmanager

from core.logging import NOISY_THIRD_PARTY_LOGGERS


@contextmanager
def isolated_cli_logging(*, logger_names=()):
    """Restore CLI logging changes and close newly attached root handlers.

    Use as a context manager or test-function decorator. Keeping the scope
    inside pytest's call phase avoids its capture contexts restoring a
    leaked call-phase level after a fixture's teardown has run.
    """
    root = logging.getLogger()
    original_list = root.handlers
    original_handlers = tuple(original_list)
    root_level = root.level
    handler_levels = {handler: handler.level for handler in original_handlers}
    names = dict.fromkeys((*NOISY_THIRD_PARTY_LOGGERS, *logger_names))
    sdk_levels = {
        logging.getLogger(name): logging.getLogger(name).level for name in names
    }
    try:
        yield
    finally:
        created = [
            handler for handler in root.handlers if handler not in original_handlers
        ]
        with ExitStack() as cleanup:
            for handler in created:
                cleanup.callback(handler.close)
            # Register every restoration before running one: a broken level
            # setter must not strand later state or owned file handlers.
            for logger, level in reversed(tuple(sdk_levels.items())):
                cleanup.callback(logger.setLevel, level)
            cleanup.callback(root.setLevel, root_level)
            for handler, level in reversed(tuple(handler_levels.items())):
                cleanup.callback(handler.setLevel, level)
            cleanup.callback(original_list.__setitem__, slice(None), original_handlers)
            cleanup.callback(setattr, root, "handlers", original_list)
