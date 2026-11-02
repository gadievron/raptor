"""Scoped logging ownership for tests that call standalone CLIs in-process."""

from __future__ import annotations

import logging
from contextlib import ExitStack, contextmanager

from core.logging import NOISY_THIRD_PARTY_LOGGERS


@contextmanager
def isolated_cli_logging():
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
    sdk_levels = {logging.getLogger(name): logging.getLogger(name).level
                  for name in NOISY_THIRD_PARTY_LOGGERS}
    try:
        yield
    finally:
        created = [handler for handler in root.handlers if handler not in original_handlers]
        with ExitStack() as cleanup:
            for handler in created:
                cleanup.callback(handler.close)
            root.handlers = original_list
            original_list[:] = original_handlers
            for handler, level in handler_levels.items():
                handler.setLevel(level)
            root.setLevel(root_level)
            for logger, level in sdk_levels.items():
                logger.setLevel(level)
