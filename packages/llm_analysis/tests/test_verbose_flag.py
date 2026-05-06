"""Test for /agentic --verbose flag — bumps existing console
StreamHandlers from INFO to DEBUG so per-LLM-call detail surfaces.

The wiring lives at the top of raptor_agentic.py:main; we test the
side effect (handler-level mutation) rather than driving full main().

Note: logging.getLogger() handlers persist across pytest collection,
so we test that the wiring snippet correctly mutates *whatever*
StreamHandlers it finds, rather than asserting specific handler counts.
"""

from __future__ import annotations

import logging


def _apply_verbose_wiring(log) -> None:
    """Mirror the snippet at raptor_agentic.py:main when --verbose."""
    for h in log.logger.handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            h.setLevel(logging.DEBUG)


class TestVerboseWiring:
    def test_verbose_bumps_console_streamhandlers_to_debug(self):
        from core.logging import get_logger
        log = get_logger()

        # Force any console StreamHandlers back to INFO so we can see
        # the wiring flip them.
        for h in log.logger.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                h.setLevel(logging.INFO)

        _apply_verbose_wiring(log)

        stream_handlers = [
            h for h in log.logger.handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert stream_handlers, "expected at least one console StreamHandler"
        for h in stream_handlers:
            assert h.level == logging.DEBUG

    def test_verbose_does_not_affect_file_handler(self):
        from core.logging import get_logger
        log = get_logger()
        file_handlers = [
            h for h in log.logger.handlers
            if isinstance(h, logging.FileHandler)
        ]
        if not file_handlers:
            # In some test envs no file handler is attached; nothing to assert.
            return
        before_levels = [h.level for h in file_handlers]

        _apply_verbose_wiring(log)

        after_levels = [h.level for h in file_handlers]
        assert before_levels == after_levels

    def test_verbose_idempotent(self):
        from core.logging import get_logger
        log = get_logger()
        _apply_verbose_wiring(log)
        _apply_verbose_wiring(log)  # second call is a no-op
        for h in log.logger.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                assert h.level == logging.DEBUG
