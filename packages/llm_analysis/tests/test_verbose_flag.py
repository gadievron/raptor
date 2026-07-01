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

import pytest


def _apply_verbose_wiring() -> None:
    """Mirror the snippet at raptor_agentic.py:main when --verbose."""
    from raptor_agentic import _configure_run_logging
    _configure_run_logging(log_level=None, verbose=True)


def _raptor_logger() -> logging.Logger:
    return logging.getLogger("raptor")


def _console_handlers():
    return [
        h for h in _raptor_logger().handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
    ]


def _file_handlers():
    return [
        h for h in _raptor_logger().handlers
        if isinstance(h, logging.FileHandler)
    ]


def _raptor_root_console_handlers():
    return [
        h for h in logging.getLogger().handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
        and getattr(h, "_raptor_root_handler", False)
    ]


class TestVerboseWiring:
    @pytest.fixture(autouse=True)
    def _init_raptor_logging(self):
        from core.logging import get_logger
        get_logger()

    def test_verbose_bumps_console_streamhandlers_to_debug(self):
        # Force any console StreamHandlers back to INFO so we can see
        # the wiring flip them.
        for h in _console_handlers():
            h.setLevel(logging.INFO)

        _apply_verbose_wiring()

        stream_handlers = _console_handlers()
        assert stream_handlers, "expected at least one console StreamHandler"
        for h in stream_handlers:
            assert h.level == logging.DEBUG

    def test_verbose_does_not_affect_file_handler(self):
        file_handlers = _file_handlers()
        if not file_handlers:
            # In some test envs no file handler is attached; nothing to assert.
            return
        before_levels = [h.level for h in file_handlers]

        _apply_verbose_wiring()

        after_levels = [h.level for h in file_handlers]
        assert before_levels == after_levels

    def test_verbose_idempotent(self):
        _apply_verbose_wiring()
        _apply_verbose_wiring()  # second call is a no-op
        for h in _console_handlers():
            assert h.level == logging.DEBUG

    def test_log_level_warning_quiets_console_and_root_handlers(self):
        from raptor_agentic import _configure_run_logging

        root_logger = logging.getLogger()
        root_before = root_logger.level
        console = _console_handlers()
        root_console = _raptor_root_console_handlers()
        console_before = [h.level for h in console]
        root_console_before = [h.level for h in root_console]

        try:
            for h in console + root_console:
                h.setLevel(logging.INFO)
            root_logger.setLevel(logging.INFO)

            _configure_run_logging(log_level="WARNING", verbose=False)

            assert console, "expected at least one console StreamHandler"
            assert root_console, "expected RAPTOR root console StreamHandler"
            assert all(h.level == logging.WARNING for h in console)
            assert all(h.level == logging.WARNING for h in root_console)
            assert root_logger.level == logging.WARNING
        finally:
            for h, level in zip(console, console_before):
                h.setLevel(level)
            for h, level in zip(root_console, root_console_before):
                h.setLevel(level)
            root_logger.setLevel(root_before)
