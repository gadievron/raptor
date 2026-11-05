"""Compatibility seams for logging ownership tests."""

import logging

import pytest


@pytest.fixture(params=["in-place", "copy-on-write"])
def handler_removal_mode(request, monkeypatch):
    """Exercise both stdlib handler-list update strategies on every Python."""
    def remove_handler(logger, handler):
        with logging._lock:
            if handler in logger.handlers:
                if request.param == "copy-on-write":
                    handlers = logger.handlers.copy()
                    handlers.remove(handler)
                    logger.handlers = handlers
                else:
                    logger.handlers.remove(handler)

    monkeypatch.setattr(logging.Logger, "removeHandler", remove_handler)
