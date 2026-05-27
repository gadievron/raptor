"""Tests for the shared registry fetch-failure log helper."""

from __future__ import annotations

import logging

import pytest

from core.http import HttpError
from packages.sca.registries._negative_cache import log_fetch_failure

_LOG = logging.getLogger("sca.registries.test")


@pytest.mark.parametrize("status,expected", [
    (404, logging.DEBUG),    # not found — expected, non-fatal
    (410, logging.DEBUG),    # gone (yanked) — expected
    (500, logging.WARNING),  # server error — real problem
    (429, logging.WARNING),  # rate-limited — operational
    (None, logging.WARNING),  # network/timeout (no status) — real problem
])
def test_404_is_debug_everything_else_warning(caplog, status, expected):
    caplog.set_level(logging.DEBUG, logger="sca.registries.test")
    log_fetch_failure(
        _LOG, "sca.registries.test", "somepkg", HttpError("x", status=status),
    )
    rec = caplog.records[-1]
    assert rec.levelno == expected
    assert "somepkg" in rec.getMessage()


def test_non_http_exception_is_warning(caplog):
    """A non-HttpError (parse error, stub TypeError) has no status → WARNING."""
    caplog.set_level(logging.DEBUG, logger="sca.registries.test")
    log_fetch_failure(_LOG, "sca.registries.test", "p", RuntimeError("boom"))
    assert caplog.records[-1].levelno == logging.WARNING


def test_empty_item_name_omits_for_clause(caplog):
    caplog.set_level(logging.DEBUG, logger="sca.registries.test")
    log_fetch_failure(_LOG, "sca.registries.test", "", HttpError("x", status=404))
    msg = caplog.records[-1].getMessage()
    assert "fetch failed:" in msg and "for" not in msg
