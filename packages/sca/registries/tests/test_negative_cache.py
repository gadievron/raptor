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


def test_circuit_break_demoted_to_debug(caplog):
    """Circuit-breaker errors are demoted to DEBUG — the breaker-opened
    WARNING from core.http is the actionable line; per-item repeats are noise."""
    caplog.set_level(logging.DEBUG, logger="sca.registries.test")
    log_fetch_failure(
        _LOG, "sca.registries.test", "somecrate",
        HttpError("Circuit open for crates.io:443", circuit_break=True),
    )
    assert caplog.records[-1].levelno == logging.DEBUG


def test_circuit_break_without_status_still_demoted(caplog):
    """circuit_break=True takes priority over status=None (which would
    normally yield WARNING)."""
    caplog.set_level(logging.DEBUG, logger="sca.registries.test")
    log_fetch_failure(
        _LOG, "sca.registries.test", "anothercrate",
        HttpError("Circuit open", status=None, circuit_break=True),
    )
    assert caplog.records[-1].levelno == logging.DEBUG


def test_fetch_or_negative_cache_circuit_break_is_debug(caplog):
    """E2E: fetch_or_negative_cache catches a circuit-break HttpError
    and the resulting log line is DEBUG, not WARNING."""
    from packages.sca.registries._negative_cache import fetch_or_negative_cache
    caplog.set_level(logging.DEBUG)

    def _raise_circuit():
        raise HttpError("Circuit open for crates.io:443", circuit_break=True)

    result = fetch_or_negative_cache(
        cache=None, key="test-crate", ttl_seconds=300,
        fetch=_raise_circuit,
        log_prefix="sca.registries.test", item_name="test-crate",
    )
    assert result is None
    circuit_records = [
        r for r in caplog.records
        if "Circuit open" in r.getMessage()
    ]
    assert len(circuit_records) == 1
    assert circuit_records[0].levelno == logging.DEBUG


def test_configure_logging_debug_file(tmp_path):
    """_configure_logging with log_dir writes debug.log capturing DEBUG
    while the console handler stays at the requested level."""
    from packages.sca.cli import _configure_logging

    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    try:
        for h in list(root.handlers):
            root.removeHandler(h)

        _configure_logging(0, log_dir=tmp_path)

        debug_log = tmp_path / "debug.log"
        assert debug_log.exists()

        test_logger = logging.getLogger("test.configure_logging")
        test_logger.debug("debug-only-message")
        test_logger.warning("warning-message")

        stream_handlers = [
            h for h in root.handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) == 1
        assert stream_handlers[0].level == logging.WARNING

        file_handlers = [
            h for h in root.handlers
            if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1
        assert file_handlers[0].level == logging.DEBUG

        for h in file_handlers:
            h.flush()
        content = debug_log.read_text()
        assert "debug-only-message" in content
        assert "warning-message" in content
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)
            if isinstance(h, logging.FileHandler):
                h.close()
        for h in original_handlers:
            root.addHandler(h)
        root.setLevel(original_level)
