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


# ---------------------------------------------------------------------------
# should_negative_cache — only authoritative not-founds are cacheable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc,expected", [
    (HttpError("404", status=404), True),     # authoritative not-found
    (HttpError("410", status=410), True),     # gone (yanked)
    (HttpError("500", status=500), False),    # server error — transient
    (HttpError("503", status=503), False),    # outage — transient
    (HttpError("429", status=429), False),    # rate-limited — transient
    (HttpError("timeout", status=None), False),   # network — transient
    (RuntimeError("boom"), False),                 # non-HTTP — transient
    (HttpError("Circuit open", status=404, circuit_break=True), False),
])
def test_should_negative_cache_only_authoritative_not_found(exc, expected):
    from packages.sca.registries._negative_cache import (
        should_negative_cache,
    )
    assert should_negative_cache(exc) is expected


def test_fetch_or_negative_cache_404_cached_transient_not(tmp_path):
    """Both directions through the shared helper: a real 404 is
    negative-cached (no re-fetch inside the TTL); a 5xx returns the
    sentinel UNCACHED so the next call retries — one outage must not
    read as 'package doesn't exist' for a whole dep list for 24h."""
    from core.json import JsonCache
    from packages.sca.registries._negative_cache import (
        fetch_or_negative_cache,
    )
    cache = JsonCache(root=tmp_path)
    calls = {"n": 0}

    def _fetch_404():
        calls["n"] += 1
        raise HttpError("404", status=404)

    assert fetch_or_negative_cache(
        cache, "k404", 3600, _fetch_404, negative_value=[],
    ) == []
    assert fetch_or_negative_cache(
        cache, "k404", 3600, _fetch_404, negative_value=[],
    ) == []
    assert calls["n"] == 1, "404 must be served from the negative entry"

    outage = {"on": True}

    def _fetch_5xx():
        calls["n"] += 1
        if outage["on"]:
            raise HttpError("503", status=503)
        return {"ok": True}

    assert fetch_or_negative_cache(
        cache, "k5xx", 3600, _fetch_5xx,
    ) is None
    outage["on"] = False
    assert fetch_or_negative_cache(
        cache, "k5xx", 3600, _fetch_5xx,
    ) == {"ok": True}, "transient failure must not poison the entry"


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
