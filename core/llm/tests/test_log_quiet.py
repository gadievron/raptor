"""Tests for ``core/llm/log_quiet.py`` — the third-party logger
silencer that suppresses INFO chatter from ``httpx`` /
``google.genai`` during /agentic and friends."""

from __future__ import annotations

import logging

from core.llm.log_quiet import quiet_noisy_loggers, _NOISY_LOGGERS


class TestQuietNoisyLoggers:
    """The level-setting is idempotent and only touches the
    listed third-party loggers; it must NOT raise the root or
    RAPTOR's own loggers."""

    def test_default_level_is_warning(self):
        # Capture pre-state, mutate, capture post-state, restore.
        before = {n: logging.getLogger(n).level for n in _NOISY_LOGGERS}
        try:
            quiet_noisy_loggers()
            for name in _NOISY_LOGGERS:
                assert logging.getLogger(name).level == logging.WARNING
        finally:
            for n, lvl in before.items():
                logging.getLogger(n).setLevel(lvl)

    def test_explicit_level_honoured(self):
        before = {n: logging.getLogger(n).level for n in _NOISY_LOGGERS}
        try:
            quiet_noisy_loggers(logging.ERROR)
            for name in _NOISY_LOGGERS:
                assert logging.getLogger(name).level == logging.ERROR
        finally:
            for n, lvl in before.items():
                logging.getLogger(n).setLevel(lvl)

    def test_root_logger_unaffected(self):
        # Defensive: must NOT touch the root logger — that would
        # silence RAPTOR's own diagnostics globally.
        root_before = logging.getLogger().level
        try:
            quiet_noisy_loggers()
            assert logging.getLogger().level == root_before
        finally:
            logging.getLogger().setLevel(root_before)

    def test_idempotent(self):
        before = {n: logging.getLogger(n).level for n in _NOISY_LOGGERS}
        try:
            quiet_noisy_loggers()
            quiet_noisy_loggers()  # second call no-ops
            quiet_noisy_loggers(logging.ERROR)  # raise to ERROR
            quiet_noisy_loggers(logging.WARNING)  # back to WARNING
            for name in _NOISY_LOGGERS:
                assert logging.getLogger(name).level == logging.WARNING
        finally:
            for n, lvl in before.items():
                logging.getLogger(n).setLevel(lvl)

    def test_targets_include_known_offenders(self):
        # Pin the membership so a future cleanup that drops a
        # logger name from the list has to acknowledge the
        # operator-facing regression in the test.
        assert "httpx" in _NOISY_LOGGERS
        assert "google.genai" in _NOISY_LOGGERS
        # Variant naming (older SDK form) also covered.
        assert "google_genai" in _NOISY_LOGGERS


class TestDispatcherAuditLogLevel:
    """``LLMDispatcher._audit`` routes high-frequency successful
    events to DEBUG; everything else stays at INFO. Audit log on
    disk continues to record every event at full fidelity — this
    is purely about terminal-output noise.

    These tests patch the actual ``_logger.log`` call inside
    server.py so a regression in the conditional surfaces here
    instead of in operator runs.
    """

    def _capture_log_call(self, event: str, status: str):
        """Invoke ``LLMDispatcher._audit`` (the bound method)
        with a synthetic event, capturing the log level it passed
        to ``_logger.log``. Mocks the audit-file path so no disk
        I/O happens.

        Strict: if ``_audit`` is refactored to call
        ``_logger.info`` / ``_logger.debug`` directly instead of
        ``_logger.log(level, ...)``, the spy sees no calls and
        the assertion catches the regression loudly (vs.
        silently returning None and passing a vacuous comparison)."""
        import threading as _thr
        from unittest.mock import patch
        from core.llm.dispatcher import server as server_mod
        # Build the AuditEvent shape ``_audit`` expects.
        ev = server_mod.AuditEvent(
            ts=0.0, event=event,
            peer_pid=None, peer_uid=None,
            token_id=None, worker_label=None,
            status=status,
        )
        # ``_audit`` is bound to ``LLMDispatcher``; we don't
        # need a real instance — just enough shape to satisfy
        # the method. Bypass ``__init__`` and stub the
        # attributes ``_audit`` reads. ``_audit_path = None``
        # short-circuits the disk path; the lock + warned-flag
        # are belt-and-braces against a future ``_audit`` body
        # that reads them BEFORE the short-circuit.
        inst = server_mod.LLMDispatcher.__new__(
            server_mod.LLMDispatcher,
        )
        inst._audit_path = None
        inst._audit_lock = _thr.Lock()
        inst._audit_warned = False
        captured: dict = {}
        def _spy_log(level, *args, **kwargs):
            captured["level"] = level
            captured["called"] = True
        with patch.object(server_mod._logger, "log", side_effect=_spy_log):
            server_mod.LLMDispatcher._audit(inst, ev)
        assert captured.get("called"), (
            "_audit did not call _logger.log — implementation may "
            "have switched to _logger.info/_logger.debug directly. "
            "Update the test to follow the new shape."
        )
        return captured["level"]

    def test_request_dispatch_ok_uses_debug(self):
        # The high-frequency case that's responsible for the
        # bulk of operator log noise during /agentic.
        assert self._capture_log_call(
            "request.dispatch", "ok",
        ) == logging.DEBUG

    def test_request_dispatch_error_stays_info(self):
        # Errors are operator-relevant; stay at INFO so the
        # operator sees them in the terminal stream.
        assert self._capture_log_call(
            "request.dispatch", "error",
        ) == logging.INFO

    def test_server_start_stays_info(self):
        # Low-frequency lifecycle events stay at INFO.
        assert self._capture_log_call(
            "server.start", "ok",
        ) == logging.INFO

    def test_token_issue_stays_info(self):
        # Token issuance — rare, security-relevant — stays at INFO.
        assert self._capture_log_call(
            "token.issue", "ok",
        ) == logging.INFO

    def test_request_error_stays_info(self):
        # Real dispatcher emits ``request.error`` events; they
        # must always be visible to operators.
        assert self._capture_log_call(
            "request.error", "error",
        ) == logging.INFO

    def test_unknown_event_type_defaults_to_info(self):
        # New event types added later default to INFO (the
        # ``_HIGH_FREQ_OK_EVENTS`` set is opt-in, not opt-out)
        # — operator-conservative: a new event type that turns
        # out to be high-frequency would surface here rather
        # than silently disappear into DEBUG.
        assert self._capture_log_call(
            "future.event", "ok",
        ) == logging.INFO

    def test_high_freq_set_is_a_set(self):
        # The set-based dispatch is a regression guard for the
        # comment in scanner.py — future high-frequency event
        # types join the demotion list cleanly without
        # re-introducing the noise on their own. Pin the type
        # so a refactor doesn't accidentally swap it for a
        # string equality check again.
        from core.llm.dispatcher import server as server_mod
        assert isinstance(server_mod._HIGH_FREQ_OK_EVENTS, frozenset)
        assert "request.dispatch" in server_mod._HIGH_FREQ_OK_EVENTS
