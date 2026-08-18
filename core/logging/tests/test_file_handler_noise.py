"""Tests for the audit-trail file handler — noise controls (file level +
separator filter) and owner-only on-disk permissions."""

import logging
import os
import re
import stat

import core.logging as core_logging
from core.logging import _drop_separator_records, _file_log_level


def _record(msg, *args):
    return logging.LogRecord(
        "raptor", logging.INFO, __file__, 1, msg, args, None,
    )


def _group_other_bits(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode) & 0o077


class TestSeparatorFilter:

    def test_equals_banner_dropped(self):
        assert _drop_separator_records(_record("=" * 70)) is False

    def test_dash_banner_dropped(self):
        assert _drop_separator_records(_record("-" * 40)) is False

    def test_mixed_decoration_dropped(self):
        assert _drop_separator_records(_record("== == == == ==")) is False

    def test_real_message_kept(self):
        assert _drop_separator_records(_record("Scan complete: 3 findings"))

    def test_message_containing_equals_kept(self):
        assert _drop_separator_records(_record("threshold = 5, mode = fast"))

    def test_short_decoration_kept(self):
        # Below the length floor — too short to be a banner, and "--"
        # style fragments can be legitimate content.
        assert _drop_separator_records(_record("=="))

    def test_lazy_format_args_expanded(self):
        # The filter must judge the FORMATTED message, not the template.
        assert _drop_separator_records(_record("%s", "=" * 70)) is False


class TestFileLogLevel:

    def test_default_is_info(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LOG_FILE_LEVEL", raising=False)
        assert _file_log_level() == logging.INFO

    def test_env_debug_restores_firehose(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_FILE_LEVEL", "DEBUG")
        assert _file_log_level() == logging.DEBUG

    def test_env_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_FILE_LEVEL", "warning")
        assert _file_log_level() == logging.WARNING

    def test_unknown_name_falls_back_to_info(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_FILE_LEVEL", "VERBOSE")
        assert _file_log_level() == logging.INFO


class TestOwnerOnlyFileHandler:
    """The JSONL audit trail is created owner-only (0o600).

    A stdlib-default 0644 audit file would let any other local user on
    a shared host read logged exception bodies / prompt fragments.
    ``_OwnerOnlyFileHandler`` applies 0o600 at creation time
    (``os.open`` with an explicit mode — no post-hoc chmod window),
    matching the deliberate 0o600 on the LLM response cache.
    """

    def test_delay_still_defers_file_creation(self, tmp_path):
        log_path = str(tmp_path / "audit.jsonl")
        handler = core_logging._OwnerOnlyFileHandler(log_path, delay=True)
        try:
            assert not os.path.exists(log_path)
        finally:
            handler.close()

    def test_file_created_owner_only(self, tmp_path):
        log_path = str(tmp_path / "audit.jsonl")
        handler = core_logging._OwnerOnlyFileHandler(log_path, delay=True)
        try:
            handler.emit(_record("sensitive payload"))
            assert os.path.exists(log_path)
            # No group/other bits regardless of the process umask.
            assert _group_other_bits(log_path) == 0
        finally:
            handler.close()

    def test_record_content_persisted(self, tmp_path):
        log_path = str(tmp_path / "audit.jsonl")
        handler = core_logging._OwnerOnlyFileHandler(log_path, delay=True)
        handler.setFormatter(core_logging.JSONFormatter())
        handler.emit(_record("audit record body"))
        handler.close()
        with open(log_path) as fh:
            assert "audit record body" in fh.read()

    def test_reopen_appends_and_stays_owner_only(self, tmp_path):
        log_path = str(tmp_path / "audit.jsonl")
        handler = core_logging._OwnerOnlyFileHandler(log_path, delay=True)
        handler.emit(_record("first"))
        handler.close()
        handler = core_logging._OwnerOnlyFileHandler(log_path, delay=True)
        handler.emit(_record("second"))
        handler.close()
        with open(log_path) as fh:
            content = fh.read()
        assert "first" in content
        assert "second" in content
        assert _group_other_bits(log_path) == 0

    def test_not_mistaken_for_console_handler(self, tmp_path):
        # ``set_console_log_level`` mutates console handlers only; the
        # audit handler must stay out of that set.
        handler = core_logging._OwnerOnlyFileHandler(
            str(tmp_path / "audit.jsonl"), delay=True,
        )
        try:
            assert not core_logging._is_console_handler(handler)
        finally:
            handler.close()


class TestRaptorLoggerWiring:
    """The singleton's audit handler uses the owner-only subclass."""

    def _file_handlers(self):
        raptor = core_logging.RaptorLogger()
        # pytest (>= 9) attaches its own capture handlers — including a
        # FileHandler on os.devnull — to every non-propagating logger
        # for the duration of each test, the raptor logger included.
        # Only the handlers the application wired are under test here.
        return [
            h for h in raptor.logger.handlers
            if isinstance(h, logging.FileHandler)
            and not type(h).__module__.startswith("_pytest")
        ]

    def test_audit_handler_is_owner_only_subclass(self):
        handlers = self._file_handlers()
        assert handlers
        for handler in handlers:
            assert isinstance(handler, core_logging._OwnerOnlyFileHandler)

    def test_audit_filename_keeps_pid_disambiguation(self):
        # Collision-safe filename shape:
        # raptor_<epoch>_pid<pid>_<4 digits>.jsonl
        pattern = re.compile(rf"raptor_\d+_pid{os.getpid()}_\d{{4}}\.jsonl$")
        for handler in self._file_handlers():
            assert pattern.search(handler.baseFilename)

    def test_emitted_audit_file_is_owner_only_on_disk(self):
        raptor = core_logging.RaptorLogger()
        raptor.info("audit-trail permission probe write")
        for handler in self._file_handlers():
            assert os.path.exists(handler.baseFilename)
            assert _group_other_bits(handler.baseFilename) == 0
