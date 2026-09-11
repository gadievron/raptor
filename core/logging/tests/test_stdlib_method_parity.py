"""RaptorLogger stdlib-``Logger`` method parity.

Call sites throughout the pipelines use the singleton exactly like a
stdlib logger — ``logger.exception(...)`` inside except-handlers is
the load-bearing case: with the method absent, every graceful-
degradation handler raised AttributeError, masking the original error
and aborting the run it was meant to save.

Also pins:
* ``taskName`` (a LogRecord attribute since Python 3.12) in the
  reserved-name set — as a plain kwarg it crashed makeRecord.
* ``stacklevel=2`` on the wrappers so the JSONL audit trail
  attributes records to the CALLER, not to core/logging itself.
"""

from __future__ import annotations

import logging
import unittest

from core.logging import RaptorLogger


class _CapturingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class StdlibMethodParityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raptor_logger = RaptorLogger()
        self.handler = _CapturingHandler()
        self.raptor_logger.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.raptor_logger.logger.removeHandler(self.handler)

    def test_exception_logs_error_with_exc_info(self) -> None:
        try:
            raise ValueError("boom-marker")
        except ValueError:
            self.raptor_logger.exception("caught %s", "it")
        rec = self.handler.records[-1]
        self.assertEqual(rec.levelno, logging.ERROR)
        self.assertEqual(rec.getMessage(), "caught it")
        self.assertIsNotNone(rec.exc_info)
        self.assertIn("boom-marker", str(rec.exc_info[1]))

    def test_exception_outside_handler_does_not_crash(self) -> None:
        # stdlib semantics: exc_info=True with no active exception is
        # legal (records "NoneType: None").
        self.raptor_logger.exception("no active exception")
        self.assertEqual(self.handler.records[-1].levelno, logging.ERROR)

    def test_log_with_explicit_level(self) -> None:
        self.raptor_logger.log(logging.WARNING, "via log()")
        rec = self.handler.records[-1]
        self.assertEqual(rec.levelno, logging.WARNING)
        self.assertEqual(rec.getMessage(), "via log()")

    def test_set_level_round_trip(self) -> None:
        previous = self.raptor_logger.logger.level
        try:
            self.raptor_logger.setLevel(logging.CRITICAL)
            self.assertEqual(
                self.raptor_logger.logger.level, logging.CRITICAL)
        finally:
            self.raptor_logger.logger.setLevel(previous)

    def test_taskname_kwarg_is_reserved_renamed(self) -> None:
        # LogRecord grew ``taskName`` in 3.12; as a raw extra it
        # raises "Attempt to overwrite 'taskName' in LogRecord".
        self.raptor_logger.info("msg", taskName="t1")
        rec = self.handler.records[-1]
        self.assertEqual(getattr(rec, "extra_taskName", None), "t1")

    def test_stacklevel_attributes_records_to_caller(self) -> None:
        # Two directions: the wrapper's own frame must NOT be the
        # attributed source, this test function MUST be.
        self.raptor_logger.info("attribution probe")
        rec = self.handler.records[-1]
        self.assertEqual(
            rec.funcName, "test_stacklevel_attributes_records_to_caller")
        self.assertTrue(
            rec.pathname.endswith("test_stdlib_method_parity.py"),
            rec.pathname,
        )

    def test_exception_attributes_to_caller(self) -> None:
        try:
            raise RuntimeError("x")
        except RuntimeError:
            self.raptor_logger.exception("probe")
        rec = self.handler.records[-1]
        self.assertEqual(rec.funcName, "test_exception_attributes_to_caller")


if __name__ == "__main__":
    unittest.main()
