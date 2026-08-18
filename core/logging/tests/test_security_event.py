"""Security-event stream substrate tests.

``log_security_event`` is an OBSERVABILITY stream restored after its
original emitters (core/git clone validation, static-analysis
scanner — commit c1af3314) were dropped in the April 2026
restructures. The substrate contract the emitters rely on:

  * events land on the "raptor" logger at WARNING with a
    ``SECURITY: <event_type> - `` message prefix and a structured
    ``event_type`` attribute (greppable in console output AND
    queryable in the JSONL audit trail);
  * emission NEVER raises — a broken sink must not turn a working
    rejection / denial path into a crash;
  * the module-level function additionally survives RaptorLogger
    initialisation failure (bootstrap-order safety for libexec
    scripts).
"""

from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

import core.logging as core_logging
from core.logging import log_security_event


class _CapturingHandler(logging.Handler):
    """Collect records for inspection without touching disk."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _SecurityEventTestBase(unittest.TestCase):
    def setUp(self) -> None:
        # Resolve the class through the module global (call-time
        # binding), not the collection-time import: an earlier test
        # reloading core.logging leaves the imported symbol pointing at
        # a stale class whose singleton is not the one the code under
        # test emits through.
        self.raptor_logger = core_logging.RaptorLogger()
        self.handler = _CapturingHandler()
        self.raptor_logger.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.raptor_logger.logger.removeHandler(self.handler)

    def _security_records(self) -> list[logging.LogRecord]:
        return [
            r for r in self.handler.records
            if r.getMessage().startswith("SECURITY: ")
        ]


class MethodEmissionTest(_SecurityEventTestBase):
    """RaptorLogger.log_security_event — the original call convention."""

    def test_emits_warning_with_event_type(self) -> None:
        self.raptor_logger.log_security_event(
            "invalid_repo_url",
            "Rejected potentially unsafe repository URL: https://x",
        )
        records = self._security_records()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.levelno, logging.WARNING)
        self.assertTrue(record.getMessage().startswith(
            "SECURITY: invalid_repo_url - ",
        ))
        self.assertEqual(record.event_type, "invalid_repo_url")

    def test_context_kwargs_surface_as_record_attributes(self) -> None:
        self.raptor_logger.log_security_event(
            "sandbox_denial", "denied", denial_type="network",
            returncode=1,
        )
        record = self._security_records()[0]
        self.assertEqual(record.denial_type, "network")
        self.assertEqual(record.returncode, 1)

    def test_never_raises_on_sink_failure(self) -> None:
        # Patch the emitting INSTANCE, not the class symbol: a
        # class-level patch silently misses when an earlier test
        # reloaded core.logging (the singleton then belongs to a
        # different class object) and the real sink runs anyway.
        with patch.object(
            self.raptor_logger, "warning",
            side_effect=OSError("sink down"),
        ):
            # Must not propagate — emission is best-effort.
            self.raptor_logger.log_security_event("probe", "sink failure")
        self.assertEqual(self._security_records(), [])

    def test_reserved_kwarg_does_not_crash_emission(self) -> None:
        # `module` is a reserved LogRecord name; _split_kwargs renames
        # it. The security stream must inherit that resilience.
        self.raptor_logger.log_security_event(
            "probe", "reserved kwarg", module="collider",
        )
        record = self._security_records()[0]
        self.assertEqual(record.extra_module, "collider")


class ModuleFunctionTest(_SecurityEventTestBase):
    """core.logging.log_security_event — for stdlib per-module loggers."""

    def test_emits_through_singleton(self) -> None:
        log_security_event(
            "untrusted_rules_dir_rejected", "refused", rules_dir="/x",
        )
        record = self._security_records()[0]
        self.assertEqual(record.event_type, "untrusted_rules_dir_rejected")
        self.assertEqual(record.rules_dir, "/x")

    def test_never_raises_when_logger_init_fails(self) -> None:
        with patch.object(
            core_logging, "RaptorLogger",
            side_effect=RuntimeError("LOG_DIR unwritable"),
        ):
            log_security_event("probe", "bootstrap failure")
        self.assertEqual(self._security_records(), [])

    def test_never_raises_on_sink_failure(self) -> None:
        # The module function resolves RaptorLogger from the module
        # globals at call time — patch the instance that resolution
        # will return, so the test stays hermetic even after an
        # earlier test reloaded core.logging.
        emitter = core_logging.RaptorLogger()
        with patch.object(
            emitter, "warning", side_effect=OSError("sink down"),
        ):
            log_security_event("probe", "sink failure")
        self.assertEqual(self._security_records(), [])


if __name__ == "__main__":
    unittest.main()
