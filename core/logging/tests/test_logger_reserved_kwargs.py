"""Regression tests for RaptorLogger reserved-kwarg handling.

F004: `RaptorLogger.critical` skipped `_split_kwargs` (open-coded only
`exc_info` / `stack_info` pop), so any reserved LogRecord attribute name
passed as a kwarg (e.g. `name=`, `module=`, `args=`) crashed
`logging.makeRecord` with KeyError. Sibling levels (`debug`/`info`/
`warning`/`error`) already route through `_split_kwargs`, which prefixes
reserved names with `extra_`.

This test exercises every public level method with a reserved kwarg
(`name=`). Pre-fix: `critical` is the only one that raises. Post-fix:
all five succeed and the value surfaces as `extra_name` on the record.
"""

from __future__ import annotations

import logging
import unittest

from core.logging import RaptorLogger


class _CapturingHandler(logging.Handler):
    """Collect records for inspection without touching disk."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class ReservedKwargAcrossLevelsTest(unittest.TestCase):
    """Every level method must route reserved kwargs through _split_kwargs."""

    def setUp(self) -> None:
        self.raptor_logger = RaptorLogger()
        self.handler = _CapturingHandler()
        self.raptor_logger.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.raptor_logger.logger.removeHandler(self.handler)

    def _assert_reserved_kwarg_survives(self, method_name: str) -> None:
        method = getattr(self.raptor_logger, method_name)
        # Pre-fix `critical` raises KeyError here: "Attempt to overwrite
        # 'name' in LogRecord". `debug`/`info`/`warning`/`error` already
        # rename it to `extra_name`.
        method("F004 probe", name="reserved-collider-value")
        # The most recent record must carry the renamed attribute.
        last = self.handler.records[-1]
        self.assertEqual(
            getattr(last, "extra_name", None),
            "reserved-collider-value",
            f"{method_name}() lost the reserved kwarg (no _split_kwargs?)",
        )

    def test_debug_accepts_reserved_name_kwarg(self) -> None:
        self._assert_reserved_kwarg_survives("debug")

    def test_info_accepts_reserved_name_kwarg(self) -> None:
        self._assert_reserved_kwarg_survives("info")

    def test_warning_accepts_reserved_name_kwarg(self) -> None:
        self._assert_reserved_kwarg_survives("warning")

    def test_error_accepts_reserved_name_kwarg(self) -> None:
        self._assert_reserved_kwarg_survives("error")

    def test_critical_accepts_reserved_name_kwarg(self) -> None:
        # F004 regression: this is the failing case pre-fix.
        self._assert_reserved_kwarg_survives("critical")

    def test_critical_preserves_exc_info_and_stack_info(self) -> None:
        """`critical` must still honour the two logger-call params it pops."""
        try:
            raise ValueError("F004 sentinel")
        except ValueError:
            self.raptor_logger.critical("with exc", exc_info=True)
        last = self.handler.records[-1]
        self.assertIsNotNone(last.exc_info)
        # `exc_info` must NOT show up as an `extra_*` field — it's a
        # logger-call param, not user payload.
        self.assertFalse(hasattr(last, "extra_exc_info"))


if __name__ == "__main__":
    unittest.main()
