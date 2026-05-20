"""Regression tests for RaptorLogger format-string / positional-args support.

Pre-fix the level methods had signature `(message: str, **kwargs)`. Callers
using the standard stdlib `logging.Logger` API — `logger.info("Processing
%s files", count)` — got `TypeError: info() takes 2 positional arguments
but 3 were given`. The bifurcation between `get_logger()` (RaptorLogger
wrapper, no positional args) and `get_logger("name")` (raw `logging.Logger`,
positional args fine) was an accidental API divergence; ~21 callsites in
the tree were silently broken because the majority pattern was the wrapper.

Post-fix: `(message: str, *args, **kwargs)` — args flow through to
`self.logger.<level>(message, *args, extra=..., exc_info=..., stack_info=...)`
and the stdlib `LogRecord.getMessage()` applies %-formatting lazily.

This test covers all five level methods × the three format styles that
matter (single %s, multi-arg, mapping-style %(name)s), plus the no-args
backwards-compat path and the args+extra interaction so future regressions
don't reintroduce the bifurcation.
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


class FormatArgsAcrossLevelsTest(unittest.TestCase):
    """Every level method must accept positional args and %-format them."""

    def setUp(self) -> None:
        self.raptor_logger = RaptorLogger()
        self.handler = _CapturingHandler()
        self.raptor_logger.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.raptor_logger.logger.removeHandler(self.handler)

    def _last_message(self) -> str:
        return self.handler.records[-1].getMessage()

    def _assert_single_arg(self, method_name: str) -> None:
        method = getattr(self.raptor_logger, method_name)
        # Pre-fix: TypeError. Post-fix: stdlib %-formatting via getMessage().
        method("Processing %s files", 42)
        self.assertEqual(self._last_message(), "Processing 42 files")

    def test_debug_accepts_positional_args(self) -> None:
        self._assert_single_arg("debug")

    def test_info_accepts_positional_args(self) -> None:
        self._assert_single_arg("info")

    def test_warning_accepts_positional_args(self) -> None:
        self._assert_single_arg("warning")

    def test_error_accepts_positional_args(self) -> None:
        self._assert_single_arg("error")

    def test_critical_accepts_positional_args(self) -> None:
        self._assert_single_arg("critical")


class FormatStyleTest(unittest.TestCase):
    """Exercise the three %-formatting shapes stdlib logging supports."""

    def setUp(self) -> None:
        self.raptor_logger = RaptorLogger()
        self.handler = _CapturingHandler()
        self.raptor_logger.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.raptor_logger.logger.removeHandler(self.handler)

    def test_multi_positional_args(self) -> None:
        self.raptor_logger.info("git fetch (depth=%d): %s @ %s", 1, "github.com/x/y", "abc123")
        self.assertEqual(
            self.handler.records[-1].getMessage(),
            "git fetch (depth=1): github.com/x/y @ abc123",
        )

    def test_mapping_style_format(self) -> None:
        # Stdlib supports `args` being a single dict for %(name)s formatting.
        self.raptor_logger.warning(
            "%(host)s failed: %(err)s",
            {"host": "example.com", "err": "timeout"},
        )
        self.assertEqual(
            self.handler.records[-1].getMessage(),
            "example.com failed: timeout",
        )

    def test_typeful_args_repr_via_pct_s(self) -> None:
        # `%s` calls str() on the arg — Path / Exception / custom objects
        # serialise without the caller pre-stringifying.
        from pathlib import Path
        self.raptor_logger.error("read failed for %s: %s", Path("/tmp/x"), ValueError("nope"))
        self.assertEqual(
            self.handler.records[-1].getMessage(),
            "read failed for /tmp/x: nope",
        )


class BackwardsCompatTest(unittest.TestCase):
    """Existing f-string + bare-message callers must still work."""

    def setUp(self) -> None:
        self.raptor_logger = RaptorLogger()
        self.handler = _CapturingHandler()
        self.raptor_logger.logger.addHandler(self.handler)

    def tearDown(self) -> None:
        self.raptor_logger.logger.removeHandler(self.handler)

    def test_no_args_no_formatting(self) -> None:
        # f-string / pre-formatted message, no positional args. Must NOT
        # try to %-format (would crash on `%` chars in the message).
        self.raptor_logger.info("Coverage: 87% of files reviewed")
        self.assertEqual(
            self.handler.records[-1].getMessage(),
            "Coverage: 87% of files reviewed",
        )

    def test_kwargs_still_route_to_extra(self) -> None:
        # Pre-existing kwarg-as-extra contract preserved (the reserved-
        # kwarg test covers the rename path; this one covers the
        # plain-passthrough path alongside positional args).
        self.raptor_logger.info("Processed %s files", 5, job_id="abc-123")
        last = self.handler.records[-1]
        self.assertEqual(last.getMessage(), "Processed 5 files")
        self.assertEqual(getattr(last, "job_id", None), "abc-123")


if __name__ == "__main__":
    unittest.main()
