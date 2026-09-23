"""Capped-by-default read contract of the shared JSON loader.

Every ``load_json`` / ``load_json_with_comments`` call pays
``DEFAULT_JSON_MAX_BYTES`` unless the site sets its own budget;
``load_json_unbounded`` is the named, justification-bearing opt-out.
The refusal direction is exercised at the REAL default with a sparse
plant (the fstat gate refuses before any read, so a >256 MiB file
costs neither disk nor read time), and the mechanism directions at a
patched default so the tests stay cheap.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import core.json.utils as json_utils
from core.json import (
    DEFAULT_JSON_MAX_BYTES,
    JsonBudgetExceededError,
    load_json,
    load_json_unbounded,
    load_json_with_comments,
)


def _sparse(path: Path, size: int) -> Path:
    """A sparse file of st_size ``size`` (no disk, no content)."""
    with path.open("wb") as fh:
        fh.truncate(size)
    return path


class TestDefaultBudgetRealValue(unittest.TestCase):
    """Two directions at the real default value."""

    def test_over_default_refused_without_read(self):
        with TemporaryDirectory() as d:
            big = _sparse(Path(d) / "big.json", DEFAULT_JSON_MAX_BYTES + 1)
            # non-strict: warn-and-None, the malformed-file contract
            with self.assertLogs("core.json.utils", level="WARNING") as logs:
                self.assertIsNone(load_json(big))
            self.assertTrue(
                any("exceeds max_bytes" in line for line in logs.output),
                logs.output,
            )

    def test_over_default_strict_raises_budget_error(self):
        with TemporaryDirectory() as d:
            big = _sparse(Path(d) / "big.json", DEFAULT_JSON_MAX_BYTES + 1)
            # The distinct subclass (still a ValueError, so existing
            # malformed-input handlers cover it) — strict callers can
            # report the refusal separately, per the class's contract.
            with self.assertRaisesRegex(
                JsonBudgetExceededError, "exceeds max_bytes",
            ):
                load_json(big, strict=True)

    def test_under_default_loads(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "f.json"
            f.write_text('{"a": 1}', encoding="utf-8")
            self.assertEqual(load_json(f), {"a": 1})


class TestDefaultResolvedAtCallTime(unittest.TestCase):
    """The default is read from the module constant per call, so the
    site-conversion tests (and deployments with a different risk
    posture) can tighten it without re-binding every signature."""

    def test_patched_default_enforced(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "f.json"
            f.write_text('{"a": "' + "x" * 64 + '"}', encoding="utf-8")
            with mock.patch.object(json_utils, "DEFAULT_JSON_MAX_BYTES", 16):
                self.assertIsNone(load_json(f))
            self.assertEqual(load_json(f)["a"], "x" * 64)

    def test_explicit_site_budget_beats_default(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "f.json"
            f.write_text('{"a": 1}', encoding="utf-8")
            with mock.patch.object(json_utils, "DEFAULT_JSON_MAX_BYTES", 4):
                self.assertEqual(load_json(f, max_bytes=64), {"a": 1})
                with self.assertLogs(
                    "core.json.utils", level="WARNING",
                ):
                    self.assertIsNone(load_json(f, max_bytes=4))


class TestUnbounded(unittest.TestCase):
    def test_reads_past_the_default(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "f.json"
            f.write_text('{"a": 1}', encoding="utf-8")
            with mock.patch.object(json_utils, "DEFAULT_JSON_MAX_BYTES", 4):
                self.assertIsNone(load_json(f))
                self.assertEqual(load_json_unbounded(f), {"a": 1})

    def test_missing_file_still_none(self):
        self.assertIsNone(load_json_unbounded("/nonexistent/x.json"))

    def test_strict_passthrough(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "f.json"
            f.write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json_unbounded(f, strict=True)


class TestWithCommentsDefaultBudget(unittest.TestCase):
    def test_over_default_refused(self):
        with TemporaryDirectory() as d:
            big = _sparse(Path(d) / "big.json", DEFAULT_JSON_MAX_BYTES + 1)
            with self.assertLogs("core.json.utils", level="WARNING") as logs:
                self.assertIsNone(load_json_with_comments(big))
            self.assertTrue(
                any("oversize" in line for line in logs.output), logs.output,
            )

    def test_patched_default_enforced_and_none_waives(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "f.json"
            f.write_text('// c\n{"a": 1}', encoding="utf-8")
            with mock.patch.object(json_utils, "DEFAULT_JSON_MAX_BYTES", 4):
                self.assertIsNone(load_json_with_comments(f))
                self.assertEqual(
                    load_json_with_comments(f, max_bytes=None), {"a": 1},
                )


class TestConstantSingleHomed(unittest.TestCase):
    def test_run_artifact_budget_aliases_the_default(self):
        from core.coverage.record import RUN_ARTIFACT_MAX_BYTES
        self.assertIs(RUN_ARTIFACT_MAX_BYTES, DEFAULT_JSON_MAX_BYTES)

    def test_default_is_the_run_artifact_class(self):
        # Churn guard, both directions documented at the constant:
        # lower starts refusing plausible large artifacts (the
        # 100 MiB SARIF class), higher stops bounding reader memory.
        self.assertEqual(DEFAULT_JSON_MAX_BYTES, 256 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
