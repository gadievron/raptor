"""Tests for ``compute_filters._read_changed_files`` fallback behaviour.

The workflow's ``changes`` job writes a list of changed files to
``$CHANGED_FILES_LIST``. ``_read_changed_files`` decides how to
interpret the four observable states:

1. env var unset                 → ``None`` (force all filters on)
2. env var set, file missing     → ``None`` (force all filters on)
3. env var set, file empty       → ``None`` (force all filters on)
4. env var set, file non-empty   → parsed list

State 3 is the cross-fork PR case: ``gh api .../pulls/N/files`` can
silently return zero entries on partial auth, and a real PR always
changes at least one file, so an empty list means "diff base
unavailable" — force-on is the safe interpretation, since the
alternative (returning ``[]``) would skip every gated matrix entry
and report a green CI while CodeQL ran nothing.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# .github/tests/test_compute_filters.py → parents[2] = repo root
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / ".github" / "scripts"))
import compute_filters  # noqa: E402


class ReadChangedFilesTests(unittest.TestCase):
    def test_unset_env_returns_none(self):
        import os as _os
        env = {k: v for k, v in _os.environ.items() if k != "CHANGED_FILES_LIST"}
        with mock.patch.dict("os.environ", env, clear=True):
            self.assertIsNone(compute_filters._read_changed_files())

    def test_missing_file_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            ghost = Path(d) / "does_not_exist.txt"
            with mock.patch.dict(
                "os.environ", {"CHANGED_FILES_LIST": str(ghost)}
            ):
                self.assertIsNone(compute_filters._read_changed_files())

    def test_empty_file_returns_none(self):
        """Fork-PR partial-auth case: gh api returned zero entries."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as f:
            f.write("")
            empty_path = f.name
        try:
            with mock.patch.dict(
                "os.environ", {"CHANGED_FILES_LIST": empty_path}
            ):
                self.assertIsNone(compute_filters._read_changed_files())
        finally:
            Path(empty_path).unlink(missing_ok=True)

    def test_whitespace_only_file_returns_none(self):
        """Blank-lines-only file — same defensive intent as empty."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as f:
            f.write("\n  \n\t\n")
            ws_path = f.name
        try:
            with mock.patch.dict(
                "os.environ", {"CHANGED_FILES_LIST": ws_path}
            ):
                self.assertIsNone(compute_filters._read_changed_files())
        finally:
            Path(ws_path).unlink(missing_ok=True)

    def test_populated_file_returns_list(self):
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as f:
            f.write("core/sandbox/context.py\n")
            f.write("packages/codeql/agent.py\n")
            pop_path = f.name
        try:
            with mock.patch.dict(
                "os.environ", {"CHANGED_FILES_LIST": pop_path}
            ):
                got = compute_filters._read_changed_files()
                self.assertEqual(
                    got,
                    ["core/sandbox/context.py", "packages/codeql/agent.py"],
                )
        finally:
            Path(pop_path).unlink(missing_ok=True)


class EvaluateFallbackTests(unittest.TestCase):
    def test_none_forces_all_filters_true(self):
        """``None`` (any of the three unavailable cases) must force-on
        every filter so CodeQL runs full analysis rather than silently
        skipping the matrix."""
        results = compute_filters.evaluate(None)
        self.assertEqual(set(results), set(compute_filters.FILTERS))
        for name, hit in results.items():
            self.assertTrue(
                hit,
                msg=f"filter {name!r} was not forced on under None input",
            )

    def test_empty_list_distinct_from_none(self):
        """Explicit empty list (genuinely no changes) → all filters off.

        ``_read_changed_files`` no longer surfaces this state to
        ``evaluate``, but the function's contract is unchanged:
        an empty list means "no files matched anything".
        """
        results = compute_filters.evaluate([])
        for name, hit in results.items():
            self.assertFalse(
                hit,
                msg=f"filter {name!r} matched on empty input",
            )


if __name__ == "__main__":
    unittest.main()
