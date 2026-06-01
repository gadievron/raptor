"""Tests for output directory resolution."""

import os
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.run.output import (
    get_output_dir,
    resolve_default_target,
    TargetMismatchError,
    unique_run_suffix,
)

# Mock that disables project resolution — for testing standalone (no project) mode.
_NO_SYMLINK = patch("core.run.output._resolve_active_project", return_value=None)


class TestGetOutputDir(unittest.TestCase):

    @_NO_SYMLINK
    def test_explicit_out_takes_priority(self, _mock):
        with TemporaryDirectory() as d:
            explicit = os.path.join(d, "my-output")
            result = get_output_dir("scan", target_name="repo", explicit_out=explicit)
            self.assertEqual(result, Path(explicit).resolve())

    def test_project_dir_produces_hyphen_subdir(self):
        with TemporaryDirectory() as d:
            with patch("core.run.output._resolve_active_project",
                       return_value=(d, "test", "")):
                result = get_output_dir("scan")
                self.assertEqual(result.parent, Path(d))
                self.assertTrue(result.name.startswith("scan-"))
                self.assertNotIn("_", result.name.split("-", 1)[1][:8])

    @_NO_SYMLINK
    def test_default_produces_underscore_dirname(self, _mock):
        result = get_output_dir("scan", target_name="myrepo")
        self.assertIn("scan_myrepo_", result.name)

    @_NO_SYMLINK
    def test_empty_target_omits_target(self, _mock):
        result = get_output_dir("scan", target_name="")
        self.assertTrue(result.name.startswith("scan_"))
        parts = result.name.split("_")
        # scan_<date>_<time>_pid<N>_<ns-tail> — at least 5 parts now
        # (4-digit monotonic-ns tail added in batch 143 for in-process
        # collision avoidance). The pid marker is no longer the LAST
        # part; assert it appears in the suffix segment instead.
        self.assertGreaterEqual(len(parts), 5)
        pid_parts = [p for p in parts if p.startswith("pid")]
        self.assertEqual(len(pid_parts), 1, f"expected one pid marker in {parts!r}")

    def test_concurrent_same_second_invocations_get_distinct_dirs(self):
        # The bug being fixed: two RAPTOR processes starting in the same
        # wall-clock second used to compute identical run-dir names.
        # mkdir(exist_ok=True) didn't fail; both wrote to the same dir;
        # CI saw "mtime collisions". PID suffix forces distinct names
        # because two simultaneous processes have different PIDs.
        with TemporaryDirectory() as d:
            with patch("core.run.output._resolve_active_project",
                       return_value=(d, "test", "")):
                # Pin the timestamp string so both calls see the same second
                with patch("time.strftime", return_value="20260427-120000"):
                    # Simulate sibling process via patched os.getpid
                    with patch("os.getpid", return_value=11111):
                        a = get_output_dir("scan")
                    with patch("os.getpid", return_value=22222):
                        b = get_output_dir("scan")
                    self.assertNotEqual(a, b,
                        "same-second invocations from different processes "
                        "must produce distinct dir names")


@contextmanager
def _mock_project(d, name="myapp", target=None):
    """Patch ``_resolve_active_project`` to return synthetic (output_dir,
    name, target) values for the test.

    ``target`` defaults to ``<d>/vulns`` so every per-test scratch dir
    gets a hermetic project-target path under it. Yields the resolved
    target string so the test body can build matching subdirs / sibling
    "other" paths against the same scratch root — no hardcoded /tmp
    literals leak into the assertions."""
    if target is None:
        target = str(Path(d) / "vulns")
    with patch("core.run.output._resolve_active_project",
               return_value=(d, name, target)):
        yield target


class TestTargetMismatch(unittest.TestCase):

    def test_matching_target_ok(self):
        with TemporaryDirectory() as d:
            with _mock_project(d) as target:
                get_output_dir("scan", target_path=target)

    def test_subdirectory_target_ok(self):
        with TemporaryDirectory() as d:
            with _mock_project(d) as target:
                subdir = str(Path(target) / "src" / "parser")
                get_output_dir("scan", target_path=subdir)

    def test_different_target_raises(self):
        with TemporaryDirectory() as d:
            with _mock_project(d):
                other = str(Path(d) / "other")
                with self.assertRaises(TargetMismatchError) as ctx:
                    get_output_dir("scan", target_path=other)
                self.assertIn("outside project", str(ctx.exception))
                self.assertIn("/project create", str(ctx.exception))
                self.assertIn("/project use none", str(ctx.exception))

    def test_no_project_target_skips_check(self):
        with TemporaryDirectory() as d:
            with _mock_project(d, target=""):
                anywhere = str(Path(d) / "anywhere")
                get_output_dir("scan", target_path=anywhere)

    def test_caller_dir_mismatch_raises(self):
        """RAPTOR_CALLER_DIR is used for mismatch check when no explicit target."""
        with TemporaryDirectory() as d:
            with _mock_project(d):
                other = str(Path(d) / "other")
                env = {"RAPTOR_CALLER_DIR": other}
                with patch.dict(os.environ, env):
                    with self.assertRaises(TargetMismatchError):
                        get_output_dir("scan")

    def test_caller_dir_matches(self):
        """RAPTOR_CALLER_DIR matching project target is fine."""
        with TemporaryDirectory() as d:
            with _mock_project(d) as target:
                env = {"RAPTOR_CALLER_DIR": target}
                with patch.dict(os.environ, env):
                    get_output_dir("scan")

    def test_explicit_out_skips_check(self):
        with TemporaryDirectory() as d:
            with _mock_project(d):
                manual = str(Path(d) / "manual")
                other = str(Path(d) / "other")
                result = get_output_dir("scan", explicit_out=manual,
                                        target_path=other)
                self.assertEqual(result, Path(manual).resolve())


class TestUniqueRunSuffix(unittest.TestCase):
    """The collision-prevention primitive used by every standalone-mode
    output-dir computation across RAPTOR."""

    # The 4-digit monotonic-ns tail (added in batch 143) makes
    # exact-string assertions impractical without also patching
    # time.monotonic_ns. Use prefix + shape assertions instead so
    # the tests survive future tail-format adjustments.
    def test_underscore_separator(self):
        with patch("time.strftime", return_value="20260427_120000"):
            with patch("os.getpid", return_value=12345):
                suffix = unique_run_suffix("_")
                self.assertTrue(suffix.startswith("20260427_120000_pid12345_"))
                tail = suffix.rsplit("_", 1)[-1]
                self.assertEqual(len(tail), 4)
                self.assertTrue(tail.isdigit())

    def test_hyphen_separator(self):
        with patch("time.strftime", return_value="20260427-120000"):
            with patch("os.getpid", return_value=12345):
                suffix = unique_run_suffix("-")
                self.assertTrue(suffix.startswith("20260427-120000-pid12345-"))
                tail = suffix.rsplit("-", 1)[-1]
                self.assertEqual(len(tail), 4)
                self.assertTrue(tail.isdigit())

    def test_default_separator_is_underscore(self):
        # Standalone mode is the more common shape, so default to '_'.
        with patch("time.strftime", return_value="20260427_120000"):
            with patch("os.getpid", return_value=12345):
                suffix = unique_run_suffix()
                self.assertTrue(suffix.startswith("20260427_120000_pid12345_"))

    def test_uses_correct_strftime_format_for_separator(self):
        # The separator threads through into strftime so the date and time
        # use the same separator as the suffix join — keeps the dirname
        # visually consistent (no mixed `-` and `_`).
        captured = {}
        def capture(fmt):
            captured["fmt"] = fmt
            return "20260427-120000"
        with patch("time.strftime", side_effect=capture):
            with patch("os.getpid", return_value=99):
                unique_run_suffix("-")
        self.assertEqual(captured["fmt"], "%Y%m%d-%H%M%S")

    def test_rejects_unsupported_separator(self):
        # Defends against strftime-directive injection — passing `%H` as
        # separator would otherwise interpolate into the format string.
        with self.assertRaises(ValueError):
            unique_run_suffix("%H")
        with self.assertRaises(ValueError):
            unique_run_suffix("/")
        with self.assertRaises(ValueError):
            unique_run_suffix("")

    def test_two_pids_produce_distinct_suffixes(self):
        # The fundamental property: two concurrent processes get different
        # PIDs and therefore different suffixes even at the same wall-clock
        # second.
        with patch("time.strftime", return_value="20260427_120000"):
            with patch("os.getpid", return_value=11111):
                a = unique_run_suffix("_")
            with patch("os.getpid", return_value=22222):
                b = unique_run_suffix("_")
            self.assertNotEqual(a, b)


class TestResolveDefaultTarget(unittest.TestCase):
    """CLAUDE.md DEFAULT TARGET DIRECTORY resolution chain — active
    project → ``RAPTOR_CALLER_DIR`` → None."""

    def test_active_project_target_wins(self):
        with TemporaryDirectory() as d:
            with _mock_project(d, target="/path/to/project/target"):
                with patch.dict(os.environ,
                                {"RAPTOR_CALLER_DIR": "/path/from/env"}):
                    self.assertEqual(resolve_default_target(),
                                     "/path/to/project/target")

    def test_falls_back_to_caller_dir_when_no_project(self):
        with _NO_SYMLINK:
            with patch.dict(os.environ,
                            {"RAPTOR_CALLER_DIR": "/path/from/env"}):
                self.assertEqual(resolve_default_target(), "/path/from/env")

    def test_returns_none_when_neither_signal_present(self):
        with _NO_SYMLINK:
            env = {k: v for k, v in os.environ.items()
                   if k != "RAPTOR_CALLER_DIR"}
            with patch.dict(os.environ, env, clear=True):
                self.assertIsNone(resolve_default_target())

    def test_empty_caller_dir_returns_none(self):
        # Empty-string env var is "not set" in CLAUDE.md's semantics.
        with _NO_SYMLINK:
            with patch.dict(os.environ, {"RAPTOR_CALLER_DIR": ""}):
                self.assertIsNone(resolve_default_target())


if __name__ == "__main__":
    unittest.main()
