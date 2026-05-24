"""Tests for the libexec/raptor-sca-run wrapper."""

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


# parents[0] = packages/sca/tests/
# parents[1] = packages/sca/
# parents[2] = packages/
# parents[3] = repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-sca-run"


def _run(*args, env_extra=None, trusted=True, **kwargs):
    """Invoke the wrapper as a real subprocess.

    By default the subprocess is marked trusted (``_RAPTOR_TRUSTED=1``)
    so it passes the libexec marker check. Pass ``trusted=False`` to
    test the refusal path.
    """
    env = os.environ.copy()
    # Strip RAPTOR_CALLER_DIR so default-target resolution doesn't
    # silently scan the test runner's cwd.
    env.pop("RAPTOR_CALLER_DIR", None)
    # Strip all trust markers from the inherited env so the test is
    # deterministic regardless of whether the runner sees CLAUDECODE
    # (e.g., running under Claude Code itself).
    for v in ("CLAUDECODE", "_RAPTOR_TRUSTED", "RAPTOR_DIR"):
        env.pop(v, None)
    if trusted:
        env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["python3", str(WRAPPER), *args],
        capture_output=True, text=True, timeout=30,
        env=env, **kwargs,
    )


class RaptorScaRunWrapperTests(unittest.TestCase):

    def setUp(self):
        # Per-test scratch dir so target/file path tests get hermetic
        # values — avoids cwd-relative paths that leaked test-order
        # pollution into the suite, and host-absolute paths like
        # /etc/hostname that depend on the runner's filesystem.
        self._tmp = TemporaryDirectory()
        self.scratch = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_wrapper_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.exists(), msg=f"missing: {WRAPPER}")
        self.assertTrue(os.access(WRAPPER, os.X_OK),
                        msg=f"not executable: {WRAPPER}")

    def test_no_args_no_caller_dir_shows_help(self):
        result = _run()
        self.assertEqual(result.returncode, 0)
        self.assertIn("raptor-sca", result.stdout)
        self.assertIn("Commands:", result.stdout)
        self.assertIn("fix", result.stdout)
        self.assertIn("check", result.stdout)
        self.assertIn("upgrade", result.stdout)

    def test_help_flag_shows_help(self):
        result = _run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Commands:", result.stdout)

    def test_short_help_flag_shows_help(self):
        result = _run("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Commands:", result.stdout)

    def test_unknown_subcommand_returns_2(self):
        result = _run("definitely-not-a-subcommand")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown subcommand", result.stderr)

    def test_nonexistent_target_returns_2(self):
        # Path under the per-test scratch tmpdir that we never create —
        # guaranteed nonexistent regardless of cwd / test ordering.
        nonexistent = str(self.scratch / "does-not-exist-xyz-12345")
        result = _run(nonexistent)
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not exist", result.stderr)

    def test_target_is_file_not_dir_returns_2(self):
        # Plant a real file under the scratch tmpdir so the test
        # doesn't depend on a host-specific path like /etc/hostname.
        f = self.scratch / "target-file"
        f.write_text("not a directory")
        result = _run(str(f))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a directory", result.stderr)

    def test_subcommand_dispatches_to_cli(self):
        """check subcommand routes to packages.sca.review.

        Offline + PyPI + django + no advisories cached → review still
        runs and emits its review-report markdown. We assert positively:
        - exit 0 or 1 (Clean or Review verdict — never 2/3 which would
          mean argparse error or internal crash)
        - stdout contains the review-report markdown header
          ``# raptor-sca check —`` so we know review.main was reached
          (not just any subcommand dispatch failure).
        """
        result = _run("check", "PyPI", "django", "4.2.10",
                      "--no-transitive", "--offline")
        self.assertNotIn("unknown subcommand", result.stderr)
        self.assertIn(result.returncode, (0, 1),
                      msg=f"unexpected rc={result.returncode}; "
                          f"stderr={result.stderr[:200]}")
        self.assertIn("# raptor-sca check —", result.stdout,
                      msg="review report header missing — dispatch may have "
                          "failed before reaching review.main")

    def test_purl_subcommand_works(self):
        """Sanity: purl is fully self-contained, should always work."""
        result = _run("purl", "PyPI", "django", "4.2.10")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "pkg:pypi/django@4.2.10")

    def test_help_scan_shows_full_scan_help(self):
        result = _run("--help-scan")
        self.assertEqual(result.returncode, 0)
        # The scan parser's --help output mentions specific scan-only flags.
        self.assertIn("--no-kev", result.stdout)
        self.assertIn("--no-epss", result.stdout)

    # --- Marker-check tests ---------------------------------------------

    def test_marker_check_refuses_without_trust_marker(self):
        """Direct invocation without any trust marker is refused."""
        result = _run("--help", trusted=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("internal dispatch script", result.stderr)
        self.assertIn("bin/raptor-sca", result.stderr)

    def test_marker_check_accepts_claudecode(self):
        """CLAUDECODE marker satisfies the trust check."""
        result = _run("--help", trusted=False, env_extra={"CLAUDECODE": "1"})
        self.assertEqual(result.returncode, 0)
        self.assertIn("Commands:", result.stdout)

    def test_marker_check_rejects_raptor_dir(self):
        """RAPTOR_DIR alone must NOT satisfy the trust check.

        The launcher (bin/raptor) sets both RAPTOR_DIR and
        _RAPTOR_TRUSTED, but RAPTOR_DIR is intentionally excluded from
        the trust-marker set: a user who happens to ``export
        RAPTOR_DIR`` in their shell for convenience would otherwise
        silently bypass the marker check. _RAPTOR_TRUSTED + CLAUDECODE
        cover all legitimate trusted-caller paths.
        """
        result = _run("--help", trusted=False,
                      env_extra={"RAPTOR_DIR": str(REPO_ROOT)})
        self.assertEqual(result.returncode, 2)
        self.assertIn("internal dispatch script", result.stderr)


if __name__ == "__main__":
    unittest.main()
