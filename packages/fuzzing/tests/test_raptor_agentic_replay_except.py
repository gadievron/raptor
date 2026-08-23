"""Tests for raptor_agentic crash replay and subprocess handling.

Per PR #488 review (grokjc): the replay loop must catch only
(OSError, subprocess.SubprocessError, ValueError) — anything else
must propagate so operators see real bugs instead of them silently
turning into "reproduced=False" replay entries.

Drives _replay_fuzz_crashes against a temp dir with a stubbed
sandbox.run that raises various exception types, asserting which
get swallowed vs which propagate.

Also pins:
- _replay_fuzz_crashes runs each replay under the full
  credential-isolation sandbox — restrict_reads=True and fake_home=True
  as the docstring promises — so attacker-derived crash inputs can't
  read ~/.ssh, ~/.aws, models.json etc. and leak them into the captured
  *.stdout.log / *.stderr.log files.
- run_command_streaming's generic exception handler returns
  (-1, "", str(e)) when subprocess.Popen itself raises, instead of
  dying on the unbound ``process`` name.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# parents[3] climbs:
#   [0] packages/fuzzing/tests/  (this file's directory)
#   [1] packages/fuzzing/
#   [2] packages/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class _ReplayCase(unittest.TestCase):
    """Shared fixture: a fake ELF target (plus asan sibling) and one
    crash input, so _replay_fuzz_crashes actually reaches its sandbox
    call site."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True,
        ))
        self.binary = Path(self.tmp) / "target"
        self.binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        self.binary.chmod(0o755)
        # _candidate_replay_binaries looks for sibling `<stem>_asan`
        # / `<stem>_debug` and only includes them if they exist and
        # are executable. Create the asan sibling so the except path
        # inside _replay_fuzz_crashes actually executes.
        asan_sibling = Path(self.tmp) / "target_asan"
        asan_sibling.write_bytes(b"\x7fELF" + b"\x00" * 60)
        asan_sibling.chmod(0o755)
        self.crash_file = Path(self.tmp) / "crash-input"
        self.crash_file.write_bytes(b"\x41" * 16)
        self.out_dir = Path(self.tmp) / "out"


class TestReplayExceptNarrowing(_ReplayCase):
    """The except clause in _replay_fuzz_crashes only catches the
    documented narrow tuple. Other exceptions propagate."""

    def _run_with_sandbox_raising(self, exc):
        """Invoke _replay_fuzz_crashes with sandbox.run patched to
        raise the given exception."""
        from raptor_agentic import _replay_fuzz_crashes
        # _replay_fuzz_crashes does `from core.sandbox import run as
        # _sandbox_run` lazily inside the function, so patch the
        # source-module attribute (core.sandbox.run) which is what
        # the lazy import will resolve to.
        with patch("core.sandbox.run", side_effect=exc):
            return _replay_fuzz_crashes(
                binary_path=self.binary,
                crash_files=[self.crash_file],
                out_dir=self.out_dir,
            )

    # === Caught (narrow tuple — should produce a "reproduced=False" entry) ===

    def test_oserror_is_caught(self):
        result = self._run_with_sandbox_raising(
            OSError("simulated FS failure"),
        )
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(any(e.get("error") for e in entries),
                        f"OSError should be caught + logged: {entries}")

    def test_subprocess_called_process_error_is_caught(self):
        exc = subprocess.CalledProcessError(returncode=1, cmd="x")
        result = self._run_with_sandbox_raising(exc)
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(any(e.get("error") for e in entries),
                        f"CalledProcessError should be caught: {entries}")

    def test_value_error_is_caught(self):
        result = self._run_with_sandbox_raising(
            ValueError("simulated bad arg"),
        )
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(any(e.get("error") for e in entries),
                        f"ValueError should be caught: {entries}")

    # === NOT caught (must propagate — real bugs, not replay failures) ===

    def test_runtime_error_propagates(self):
        """RuntimeError is the canonical "something unexpected went
        wrong in our own code" exception. Pre-narrowing it was
        swallowed and the operator never saw the bug."""
        with self.assertRaises(RuntimeError):
            self._run_with_sandbox_raising(
                RuntimeError("real bug in sandbox setup"),
            )

    def test_attribute_error_propagates(self):
        """AttributeError typically means "we called a method that
        doesn't exist" — a real RAPTOR bug. Must NOT be swallowed."""
        with self.assertRaises(AttributeError):
            self._run_with_sandbox_raising(
                AttributeError("None has no .returncode"),
            )

    def test_keyboard_interrupt_propagates(self):
        """Ctrl-C must always propagate — operator interrupts mean
        STOP, not 'record this as a failed replay and continue'."""
        with self.assertRaises(KeyboardInterrupt):
            self._run_with_sandbox_raising(KeyboardInterrupt())


class _FakeCompleted:
    """Minimal stand-in for subprocess.CompletedProcess (bytes streams)."""

    def __init__(self):
        self.stdout = b"replay stdout"
        self.stderr = b"replay stderr"
        self.returncode = 1


class TestReplaySandboxIsolation(_ReplayCase):
    """_replay_fuzz_crashes engages restrict_reads + fake_home."""

    def _replay_and_capture_kwargs(self):
        from raptor_agentic import _replay_fuzz_crashes
        calls = []

        def _fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return _FakeCompleted()

        # The lazy `from core.sandbox import run` inside the function
        # resolves at call time — patch the source-module attribute.
        with patch("core.sandbox.run", side_effect=_fake_run):
            result = _replay_fuzz_crashes(
                binary_path=self.binary,
                crash_files=[self.crash_file],
                out_dir=self.out_dir,
            )
        return result, calls

    def test_restrict_reads_engaged(self):
        _, calls = self._replay_and_capture_kwargs()
        self.assertTrue(calls, "sandbox run was never invoked")
        for _cmd, kwargs in calls:
            self.assertIs(kwargs.get("restrict_reads"), True,
                          f"restrict_reads missing/false: {kwargs}")

    def test_fake_home_engaged(self):
        _, calls = self._replay_and_capture_kwargs()
        self.assertTrue(calls, "sandbox run was never invoked")
        for _cmd, kwargs in calls:
            self.assertIs(kwargs.get("fake_home"), True,
                          f"fake_home missing/false: {kwargs}")

    def test_network_blocked_and_output_set(self):
        """fake_home requires output=; block_network stays engaged."""
        _, calls = self._replay_and_capture_kwargs()
        self.assertTrue(calls, "sandbox run was never invoked")
        for _cmd, kwargs in calls:
            self.assertIs(kwargs.get("block_network"), True)
            self.assertTrue(kwargs.get("output"),
                            "output= must be set so fake_home can "
                            "materialise inside a writable dir")

    def test_replay_entries_still_recorded(self):
        """The isolation kwargs must not change the replay contract:
        stdout/stderr logs written, reproduced flag from returncode."""
        result, _ = self._replay_and_capture_kwargs()
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(entries, "no replay entries recorded")
        for entry in entries:
            self.assertTrue(entry.get("reproduced"))
            self.assertTrue(Path(entry["stdout"]).exists())
            self.assertTrue(Path(entry["stderr"]).exists())


class TestReplayTimeoutStillIsolated(_ReplayCase):
    """TimeoutExpired replays keep partial logs (regression guard for
    the fix touching the sandbox call site)."""

    def test_timeout_records_reproduced_entry(self):
        from raptor_agentic import _replay_fuzz_crashes
        exc = subprocess.TimeoutExpired(cmd="x", timeout=15,
                                        output=b"partial", stderr=b"")
        with patch("core.sandbox.run", side_effect=exc):
            result = _replay_fuzz_crashes(
                binary_path=self.binary,
                crash_files=[self.crash_file],
                out_dir=self.out_dir,
            )
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(entries)
        self.assertEqual(entries[0]["returncode"], "timeout")
        self.assertTrue(entries[0]["reproduced"])


class TestRunCommandStreamingPopenFailure(unittest.TestCase):
    """run_command_streaming returns gracefully when Popen raises."""

    def test_popen_oserror_returns_minus_one(self):
        from raptor_agentic import run_command_streaming
        env_patch = patch.dict("os.environ", {}, clear=False)
        with env_patch:
            import os as _os
            _os.environ.pop("RAPTOR_LLM_SOCKET", None)
            with patch(
                "raptor_agentic.subprocess.Popen",
                side_effect=OSError("simulated exec failure"),
            ):
                rc, stdout, stderr = run_command_streaming(
                    ["definitely-not-a-real-binary"],
                    "test spawn",
                    timeout=5,
                )
        self.assertEqual(rc, -1)
        self.assertEqual(stdout, "")
        self.assertIn("simulated exec failure", stderr)

    def test_popen_filenotfound_returns_minus_one(self):
        from raptor_agentic import run_command_streaming
        env_patch = patch.dict("os.environ", {}, clear=False)
        with env_patch:
            import os as _os
            _os.environ.pop("RAPTOR_LLM_SOCKET", None)
            with patch(
                "raptor_agentic.subprocess.Popen",
                side_effect=FileNotFoundError("no such file"),
            ):
                rc, stdout, stderr = run_command_streaming(
                    ["missing"], "test spawn", timeout=5,
                )
        self.assertEqual(rc, -1)
        self.assertEqual(stdout, "")
        self.assertIn("no such file", stderr)


if __name__ == "__main__":
    unittest.main()
