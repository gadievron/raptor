"""E2E enforcement of the tempfile.gettempdir() writable baseline.

Exercises the full path: context.py resolves tempfile.gettempdir() →
passes to backend (Landlock on Linux, Seatbelt on macOS) → backend
enforces write allow/deny.

Three assertions:
  1. Default baseline: writes under gettempdir() succeed.
  2. exclude_tmp_baseline=True: writes under gettempdir() are BLOCKED.
  3. A dir outside the allowlist is always blocked (sanity).

This is the only test that verifies the context.py fix (hardcoded
"/tmp" → tempfile.gettempdir()) produces correct enforcement on
BOTH platforms. Without it, a regression to "/tmp" would pass CI
on Linux (where /tmp == gettempdir()) but silently break macOS
(where gettempdir() returns $TMPDIR, usually /var/folders/…).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

import pytest

_LINUX = sys.platform == "linux"
_DARWIN = sys.platform == "darwin"


def _sandbox_usable() -> bool:
    """Quick probe: can the sandbox enforce anything on this host?"""
    if _LINUX:
        from core.sandbox import landlock
        return landlock.check_landlock_available()
    if _DARWIN:
        from core.sandbox import _macos_spawn
        return _macos_spawn.is_available()
    return False


pytestmark = pytest.mark.skipif(
    not _sandbox_usable(),
    reason="sandbox enforcement unavailable on this host",
)


def _write_probe_script(target_file: str) -> list[str]:
    """Return a command that tries to write a file and prints the outcome."""
    py = (
        "import sys\n"
        f"target = {target_file!r}\n"
        "try:\n"
        "    open(target, 'w').write('x')\n"
        "    print('WRITTEN')\n"
        "except OSError as e:\n"
        "    print(f'BLOCKED {e.errno}')\n"
    )
    if _DARWIN:
        return ["/usr/bin/python3", "-c", py]
    return [sys.executable, "-S", "-c", py]


class TestTmpBaselineEnforcement:
    """Writable-baseline tests going through context.py's public API."""

    def test_default_baseline_allows_gettempdir(self, tmp_path):
        """The default writable baseline includes tempfile.gettempdir().
        A sandboxed child must be able to write there."""
        from core.sandbox import run as sandbox_run

        output = tmp_path / "out"
        output.mkdir()
        probe_file = os.path.join(tempfile.gettempdir(), f"raptor_test_{os.getpid()}")

        try:
            r = sandbox_run(
                _write_probe_script(probe_file),
                target=str(tmp_path), output=str(output),
                capture_output=True, text=True, timeout=15,
            )
            assert r.returncode == 0, f"sandbox call failed: {r.stderr}"
            assert "WRITTEN" in r.stdout, (
                f"expected write to {probe_file} to succeed under default "
                f"baseline; got: {r.stdout.strip()}"
            )
        finally:
            try:
                os.unlink(probe_file)
            except OSError:
                pass

    def test_exclude_tmp_baseline_blocks_gettempdir(self, tmp_path):
        """With exclude_tmp_baseline=True, even gettempdir() is blocked."""
        from core.sandbox import run as sandbox_run

        output = tmp_path / "out"
        output.mkdir()
        probe_file = os.path.join(tempfile.gettempdir(), f"raptor_test_{os.getpid()}")

        r = sandbox_run(
            _write_probe_script(probe_file),
            target=str(tmp_path), output=str(output),
            exclude_tmp_baseline=True,
            capture_output=True, text=True, timeout=15,
        )
        # The child process may exit 0 (caught OSError) or non-zero
        # (uncaught signal from sandbox). Either way, the write must
        # NOT have succeeded.
        assert "WRITTEN" not in (r.stdout or ""), (
            f"exclude_tmp_baseline=True did NOT block write to "
            f"{probe_file}; stdout: {r.stdout.strip()}"
        )
        # Clean up in case enforcement somehow failed
        try:
            os.unlink(probe_file)
        except OSError:
            pass

    def test_write_outside_allowlist_blocked(self, tmp_path):
        """A directory not in target/output/tmp must be blocked."""
        from core.sandbox import run as sandbox_run

        output = tmp_path / "out"
        output.mkdir()
        # Use a path well outside any writable baseline. tmp_path
        # itself is under gettempdir() on most hosts, so a subdir
        # of it would be allowed. Place the probe under the user's
        # home instead — never in the writable allowlist.
        blocked_dir = os.path.join(
            os.path.expanduser("~"), f".raptor_test_blocked_{os.getpid()}"
        )
        os.makedirs(blocked_dir, exist_ok=True)
        probe_file = os.path.join(blocked_dir, "should_not_exist")

        try:
            r = sandbox_run(
                _write_probe_script(probe_file),
                target=str(tmp_path / "target_dummy"),
                output=str(output),
                capture_output=True, text=True, timeout=15,
            )
            assert "WRITTEN" not in (r.stdout or ""), (
                f"write outside allowlist was NOT blocked; "
                f"stdout: {r.stdout.strip()}"
            )
            assert not os.path.exists(probe_file)
        finally:
            shutil.rmtree(blocked_dir, ignore_errors=True)
