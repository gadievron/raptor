"""The generated build script's per-file compile timeout must fire.

Regression: the script did a blocking stderr read() BEFORE
wait(timeout), so a hung compiler that held stderr open (writing
little) pinned the script at the read forever and the documented
kill-after-timeout never executed.
"""

import os
import subprocess
import sys
from pathlib import Path

from core.build.build_detector import BuildDetector


def _generate(tmp_path: Path, compiler: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    src = repo / "a.c"
    src.write_text("int main(void) { return 0; }\n")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    script = repo / ".raptor_build_test.py"
    script.touch()

    detector = BuildDetector(repo)
    detector._write_build_script(script, build_dir, [src], compiler, [], [])
    return script


def test_generated_script_is_valid_python(tmp_path):
    script = _generate(tmp_path, "true")
    compile(script.read_text(), str(script), "exec")


def test_hung_compiler_is_killed_after_timeout(tmp_path):
    # Fake compiler: holds stderr open, writes nothing, sleeps far past
    # the (overridden) compile timeout.
    # `exec` keeps it a single process so the script's proc.kill()
    # reaps it fully (no orphaned grandchild holding inherited fds,
    # which would stall this test's own capture_output).
    hung = tmp_path / "hung-cc"
    hung.write_text("#!/bin/sh\nexec sleep 300\n")
    hung.chmod(0o755)

    script = _generate(tmp_path, str(hung))

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,  # the outer guard: pre-fix the script hung here
        env={**os.environ, "RAPTOR_COMPILE_TIMEOUT_S": "2"},
    )

    assert "compile timeout 2s" in result.stderr
    assert "Compiled 0/1 files (1 failed)" in result.stdout


def test_successful_compile_still_captures_stderr(tmp_path):
    # Fake compiler: emits a diagnostic on stderr and fails.
    noisy = tmp_path / "noisy-cc"
    noisy.write_text("#!/bin/sh\necho 'a.c: error: boom' >&2\nexit 1\n")
    noisy.chmod(0o755)

    script = _generate(tmp_path, str(noisy))

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )

    assert "a.c: error: boom" in result.stderr
    assert "Compiled 0/1 files (1 failed)" in result.stdout
