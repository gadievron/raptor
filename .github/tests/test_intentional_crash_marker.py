"""The crash opt-in must remain explicit even when marker filters are cleared."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.slow
@pytest.mark.parametrize("opt_in", [False, True], ids=["default", "explicit-opt-in"])
def test_native_crash_marker_requires_explicit_option(tmp_path, opt_in):
    marker = tmp_path / "native-case-ran"
    tests = tmp_path / "test_selection.py"
    tests.write_text(
        "from pathlib import Path\nimport pytest\n"
        "def test_ordinary(): pass\n"
        "@pytest.mark.intentional_crash\n"
        "def test_native_case():\n"
        f"    Path({str(marker)!r}).write_text('ran')\n"
    )
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    env.pop("PYTEST_ADDOPTS", None)
    args = [sys.executable, "-m", "pytest", "-p", "conftest", "--noconftest",
            "-c", str(ROOT / "pytest.ini"), str(tests), "-m", "", "-q"]
    if opt_in:
        args.append("--run-crash-tests")
    proc = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert marker.exists() is opt_in
    assert ("2 passed" if opt_in else "1 passed, 1 deselected") in proc.stdout
