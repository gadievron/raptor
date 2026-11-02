"""CodeQL library imports preserve paths; direct CLIs bootstrap themselves."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULES = (
    "language_detector", "database_manager", "query_runner", "agent",
    "dataflow_validator", "dataflow_visualizer", "autonomous_analyzer", "offline",
)


def _env(tmp_path):
    # These probes use a normal interpreter, without an operator session,
    # credentials, or inherited paths to user state.
    return {
        "PATH": os.defpath,
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "RAPTOR_DIR": str(ROOT),
        "RAPTOR_OUT_DIR": str(tmp_path / "out"),
        "RAPTOR_REGISTRY_HOME": str(tmp_path / "registry"),
        "_RAPTOR_TRUSTED": "1",
    }


@pytest.mark.parametrize("module", MODULES)
def test_library_import_preserves_path(module, tmp_path):
    # A fresh interpreter prevents prior imports from hiding side effects.
    code = """
import importlib
import sys
sys.path.insert(0, sys.argv[1])
original = sys.path
before = original.copy()
importlib.import_module('packages.codeql.' + sys.argv[2])
assert sys.path is original
assert sys.path == before, (before, sys.path)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT), module],
        env=_env(tmp_path), cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("module", MODULES)
def test_direct_cli_bootstraps_from_another_directory(module, tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "packages" / "codeql" / f"{module}.py"),
         "--help"],
        env=_env(tmp_path), cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "usage:" in result.stdout.lower()
