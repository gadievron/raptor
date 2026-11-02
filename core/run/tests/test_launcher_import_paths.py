"""Launcher imports preserve paths while direct execution bootstraps them."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
LAUNCHERS = (
    "raptor", "raptor_agentic", "raptor_openant", "raptor_fuzzing", "raptor_codeql",
    "packages.binary_analysis.cli",
)


@pytest.fixture
def child_env(tmp_path):
    # Each child owns its state and inherits no operator session or credentials.
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


@pytest.mark.parametrize("module", LAUNCHERS)
def test_library_import_preserves_path(module, child_env, tmp_path):
    code = """
import importlib
import sys
sys.path.insert(0, sys.argv[1])
original = sys.path
before = original.copy()
importlib.import_module(sys.argv[2])
assert sys.path is original
assert sys.path == before, (before, sys.path)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT), module],
        env=child_env, cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("module", LAUNCHERS)
def test_direct_cli_bootstraps_from_another_directory(module, child_env, tmp_path):
    script = ROOT.joinpath(*module.split(".")).with_suffix(".py")
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--help"],
        env=child_env, cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "usage:" in result.stdout.lower()
