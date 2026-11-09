"""Analysis help remains available without importing analysis providers."""

from pathlib import Path
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli
from packages.llm_analysis.cli import build_parser


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_script_help_does_not_import_analysis_runtime(flag):
    root = Path(__file__).resolve().parents[3]
    agent = root / "packages/llm_analysis/agent.py"
    script = f'''
import builtins
import os
import runpy
import sys
os.environ["RAPTOR_DIR"] = {str(root)!r}
sys.argv = [{str(agent)!r}, {flag!r}]
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "core" or name.startswith("core."):
        raise AssertionError("analysis runtime imported during help: " + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
runpy.run_path({str(agent)!r}, run_name="__main__")
'''
    result = run_standalone_cli(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
    assert "--context-toolloop" in result.stdout
    assert "OUTPUT_DIR=" not in result.stdout + result.stderr


def test_parser_preserves_analysis_options():
    args = build_parser().parse_args([
        "--repo", "target", "--findings", "findings.json",
        "--max-findings", "0", "--model", "chosen",
        "--context-toolloop", "--no-deep-validate",
    ])
    assert args.repo == "target"
    assert args.findings == "findings.json"
    assert args.max_findings == 0
    assert args.model == ["chosen"]
    assert args.context_toolloop is True
    assert args.no_deep_validate is True
