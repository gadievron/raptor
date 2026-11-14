"""Pretransfer fixture metadata failures retire only their acquired descriptor."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("kind", ["error", "interrupt"])
def test_fixture_metadata_failure_retires_untransferred_descriptor(
    tmp_path, phase, kind
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_stream_fixture_metadata_setup.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, "-I", str(script), str(root), str(tmp_path), phase, kind],
            timeout=20,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    assert result.returncode == 0, result.stderr
    assert '"result": "STREAM_FIXTURE_METADATA_OK"' in result.stdout
