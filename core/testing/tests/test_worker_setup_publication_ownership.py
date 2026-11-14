"""Worker fixture setup restores published state on every exit."""

from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env


@pytest.mark.slow
@pytest.mark.parametrize(
    "case,stage,outcome",
    [
        ('runner', 'runner', 'error'),
        ('runner', 'runner', 'interrupt'),
        ('proxy', 'proxy', 'error'),
        ('proxy', 'proxy', 'interrupt'),
        ('heap', 'heap-path', 'error'),
        ('heap', 'heap-path', 'interrupt'),
        ('heap', 'heap-budget', 'error'),
        ('heap', 'heap-budget', 'interrupt'),
        ('heap', 'heap-subprocess', 'error'),
        ('heap', 'heap-subprocess', 'interrupt'),
        ('runner', 'normal', 'error'),
        ('proxy', 'normal', 'error'),
        ('heap', 'normal', 'error'),
    ],
)

def test_worker_fixture_setup_restores_published_state(
    tmp_path, case, stage, outcome
):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name("_worker_setup_publication.py")
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [
                sys.executable,
                "-I",
                str(script),
                str(root),
                str(tmp_path),
                case,
                stage,
                outcome,
                "candidate",
            ],
            timeout=20,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    assert result.returncode == 0, result.stderr
    assert '"result": "WORKER_SETUP_OWNER_OK"' in result.stdout
    assert not result.stderr
