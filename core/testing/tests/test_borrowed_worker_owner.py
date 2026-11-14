"""The concurrency proof owns its setup thread outside the group under test."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_borrowed_worker_owner.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, stage, str(after)],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'BORROWED_WORKER_OWNER_OK'


@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_actual_borrowed_setup_worker_retires_on_lifecycle_fault(error, stage, after, tmp_path):
    _exercise(tmp_path, error, stage, after)


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('cleanup', ['none', 'release', 'join'])
@pytest.mark.parametrize('count', [1, 3])
def test_original_owned_and_borrowed_group_controls(finish, cleanup, count, tmp_path):
    _exercise(tmp_path, 'none', f'control-{finish}-{cleanup}-{count}', False)
