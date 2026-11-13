"""Synchronous throttle holders retire before their test scope ends."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow
METHODS = ['test_limits_concurrency', 'test_respects_throttle_down']


def _exercise(tmp_path, error, method, position, after, stage):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_throttle_acquire_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, method, str(position), str(after), stage],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'THROTTLE_ACQUIRE_WORKER_OK'


@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('position', [0, 3, 5])
@pytest.mark.parametrize('after', [False, True])
@pytest.mark.parametrize('stage', ['start', 'join'])
def test_actual_acquire_worker_fault_retires_started_threads(method, error, position, after, stage, tmp_path):
    _exercise(tmp_path, error, method, position, after, stage)


@pytest.mark.parametrize('method', METHODS)
def test_original_six_workers_preserve_concurrency_assertions(method, tmp_path):
    _exercise(tmp_path, 'none', method, 0, False, 'normal')
