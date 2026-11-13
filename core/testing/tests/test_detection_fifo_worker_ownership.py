"""Detection FIFO readers retire before fixture paths and release peers."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, mode, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_detection_fifo_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, mode, stage, str(after)],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'DETECTION_FIFO_WORKER_OK'


@pytest.mark.parametrize('mode', ['header', 'cmake'])
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_actual_detection_fifo_worker_fault_retires_before_peer_close(mode, error, stage, after, tmp_path):
    _exercise(tmp_path, error, mode, stage, after)


@pytest.mark.parametrize('mode', ['header', 'cmake'])
def test_original_refusal_and_real_positive_signal(mode, tmp_path):
    _exercise(tmp_path, 'none', mode, 'normal', False)
