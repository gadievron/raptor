"""Cooldown restoration workers release their real held throttle slot."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, position, after, stage):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_throttle_restore_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, str(position), str(after), stage],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'THROTTLE_RESTORE_WORKER_OK'


@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('position', [0, 1])
@pytest.mark.parametrize('after', [False, True])
@pytest.mark.parametrize('stage', ['start', 'join'])
def test_actual_restore_worker_fault_releases_holder_and_waiter(error, position, after, stage, tmp_path):
    _exercise(tmp_path, error, position, after, stage)


def test_original_clock_restore_admits_waiter_before_slot_release(tmp_path):
    _exercise(tmp_path, 'none', 0, False, 'normal')
