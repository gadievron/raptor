"""Journal-sweep workers finish after their holder closes and before fixtures retire."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_journal_sweep_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, stage, str(after)],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'JOURNAL_SWEEP_WORKER_OK'


@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_actual_sweep_worker_fault_closes_holder_and_retires_worker(error, stage, after, tmp_path):
    _exercise(tmp_path, error, stage, after)


def test_original_real_held_lock_refusal_and_index_assertions(tmp_path):
    _exercise(tmp_path, 'none', 'normal', False)
