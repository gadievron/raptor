"""Owned-tree copy workers retire before filesystem fixture restoration."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, error, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_etc_copy_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), error, stage, str(after)], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'ETC_COPY_WORKER_OK'

@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_copy_worker_retires_after_caller_fault(tmp_path, error, stage, after):
    _exercise(tmp_path, error, stage, after)

def test_original_fifo_copy_contract(tmp_path):
    _exercise(tmp_path, 'none', 'normal', False)


@pytest.mark.parametrize('stage', ['control-copy', 'control-link'])
def test_original_copy_permission_controls(tmp_path, stage):
    _exercise(tmp_path, 'none', stage, False)
