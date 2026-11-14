"""Summary fixture callers finish before state and evidence restoration."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, error, mode, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_summary_thread_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), error, mode, stage, str(after)], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'SUMMARY_THREAD_WORKER_OK'

@pytest.mark.parametrize('mode', ['state', 'denials'])
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_summary_callers_retire_after_caller_fault(tmp_path, error, mode, stage, after):
    _exercise(tmp_path, error, mode, stage, after)

@pytest.mark.parametrize('mode', ['state', 'denials'])
def test_original_summary_concurrency_contract(tmp_path, mode):
    _exercise(tmp_path, 'none', mode, 'normal', False)
