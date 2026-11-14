"""Concurrent prompt-file users retire before their cache fixture."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, error, stage, after, position):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_cc_prompt_file_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), error, stage, str(after), str(position)], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'CC_PROMPT_FILE_WORKER_OK'

@pytest.mark.parametrize('position', [0, 7])
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_prompt_file_users_retire_after_caller_fault(tmp_path, error, stage, after, position):
    _exercise(tmp_path, error, stage, after, position)

def test_original_shared_prompt_file_contract(tmp_path):
    _exercise(tmp_path, 'none', 'normal', False, 0)

