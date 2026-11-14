"""Stubbed egress callers retire before environment restoration."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, error, stage, after, state):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_egress_first_call_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), error, stage, str(after), state], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'EGRESS_FIRST_CALL_WORKER_OK'

@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_egress_callers_retire_after_caller_fault(tmp_path, error, stage, after):
    _exercise(tmp_path, error, stage, after, "borrowed")

@pytest.mark.parametrize('state', ['missing', 'empty', 'borrowed'])
def test_native_first_call_transition_restores_inherited_state(tmp_path, state):
    _exercise(tmp_path, 'none', 'normal', False, state)

