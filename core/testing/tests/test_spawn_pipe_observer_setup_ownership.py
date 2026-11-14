"""Pipe recorder metadata fixture generations do not reclaim consumed descriptors."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_spawn_pipe_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'SPAWN_PIPE_OBSERVER_OK'

@pytest.mark.parametrize('consumer', ['1', '2'])
@pytest.mark.parametrize('outcome', ['error', 'interrupt'])
def test_metadata_observation_failure_retires_both_unpublished_endpoints(tmp_path, consumer, outcome):
    _exercise(tmp_path, consumer, outcome)

