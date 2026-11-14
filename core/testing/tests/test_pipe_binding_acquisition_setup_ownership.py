from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(state + '-' + str(position) + '-' + phase, outcome) for state in ['ordinary', 'borrowed'] for position in [1, 2] for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_unrelated_pipe_allocation_is_owned_before_metadata(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_pipe_binding_acquisition_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'PIPE_BINDING_ACQUISITION_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['ordinary-normal', 'ordinary-error', 'ordinary-interrupt', 'borrowed-normal', 'borrowed-error', 'borrowed-interrupt'])
def test_original_selected_and_unrelated_pipe_binding_controls(tmp_path, consumer):
    test_unrelated_pipe_allocation_is_owned_before_metadata(tmp_path, consumer, "control")
