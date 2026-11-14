from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(mode, outcome) for mode in ['1-before', '1-after', '2-before', '2-after'] for outcome in ['error', 'interrupt']])
def test_unpublished_trace_pipe_pair_retired_after_observer_failure(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_trace_pipe_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'TRACE_PIPE_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['fork-OSError', 'fork-KeyboardInterrupt', 'read-OSError', 'read-KeyboardInterrupt', 'none-None'])
def test_original_fake_trace_pipe_controls(tmp_path, consumer):
    test_unpublished_trace_pipe_pair_retired_after_observer_failure(tmp_path, consumer, "control")
