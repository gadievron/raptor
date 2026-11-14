from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(kind + '-' + str(position) + '-' + phase, outcome) for kind in ['argv', 'second-pipe', 'pool'] for position in [1, 2] for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_outer_spawn_tracker_owns_unpublished_pipe_pair(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_spawn_outer_pipe_tracker.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'SPAWN_OUTER_TRACKER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ["argv", "second-pipe", "pool"])
def test_original_outer_tracker_refusal_controls(tmp_path, consumer):
    test_outer_spawn_tracker_owns_unpublished_pipe_pair(tmp_path, consumer, "control")
