from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(phase, outcome) for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_holder_open_is_owned_before_metadata_observation(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_checklist_holder_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'CHECKLIST_HOLDER_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['Event:0:RuntimeError', 'Event:0:KeyboardInterrupt', 'Thread:0:RuntimeError', 'Thread:0:KeyboardInterrupt', 'start:0:RuntimeError', 'start:0:KeyboardInterrupt', 'start:1:RuntimeError', 'start:1:KeyboardInterrupt', 'normal:0:None'])
def test_original_holder_constructor_start_and_lock_controls(tmp_path, consumer):
    test_holder_open_is_owned_before_metadata_observation(tmp_path, consumer, "control")
