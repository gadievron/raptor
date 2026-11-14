from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(mode, outcome) for mode in ['1-before', '1-after', '2-before', '2-after'] for outcome in ['error', 'interrupt']])
def test_unpublished_pipe_pair_retired_after_observer_failure(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_pipe_unwind_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'PIPE_UNWIND_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['native-body-0-OSError', 'native-body-0-KeyboardInterrupt', 'native-body-0-RuntimeError', 'native-body-1-OSError', 'native-body-1-KeyboardInterrupt', 'native-body-1-RuntimeError', 'native-body-2-OSError', 'native-body-2-KeyboardInterrupt', 'native-body-2-RuntimeError', 'native-body-3-OSError', 'native-body-3-KeyboardInterrupt', 'native-body-3-RuntimeError', 'native-allocation-0-OSError', 'native-allocation-0-KeyboardInterrupt', 'native-allocation-0-RuntimeError', 'native-allocation-1-OSError', 'native-allocation-1-KeyboardInterrupt', 'native-allocation-1-RuntimeError', 'native-allocation-2-OSError', 'native-allocation-2-KeyboardInterrupt', 'native-allocation-2-RuntimeError', 'native-allocation-3-OSError', 'native-allocation-3-KeyboardInterrupt', 'native-allocation-3-RuntimeError', 'native-fork-0-OSError', 'native-fork-0-KeyboardInterrupt', 'native-fork-0-RuntimeError', 'native-fork-1-OSError', 'native-fork-1-KeyboardInterrupt', 'native-fork-1-RuntimeError', 'native-fork-2-OSError', 'native-fork-2-KeyboardInterrupt', 'native-fork-2-RuntimeError', 'native-fork-3-OSError', 'native-fork-3-KeyboardInterrupt', 'native-fork-3-RuntimeError', 'transfer-normal', 'transfer-fork'])
def test_original_pipe_unwind_and_transfer_controls(tmp_path, consumer):
    test_unpublished_pipe_pair_retired_after_observer_failure(tmp_path, consumer, "control")
