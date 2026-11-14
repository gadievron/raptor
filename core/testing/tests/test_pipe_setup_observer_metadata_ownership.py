from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(mode, outcome) for mode in ['1-before', '1-after', '2-before', '2-after'] for outcome in ['error', 'interrupt']])
def test_unpublished_startup_pipe_pair_retired_after_metadata_failure(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_pipe_setup_observer_metadata.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'PIPE_SETUP_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['0:spawn:OSError', '0:spawn:KeyboardInterrupt', '1:spawn:OSError', '1:spawn:KeyboardInterrupt', '2:spawn:OSError', '2:spawn:KeyboardInterrupt', '3:spawn:OSError', '3:spawn:KeyboardInterrupt', '4:spawn:OSError', '4:spawn:KeyboardInterrupt', '5:spawn:OSError', '5:spawn:KeyboardInterrupt', '6:spawn:OSError', '6:spawn:KeyboardInterrupt', '7:spawn:OSError', '7:spawn:KeyboardInterrupt', '0:pipe-2:OSError', '0:pipe-2:KeyboardInterrupt', '7:pipe-2:OSError', '7:pipe-2:KeyboardInterrupt', '7:pipe-3:OSError', '7:pipe-3:KeyboardInterrupt'])
def test_original_drain_startup_fault_controls(tmp_path, consumer):
    test_unpublished_startup_pipe_pair_retired_after_metadata_failure(tmp_path, consumer, "control")
