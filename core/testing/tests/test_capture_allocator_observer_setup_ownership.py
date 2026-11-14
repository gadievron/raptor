from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(caller + ':' + str(position) + ':' + phase, outcome) for caller in ['duplicate', 'fixture-exit'] for position in [1, 2] for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_capture_allocator_owns_pair_before_metadata(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_capture_allocator_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'CAPTURE_ALLOCATOR_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['duplicate:allocate:0:RuntimeError', 'duplicate:allocate:0:KeyboardInterrupt', 'duplicate:allocate:0:SystemExit', 'duplicate:record:0:RuntimeError', 'duplicate:record:0:KeyboardInterrupt', 'duplicate:record:0:SystemExit', 'duplicate:record:1:RuntimeError', 'duplicate:record:1:KeyboardInterrupt', 'duplicate:record:1:SystemExit', 'fixture-exit:allocate:0:RuntimeError', 'fixture-exit:allocate:0:KeyboardInterrupt', 'fixture-exit:allocate:0:SystemExit', 'fixture-exit:record:0:RuntimeError', 'fixture-exit:record:0:KeyboardInterrupt', 'fixture-exit:record:0:SystemExit', 'fixture-exit:record:1:RuntimeError', 'fixture-exit:record:1:KeyboardInterrupt', 'fixture-exit:record:1:SystemExit', 'duplicate:none:0:None', 'fixture-exit:none:0:None'])
def test_original_capture_allocation_record_and_positive_controls(tmp_path, consumer):
    test_capture_allocator_owns_pair_before_metadata(tmp_path, consumer, "control")
