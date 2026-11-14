from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [('0:' + str(position) + ':' + phase, outcome) for position in [1, 2] for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_bridge_allocator_owns_pair_before_observer_metadata(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_bridge_allocator_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'BRIDGE_ALLOCATOR_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['0:constructor:RuntimeError', '0:constructor:KeyboardInterrupt', '0:constructor:SystemExit', '0:start:RuntimeError', '0:start:KeyboardInterrupt', '0:start:SystemExit', '1:constructor:RuntimeError', '1:constructor:KeyboardInterrupt', '1:constructor:SystemExit', '1:start:RuntimeError', '1:start:KeyboardInterrupt', '1:start:SystemExit', '2:constructor:RuntimeError', '2:constructor:KeyboardInterrupt', '2:constructor:SystemExit', '2:start:RuntimeError', '2:start:KeyboardInterrupt', '2:start:SystemExit', '3:constructor:RuntimeError', '3:constructor:KeyboardInterrupt', '3:constructor:SystemExit', '3:start:RuntimeError', '3:start:KeyboardInterrupt', '3:start:SystemExit', '4:constructor:RuntimeError', '4:constructor:KeyboardInterrupt', '4:constructor:SystemExit', '4:start:RuntimeError', '4:start:KeyboardInterrupt', '4:start:SystemExit', '5:constructor:RuntimeError', '5:constructor:KeyboardInterrupt', '5:constructor:SystemExit', '5:start:RuntimeError', '5:start:KeyboardInterrupt', '5:start:SystemExit', '6:constructor:RuntimeError', '6:constructor:KeyboardInterrupt', '6:constructor:SystemExit', '6:start:RuntimeError', '6:start:KeyboardInterrupt', '6:start:SystemExit'])
def test_original_local_worker_constructor_and_start_controls(tmp_path, consumer):
    test_bridge_allocator_owns_pair_before_observer_metadata(tmp_path, consumer, "control")
