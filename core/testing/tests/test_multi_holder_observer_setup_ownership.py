from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(str(index) + ':' + phase, outcome) for index in range(4) for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_native_holder_is_owned_before_observer_metadata(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_multi_holder_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'MULTI_HOLDER_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['0:event:0:RuntimeError', '0:event:0:KeyboardInterrupt', '0:event:0:SystemExit', '0:event:1:RuntimeError', '0:event:1:KeyboardInterrupt', '0:event:1:SystemExit', '0:thread:0:RuntimeError', '0:thread:0:KeyboardInterrupt', '0:thread:0:SystemExit', '0:thread:1:RuntimeError', '0:thread:1:KeyboardInterrupt', '0:thread:1:SystemExit', '1:event:0:RuntimeError', '1:event:0:KeyboardInterrupt', '1:event:0:SystemExit', '1:event:1:RuntimeError', '1:event:1:KeyboardInterrupt', '1:event:1:SystemExit', '1:thread:0:RuntimeError', '1:thread:0:KeyboardInterrupt', '1:thread:0:SystemExit', '1:thread:1:RuntimeError', '1:thread:1:KeyboardInterrupt', '1:thread:1:SystemExit', '2:event:0:RuntimeError', '2:event:0:KeyboardInterrupt', '2:event:0:SystemExit', '2:event:1:RuntimeError', '2:event:1:KeyboardInterrupt', '2:event:1:SystemExit', '2:thread:0:RuntimeError', '2:thread:0:KeyboardInterrupt', '2:thread:0:SystemExit', '2:thread:1:RuntimeError', '2:thread:1:KeyboardInterrupt', '2:thread:1:SystemExit', '3:event:0:RuntimeError', '3:event:0:KeyboardInterrupt', '3:event:0:SystemExit', '3:event:1:RuntimeError', '3:event:1:KeyboardInterrupt', '3:event:1:SystemExit', '3:thread:0:RuntimeError', '3:thread:0:KeyboardInterrupt', '3:thread:0:SystemExit', '3:thread:1:RuntimeError', '3:thread:1:KeyboardInterrupt', '3:thread:1:SystemExit'])
def test_original_native_holder_construction_fault_controls(tmp_path, consumer):
    test_native_holder_is_owned_before_observer_metadata(tmp_path, consumer, "control")
