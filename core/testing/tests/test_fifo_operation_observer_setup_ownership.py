from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(mode + ':' + phase, outcome) for mode in ['writer', 'reader-open', 'reader-eof'] for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_fifo_operation_retires_fd_before_metadata_registration(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_fifo_operation_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'FIFO_OPERATION_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['writer:none:0:None', 'reader-open:none:0:None', 'reader-eof:none:0:None', 'writer:start:0:OSError', 'writer:start:0:KeyboardInterrupt', 'writer:start:0:SystemExit', 'writer:start:1:OSError', 'writer:start:1:KeyboardInterrupt', 'writer:start:1:SystemExit', 'writer:wait:0:OSError', 'writer:wait:0:KeyboardInterrupt', 'writer:wait:0:SystemExit', 'writer:wait:1:OSError', 'writer:wait:1:KeyboardInterrupt', 'writer:wait:1:SystemExit', 'reader-open:start:0:OSError', 'reader-open:start:0:KeyboardInterrupt', 'reader-open:start:0:SystemExit', 'reader-open:start:1:OSError', 'reader-open:start:1:KeyboardInterrupt', 'reader-open:start:1:SystemExit', 'reader-open:wait:0:OSError', 'reader-open:wait:0:KeyboardInterrupt', 'reader-open:wait:0:SystemExit', 'reader-open:wait:1:OSError', 'reader-open:wait:1:KeyboardInterrupt', 'reader-open:wait:1:SystemExit', 'reader-eof:start:0:OSError', 'reader-eof:start:0:KeyboardInterrupt', 'reader-eof:start:0:SystemExit', 'reader-eof:start:1:OSError', 'reader-eof:start:1:KeyboardInterrupt', 'reader-eof:start:1:SystemExit', 'reader-eof:wait:0:OSError', 'reader-eof:wait:0:KeyboardInterrupt', 'reader-eof:wait:0:SystemExit', 'reader-eof:wait:1:OSError', 'reader-eof:wait:1:KeyboardInterrupt', 'reader-eof:wait:1:SystemExit', 'callee:none:0:OSError', 'callee:none:0:KeyboardInterrupt', 'callee:none:0:SystemExit'])
def test_original_fifo_watchdog_timeout_boundary_and_callee_controls(tmp_path, consumer):
    test_fifo_operation_retires_fd_before_metadata_registration(tmp_path, consumer, "control")
