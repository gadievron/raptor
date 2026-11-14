from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
@pytest.mark.slow
@pytest.mark.parametrize('consumer,outcome', [(kind + '-' + phase, outcome) for kind in ['parser', 'usage', 'trickle'] for phase in ['before', 'after'] for outcome in ['error', 'interrupt']])
def test_unpublished_socket_duplicate_retired_after_observer_failure(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_socket_worker_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'SOCKET_WORKER_OBSERVER_OK'

@pytest.mark.slow
@pytest.mark.parametrize("consumer", ['parser-dup-OSError', 'parser-dup-KeyboardInterrupt', 'parser-socket-OSError', 'parser-socket-KeyboardInterrupt', 'parser-event-OSError', 'parser-event-KeyboardInterrupt', 'parser-construction-OSError', 'parser-construction-KeyboardInterrupt', 'parser-start-OSError', 'parser-start-KeyboardInterrupt', 'parser-after-start-OSError', 'parser-after-start-KeyboardInterrupt', 'usage-dup-OSError', 'usage-dup-KeyboardInterrupt', 'usage-socket-OSError', 'usage-socket-KeyboardInterrupt', 'usage-event-OSError', 'usage-event-KeyboardInterrupt', 'usage-construction-OSError', 'usage-construction-KeyboardInterrupt', 'usage-start-OSError', 'usage-start-KeyboardInterrupt', 'usage-after-start-OSError', 'usage-after-start-KeyboardInterrupt', 'trickle-dup-OSError', 'trickle-dup-KeyboardInterrupt', 'trickle-socket-OSError', 'trickle-socket-KeyboardInterrupt', 'trickle-event-OSError', 'trickle-event-KeyboardInterrupt', 'trickle-construction-OSError', 'trickle-construction-KeyboardInterrupt', 'trickle-start-OSError', 'trickle-start-KeyboardInterrupt', 'trickle-after-start-OSError', 'trickle-after-start-KeyboardInterrupt'])
def test_original_socket_worker_setup_fault_controls(tmp_path, consumer):
    test_unpublished_socket_duplicate_retired_after_observer_failure(tmp_path, consumer, "control")
