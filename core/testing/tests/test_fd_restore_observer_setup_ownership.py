"""Acquiring descriptor observers retire unpublished resources on metadata failure."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, mode, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_fd_restore_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), mode, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'FD_RESTORE_OBSERVER_OK'

@pytest.mark.parametrize('mode', ['pipe-first-before', 'pipe-first-after', 'pipe-second-before', 'pipe-second-after', 'dup-before', 'dup-after'])
@pytest.mark.parametrize('outcome', ['error', 'interrupt'])
def test_unpublished_descriptors_close_before_caller_cleanup(tmp_path, mode, outcome):
    _exercise(tmp_path, mode, outcome)

@pytest.mark.parametrize('mode', ['native-0-dup-OSError', 'native-0-dup-KeyboardInterrupt', 'native-0-install-OSError', 'native-0-install-KeyboardInterrupt', 'native-0-body-OSError', 'native-0-body-KeyboardInterrupt', 'native-0-restore-OSError', 'native-0-restore-KeyboardInterrupt', 'native-1-dup-OSError', 'native-1-dup-KeyboardInterrupt', 'native-1-install-OSError', 'native-1-install-KeyboardInterrupt', 'native-1-body-OSError', 'native-1-body-KeyboardInterrupt', 'native-1-restore-OSError', 'native-1-restore-KeyboardInterrupt', 'native-2-dup-OSError', 'native-2-dup-KeyboardInterrupt', 'native-2-install-OSError', 'native-2-install-KeyboardInterrupt', 'native-2-body-OSError', 'native-2-body-KeyboardInterrupt', 'native-2-restore-OSError', 'native-2-restore-KeyboardInterrupt', 'native-handoff'])
def test_original_warning_faults_and_successful_handoff(tmp_path, mode):
    _exercise(tmp_path, mode, 'control')
