"""Capture duplicate observer metadata fixture generations do not reclaim consumed descriptors."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_capture_duplicate_observer_setup.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'CAPTURE_DUPLICATE_OBSERVER_OK'

@pytest.mark.parametrize('consumer', ['duplicate-before', 'duplicate-after', 'fixture-exit-before', 'fixture-exit-after'])
@pytest.mark.parametrize('outcome', ['error', 'interrupt'])
def test_metadata_failure_retires_unpublished_capture_duplicate(tmp_path, consumer, outcome):
    _exercise(tmp_path, consumer, outcome)


@pytest.mark.parametrize("case", ['native-duplicate-0-1-OSError', 'native-duplicate-0-1-KeyboardInterrupt', 'native-duplicate-0-2-OSError', 'native-duplicate-0-2-KeyboardInterrupt', 'native-duplicate-1-1-OSError', 'native-duplicate-1-1-KeyboardInterrupt', 'native-duplicate-1-2-OSError', 'native-duplicate-1-2-KeyboardInterrupt', 'native-fixture-close', 'native-fixture-interrupt', 'native-fixture-normal', 'pipe-positive-duplicate', 'pipe-duplicate-allocate-0-RuntimeError', 'pipe-duplicate-allocate-0-KeyboardInterrupt', 'pipe-duplicate-allocate-0-SystemExit', 'pipe-duplicate-record-0-RuntimeError', 'pipe-duplicate-record-0-KeyboardInterrupt', 'pipe-duplicate-record-0-SystemExit', 'pipe-duplicate-record-1-RuntimeError', 'pipe-duplicate-record-1-KeyboardInterrupt', 'pipe-duplicate-record-1-SystemExit', 'pipe-positive-fixture-exit', 'pipe-fixture-exit-allocate-0-RuntimeError', 'pipe-fixture-exit-allocate-0-KeyboardInterrupt', 'pipe-fixture-exit-allocate-0-SystemExit', 'pipe-fixture-exit-record-0-RuntimeError', 'pipe-fixture-exit-record-0-KeyboardInterrupt', 'pipe-fixture-exit-record-0-SystemExit', 'pipe-fixture-exit-record-1-RuntimeError', 'pipe-fixture-exit-record-1-KeyboardInterrupt', 'pipe-fixture-exit-record-1-SystemExit'])
def test_existing_capture_fault_and_allocation_controls(tmp_path, case):
    _exercise(tmp_path, case, "control")
