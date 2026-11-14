"""Foreign dependency-mock publishers retire before their registry owner."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, error, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_foreign_registry_mock_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), error, stage, str(after)], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'FOREIGN_REGISTRY_MOCK_OK'

@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_foreign_mock_publisher_retires_after_caller_fault(tmp_path, error, stage, after):
    _exercise(tmp_path, error, stage, after)

def test_foreign_mock_publication_and_owner_restoration(tmp_path):
    _exercise(tmp_path, 'none', 'normal', False)

@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_existing_dependency_mock_caller(tmp_path, outcome):
    _exercise(tmp_path, 'none', 'control-' + outcome, False)
