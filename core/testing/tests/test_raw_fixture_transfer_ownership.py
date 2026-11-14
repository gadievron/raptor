"""Raw fixture transfers do not reclaim a later owner of the same inode."""
from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env
pytestmark = pytest.mark.slow

def _exercise(tmp_path, consumer, outcome):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_raw_fixture_transfers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), consumer, outcome, 'candidate'], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'RAW_FIXTURE_TRANSFER_OK'

@pytest.mark.parametrize('consumer', ['raw', 'stream'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_actual_consumption_preserves_same_inode_replacement(tmp_path, consumer, outcome):
    _exercise(tmp_path, consumer, outcome)

@pytest.mark.parametrize('consumer', ['setup-before', 'setup-after'])
@pytest.mark.parametrize('outcome', ['error', 'interrupt'])
def test_private_consumer_setup_failure_retires_raw_owner(tmp_path, consumer, outcome):
    _exercise(tmp_path, consumer, outcome)
