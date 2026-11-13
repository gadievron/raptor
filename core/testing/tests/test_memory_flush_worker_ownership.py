"""Source-backed JSON memory writers retire before their storage owner."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, position, after, stage):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_memory_flush_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, str(position), str(after), stage],
            timeout=300, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'MEMORY_FLUSH_WORKER_OK'


@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('position', [0, 1])
@pytest.mark.parametrize('after', [False, True])
@pytest.mark.parametrize('stage', ['start', 'join'])
def test_actual_memory_writer_fault_retires_started_threads(error, position, after, stage, tmp_path):
    _exercise(tmp_path, error, position, after, stage)


def test_original_two_writers_preserve_all_twenty_entries(tmp_path):
    _exercise(tmp_path, 'none', 0, False, 'normal')
