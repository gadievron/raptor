from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize('mode', ['regression', 'normal', 'regular'] + [f'{stage}-{timing}-{error}' for stage in ('start', 'join') for timing in ('before', 'after') for error in ('RuntimeError', 'KeyboardInterrupt')])
def test_summary_fifo_reader_is_retired(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_summary_fifo_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), mode], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'SUMMARY_FIFO_WORKER_OK'
