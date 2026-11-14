from pathlib import Path
import subprocess
import sys
import pytest
from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

@pytest.mark.slow
@pytest.mark.parametrize('mode', ['regression', 'normal', 'cross-uid'])
def test_annotation_fifo_reader_is_retired(tmp_path, mode):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_annotation_fifo_release.py')
    with standalone_cli_env() as env:
        result = run_in_process_group([sys.executable, '-I', str(script), str(root), str(tmp_path), mode], timeout=40, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'ANNOTATION_FIFO_RELEASE_OK'
