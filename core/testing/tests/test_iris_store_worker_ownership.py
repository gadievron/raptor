"""Real IRIS store workers retire before their scratch and signing state."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow
METHODS = ['test_persist_waits_for_lock_then_merges', 'test_annotation_promotion_waits_for_lock']


def _exercise(tmp_path, method, error, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_iris_store_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, method, stage, str(after)],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'IRIS_WORKER_OK'


@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('after', [False, True])
@pytest.mark.parametrize('stage', ['start', 'join'])
def test_worker_fault_retires_before_method_returns(method, error, after, stage, tmp_path):
    _exercise(tmp_path, method, error, stage, after)


@pytest.mark.parametrize('method', METHODS)
def test_original_real_store_lock_and_merge_assertions(method, tmp_path):
    _exercise(tmp_path, method, 'none', 'normal', False)
