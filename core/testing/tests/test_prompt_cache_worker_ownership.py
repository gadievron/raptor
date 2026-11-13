"""Prompt-cache fixture workers retire before cache ownership restores."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, position, after, stage):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_prompt_cache_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, str(position), str(after), stage],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'PROMPT_CACHE_WORKER_OK'


@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('position', [0, 1])
@pytest.mark.parametrize('after', [False, True])
@pytest.mark.parametrize('stage', ['start', 'join'])
def test_actual_prompt_workers_retire_before_fixture_restore(error, position, after, stage, tmp_path):
    _exercise(tmp_path, error, position, after, stage)


def test_original_cleanup_and_creation_keep_new_owner(tmp_path):
    _exercise(tmp_path, 'none', 0, False, 'normal')
