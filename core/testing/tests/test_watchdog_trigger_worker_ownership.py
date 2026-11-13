"""Watchdog unit workers retire while their recorder and poll bindings are owned."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, mode, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_watchdog_trigger_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, mode, stage, str(after)],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'WATCHDOG_TRIGGER_WORKER_OK'


@pytest.mark.parametrize('mode', ['change', 'orphaned'])
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_actual_watchdog_worker_fault_retires_before_bindings_restore(mode, error, stage, after, tmp_path):
    _exercise(tmp_path, error, mode, stage, after)


@pytest.mark.parametrize('mode', ['change', 'orphaned'])
def test_original_recorded_watchdog_trigger(mode, tmp_path):
    _exercise(tmp_path, 'none', mode, 'normal', False)


@pytest.mark.parametrize('control', ['premature-action', 'missing-action'])
def test_existing_assertion_failure_controls(control, tmp_path):
    _exercise(tmp_path, 'none', 'control', control, False)
