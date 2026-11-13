"""Foreign module publishers retire before their exact registry owner restores."""
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.slow


def _exercise(tmp_path, error, state, stage, after):
    root = Path(__file__).resolve().parents[3]
    script = Path(__file__).with_name('_foreign_import_workers.py')
    with standalone_cli_env() as env:
        result = run_in_process_group(
            [sys.executable, '-I', str(script), str(root), str(tmp_path), error, state, stage, str(after)],
            timeout=40, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'FOREIGN_IMPORT_WORKER_OK'


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('error', ['RuntimeError', 'KeyboardInterrupt'])
@pytest.mark.parametrize('stage', ['start', 'join'])
@pytest.mark.parametrize('after', [False, True])
def test_actual_foreign_publication_retires_before_owner_undo(state, error, stage, after, tmp_path):
    _exercise(tmp_path, error, state, stage, after)


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
def test_original_publication_and_exact_owner_restoration(state, tmp_path):
    _exercise(tmp_path, 'none', state, 'normal', False)


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('count', [1, 3])
def test_existing_selected_slot_caller_controls(state, outcome, count, tmp_path):
    _exercise(tmp_path, 'none', state, f'control-{outcome}-{count}', False)
