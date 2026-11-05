"""Mac routing, timeout diagnostics and failure status stay wired together."""

import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _job():
    text = (ROOT / '.github/workflows/tests.yml').read_text()
    return text.split('  python-unit-tests-sandbox-macos:\n', 1)[1].split('\n  sandbox-feature-matrix:', 1)[0]


def _step(name):
    match = re.search(r'(?ms)^      - name: ' + re.escape(name) + r'\n(.*?)(?=^      - |\Z)', _job())
    assert match, name
    return match.group(1)


def test_macos_gate_files_and_audit_use_platform_selection():
    workflow = (ROOT / '.github/workflows/tests.yml').read_text()
    assert "needs.changes.outputs.sandbox_macos == 'true'" in _job()
    assert 'SANDBOX_FILES: ${{ needs.changes.outputs.sandbox_macos_files }}' in _job()
    for output, value in [('sandbox_macos', 'run'), ('sandbox_macos_files', 'files'), ('sandbox_macos_audit', 'native_audit')]:
        assert output + ': ${{ steps.macos_scope.outputs.' + value + ' }}' in workflow
    assert 'id: macos_scope' in workflow
    assert 'SCOPE_MODE: ${{ steps.scope.outputs.scope_mode }}' in workflow
    assert 'run: python3 .github/scripts/macos_test_scope.py' in workflow
    assert "if: needs.changes.outputs.sandbox_macos_audit == 'true'" in _step('Run native audit checks (macOS slow)')
    assert 'timeout-minutes: 15' in _job()
    assert 'timeout-minutes: 8' in _step('Run sandbox tests (macOS)')
    assert 'timeout-minutes: 4' in _step('Run native audit checks (macOS slow)')
    upload = _step('Retain macOS sandbox diagnostics')
    assert 'if: always()' in upload
    assert 'timeout-minutes: 2' in upload and 'continue-on-error: true' in upload
    assert 'sandbox-macos*.log' in upload and 'sandbox-macos*.xml' in upload


@pytest.mark.parametrize('step', ['Run sandbox tests (macOS)', 'Run native audit checks (macOS slow)'],
                         ids=['default-phase', 'native-audit'])
@pytest.mark.parametrize('status', [0, 23], ids=['pass', 'failure'])
def test_real_shell_retains_failure_status_and_diagnostics(tmp_path, step, status):
    body = _step(step)
    match = re.search(r'(?ms)^        run: \|\n((?:          [^\n]*\n|[ \t]*\n)+)', body)
    assert match, body
    command = textwrap.dedent(match.group(1))
    venv = tmp_path / 'venv'
    toolbin = venv / 'bin'
    toolbin.mkdir(parents=True)
    (toolbin / 'activate').write_text('')
    python = toolbin / 'python'
    python.write_text(f'#!{sys.executable}\n' + (
        'import os, pathlib, sys\n'
        'if sys.argv[1].endswith("pytest_workers.py"):\n'
        '    print(0)\n'
        '    raise SystemExit(0)\n'
        'assert sys.argv[1:3] == ["-m", "pytest"]\n'
        'xml = next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--junitxml="))\n'
        'pathlib.Path(xml).write_text("<testsuite/>")\n'
        'print("owned pytest diagnostic", flush=True)\n'
        'raise SystemExit(int(os.environ["TEST_STATUS"]))\n'
    ))
    python.chmod(0o700)
    env = dict(os.environ, HOME=str(tmp_path), VENV_PATH=str(venv),
               PATH=str(toolbin) + os.pathsep + os.defpath, RUNNER_TEMP=str(tmp_path),
               SANDBOX_FILES='core/sandbox/tests/test_owned.py', TEST_STATUS=str(status))
    result = subprocess.run(['bash', '-c', command], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == status, result.stdout + result.stderr
    assert 'owned pytest diagnostic' in result.stdout
    logs = list(tmp_path.glob('sandbox-macos*.log'))
    assert len(logs) == 1 and 'owned pytest diagnostic' in logs[0].read_text()
    assert len(list(tmp_path.glob('sandbox-macos*.xml'))) == 1


def test_browser_runtime_is_provisioned_only_for_its_native_family():
    workflow = (ROOT / '.github/workflows/sandbox-wrappers.yml').read_text()
    step = workflow.split('      - name: Install isolated Chromium runtime\n', 1)[1].split('      - name:', 1)[0]
    assert "if: contains(matrix.families, 'playwright-browser')" in step
    assert 'timeout-minutes: 5' in step
