"""Exercise nightly cache branches without package, network or system actions."""

import json
from pathlib import Path
import re
import sys
import textwrap

import pytest

from core.testing.standalone_cli import run_standalone_cli

ROOT = Path(__file__).resolve().parents[2]


def _step(name):
    workflow = (ROOT / '.github/workflows/nightly.yml').read_text()
    parts = re.split(r'^      - name: ', workflow, flags=re.M)[1:]
    return next(part for part in parts if part.splitlines()[0] == name)


def _script():
    step = _step('Install binary-analysis toolchain (radare2 + LLVM 21)')
    body = re.search(r'^        run: \|\n((?:          .*\n|\n)+)', step, re.M)
    assert body is not None
    return textwrap.dedent(body[1])


FAKE = r'''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps([name, *args]) + '\n')
fail = os.environ.get('FAIL', '')
if name == 'python3':
    phase = args[1]
    if phase == fail:
        sys.exit(23)
    if fail == phase + '-write':
        pathlib.Path(args[-1]).write_text('partial')
        sys.exit(28)
    if phase == 'snapshot':
        pathlib.Path(args[-1]).write_text('{}')
    elif phase == 'extract':
        pathlib.Path(args[-1]).write_text(
            'Start-Date: fixture\nInstall: radare2:amd64 (1), '
            'llvm-21:amd64 (21), fonts-tool-dependency:amd64 (1)\nEnd-Date: fixture\n')
    else:
        sys.exit(91)
elif name == 'sudo':
    if args[0] == 'dpkg' and fail in ('dpkg', 'repair'):
        sys.exit(24)
    if args[:3] == ['apt-get', 'install', '-f'] and fail == 'repair':
        sys.exit(25)
    if args == ['apt-get', 'update'] and fail == 'install':
        sys.exit(26)
    if '--download-only' in args:
        if fail == 'download':
            sys.exit(27)
        pathlib.Path(os.environ['DEBS_DIR'], 'captured.deb').write_text('inert')
    if args[0] not in ('dpkg', 'apt-get', 'mkdir', 'find', 'chown',
                        'update-alternatives', os.environ['LLVM_SCRIPT']):
        sys.exit(92)
elif name not in ('wget', 'chmod', 'r2', 'clang', 'llvm-cov', 'llvm-profdata'):
    sys.exit(93)
'''


def _run(tmp_path, *, warm=False, fail='', partial=False, usable=None):
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    fake = bindir / 'fake'
    fake.write_text(f'#!{sys.executable}\n' + FAKE)
    fake.chmod(0o755)
    for name in ('sudo', 'wget', 'chmod', 'python3', 'r2', 'clang',
                 'llvm-cov', 'llvm-profdata'):
        (bindir / name).symlink_to(fake)
    debs = tmp_path / 'debs'
    debs.mkdir()
    if warm or partial:
        (debs / 'old.deb').write_text('inert')
    llvm_script = tmp_path / 'llvm.sh'
    script = _script().replace('/tmp/llvm.sh', str(llvm_script))
    for name in ('llvm-cov', 'llvm-profdata'):
        script = script.replace(f'/usr/lib/llvm-21/bin/{name}', str(bindir / name))
    script_path = tmp_path / 'toolchain.sh'
    script_path.write_text(script)
    path_file = tmp_path / 'github-path'
    log = tmp_path / 'calls.jsonl'
    env = {'PATH': f'{bindir}:/usr/bin:/bin', 'HOME': str(tmp_path),
           'RUNNER_TEMP': str(tmp_path), 'DEBS_DIR': str(debs),
           'APT_CACHE_USABLE': str(warm if usable is None else usable).lower(),
           'GITHUB_PATH': str(path_file), 'CALL_LOG': str(log),
           'LLVM_SCRIPT': str(llvm_script), 'FAIL': fail}
    result = run_standalone_cli(
        ['/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(script_path)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    return result, calls, path_file, debs


def _published(calls, path_file):
    alternatives = [call for call in calls if call[:2] == ['sudo', 'update-alternatives']]
    assert len(alternatives) == 2
    assert path_file.read_text() == '/usr/lib/llvm-21/bin\n'
    assert [call[0] for call in calls[-4:]] == ['r2', 'clang', 'llvm-cov', 'llvm-profdata']


def test_cold_window_packages_and_install_order(tmp_path):
    result, calls, path_file, debs = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert calls[0][0:3] == ['python3', '.github/scripts/apt_history_window.py', 'snapshot']
    sudo = [call[1:] for call in calls if call[0] == 'sudo']
    assert sudo[:4] == [
        ['apt-get', 'update'],
        ['apt-get', 'install', '-y', '--no-install-recommends', 'radare2'],
        [str(tmp_path / 'llvm.sh'), '21'],
        ['apt-get', 'install', '-y', '--no-install-recommends', 'llvm-21', 'clang-21'],
    ]
    download, = [call for call in calls if '--download-only' in call]
    assert download[-3:] == ['fonts-tool-dependency', 'llvm-21', 'radare2']
    assert (debs / 'captured.deb').is_file()
    _published(calls, path_file)


@pytest.mark.parametrize('fail', ['', 'dpkg', 'repair'])
def test_warm_install_and_repair(tmp_path, fail):
    result, calls, path_file, _ = _run(tmp_path, warm=True, fail=fail)
    assert result.returncode == (25 if fail == 'repair' else 0)
    assert calls[0][:3] == ['sudo', 'dpkg', '-i']
    assert not any(call[0] == 'python3' or '--download-only' in call for call in calls)
    repairs = [call for call in calls if call[:4] == ['sudo', 'apt-get', 'install', '-f']]
    assert len(repairs) == bool(fail)
    if fail == 'repair':
        assert not path_file.exists()
    else:
        _published(calls, path_file)


@pytest.mark.parametrize('fail', ['snapshot', 'extract', 'snapshot-write', 'extract-write', 'download'])
def test_capture_failure_publishes_tools_but_fails_step(tmp_path, fail):
    result, calls, path_file, _ = _run(tmp_path, fail=fail)
    assert result.returncode != 0
    assert ['sudo', 'apt-get', 'install', '-y', '--no-install-recommends', 'llvm-21', 'clang-21'] in calls
    if fail.startswith(('snapshot', 'extract')):
        assert not any('--download-only' in call for call in calls)
    if fail.startswith('snapshot'):
        assert 'refusing cache capture' in result.stdout
        assert not any(call[0] == 'python3' and call[2] == 'extract' for call in calls)
    _published(calls, path_file)


def test_original_install_failure_stops_later_commands(tmp_path):
    result, calls, path_file, _ = _run(tmp_path, fail='install')
    assert result.returncode == 26
    assert calls[-1] == ['sudo', 'apt-get', 'update']
    assert not path_file.exists()


@pytest.mark.parametrize('usable', [False, True])
def test_restore_failure_or_empty_hit_takes_cold_path(tmp_path, usable):
    result, calls, path_file, debs = _run(tmp_path, partial=not usable, usable=usable)
    assert result.returncode == 0
    assert not (debs / 'old.deb').exists()
    assert calls[0][0] == 'python3'
    assert not any(call[:2] == ['sudo', 'dpkg'] for call in calls)
    _published(calls, path_file)


def test_cache_save_remains_bound_to_successful_outcome():
    save = _step('Save apt toolchain cache')
    assert "if: steps.apt-debs.outputs.cache-hit != 'true' && steps.toolchain.outcome == 'success'" in save
    assert 'continue-on-error: true' in save
    restore = _step('Restore apt toolchain cache (radare2 + LLVM 21 .debs)')
    keys = [re.search(r'^          key: (.+)$', step, re.M)[1] for step in (restore, save)]
    assert keys[0] == keys[1]
    assert "${{ hashFiles('.github/scripts/apt_history_window.py') }}-v3" in keys[0]
    assert 'path: ${{ runner.temp }}/apt-debs' in restore
    assert 'path: ${{ runner.temp }}/apt-debs' in save
    assert 'continue-on-error: true' in restore
    assert 'continue-on-error: true' in _step('Install binary-analysis toolchain (radare2 + LLVM 21)')
