"""Exercise dependency provisioning using owned package-manager stand-ins."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / '.github/scripts/with-ubuntu-apt.sh'


@pytest.fixture
def apt_runner(tmp_path):
    owned = tmp_path / 'owned apt setup'
    owned.mkdir()
    release = owned / 'os-release'
    keyring = owned / 'ubuntu-keyring.gpg'
    keyring.write_text('owned fixture; never used by real apt')
    script = HELPER.read_text().replace('. /etc/os-release', f'. "{release}"')
    script = script.replace('/usr/share/keyrings/ubuntu-archive-keyring.gpg', str(keyring))
    script = script.replace('/tmp/raptor-ci-apt.XXXXXXXX', str(owned / 'apt.XXXXXXXX'))
    helper = owned / 'helper.sh'
    helper.write_text(script)
    tools = owned / 'bin'
    tools.mkdir()
    log = owned / 'calls.jsonl'
    fake = f'#!{sys.executable}\n' + r'''
import json, os, pathlib, re, sys
name = pathlib.Path(sys.argv[0]).name
if name == 'dpkg':
    print(os.environ.get('FAKE_ARCH', 'amd64'))
    raise SystemExit(0)
config = pathlib.Path(os.environ['APT_CONFIG'])
text = config.read_text()
source = pathlib.Path(re.search(r'Dir::Etc::sourcelist "([^"]+)";', text)[1])
lists = pathlib.Path(re.search(r'Dir::State::lists "([^"]+)";', text)[1])
stage = config.parent.name
phase = 'update' if 'update' in sys.argv else 'install'
row = dict(name=name, args=sys.argv[1:], stage=stage, phase=phase,
           config=text, sources=source.read_text(), lists=str(lists),
           empty_lists=not any(lists.iterdir()))
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write(json.dumps(row) + '\n')
if phase == 'update':
    (lists / 'owned-index').write_text(stage)
failures = os.environ.get('FAIL_PHASES', '').split(',')
if stage + ':' + phase in failures:
    raise SystemExit(100)
# Model apt's warning-only update unless strict index failure mode is set.
if stage == 'primary' and phase == 'update' and os.environ.get('WARN_UPDATE'):
    raise SystemExit(100 if 'APT::Update::Error-Mode=any' in sys.argv else 0)
'''
    for name in ('apt-get', 'dpkg', 'python-owned'):
        path = tools / name
        path.write_text(fake)
        path.chmod(0o700)

    def run(*, failures='', warning=False, codename='noble', system='ubuntu',
            arch='amd64', missing_key=False, mode='packages'):
        release.write_text(f'ID={system}\nVERSION_CODENAME={codename}\n')
        if missing_key:
            keyring.unlink()
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.defpath,
                   CALL_LOG=str(log), FAIL_PHASES=failures,
                   FAKE_ARCH=arch, WARN_UPDATE='1' if warning else '')
        args = ['bash', str(helper), mode]
        args += ['one-package', 'another-package'] if mode == 'packages' else [str(tools / 'python-owned')]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=10)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    return run


@pytest.mark.parametrize('failures,expected,status', [
    ('', [('primary', 'update'), ('primary', 'install')], 0),
    ('primary:update', [('primary', 'update'), ('fallback', 'update'), ('fallback', 'install')], 0),
    ('primary:install', [('primary', 'update'), ('primary', 'install'), ('fallback', 'update'), ('fallback', 'install')], 0),
    ('primary:update,fallback:update', [('primary', 'update'), ('fallback', 'update')], 100),
    ('primary:install,fallback:install', [('primary', 'update'), ('primary', 'install'), ('fallback', 'update'), ('fallback', 'install')], 100),
])
def test_bounded_routes_preserve_setup_failures(apt_runner, failures, expected, status):
    result, calls = apt_runner(failures=failures)
    assert result.returncode == status, result.stdout + result.stderr
    assert [(call['stage'], call['phase']) for call in calls] == expected
    for call in calls:
        if call['phase'] == 'update':
            assert call['empty_lists']
            assert 'APT::Update::Error-Mode=any' in call['args']
        else:
            assert call['args'] == ['install', '-y', '--no-install-recommends', '--', 'one-package', 'another-package']
        assert 'Acquire::Retries "2";' in call['config']
        assert 'Acquire::https::Timeout "20";' in call['config']
        assert 'Dir::Etc::sourceparts "-";' in call['config']
        assert 'AllowUnauthenticated "false"' in call['config']
        assert 'AllowInsecureRepositories "false"' in call['config']
        assert all('signed-by=' in row for row in call['sources'].splitlines())
    updates = [call for call in calls if call['phase'] == 'update']
    assert len({call['lists'] for call in updates}) == len(updates)
    if len(updates) == 2:
        assert 'https://mirrors.kernel.org/ubuntu' in updates[1]['sources']
        assert 'archive.ubuntu.com' not in updates[1]['sources']
    assert 'stage=primary' in result.stderr
    if status:
        assert 'failed on both signed archive routes' in result.stderr


def test_warning_only_incomplete_index_is_a_failed_route(apt_runner):
    result, calls = apt_runner(warning=True)
    assert result.returncode == 0, result.stderr
    assert [(call['stage'], call['phase']) for call in calls] == [
        ('primary', 'update'), ('fallback', 'update'), ('fallback', 'install')]
    assert 'index refresh failed status=100' in result.stderr


@pytest.mark.parametrize('codename', ['noble', 'resolute'])
def test_each_route_keeps_actual_release_and_security_pockets(apt_runner, codename):
    result, calls = apt_runner(codename=codename, failures='primary:update')
    assert result.returncode == 0, result.stderr
    for call in calls:
        rows = call['sources'].splitlines()
        assert len(rows) == 3
        pockets = [row.split()[-5] for row in rows]
        assert pockets == [codename, codename + '-updates', codename + '-security']
        assert all(row.endswith('main restricted universe multiverse') for row in rows)


@pytest.mark.parametrize('kwargs', [dict(system='debian'), dict(codename='bad/path'),
                                   dict(arch='arm64'), dict(missing_key=True)])
def test_unsupported_or_unsigned_setup_never_invokes_apt(apt_runner, kwargs):
    result, calls = apt_runner(**kwargs)
    assert result.returncode != 0
    assert calls == []


def test_playwright_dependency_install_inherits_each_scoped_config(apt_runner):
    result, calls = apt_runner(mode='playwright', failures='primary:install')
    assert result.returncode == 0, result.stderr
    installs = [call for call in calls if call['phase'] == 'install']
    assert [call['stage'] for call in installs] == ['primary', 'fallback']
    assert all(call['name'] == 'python-owned' for call in installs)
    assert all(call['args'] == ['-m', 'playwright', 'install-deps', 'chromium'] for call in installs)


def test_workflows_use_scoped_helper_before_browser_download():
    wrappers = (ROOT / '.github/workflows/sandbox-wrappers.yml').read_text()
    nightly = (ROOT / '.github/workflows/nightly.yml').read_text()
    selftest = (ROOT / '.github/workflows/nightly-self-test.yml').read_text()
    assert 'with-ubuntu-apt.sh packages "${packages[@]}"' in wrappers
    assert 'with-ubuntu-apt.sh packages radare2 gcc' in selftest
    for workflow, download in ((wrappers, '"$VENV_PATH/bin/python" -m playwright install chromium'),
                               (nightly, 'python -m playwright install --only-shell chromium')):
        assert 'with-ubuntu-apt.sh playwright' in workflow
        assert '"$GITHUB_WORKSPACE/$VENV_PATH/bin/python"' in workflow
        assert workflow.index('with-ubuntu-apt.sh playwright') < workflow.index(download)
    helper = HELPER.read_text()
    assert 'trusted=yes' not in helper
    assert 'Check-Valid-Until' not in helper
    assert 'AllowDowngradeToInsecureRepositories "false"' in helper
    assert re.search(r'for stage in primary fallback;', helper)
