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
import json, os, pathlib, re, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
if name == 'dpkg':
    print(os.environ.get('FAKE_ARCH', 'amd64'))
    raise SystemExit(0)
config = pathlib.Path(os.environ['APT_CONFIG'])
text = config.read_text()
source = pathlib.Path(re.search(r'Dir::Etc::sourcelist "([^"]+)";', text)[1])
lists = pathlib.Path(re.search(r'Dir::State::lists "([^"]+)";', text)[1])
stage = config.parent.name
phase = ('browser' if name == 'python-owned' and os.environ.get('COMBINED_BROWSER')
         else 'update' if 'update' in sys.argv else 'install')
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
if (phase == 'install' and 'one-package' in sys.argv
        and stage + ':parser' in failures):
    raise SystemExit(100)
if phase == 'browser':
    # Match Playwright's real two-command dependency installer. The shell
    # helper supplies strict signed routes through its scoped APT_CONFIG.
    status = subprocess.call(['apt-get', 'update'])
    if not status:
        status = subprocess.call(['apt-get', 'install', '-y', '--no-install-recommends', 'owned-chromium'])
    raise SystemExit(status)
# Model apt's warning-only update unless strict index failure mode is set.
if stage == 'primary' and phase == 'update' and os.environ.get('WARN_UPDATE'):
    raise SystemExit(100 if ('APT::Update::Error-Mode=any' in sys.argv
                            or 'APT::Update::Error-Mode \"any\";' in text) else 0)
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
                   FAKE_ARCH=arch, WARN_UPDATE='1' if warning else '',
                   COMBINED_BROWSER='1' if mode == 'packages-playwright' else '')
        args = ['bash', str(helper), mode]
        if mode == 'packages':
            args += ['one-package', 'another-package']
        else:
            args += [str(tools / 'python-owned')]
            if mode == 'packages-playwright':
                args += ['one-package', 'another-package']
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
    for workflow, mode, download in ((wrappers, 'packages-playwright', '"$VENV_PATH/bin/python" -m playwright install chromium'),
                                     (nightly, 'playwright', 'python -m playwright install --only-shell chromium')):
        assert 'with-ubuntu-apt.sh ' + mode in workflow
        assert '"$GITHUB_WORKSPACE/$VENV_PATH/bin/python"' in workflow
        assert workflow.index('with-ubuntu-apt.sh ' + mode) < workflow.index(download)
    helper = HELPER.read_text()
    assert 'trusted=yes' not in helper
    assert 'Check-Valid-Until' not in helper
    assert 'AllowDowngradeToInsecureRepositories "false"' in helper
    assert re.search(r'for stage in primary fallback;', helper)


@pytest.mark.parametrize('failures,status,stages', [
    ('', 0, ['primary']),
    ('primary:update', 0, ['primary', 'fallback']),
    ('primary:browser', 0, ['primary', 'fallback']),
    ('primary:parser', 0, ['primary', 'fallback']),
    ('primary:parser,fallback:parser', 100, ['primary', 'fallback']),
])
def test_combined_browser_and_parser_install_share_one_refresh_per_route(apt_runner, failures, status, stages):
    result, calls = apt_runner(mode='packages-playwright', failures=failures)
    assert result.returncode == status, result.stdout + result.stderr
    browsers = [call for call in calls if call['name'] == 'python-owned']
    assert [call['stage'] for call in browsers] == stages
    updates = [call for call in calls if call['phase'] == 'update']
    assert len(updates) <= len(stages)
    assert len({call['stage'] for call in updates}) == len(updates)
    for call in calls:
        assert 'APT::Update::Error-Mode "any";' in call['config']
        assert 'AllowUnauthenticated "false"' in call['config']
        assert all('signed-by=' in row for row in call['sources'].splitlines())
    parser_installs = [call for call in calls if 'one-package' in call['args']]
    for call in parser_installs:
        assert call['args'] == ['install', '-y', '--no-install-recommends', '--', 'one-package', 'another-package']
        assert any(update['stage'] == call['stage'] for update in updates)
    if not failures:
        assert [(call['name'], call['phase']) for call in calls] == [
            ('python-owned', 'browser'), ('apt-get', 'update'),
            ('apt-get', 'install'), ('apt-get', 'install')]
        assert len(parser_installs) == 1
    if status:
        assert 'failed on both signed archive routes' in result.stderr


def test_combined_playwright_update_warning_uses_independent_fallback(apt_runner):
    result, calls = apt_runner(mode='packages-playwright', warning=True)
    assert result.returncode == 0, result.stderr
    assert [call['stage'] for call in calls if call['phase'] == 'update'] == ['primary', 'fallback']
    assert [call['stage'] for call in calls if 'one-package' in call['args']] == ['fallback']


def test_other_ubuntu_jobs_reuse_signed_archives_without_replacing_llvm_sources():
    docker = (ROOT / '.github/workflows/dockerhub-publish.yml').read_text()
    weekly = (ROOT / '.github/workflows/weekly_corpus.yml').read_text()
    nightly = (ROOT / '.github/workflows/nightly.yml').read_text()
    assert 'with-ubuntu-apt.sh packages buildah skopeo' in docker
    for workflow in (weekly, nightly):
        assert 'with-ubuntu-apt.sh packages radare2' in workflow
        assert 'sudo /tmp/llvm.sh 21' in workflow
        assert 'sudo apt-get install -y --no-install-recommends llvm-21 clang-21' in workflow
    assert 'sudo apt-get install -f -y --no-install-recommends' in nightly
    assert '--reinstall --download-only' in nightly


def test_uidmap_fallback_keeps_the_existing_host_policy_and_avoids_warm_refresh():
    action = (ROOT / '.github/actions/enable-userns/action.yml').read_text()
    assert "dpkg-query -W -f='${Status}' uidmap" in action
    assert "grep -qx 'install ok installed'" in action
    assert 'with-ubuntu-apt.sh packages uidmap' in action
    assert 'sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0' in action
