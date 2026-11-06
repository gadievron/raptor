"""Scheduled runners reuse exact project envs and fingerprint standalone tools."""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import textwrap
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
PIN = '.github/scripts/semgrep-cli.txt'
CONSUMERS = [
    ('nightly-self-test.yml', 'self-test'),
    ('nightly.yml', 'slow-integration'),
    ('nightly.yml', 'semgrep-regressions'),
]


def job(file, name):
    source = (ROOT / '.github/workflows' / file).read_text().split('\njobs:\n', 1)[1]
    match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:|\Z)',
                      source, re.M | re.S)
    assert match is not None
    return match[1]


def steps(source):
    return re.split(r'^      - ', source, flags=re.M)[1:]


def named_step(source, name):
    matches = [body for body in steps(source) if body.splitlines()[0] == f'name: {name}']
    assert len(matches) == 1, f'expected one {name} step'
    return matches[0]


def script(body):
    run = re.search(r'^        run: \|\n((?:          .*\n|\n)+)', body, re.M)
    if run:
        return textwrap.dedent(run[1])
    run = re.search(r'^        run: (.+)$', body, re.M)
    assert run is not None
    return run[1]


def test_semgrep_pin_has_one_exact_version():
    assert re.fullmatch(r'semgrep==[0-9]+\.[0-9]+\.[0-9]+\n', (ROOT / PIN).read_text())


def test_all_semgrep_installers_use_the_pin_and_include_it_in_download_cache_inputs():
    owners = set()
    for path in (ROOT / '.github/workflows').glob('*.y*ml'):
        source = path.read_text().split('\njobs:\n', 1)[1]
        for match in re.finditer(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)', source, re.M | re.S):
            body = match[2]
            installers = [step for step in steps(body) if 'uv tool install' in step and 'semgrep' in step]
            if not installers:
                continue
            owners.add((path.name, match[1]))
            assert len(installers) == 1
            assert f'"$(cat {PIN})"' in script(installers[0])
            assert not re.search(r'semgrep==[0-9]', script(installers[0]))
            uv = named_step(body, 'Install uv')
            assert {'uv.lock', 'pyproject.toml', 'uv.toml', PIN} <= set(
                re.findall(r'^            (\S+)$', uv, re.M))
    assert owners == set(CONSUMERS)


@pytest.mark.parametrize('file,name', [
    ('nightly-self-test.yml', 'self-test'), ('ubuntu26-canary.yml', 'sandbox-canary'),
])
def test_scheduled_jobs_use_shared_exact_venv_and_save_successful_rebuilds(file, name):
    source = job(file, name)
    restore = named_step(source, 'Restore or rebuild venv')
    assert '        uses: ./.github/actions/setup-venv\n' in restore
    assert "          save-on-rebuild: 'true'\n" in restore
    assert 'uv-export-extra-args' not in restore  # Same base/dev export as before.
    assert 'cache-key-prefix' not in restore  # Share the exact base-env identity.
    assert 'uv venv' not in source
    assert source.index('actions/setup-python@') < source.index('uses: ./.github/actions/setup-venv')


def test_canary_still_probes_and_asserts_the_real_host_before_cache_restore():
    source = job('ubuntu26-canary.yml', 'sandbox-canary')
    assert '    runs-on: ubuntu-26.04\n' in source
    names = [body.splitlines()[0] for body in steps(source)]
    restore = names.index('name: Restore or rebuild venv')
    for name in ['Probe kernel features (stock image)', 'Enable unprivileged user namespaces',
                 'Probe kernel features (userns enabled)', 'Assert the ubuntu-24.04 capability baseline holds']:
        assert names.index('name: ' + name) < restore
    assert 'python -m pytest core/sandbox' in script(named_step(source, 'Run sandbox fast tier'))


def test_selftest_still_runs_the_full_tier_zero_and_refuses_missing_toolchains():
    source = job('nightly-self-test.yml', 'self-test')
    run = script(named_step(source, 'Run self-test (tier 0)'))
    assert 'python libexec/raptor-self-test' in run and '--timeout 600' in run
    refuse = named_step(source, 'Refuse a toolchain-less self-test nightly')
    assert 'if: ${{ !cancelled() }}' in refuse
    assert 'command -v r2' in script(refuse) and 'command -v gcc' in script(refuse)


@pytest.mark.parametrize('file,name', CONSUMERS)
def test_real_semgrep_install_shell_uses_the_setup_python_and_exact_pin(tmp_path, file, name):
    source = job(file, name)
    installer = next(body for body in steps(source) if 'uv tool install' in body and 'semgrep' in body)
    command = script(installer)
    assert 'source ' not in command, 'standalone tools must not bind to the project venv'
    pin = tmp_path / PIN
    pin.parent.mkdir(parents=True)
    pin.write_bytes((ROOT / PIN).read_bytes())
    tools = tmp_path / 'tools with spaces'
    tools.mkdir()
    (tools / 'python3').symlink_to(sys.executable)
    record = tmp_path / 'uv-argv.json'
    uv = tools / 'uv'
    uv.write_text(f'#!{sys.executable}\nimport json,os,pathlib,sys\npathlib.Path(os.environ["UV_RECORD"]).write_text(json.dumps(sys.argv[1:]))\n')
    uv.chmod(0o755)
    semgrep = tools / 'semgrep'
    semgrep.write_text('#!/bin/sh\nexit 0\n')
    semgrep.chmod(0o755)
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', command],
        cwd=tmp_path, env=dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin', UV_RECORD=str(record)),
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(record.read_text()) == [
        'tool', 'install', '--python', str(tools / 'python3'), pin.read_text().strip(),
    ]


def test_tool_pin_changes_have_a_ci_lint_owner():
    with patch.object(sys, 'path', [str(ROOT / '.github/scripts'), *sys.path]):
        from test_scope import TIERS, file_in_dir
    assert any(file_in_dir(Path(PIN), owner) for owner in TIERS['ci_lint']['extra_triggers'])
