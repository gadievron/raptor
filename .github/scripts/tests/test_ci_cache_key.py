"""Cache identity changes follow dependency, interpreter and host changes."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import json
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parents[1]
spec = importlib.util.spec_from_file_location('ci_cache_keys', SCRIPTS / 'ci_cache_key.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)

HOST = dict(system='Linux', machine='x86_64', release={'ID': 'ubuntu', 'VERSION_ID': '24.04'},
            libc=['glibc', '2.39'], image_os='ubuntu24', image_version='20261101.1')
PYTHON = dict(implementation='cpython', version='3.14.4', cache_tag='cpython-314',
              abi='cpython-314-x86_64-linux-gnu', base_prefix='/opt/python/3.14.4', base_executable='/opt/python/3.14.4/bin/python')


@pytest.fixture
def repo(tmp_path):
    (tmp_path / 'uv.lock').write_text('version = 1\n')
    (tmp_path / 'pyproject.toml').write_text('[project]\nname = "owned"\n')
    return tmp_path


def key(repo, **kwargs):
    return cache.venv_key(repo, HOST, PYTHON, **kwargs)


def test_unchanged_inputs_share_the_exact_identity(repo):
    assert key(repo) == cache.venv_key(repo, deepcopy(HOST), deepcopy(PYTHON))
    assert key(repo).startswith('venv-v3-')


@pytest.mark.parametrize('name', ['uv.lock', 'pyproject.toml', 'uv.toml', '.github/actions/setup-venv/action.yml'])
def test_install_input_changes_invalidate_the_environment(repo, name):
    before = key(repo)
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('changed = true\n')
    assert key(repo) != before


@pytest.mark.parametrize('field,value', [('system', 'Darwin'), ('machine', 'aarch64'),
                                        ('release', {'ID': 'ubuntu', 'VERSION_ID': '26.04'}),
                                        ('libc', ['musl', '1.2']), ('image_version', '20261108.1')])
def test_native_environments_do_not_cross_host_abis(repo, field, value):
    host = deepcopy(HOST)
    host[field] = value
    assert cache.venv_key(repo, host, PYTHON) != key(repo)


@pytest.mark.parametrize('field,value', [('implementation', 'pypy'), ('version', '3.14.5'),
                                        ('abi', 'cpython-314t-x86_64-linux-gnu'),
                                        ('base_prefix', '/new/python/3.14.4'),
                                        ('base_executable', '/new/python/bin/python')])
def test_interpreter_build_and_location_changes_invalidate_the_environment(repo, field, value):
    interpreter = deepcopy(PYTHON)
    interpreter[field] = value
    assert cache.venv_key(repo, HOST, interpreter) != key(repo)


@pytest.mark.parametrize('kwargs', [dict(export_args='--extra web'), dict(export_args='--no-dev'), dict(export_args='--no-dev --extra cvss'),
                                      dict(export_args='--extra cvss'), dict(prefix='venv-web'), dict(venv_path='other-venv'), dict(install_method='sync')])
def test_profile_and_workspace_locations_cannot_collide(repo, kwargs):
    assert key(repo, **kwargs) != key(repo)


def test_another_checkout_cannot_receive_old_console_script_shebangs(repo):
    other = repo / 'other'
    other.mkdir()
    for name in ('uv.lock', 'pyproject.toml'):
        (other / name).write_bytes((repo / name).read_bytes())
    assert key(other) != key(repo)


@pytest.mark.parametrize('prefix', ['', 'bad\nkey', 'bad/prefix'])
def test_invalid_prefix_cannot_enter_github_output(repo, prefix):
    with pytest.raises(ValueError):
        key(repo, prefix=prefix)


def test_missing_locked_inputs_do_not_produce_a_usable_key(repo):
    (repo / 'uv.lock').unlink()
    with pytest.raises(OSError):
        key(repo)


@pytest.fixture
def tool_repo(repo):
    location = repo / '.github/scripts/codeql-cli.json'
    location.parent.mkdir(parents=True)
    location.write_bytes((SCRIPTS / 'codeql-cli.json').read_bytes())
    return repo


def test_codeql_checksum_change_invalidates_even_an_unchanged_version(tool_repo):
    before = cache.codeql_metadata(tool_repo, HOST)
    path = tool_repo / '.github/scripts/codeql-cli.json'
    data = json.loads(path.read_text())
    data['sha256'] = 'a' * 64
    path.write_text(json.dumps(data))
    after = cache.codeql_metadata(tool_repo, HOST)
    assert before['version'] == after['version']
    assert before['key'] != after['key']


def test_portable_codeql_archive_does_not_invalidate_on_image_or_python_updates(tool_repo):
    host = dict(HOST, image_version='20261201.1', release={'ID': 'ubuntu', 'VERSION_ID': '26.04'})
    assert cache.codeql_metadata(tool_repo, host)['key'] == cache.codeql_metadata(tool_repo, HOST)['key']


@pytest.mark.parametrize('field,value', [('version', '2; command'), ('sha256', 'not-a-sha'), ('libraries_ref', 'main')])
def test_codeql_metadata_is_validated_before_reaching_shell_or_checkout(tool_repo, field, value):
    path = tool_repo / '.github/scripts/codeql-cli.json'
    data = json.loads(path.read_text())
    data[field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        cache.codeql_metadata(tool_repo, HOST)


def test_wrong_codeql_architecture_fails_before_cache_restore(tool_repo):
    with pytest.raises(ValueError, match='Linux x64'):
        cache.codeql_metadata(tool_repo, dict(HOST, machine='aarch64'))


def test_cli_outputs_are_small_and_the_week_does_not_affect_venv_identity(repo, monkeypatch):
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cache, 'host_identity', lambda: deepcopy(HOST))
    monkeypatch.setattr(cache, 'interpreter_identity', lambda: deepcopy(PYTHON))
    monkeypatch.setenv('VENV_CACHE_PREFIX', 'venv')
    monkeypatch.setenv('VENV_CACHE_EXPORT_ARGS', '')
    monkeypatch.setenv('VENV_PATH', '.venv')
    output = repo / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    assert cache.main([]) == 0
    values = dict(line.split('=', 1) for line in output.read_text().splitlines())
    assert values['key'] == key(repo)
    assert 'week' in values
    assert len(output.read_bytes()) < 512


def test_all_assembled_venv_producers_and_consumers_use_the_same_helper():
    files = [ROOT / '.github/workflows/tests.yml', ROOT / '.github/actions/setup-venv/action.yml']
    count = 0
    for path in files:
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            if line.strip() == 'path: ${{ env.VENV_PATH }}':
                assert lines[index + 1].strip() == 'key: ${{ steps.venv-key.outputs.key }}'
                count += 1
    assert count == 7
    assert files[0].read_text().count('id: venv-key') == 2
    assert 'VENV_CACHE_EXPORT_ARGS: ${{ inputs.uv-export-extra-args }}' in files[1].read_text()
    assert 'restore-keys:' not in files[1].read_text()


def test_native_tool_cache_is_platform_scoped_refreshes_weekly_and_can_miss():
    workflow = (ROOT / '.github/workflows/nightly.yml').read_text()
    block = workflow.split('      - name: Restore apt toolchain cache', 1)[1].split('      - name: Install binary-analysis', 1)[0]
    assert 'continue-on-error: true' in block
    assert 'steps.native_venv.outputs.platform-key' in block
    assert 'steps.native_venv.outputs.week' in block
    assert 'APT_CACHE_USABLE:' in workflow
    assert '[[ "$APT_CACHE_USABLE" == true ]] && ls' in workflow
    assert workflow.count('key: ${{ steps.codeql_identity.outputs.key }}') == 4
    assert workflow.count('CODEQL_SHA256: ${{ steps.codeql_identity.outputs.sha256 }}') == 2
    pin = json.loads((SCRIPTS / 'codeql-cli.json').read_text())['libraries_ref']
    assert re.fullmatch(r'[0-9a-f]{40}', pin)
    checkout_blocks = re.findall(
        r'repository: github/codeql\n(.*?)(?=\n      - |\Z)', workflow, re.S)
    assert len(checkout_blocks) == 2
    for checkout in checkout_blocks:
        assert re.search(r'^          ref: ' + pin + r'$', checkout, re.M)
        assert 'persist-credentials: false' in checkout
    assert 'ref: ${{ steps.codeql_identity.outputs.libraries_ref }}' not in workflow


def test_bytecode_restores_are_optional_and_prefix_hits_still_recompile():
    workflow = (ROOT / '.github/workflows/tests.yml').read_text()
    block = workflow.split('        id: pycache\n', 1)[1].split('      - name: Start LLM hostname tripwire', 1)[0]
    assert 'continue-on-error: true' in block
    assert "steps.pycache.outcome != 'success' || steps.pycache.outputs.cache-hit != 'true'" in block
    assert 'steps.fast_venv.outputs.cache-key' in block
    assert "'packages/**/*.py', '*.py'" in block
    assert '\n            __pycache__\n' in block
    assert '--invalidation-mode checked-hash' in block


def test_builder_interpreter_is_the_one_fingerprinted_before_restore():
    for name in ('.github/actions/setup-venv/action.yml', '.github/workflows/tests.yml'):
        workflow = (ROOT / name).read_text()
        commands = [line.strip() for line in workflow.splitlines() if line.strip().startswith('uv venv')]
        assert commands
        assert all('uv venv --clear --python "$(command -v python3)" "$VENV_PATH"' == command for command in commands)


def test_every_explicit_uv_cache_key_covers_project_lock_and_config():
    import re
    files = list((ROOT / '.github/workflows').glob('*.y*ml')) + [ROOT / '.github/actions/setup-venv/action.yml']
    seen = 0
    cached_setups = 0
    for file in files:
        text = file.read_text()
        lines_by_step = text.splitlines()
        for index, line in enumerate(lines_by_step):
            if "uses: astral-sh/setup-uv@" not in line:
                continue
            indent = len(line) - len(line.lstrip())
            block = []
            for following in lines_by_step[index + 1:]:
                following_indent = len(following) - len(following.lstrip())
                if following.strip() and (following_indent < indent or (
                    following_indent <= indent and following.lstrip().startswith("- ")
                )):
                    break
                block.append(following)
            enabled = next((entry.strip() for entry in block
                            if entry.strip().startswith("enable-cache:")), None)
            if enabled and not re.fullmatch(r"enable-cache: false(?:\s+#.*)?", enabled):
                cached_setups += 1
                assert any("cache-dependency-glob: |" in entry for entry in block), file
        for match in re.finditer(r'(?m)^( +)cache-dependency-glob: \|\n', text):
            indent = len(match[1])
            lines = []
            for line in text[match.end():].splitlines():
                if len(line) - len(line.lstrip()) <= indent:
                    break
                lines.append(line.strip())
            assert {'uv.lock', 'pyproject.toml', 'uv.toml'} <= set(lines), file
            seen += 1
        assert not re.search(r'cache-dependency-glob: ["\']?uv\.lock', text), file
    # Non-vacuousness follows actual cache owners; removing redundant setup
    # steps must not require a stale minimum workflow/action count.
    assert seen >= cached_setups > 0


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != 'linux', reason='the tier image uses GNU sha256sum and Bash')
@pytest.mark.parametrize('state', ['match', 'changed-lock', 'uv-config', 'missing-stamp', 'export-failure'])
def test_real_image_reconcile_guard_preserves_fresh_inputs_and_failures(tmp_path, state):
    if shutil.which('sha256sum') is None:
        pytest.skip('GNU sha256sum is required by the image workflow')
    for name in ('pyproject.toml', 'uv.lock'):
        (tmp_path / name).write_text('owned = true\n')
    stamp = tmp_path / 'baked.hash'
    stamp.write_text(''.join(hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() + '  ' + name + '\n'
                             for name in ('pyproject.toml', 'uv.lock')))
    if state == 'changed-lock':
        (tmp_path / 'uv.lock').write_text('changed = true\n')
    elif state in ('uv-config', 'export-failure'):
        (tmp_path / 'uv.toml').write_text('# forces reconciliation\n')
    elif state == 'missing-stamp':
        stamp.unlink()
    tools = tmp_path / 'bin'
    tools.mkdir()
    uv = tools / 'uv'
    uv.write_text('#!' + sys.executable + '\n' + """import json, os, pathlib, sys
with open(os.environ['OWNED_CALLS'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1] == 'export':
    if os.environ['FAIL_EXPORT'] == 'true':
        raise SystemExit(29)
    pathlib.Path(sys.argv[sys.argv.index('--output-file') + 1]).write_text('owned==1.0\\n')
""")
    uv.chmod(0o700)
    workflow = (ROOT / '.github/workflows/_tier.yml').read_text()
    block = workflow.split('      - name: Reconcile deps\n', 1)[1].split('      - name: Run tests\n', 1)[0]
    body = re.search(r'(?ms)^        run: \|\n((?:          [^\n]*\n|[ \t]*\n)+)', block)[1]
    import textwrap
    command = textwrap.dedent(body).replace('/etc/raptor-ci-deps.hash', shlex.quote(str(stamp)))
    calls = tmp_path / 'calls.jsonl'
    env = dict(os.environ, PATH=str(tools) + os.pathsep + os.defpath, RUNNER_TEMP=str(tmp_path),
               OWNED_CALLS=str(calls), FAIL_EXPORT=str(state == 'export-failure').lower())
    result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', command],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == (29 if state == 'export-failure' else 0), result.stderr
    observed = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    if state == 'match':
        assert observed == []
    elif state == 'export-failure':
        assert len(observed) == 1 and observed[0][0] == 'export'
    else:
        assert observed[-1] == ['pip', 'sync', '--system', str(tmp_path / 'tier-requirements.txt')]
        assert (tmp_path / 'tier-requirements.txt').read_text() == 'owned==1.0\n'


@pytest.mark.parametrize('method', ['', 'invalid', 'sync\nkey'])
def test_invalid_install_method_cannot_create_a_cache_identity(repo, method):
    with pytest.raises(ValueError, match='invalid venv install method'):
        key(repo, install_method=method)


def test_cli_includes_selected_install_method_in_the_exact_key(repo, monkeypatch):
    monkeypatch.chdir(repo)
    monkeypatch.setattr(cache, 'host_identity', lambda: deepcopy(HOST))
    monkeypatch.setattr(cache, 'interpreter_identity', lambda: deepcopy(PYTHON))
    monkeypatch.setenv('VENV_CACHE_INSTALL_METHOD', 'sync')
    monkeypatch.setenv('VENV_CACHE_PREFIX', 'venv')
    monkeypatch.setenv('VENV_CACHE_EXPORT_ARGS', '')
    monkeypatch.setenv('VENV_PATH', '.venv')
    output = repo / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    assert cache.main([]) == 0
    values = dict(line.split('=', 1) for line in output.read_text().splitlines())
    assert values['key'] == key(repo, install_method='sync')
    assert values['key'] != key(repo)
