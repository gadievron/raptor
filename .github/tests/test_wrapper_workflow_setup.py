"""Execute the workflow's setup commands with owned package-manager stand-ins."""

import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _step(name):
    workflow = (ROOT / '.github/workflows/sandbox-wrappers.yml').read_text()
    match = re.search(r'(?ms)^      - name: ' + re.escape(name) + r'\n(.*?)(?=^      - |\Z)', workflow)
    assert match, name
    return match.group(1)


def _command(step):
    match = re.search(r'(?ms)^        run: \|\n((?:          [^\n]*\n|[ \t]*\n)+)', step)
    assert match, step
    return textwrap.dedent(match.group(1))


def _tools(tmp_path):
    toolbin = tmp_path / 'bin'
    toolbin.mkdir()
    script = f'#!{sys.executable}\n' + textwrap.dedent('''\
        import json, os, pathlib, sys
        name = pathlib.Path(sys.argv[0]).name
        with open(os.environ['SETUP_CALLS'], 'a') as output:
            output.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
        if name == 'brew' and sys.argv[1] == '--prefix':
            if sys.argv[2] == os.environ.get('FAIL_BREW_PREFIX'):
                raise SystemExit(29)
            print(str(pathlib.Path(os.environ['SETUP_ROOT']) / sys.argv[2]))
        if name == os.environ.get('FAIL_TOOL'):
            raise SystemExit(29)
    ''')
    for name in ('sudo', 'brew', 'uv', 'gem', 'ROPgadget'):
        target = toolbin / name
        target.write_text(script)
        target.chmod(0o700)
    return dict(os.environ, PATH=str(toolbin) + os.pathsep + os.defpath,
                SETUP_CALLS=str(tmp_path / 'calls'), SETUP_ROOT=str(tmp_path),
                GITHUB_PATH=str(tmp_path / 'github-path'), VENV_PATH=str(tmp_path),
                RUNNER_TEMP=str(tmp_path), GITHUB_WORKSPACE=str(tmp_path),
                FAIL_TOOL='', FAIL_BREW_PREFIX='')


@pytest.mark.parametrize('platform', ['Linux', 'macOS'])
@pytest.mark.parametrize('radare,gadgets', list(itertools.product([False, True], repeat=2)),
                         ids=['base', 'gadgets', 'radare', 'all-tools'])
def test_native_setup_installs_only_selected_tool_groups(tmp_path, platform, radare, gadgets):
    step = _step('Install ' + platform + ' parser tools')
    condition = f"if: runner.os == '{platform}'"
    if platform == 'macOS':
        condition += " && toJSON(matrix.families) != '[]'"
    assert condition + '\n' in step
    assert "NEEDS_RADARE2: ${{ contains(matrix.families, 'radare2') }}" in step
    assert "NEEDS_GADGETS: ${{ contains(matrix.families, 'gadget-parsers') }}" in step
    assert 'timeout-minutes: 8' in step
    env = _tools(tmp_path)
    env.update(NEEDS_RADARE2=str(radare).lower(), NEEDS_GADGETS=str(gadgets).lower())
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in Path(env['SETUP_CALLS']).read_text().splitlines()]
    expected = ['binutils'] + (['libseccomp2'] if platform == 'Linux' else [])
    expected += ['radare2'] if radare else []
    expected += ['ruby'] if gadgets else []
    if platform == 'Linux':
        assert calls == [['sudo', 'apt-get', 'update'],
                         ['sudo', 'apt-get', 'install', '-y', '--no-install-recommends', *expected]]
    else:
        assert calls[0] == ['brew', 'install', *expected]
        assert (['brew', '--prefix', 'ruby'] in calls) == gadgets
        paths = Path(env['GITHUB_PATH']).read_text().splitlines()
        assert (str(tmp_path / 'ruby/bin') in paths) == gadgets
        assert str(tmp_path / 'binutils/libexec/gnubin') in paths


@pytest.mark.parametrize('platform,failure,prefix', [
    ('Linux', 'sudo', ''), ('macOS', 'brew', ''),
    ('macOS', '', 'ruby'), ('macOS', '', 'binutils'),
], ids=['apt', 'brew-install', 'ruby-prefix', 'binutils-prefix'])
def test_native_setup_refuses_package_manager_and_prefix_failures(tmp_path, platform, failure, prefix):
    step = _step('Install ' + platform + ' parser tools')
    env = _tools(tmp_path)
    env.update(NEEDS_RADARE2='true', NEEDS_GADGETS='true',
               FAIL_TOOL=failure, FAIL_BREW_PREFIX=prefix)
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 29, result.stdout + result.stderr
    if prefix == 'ruby':
        assert not Path(env['GITHUB_PATH']).exists()


@pytest.mark.parametrize('failure', ['', 'uv'], ids=['pass', 'python-install-failure'])
def test_python_parser_dependencies_include_elf_worker_and_preserve_failures(tmp_path, failure):
    step = _step('Install Python parser dependencies')
    assert "if: contains(matrix.families, 'gadget-parsers') || contains(matrix.families, 'elf-worker')" in step
    assert 'timeout-minutes: 8' in step
    env = _tools(tmp_path)
    env['FAIL_TOOL'] = failure
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == (29 if failure else 0), result.stdout + result.stderr
    calls = [json.loads(line) for line in Path(env['SETUP_CALLS']).read_text().splitlines()]
    assert calls[0] == ['uv', 'pip', 'install', '--python', str(tmp_path / 'bin/python'),
                        'pwntools==4.15.0', 'ROPgadget==7.7', 'capstone==5.0.6']
    assert len(calls) == 1


@pytest.mark.parametrize('failure', ['', 'gem'], ids=['pass', 'ruby-install-failure'])
def test_ruby_parser_dependencies_stay_gated_and_preserve_failures(tmp_path, failure):
    step = _step('Install Ruby parser dependencies')
    assert "if: contains(matrix.families, 'gadget-parsers')" in step
    assert 'timeout-minutes: 8' in step
    env = _tools(tmp_path)
    env['FAIL_TOOL'] = failure
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == (29 if failure else 0), result.stdout + result.stderr
    calls = [json.loads(line) for line in Path(env['SETUP_CALLS']).read_text().splitlines()]
    assert calls == [['gem', 'install', '--no-document', '--install-dir',
                      str(tmp_path / 'wrapper-gems'), 'one_gadget', '-v', '1.10.0']]
