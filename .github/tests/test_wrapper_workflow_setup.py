"""Execute the workflow's setup commands with owned package-manager stand-ins."""

import ast
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
        if name == 'dpkg-query':
            if os.environ.get('UIDMAP_INSTALLED') == 'true':
                print('install ok installed')
                raise SystemExit(0)
            raise SystemExit(1)
        if name == 'brew' and sys.argv[1] == '--prefix':
            if sys.argv[2] == os.environ.get('FAIL_BREW_PREFIX'):
                raise SystemExit(29)
            print(str(pathlib.Path(os.environ['SETUP_ROOT']) / sys.argv[2]))
        if name == os.environ.get('FAIL_TOOL'):
            raise SystemExit(29)
    ''')
    for name in ('sudo', 'brew', 'uv', 'gem', 'ROPgadget', 'dpkg-query'):
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
    step = _step('Install Linux parser tools and Chromium dependencies' if platform == 'Linux'
                 else 'Install macOS parser tools')
    condition = f"if: runner.os == '{platform}'"
    if platform == 'macOS':
        condition += " && toJSON(matrix.families) != '[]'"
    assert condition + '\n' in step
    assert "NEEDS_RADARE2: ${{ contains(matrix.families, 'radare2') }}" in step
    assert "NEEDS_GADGETS: ${{ contains(matrix.families, 'gadget-parsers') }}" in step
    assert 'timeout-minutes: 8' in step
    env = _tools(tmp_path)
    env.update(NEEDS_RADARE2=str(radare).lower(), NEEDS_GADGETS=str(gadgets).lower(), NEEDS_BROWSER='false')
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in Path(env['SETUP_CALLS']).read_text().splitlines()]
    expected = ['binutils'] + (['libseccomp2'] if platform == 'Linux' else [])
    expected += ['radare2'] if radare else []
    expected += ['ruby'] if gadgets else []
    if platform == 'Linux':
        assert calls == [['sudo', 'bash', '.github/scripts/with-ubuntu-apt.sh',
                          'packages', *expected]]
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
    step = _step('Install Linux parser tools and Chromium dependencies' if platform == 'Linux'
                 else 'Install macOS parser tools')
    env = _tools(tmp_path)
    env.update(NEEDS_RADARE2='true', NEEDS_GADGETS='true', NEEDS_BROWSER='false',
               FAIL_TOOL=failure, FAIL_BREW_PREFIX=prefix)
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 29, result.stdout + result.stderr
    if prefix == 'ruby':
        assert not Path(env['GITHUB_PATH']).exists()


@pytest.mark.parametrize('missing', [False, True], ids=['cached-tool', 'missing-tool'])
def test_cached_python_parser_tools_cover_elf_worker_and_refuse_missing_tool(tmp_path, missing):
    step = _step('Expose cached Python parser tools')
    assert "if: contains(matrix.families, 'gadget-parsers') || contains(matrix.families, 'elf-worker')" in step
    assert 'uv pip install' not in _command(step)
    env = _tools(tmp_path)
    env['VENV_PATH'] = '.venv'
    tool = tmp_path / '.venv/bin/ROPgadget'
    tool.parent.mkdir(parents=True)
    if not missing:
        tool.write_text('#!/bin/sh\nexit 0\n')
        tool.chmod(0o700)
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == (1 if missing else 0), result.stdout + result.stderr
    assert not Path(env['SETUP_CALLS']).exists()
    if missing:
        assert not Path(env['GITHUB_PATH']).exists()
    else:
        assert Path(env['GITHUB_PATH']).read_text().strip() == str(tmp_path / '.venv/bin')


@pytest.mark.parametrize('radare,gadgets', list(itertools.product([False, True], repeat=2)),
                         ids=['browser', 'browser-gadgets', 'browser-radare', 'all-tools'])
def test_linux_browser_and_parser_packages_share_the_signed_helper(tmp_path, radare, gadgets):
    step = _step('Install Linux parser tools and Chromium dependencies')
    env = _tools(tmp_path)
    env.update(NEEDS_RADARE2=str(radare).lower(), NEEDS_GADGETS=str(gadgets).lower(),
               NEEDS_BROWSER='true', VENV_PATH='.venv')
    result = subprocess.run(['bash', '-c', _command(step)], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    packages = ['binutils', 'libseccomp2'] + (['radare2'] if radare else []) + (['ruby'] if gadgets else [])
    calls = [json.loads(line) for line in Path(env['SETUP_CALLS']).read_text().splitlines()]
    assert calls == [['sudo', 'bash', '.github/scripts/with-ubuntu-apt.sh', 'packages-playwright',
                      str(tmp_path / '.venv/bin/python'), *packages]]


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


def _cache_expression(text, platform, families):
    expression = text.strip().removeprefix('${{').removesuffix('}}').strip()
    expression = re.sub(r"contains\(matrix\.families, '([^']+)'\)",
                        lambda match: repr(match[1] in families), expression)
    expression = expression.replace('runner.os', repr(platform)).replace('&&', ' and ').replace('||', ' or ')

    def visit(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                result = visit(value)
                if isinstance(node.op, ast.And) and not result:
                    return result
                if isinstance(node.op, ast.Or) and result:
                    return result
            return result
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            return visit(node.left) == visit(node.comparators[0])
        raise AssertionError('Unsupported cache expression: ' + ast.dump(node))

    return visit(ast.parse(expression, mode='eval').body)


@pytest.mark.parametrize('platform', ['Linux', 'macOS'])
@pytest.mark.parametrize('families', [[], ['radare2'], ['gadget-parsers'], ['elf-worker'],
                                    ['gadget-parsers', 'elf-worker', 'playwright-browser']],
                         ids=['contracts', 'unrelated-native', 'gadgets', 'elf', 'full-parser-selection'])
def test_parser_group_is_selected_only_for_its_families(platform, families):
    import tomllib

    workflow = (ROOT / '.github/workflows/sandbox-wrappers.yml').read_text()
    uv_step = workflow.split('      - uses: astral-sh/setup-uv@', 1)[1].split('      - uses:', 1)[0]
    globs = re.search(r'(?m)^          cache-dependency-glob: \|\n((?:            [^\n]*\n)+)', uv_step)
    assert globs
    assert {line.strip() for line in globs[1].splitlines()} == {'uv.lock', 'pyproject.toml', 'uv.toml'}
    needed = bool({'gadget-parsers', 'elf-worker'} & set(families))
    suffix = re.search(r'(?m)^          cache-suffix: (.+)$', uv_step)[1]
    assert _cache_expression(suffix, platform, families) == ('sandbox-wrappers' if needed else 'base')
    args = re.search(r'(?m)^          uv-export-extra-args: >-\n((?:            [^\n]*\n)+)', workflow)
    assert args
    selected = ' '.join(_cache_expression(line, platform, families) if '${{' in line else line.strip()
                        for line in args[1].splitlines()).split()
    base = '--extra binary --extra r2pipe --extra frida --extra llm --extra grammars --extra web'.split()
    assert selected == base + (['--group', 'sandbox-wrappers'] if needed else [])
    assert 'requirements-file:' not in workflow
    pruning = re.search(r'(?m)^          prune-cache: (.+)$', uv_step)[1]
    assert _cache_expression(pruning, platform, families) is (platform == 'macOS' and needed)
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    group = project['dependency-groups']['sandbox-wrappers']
    assert {re.split(r'[<>=!~]', requirement, maxsplit=1)[0].lower() for requirement in group} == {
        'pwntools', 'ropgadget', 'capstone',
    }


@pytest.mark.parametrize('installed,failure', [(True, ''), (False, ''), (False, 'sudo')],
                         ids=['warm-no-archive', 'missing-signed-fallback', 'install-failure'])
def test_userns_setup_refreshes_archives_only_for_missing_uidmap(tmp_path, installed, failure):
    action = (ROOT / '.github/actions/enable-userns/action.yml').read_text()
    command = textwrap.dedent(action.split('      run: |\n', 1)[1])
    env = _tools(tmp_path)
    env.update(UIDMAP_INSTALLED=str(installed).lower(), FAIL_TOOL=failure)
    result = subprocess.run(['bash', '-eo', 'pipefail', '-c', command], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == (29 if failure else 0), result.stdout + result.stderr
    calls = [json.loads(line) for line in Path(env['SETUP_CALLS']).read_text().splitlines()]
    assert calls[0] == ['dpkg-query', '-W', '-f=${Status}', 'uidmap']
    archive = ['sudo', 'bash', '.github/scripts/with-ubuntu-apt.sh', 'packages', 'uidmap']
    policy = ['sudo', 'sysctl', '-w', 'kernel.apparmor_restrict_unprivileged_userns=0']
    assert (archive in calls) is (not installed)
    assert (policy in calls) is (not failure)
    assert len(calls) == (2 if installed or failure else 3)
