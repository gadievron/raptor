"""Prove Ruff job savings retain changed inputs and conservative fallbacks."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
with patch.object(sys, 'path', [str(SCRIPTS), *sys.path]):
    spec = importlib.util.spec_from_file_location('ruff_scope_under_test', SCRIPTS / 'ruff_scope.py')
    scope = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scope)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / 'pyproject.toml').write_text('''[dependency-groups]
lint = ["ruff==0.15.12"]
[tool.ruff]
target-version = "py312"
''')
    return tmp_path


def write(repo, name, text='value = 1\n'):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return name


@pytest.mark.parametrize('name', ['docs/guide.md', 'notes.txt', 'data/pins.json', 'engine/rule.yaml', 'code/example.c'])
def test_known_non_ruff_edits_skip_runners(repo, name):
    result = scope.plan(repo, [write(repo, name)], ['pyproject.toml'])
    assert result['mode'] == 'skip'
    assert result['files'] == []


@pytest.mark.parametrize('name', ['module.py', 'types/definition.pyi', 'analysis/book.ipynb', '.github/scripts/helper.py', '.py'])
def test_all_default_python_file_types_are_selected(repo, name):
    assert scope.plan(repo, [write(repo, name)], ['pyproject.toml'])['files'] == [name]


@pytest.mark.parametrize('name', ['pyproject.toml', 'nested/pyproject.toml', 'ruff.toml', 'nested/.ruff.toml',
                                 '.gitignore', 'nested/.ignore', '.gitmodules', '.gitattributes', 'nested/.gitattributes', 'uv.lock', 'uv.toml',
                                 '.github/workflows/lint.yml', '.github/scripts/ruff_scope.py',
                                 '.github/scripts/ci_change_scope.py'])
def test_config_and_harness_edits_require_full_tree(repo, name):
    assert scope.plan(repo, [name], ['pyproject.toml'])['files'] == ['.']


@pytest.mark.parametrize('changed', [None, ['deleted.py'], ['deleted.md']])
def test_unknown_history_and_deletions_are_never_empty_coverage(repo, changed):
    assert scope.plan(repo, changed, ['pyproject.toml'])['mode'] == 'full'


@pytest.mark.parametrize('configs', [None, []])
def test_unknown_config_inventory_retains_full_coverage(repo, configs):
    assert scope.plan(repo, [], configs)['mode'] == 'full'


@pytest.mark.parametrize('config', [
    '[tool.ruff]\ninclude = ["*.txt"]\n',
    '[tool.ruff]\nextend-include = ["*.txt"]\n',
    '[tool.ruff]\nextend = "../other.toml"\n',
    '[tool.ruff]\nextension = { txt = "python" }\n',
    '[tool.ruff]\npreview = true\n',
    '[tool.ruff.lint]\npreview = true\n',
    'not valid toml',
])
def test_custom_or_unreadable_discovery_cannot_suppress_lint(repo, config):
    root = repo / 'pyproject.toml'
    root.write_text('[dependency-groups]\nlint = ["ruff==0.15.12"]\n' + config)
    assert scope.plan(repo, [write(repo, 'notes.txt')], ['pyproject.toml'])['mode'] == 'full'


@pytest.mark.parametrize('name', ['ruff.toml', '.ruff.toml', 'subproject/pyproject.toml'])
def test_existing_alternate_and_nested_configs_keep_full_discovery(repo, name):
    write(repo, name, '[tool.ruff]\n')
    assert scope.plan(repo, [write(repo, 'notes.txt')], ['pyproject.toml', name])['mode'] == 'full'


def test_unrelated_nested_project_metadata_does_not_expand_discovery(repo):
    nested = write(repo, 'subproject/pyproject.toml', '[project]\nname = "owned"\n')
    assert scope.plan(repo, [write(repo, 'notes.txt')], ['pyproject.toml', nested])['mode'] == 'skip'


def test_tool_upgrade_cannot_silently_inherit_old_discovery_assumptions(repo):
    path = repo / 'pyproject.toml'
    path.write_text(path.read_text().replace('0.15.12', '999.0.0'))
    assert scope.plan(repo, [write(repo, 'notes.txt')], ['pyproject.toml'])['mode'] == 'full'


def test_symlink_cannot_hide_python_inputs_behind_a_different_extension(repo):
    write(repo, 'source.py')
    (repo / 'link.txt').symlink_to('source.py')
    assert scope.plan(repo, ['link.txt'], ['pyproject.toml'])['mode'] == 'full'


@pytest.mark.parametrize('event', ['pull_request', 'push', 'merge_group'])
def test_cli_uses_current_event_base_and_small_boolean_output(repo, monkeypatch, event):
    monkeypatch.chdir(repo)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setenv('BASE_SHA', 'b' * 40)
    output = repo / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    observed = []

    def changed(root, base):
        observed.append((root, base))
        return [write(repo, 'notes.txt')]

    monkeypatch.setattr(scope, 'changed_paths', changed)
    monkeypatch.setattr(scope, 'tracked_configs', lambda _: ['pyproject.toml'])
    assert scope.main([]) == 0
    assert observed == [(repo, 'b' * 40)]
    assert output.read_text() == 'ruff_run=false\n'


@pytest.mark.parametrize('event', ['schedule', 'workflow_dispatch', 'unexpected'])
def test_deliberate_and_unknown_events_run_full_tree(repo, monkeypatch, event):
    monkeypatch.chdir(repo)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setenv('GITHUB_OUTPUT', str(repo / 'output'))
    monkeypatch.setattr(scope, 'changed_paths', lambda *_: pytest.fail('full run asked for a diff'))
    monkeypatch.setattr(scope, 'tracked_configs', lambda _: ['pyproject.toml'])
    files = repo / 'files.nul'
    assert scope.main(['--files-out', str(files)]) == 0
    assert files.read_bytes() == b'./.\0'
    assert (repo / 'output').read_text() == 'ruff_run=true\n'


def test_filename_handoff_preserves_whitespace_options_and_argfile_markers(repo, monkeypatch):
    names = ['with spaces.py', 'with\nnewline.py', '-options.py', '@arguments.py']
    for name in names:
        write(repo, name)
    monkeypatch.chdir(repo)
    monkeypatch.setenv('EVENT', 'pull_request')
    monkeypatch.setenv('GITHUB_OUTPUT', str(repo / 'output'))
    monkeypatch.setattr(scope, 'changed_paths', lambda *_: names)
    monkeypatch.setattr(scope, 'tracked_configs', lambda _: ['pyproject.toml'])
    files = repo / 'files.nul'
    assert scope.main(['--files-out', str(files)]) == 0
    assert files.read_bytes().split(b'\0')[:-1] == [('./' + name).encode() for name in sorted(names)]
    assert (repo / 'output').read_text() == 'ruff_run=true\n'


def test_config_inventory_keeps_nul_delimited_paths_and_bounded_git_call(repo, monkeypatch):
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout=b'pyproject.toml\0nested dir/pyproject.toml\0')

    monkeypatch.setattr(scope, 'subprocess', SimpleNamespace(run=execute, SubprocessError=subprocess.SubprocessError))
    assert scope.tracked_configs(repo) == ['pyproject.toml', 'nested dir/pyproject.toml']
    assert calls == [(['git', 'ls-files', '-z', '--', '*.toml'],
                      dict(cwd=repo, capture_output=True, check=True, timeout=10))]


def test_git_inventory_failure_remains_unknown(repo, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError('owned git failure')

    monkeypatch.setattr(scope, 'subprocess', SimpleNamespace(run=fail, SubprocessError=subprocess.SubprocessError))
    assert scope.tracked_configs(repo) is None


def test_ruff_jobs_depend_on_existing_scope_without_new_runner_job():
    workflow = (SCRIPTS.parent / 'workflows/lint.yml').read_text()
    assert 'ruff_run: ${{ steps.ruff_scope.outputs.ruff_run }}' in workflow
    assert workflow.count('needs.command-metadata.outputs.ruff_run') == 2
    assert workflow.count('    runs-on:') == 5
    assert 'xargs -0 -r ruff check --output-format=github --' in workflow
    assert 'CHANGED_FILES:' not in workflow
    assert "steps.changed.outputs.files" not in workflow
    assert workflow.count('github.event.merge_group.base_sha') == 2


@pytest.mark.parametrize('text', [
    '[tool]\nruff = "unknown"\n',
    '[tool.ruff]\nlint = "unknown"\n',
    '[dependency-groups]\nlint = "unknown"\n',
])
def test_unrecognised_config_shapes_keep_full_linting(repo, text):
    (repo / 'pyproject.toml').write_text(text)
    assert scope.plan(repo, [write(repo, 'notes.txt')], ['pyproject.toml'])['mode'] == 'full'


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != 'linux', reason='the lint workflow uses Ubuntu xargs')
@pytest.mark.parametrize('lint_code', [0, 1])
def test_real_workflow_command_bounds_large_argv_and_preserves_failure(tmp_path, lint_code):
    if shutil.which('xargs') is None:
        pytest.skip('xargs is required by this workflow integration test')
    binary = tmp_path / 'bin'
    binary.mkdir()
    records = tmp_path / 'calls.jsonl'
    spy = binary / 'ruff'
    spy.write_text('#!' + sys.executable + '\n' + """import json, os, sys
with open(os.environ['OWNED_RUFF_RECORDS'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
raise SystemExit(int(os.environ['OWNED_RUFF_CODE']))
""")
    spy.chmod(0o700)
    names = ['./with spaces.py', './with\nnewline.py', './-options.py', './@arguments.py']
    names += ['./' + 'long-directory-name/' * 8 + str(index) + '.py' for index in range(4000)]
    payload = b''.join(name.encode() + b'\0' for name in names)
    assert len(payload) > 512 * 1024
    (tmp_path / 'ruff-files.nul').write_bytes(payload)
    workflow = (SCRIPTS.parent / 'workflows/lint.yml').read_text()
    command = next(line.strip() for line in workflow.splitlines() if line.strip().startswith('xargs '))
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ.get('PATH', os.defpath),
               RUNNER_TEMP=str(tmp_path), OWNED_RUFF_RECORDS=str(records), OWNED_RUFF_CODE=str(lint_code))
    result = subprocess.run(['/bin/bash', '-e', '-c', command], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if lint_code == 0 else 123), result.stderr
    calls = [json.loads(line) for line in records.read_text().splitlines()]
    assert len(calls) > 1
    assert all(call[:3] == ['check', '--output-format=github', '--'] for call in calls)
    assert [name for call in calls for name in call[3:]] == names
