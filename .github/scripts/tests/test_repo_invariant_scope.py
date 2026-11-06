"""Invariant step savings preserve input coverage and fail-open execution gates."""

from pathlib import Path
import sys
from unittest.mock import patch

import pytest
import yaml

from core.testing.gitrepo import git_run, init_scratch_repo

SCRIPTS = Path(__file__).resolve().parents[1]
with patch.object(sys, 'path', [str(SCRIPTS), *sys.path]), patch.dict(sys.modules):
    import repo_invariant_scope as scope


def write(repo, name):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('value = 1\n')
    return name


@pytest.mark.parametrize('name, env, redos', [
    ('README.md', False, False), ('docs/architecture.md', False, False),
    ('LICENSE', False, False), ('docs/environment.md', True, False),
    ('core/reader.py', True, True), ('entry.py', True, True),
    ('core/tests/test_reader.py', True, False),
    ('packages/x/fixtures/reader.py', True, False),
    ('core/scripts/verify.py', True, False),
    ('core/testing/state_isolation.py', True, True),
    ('core/testing_helpers/reader.py', True, True),
    ('core/build/reader.py', True, True),
    ('libexec/wrapper', True, True), ('bin/wrapper', True, False),
    ('.devcontainer/helper.py', True, False), ('.devcontainer/Dockerfile', True, False),
    ('core/config.json', False, True),
    ('core/llm/model_brokers/registry.json', True, True),
    ('core/tests/fixture.txt', False, False),
    ('.github/tests/data/redos_pins.json', True, True),
    ('.github/scripts/check_env_docs.py', True, True),
    ('.github/scripts/runtime_universe.py', True, True),
    ('.github/workflows/lint.yml', True, True),
])
def test_input_families(tmp_path, name, env, redos):
    result = scope.plan(tmp_path, [write(tmp_path, name)])
    assert result == {'env_docs_run': env, 'redos_run': redos}


@pytest.mark.parametrize('name', [
    'conftest.py', 'core/tests/conftest.py', 'pytest.ini', 'pyproject.toml',
    'uv.lock', 'uv.toml', 'requirements-dev.txt', '.gitattributes', '.gitmodules',
    '.gitignore', '.python-version',
])
def test_execution_and_discovery_changes_keep_both_steps(tmp_path, name):
    assert all(scope.plan(tmp_path, [write(tmp_path, name)]).values())


@pytest.mark.parametrize('changed', [None, ['deleted.py'], ['deleted.md'], ['../escape.md'], ['/absolute.md'], ['./README.md']])
def test_unknown_deleted_or_noncanonical_paths_keep_coverage(tmp_path, changed):
    write(tmp_path, 'README.md')
    assert all(scope.plan(tmp_path, changed).values())


def test_directory_change_is_not_empty_coverage(tmp_path):
    (tmp_path / 'new_submodule').mkdir()
    assert all(scope.plan(tmp_path, ['new_submodule']).values())


def test_known_empty_diff_can_skip_both(tmp_path):
    assert not any(scope.plan(tmp_path, []).values())


@pytest.mark.parametrize('which', ['env', 'redos'])
def test_roots_are_derived_and_support_nested_prefixes(tmp_path, monkeypatch, which):
    if which == 'env':
        monkeypatch.setattr(scope.env_docs, 'PY_ROOTS', ['new/nested'])
    else:
        monkeypatch.setattr(scope.runtime, 'RUNTIME_ROOTS', ('new/nested',))
    result = scope.plan(tmp_path, [write(tmp_path, 'new/nested/reader.py')])
    assert result == {'env_docs_run': which == 'env', 'redos_run': which == 'redos'}


def test_scanner_language_extensions_and_scope_share_detection(tmp_path, monkeypatch):
    path = tmp_path / 'core/new_extension.source'
    path.parent.mkdir()
    path.write_text("import os\nos.getenv('RAPTOR_FUTURE_LANGUAGE')\n")
    original = scope.env_docs.source_kind
    monkeypatch.setattr(scope.env_docs, 'source_kind',
                        lambda path: 'python' if path.suffix == '.source' else original(path))
    assert scope.plan(tmp_path, ['core/new_extension.source'])['env_docs_run']
    inventory = scope.env_docs.scan_tree(tmp_path)
    assert 'RAPTOR_FUTURE_LANGUAGE' in inventory.vars


@pytest.mark.parametrize('event', ['pull_request', 'push', 'merge_group'])
def test_event_diff_and_output_append(tmp_path, monkeypatch, event):
    write(tmp_path, 'README.md')
    output = tmp_path / 'outputs'
    output.write_text('previous=value\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setenv('BASE_SHA', 'a' * 40)
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    calls = []

    def changes(repo, base):
        calls.append((repo, base))
        return ['README.md']

    monkeypatch.setattr(scope, 'changed_paths', changes)
    assert scope.main() == 0
    assert calls == [(tmp_path.resolve(), 'a' * 40)]
    assert output.read_text() == 'previous=value\nenv_docs_run=false\nredos_run=false\n'


@pytest.mark.parametrize('event', ['schedule', 'workflow_dispatch', '', 'future_event'])
def test_deliberate_and_unrecognised_runs_keep_full_checks(tmp_path, monkeypatch, event):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setenv('GITHUB_OUTPUT', str(tmp_path / 'outputs'))
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: pytest.fail('must not scope deliberate full runs'))
    assert scope.main() == 0
    assert (tmp_path / 'outputs').read_text() == 'env_docs_run=true\nredos_run=true\n'


def test_real_git_uses_full_push_range_and_both_rename_paths(tmp_path):
    repo = init_scratch_repo(tmp_path)
    write(repo, 'core/reader.py')
    write(repo, 'README.md')
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'base')
    base = git_run(repo, 'rev-parse', 'HEAD')
    (repo / 'core/reader.py').write_text('value = 2\n')
    git_run(repo, 'commit', '-qam', 'source edit')
    (repo / 'README.md').write_text('documentation edit\n')
    git_run(repo, 'commit', '-qam', 'docs edit')
    changes = scope.changed_paths(repo, base)
    assert 'core/reader.py' in changes
    assert all(scope.plan(repo, changes).values())
    (repo / 'docs').mkdir()
    git_run(repo, 'mv', 'core/reader.py', 'docs/moved.txt')
    git_run(repo, 'commit', '-qam', 'rename')
    changes = scope.changed_paths(repo, base)
    assert {'core/reader.py', 'docs/moved.txt'} <= set(changes)
    assert all(scope.plan(repo, changes).values())


def test_workflow_gates_only_reviewed_steps_and_preserves_failure_reporting():
    jobs = yaml.safe_load((SCRIPTS.parent / 'workflows/lint.yml').read_text())['jobs']
    assert len(jobs) == 5
    job = jobs['repo-invariants']
    assert 'needs' not in job  # Independent of command-metadata's runner queue.
    step = next(s for s in job['steps'] if s.get('id') == 'invariant_scope')
    assert 'github.event.merge_group.base_sha' in step['env']['BASE_SHA']
    assert step['run'] == 'python3 .github/scripts/repo_invariant_scope.py'
    steps = {s['name']: s for s in job['steps']}
    for name, output in [('Run env-var documentation drift check', 'env_docs_run'),
                         ('Install pytest', 'redos_run'), ('Run ReDoS idiom census', 'redos_run')]:
        assert steps[name]['if'] == "${{ steps.invariant_scope.outputs." + output + " != 'false' }}"
    for step in job['steps']:
        if 'run' in step and 'python3 .github/scripts/check_' in step['run']:
            if 'check_env_docs.py' in step['run']:
                continue
            if 'check_skip_budget.py' in step['run']:
                assert "steps.redos_census.outcome == 'failure'" in step['if']
            else:
                assert 'if' not in step, step['name']
    assert 'repo-invariants' in jobs['lint-passed']['needs']
