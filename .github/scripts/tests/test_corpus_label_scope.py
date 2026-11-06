"""Corpus pin dispatch preserves complete ranges and avoids empty runners."""
from pathlib import Path
import json
import os
import subprocess
import textwrap
import re
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.testing.gitrepo import git_run, init_scratch_repo

SCRIPTS = Path(__file__).resolve().parents[1]
with patch.object(sys, 'path', [str(SCRIPTS), *sys.path]):
    import corpus_label_scope as scope


def write(repo, name, text='{}'):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return name


@pytest.mark.parametrize('name, expected', [
    ('README.md', []), ('docs/architecture.md', []),
    ('core/other.py', []), ('core/tests/test_other.py', []),
    ('core/audit/corpus/labels/a.label.json', ['core/audit/corpus/labels/a.label.json']),
    ('core/audit/corpus/labels/nested/a.label.json', ['core/audit/corpus/labels/nested/a.label.json']),
    ('core/audit/corpus/sources.json', scope.FULL),
    ('core/audit/corpus/lint.py', scope.FULL),
    ('core/audit/corpus/definitions.py', scope.FULL),
    ('.github/workflows/corpus-labels.yml', scope.FULL),
    ('.github/scripts/corpus_label_scope.py', scope.FULL),
    ('.github/scripts/ci_change_scope.py', scope.FULL),
    ('uv.lock', scope.FULL), ('pyproject.toml', scope.FULL),
    ('core/__init__.py', scope.FULL), ('core/audit/__init__.py', scope.FULL),
])
def test_input_families(tmp_path, name, expected):
    assert scope.select(tmp_path, [write(tmp_path, name)]) == expected


@pytest.mark.parametrize('changed', [None, [scope.LABELS + '/deleted.label.json'], ['../escape'], ['/absolute'], ['./README.md'], ['']])
def test_unknown_deleted_or_noncanonical_inputs_keep_full_checks(tmp_path, changed):
    write(tmp_path, 'README.md')
    assert scope.select(tmp_path, changed) == scope.FULL


def test_empty_diff_skips_and_duplicates_do_not_duplicate_work(tmp_path):
    name = write(tmp_path, scope.LABELS + '/one.label.json')
    assert scope.select(tmp_path, []) == []
    assert scope.select(tmp_path, [name, name]) == [name]


def test_large_selection_broadens_without_large_exec_arguments(tmp_path):
    names = [write(tmp_path, scope.LABELS + '/' + 'x' * 180 + str(i) + '.label.json')
             for i in range(200)]
    assert sum(len(name) for name in names) > 32 * 1024
    assert scope.select(tmp_path, names) == scope.FULL


@pytest.mark.parametrize('name', ['docs/deleted.md', 'core/tests/deleted.py'])
def test_unrelated_deletions_do_not_allocate_pin_runner(tmp_path, name):
    assert scope.select(tmp_path, [name]) == []


def test_directory_or_deleted_label_keeps_full_coverage(tmp_path):
    (tmp_path / scope.LABELS).mkdir(parents=True)
    assert scope.select(tmp_path, [scope.LABELS]) == scope.FULL
    assert scope.select(tmp_path, [scope.LABELS + '/gone.label.json']) == scope.FULL


@pytest.mark.parametrize('event', ['pull_request', 'merge_group'])
def test_full_event_range_survives_a_moving_main(tmp_path, monkeypatch, event):
    repo = init_scratch_repo(tmp_path)
    name = write(repo, scope.LABELS + '/two words\nsecond.label.json')
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'base')
    base = git_run(repo, 'rev-parse', 'HEAD')
    write(repo, name, '{"changed": true}')
    git_run(repo, 'commit', '-qam', 'label edit')
    write(repo, 'README.md', 'later docs commit')
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'docs')
    # The old merge-base against this moving ref would produce an empty diff.
    git_run(repo, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
    monkeypatch.chdir(repo)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setenv('BASE_SHA', base)
    output = tmp_path / 'outputs'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    assert scope.main([]) == 0
    assert output.read_text() == 'pins_run=true\n'
    assert scope.select(repo, scope.changed_paths(repo, base)) == [name]


def test_shallow_checkout_fetches_only_the_event_base(tmp_path):
    source = init_scratch_repo(tmp_path / 'source')
    name = write(source, scope.LABELS + '/one.label.json')
    git_run(source, 'add', '.')
    git_run(source, 'commit', '-qm', 'base')
    base = git_run(source, 'rev-parse', 'HEAD')
    write(source, name, '{"changed": true}')
    git_run(source, 'commit', '-qam', 'label edit')
    clone = tmp_path / 'clone'
    git_run(tmp_path, 'clone', '--depth=1', source.as_uri(), str(clone))
    assert base not in git_run(clone, 'rev-list', '--all')
    assert scope.changed_paths(clone, base) == [name]
    git_run(clone, 'cat-file', '-e', base + '^{commit}')


def test_lint_preserves_filename_boundaries_and_failure_status(tmp_path, monkeypatch, capsys):
    name = write(tmp_path, scope.LABELS + '/no-fixture space and\nnewline.label.json')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('EVENT', 'pull_request')
    monkeypatch.setenv('BASE_SHA', 'a' * 40)
    monkeypatch.setattr(scope, 'changed_paths', lambda repo, base: [name])
    output = tmp_path / 'outputs'
    output.write_text('previous=value\n')
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(scope, 'subprocess', SimpleNamespace(run=run))
    assert scope.main(['--lint', '--cache-dir', 'owned cache']) == 2
    command, options = calls[0]
    assert command == [sys.executable, '-m', 'core.audit.corpus.lint', '--mode', 'pins',
                       '--fetch-missing', '--cache-dir', 'owned cache', name]
    assert options == {'cwd': tmp_path, 'check': False}
    assert output.read_text() == 'previous=value\npins_run=true\n'
    captured = capsys.readouterr()
    assert captured.out == ''  # Diagnostic paths must not trigger lint-log warnings.
    assert json.loads(captured.err)['pin_paths'] == [name]


def test_no_work_never_starts_linter(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('EVENT', 'pull_request')
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: [])
    monkeypatch.setattr(scope, 'subprocess', SimpleNamespace(run=lambda *args, **kwargs: pytest.fail('empty lint')))
    assert scope.main(['--lint']) == 0


@pytest.mark.parametrize('event', ['schedule', 'workflow_dispatch', 'push', '', 'future'])
def test_non_pr_events_preserve_full_selection(tmp_path, monkeypatch, event):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: pytest.fail('not an event-range dispatch'))
    output = tmp_path / 'outputs'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    assert scope.main([]) == 0
    assert output.read_text() == 'pins_run=true\n'


def test_workflow_gates_runner_and_keeps_all_required_owners():
    text = (SCRIPTS.parent / 'workflows/corpus-labels.yml').read_text()
    jobs = dict(re.findall(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)', text.split('\njobs:\n', 1)[1], re.M | re.S))
    assert set(jobs) == {'schema-lint', 'pin-lint-pr', 'pin-lint-sweep', 'corpus-labels-passed'}
    schema = jobs['schema-lint']
    assert not re.search(r'^    (?:if|needs):', schema, re.M)
    assert 'pins_run: ${{ steps.pin_scope.outputs.pins_run }}' in schema
    assert schema.index('--mode schema') < schema.index('id: pin_scope')
    pr = jobs['pin-lint-pr']
    assert 'needs: schema-lint' in pr
    assert "needs.schema-lint.outputs.pins_run != 'false'" in pr
    assert 'github.event.pull_request.base.sha' in schema and 'github.event.merge_group.base_sha' in schema
    assert 'github.event.pull_request.base.sha' in pr and 'github.event.merge_group.base_sha' in pr
    assert 'corpus_label_scope.py --lint' in pr
    assert 'shell: bash' in pr and '| tee pin-lint.log' in pr
    assert 'origin/main' not in pr and 'CHANGED_FILES' not in pr
    assert 'fetch-depth: 1' in pr
    assert 'sources.json' in pr and 'sources.py' in pr
    assert 'corpus-lint-v2-' in pr
    assert '--tree-search' in jobs['pin-lint-sweep']
    assert 'actions/cache@' not in jobs['pin-lint-sweep']
    assert 'mktemp -d' in jobs['pin-lint-sweep']
    gate = jobs['corpus-labels-passed']
    assert 'if: always()' in gate
    assert 'needs: [schema-lint, pin-lint-pr, pin-lint-sweep]' in gate
    assert "join(needs.*.result, ' ')" in gate


@pytest.mark.parametrize('status', [0, 2])
def test_real_weekly_shell_uses_fresh_cache_and_preserves_failure(tmp_path, status):
    text = (SCRIPTS.parent / 'workflows/corpus-labels.yml').read_text()
    weekly = text.split('  pin-lint-sweep:\n', 1)[1].split('  # Aggregate gate', 1)[0]
    script = textwrap.dedent(weekly.split('        run: |\n', 1)[1])
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    python = binaries / 'python3'
    python.write_text('#!' + sys.executable + '\n'
                      'import json,os,sys\n'
                      'from pathlib import Path\n'
                      'Path(os.environ["OWNED_PIN_ARGS"]).write_text(json.dumps(sys.argv[1:]))\n'
                      'print("owned pin result",flush=True)\n'
                      'sys.exit(int(os.environ["OWNED_PIN_STATUS"]))\n')
    python.chmod(0o700)
    runner_temp = tmp_path / 'runner temp'
    runner_temp.mkdir()
    arguments = tmp_path / 'arguments.json'
    result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                            cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PATH': str(binaries) + os.pathsep + os.defpath,
                                 'RUNNER_TEMP': str(runner_temp), 'OWNED_PIN_ARGS': str(arguments),
                                 'OWNED_PIN_STATUS': str(status)}, timeout=10)
    assert result.returncode == status, result.stderr
    argv = json.loads(arguments.read_text())
    cache = Path(argv[argv.index('--cache-dir') + 1])
    assert cache.parent == runner_temp
    assert cache.name.startswith('corpus-pin-sweep.')
    assert not cache.exists()
    assert '--fetch-missing' in argv and '--tree-search' in argv
    assert (tmp_path / 'pin-lint.log').read_text() == 'owned pin result\n'
