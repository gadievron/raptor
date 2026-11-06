"""Unit tests for the preflight changed-test-file scoper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "preflight_scope.py"


@pytest.fixture(scope="module")
def ps():
    spec = importlib.util.spec_from_file_location("preflight_scope", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(mod)
    return mod


def _tree(root: Path, files: list[str]) -> Path:
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    return root


class TestChangedTestFiles:
    def test_keeps_only_existing_test_files(self, ps, tmp_path):
        repo = _tree(tmp_path, [
            "core/audit/tests/test_b.py",
            "core/audit/tests/test_a.py",
            "core/audit/validate.py",
            "docs/audit.md",
        ])
        changed = [
            "core/audit/tests/test_b.py",
            "core/audit/tests/test_a.py",
            "core/audit/validate.py",       # not a test
            "docs/audit.md",                # not Python
            "core/audit/tests/test_gone.py",  # deleted in this PR
        ]
        assert ps.changed_test_files(changed, repo) == [
            "core/audit/tests/test_a.py",
            "core/audit/tests/test_b.py",
        ]

    def test_excludes_conftest_and_fixtures(self, ps, tmp_path):
        repo = _tree(tmp_path, [
            "conftest.py",
            "core/audit/tests/conftest.py",
            "core/audit/tests/fixtures/test_app.py",
            "core/audit/tests/test_real.py",
        ])
        changed = [
            "conftest.py",
            "core/audit/tests/conftest.py",
            "core/audit/tests/fixtures/test_app.py",
            "core/audit/tests/test_real.py",
        ]
        assert ps.changed_test_files(changed, repo) == [
            "core/audit/tests/test_real.py",
        ]

    def test_deduplicates(self, ps, tmp_path):
        repo = _tree(tmp_path, ["packages/sca/tests/test_x.py"])
        changed = ["packages/sca/tests/test_x.py"] * 3
        assert ps.changed_test_files(changed, repo) == [
            "packages/sca/tests/test_x.py",
        ]


class TestMain:
    def _run(self, ps, tmp_path, monkeypatch, changed_lines=None,
             changed_arg=True):
        out = tmp_path / "github_output.txt"
        out.write_text("", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        argv = ["--repo", str(tmp_path)]
        if changed_arg:
            cf = tmp_path / "changed_files.txt"
            if changed_lines is not None:
                cf.write_text("\n".join(changed_lines), encoding="utf-8")
            argv += ["--changed-files", str(cf)]
        rc = ps.main(argv)
        assert rc == 0
        return dict(
            line.split("=", 1)
            for line in out.read_text(encoding="utf-8").splitlines()
        )

    def test_emits_run_true_and_sorted_file_list(
        self, ps, tmp_path, monkeypatch
    ):
        _tree(tmp_path, [
            "core/x/tests/test_b.py",
            "core/x/tests/test_a.py",
        ])
        outputs = self._run(
            ps, tmp_path, monkeypatch,
            changed_lines=[
                "core/x/tests/test_b.py",
                "core/x/tests/test_a.py",
            ],
        )
        assert outputs["run"] == "true"
        assert outputs["test_files"] == (
            "core/x/tests/test_a.py core/x/tests/test_b.py"
        )

    def test_no_changed_tests_emits_run_false(
        self, ps, tmp_path, monkeypatch
    ):
        _tree(tmp_path, ["core/x/module.py"])
        outputs = self._run(
            ps, tmp_path, monkeypatch, changed_lines=["core/x/module.py"],
        )
        assert outputs["run"] == "false"
        assert outputs["test_files"] == ""

    def test_missing_list_file_emits_run_false(
        self, ps, tmp_path, monkeypatch
    ):
        outputs = self._run(
            ps, tmp_path, monkeypatch, changed_lines=None,
        )
        assert outputs["run"] == "false"

    def test_no_list_argument_emits_run_false(
        self, ps, tmp_path, monkeypatch
    ):
        outputs = self._run(
            ps, tmp_path, monkeypatch, changed_arg=False,
        )
        assert outputs["run"] == "false"


def test_git_scope_uses_complete_range_and_preserves_filenames(ps, tmp_path, monkeypatch):
    from core.testing.gitrepo import git_run, init_scratch_repo

    repo = init_scratch_repo(tmp_path)
    _tree(repo, ['core/x/tests/test_deleted.py'])
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'base')
    base = git_run(repo, 'rev-parse', 'HEAD')
    names = ['core/x/tests/test_with spaces.py', 'core/x/tests/test_with\nnewline.py']
    _tree(repo, names)
    (repo / 'core/x/tests/test_deleted.py').unlink()
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'tests in earlier commit')
    _tree(repo, ['docs/tip.md'])
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'unrelated tip')
    git_run(repo, 'update-ref', 'refs/remotes/origin/main', 'HEAD')
    output = tmp_path / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    calls = []
    monkeypatch.setattr(ps, 'run_tests', lambda files, root: calls.append((files, root)) or 2)
    assert ps.main(['--repo', str(repo), '--base', base, '--run']) == 2
    assert calls == [(sorted(names), repo)]
    assert output.read_text() == 'run=true\n'


@pytest.mark.parametrize('base', ['', 'unknown', '0' * 40])
def test_unknown_git_history_fails_without_running_or_publishing_skip(ps, tmp_path, monkeypatch, capsys, base):
    output = tmp_path / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    monkeypatch.setattr(ps, 'run_tests', lambda *_: pytest.fail('unknown history ran tests'))
    assert ps.main(['--base', base, '--repo', str(tmp_path), '--run']) == 2
    assert not output.exists()
    assert 'unknown history' in capsys.readouterr().err


@pytest.mark.parametrize('changed', [[], ['docs/only.md']])
def test_empty_git_selection_never_runs_the_whole_suite(ps, tmp_path, monkeypatch, changed):
    output = tmp_path / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    monkeypatch.setattr(ps, 'changed_paths', lambda *_: changed)
    monkeypatch.setattr(ps, 'run_tests', lambda *_: pytest.fail('empty selection invoked pytest'))
    assert ps.main(['--base', 'a' * 40, '--repo', str(tmp_path), '--run']) == 0
    assert output.read_text() == 'run=false\n'


def test_large_selection_stays_in_process_and_out_of_job_outputs(ps, tmp_path, monkeypatch):
    # Well beyond Linux's per-argument/environment-string limit and the API's
    # PR file-list cap, without thousands of incidental fixture filesystem writes.
    names = [f"core/tests/test_{i}_{'x' * 180}.py" for i in range(4000)]
    assert len(' '.join(names).encode()) > 128 * 1024
    monkeypatch.setattr(ps, 'changed_paths', lambda *_: names)
    monkeypatch.setattr(ps, 'changed_test_files', lambda changed, _: changed)
    observed = []
    monkeypatch.setattr(ps, 'run_tests', lambda files, root: observed.append(files) or 0)
    output = tmp_path / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    assert ps.main(['--base', 'a' * 40, '--repo', str(tmp_path), '--run']) == 0
    assert observed == [names]
    assert output.read_text() == 'run=true\n'


@pytest.mark.parametrize('failure', [False, True])
def test_pytest_api_restores_borrowed_path_and_cwd(ps, tmp_path, failure):
    from types import ModuleType

    borrowed_path = sys.path
    contents = list(sys.path)
    cwd = Path.cwd()
    fake_pytest = ModuleType('pytest')
    seen = []

    def main(files):
        assert sys.path[0] == str(tmp_path)
        assert Path.cwd() == tmp_path
        seen.append(files)
        if failure:
            raise RuntimeError('owned pytest failure')
        return 5

    fake_pytest.main = main
    with patch.dict(sys.modules, {'pytest': fake_pytest}):
        if failure:
            with pytest.raises(RuntimeError, match='owned pytest failure'):
                ps.run_tests(['test with\nnewline.py'], tmp_path)
        else:
            assert ps.run_tests(['test with\nnewline.py'], tmp_path) == 5
    assert seen == [['test with\nnewline.py']]
    assert sys.path is borrowed_path
    assert sys.path == contents
    assert Path.cwd() == cwd


def test_import_preserves_borrowed_path():
    borrowed_path = sys.path
    contents = list(sys.path)
    spec = importlib.util.spec_from_file_location('owned_preflight_import', _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert sys.path is borrowed_path
    assert sys.path == contents


@pytest.mark.parametrize('failing', [False, True])
def test_real_cli_runs_whitespace_paths_and_propagates_pytest_status(tmp_path, failing):
    import os
    import subprocess
    from core.testing.gitrepo import git_run, init_scratch_repo

    repo = init_scratch_repo(tmp_path)
    _tree(repo, ['README.md'])
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'base')
    base = git_run(repo, 'rev-parse', 'HEAD')
    names = ['core/x/tests/test_with spaces.py', 'core/x/tests/test_with\nnewline.py']
    for name in names:
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f'def test_selected():\n    assert {not failing!r}\n')
    (repo / 'pytest.ini').write_text('[pytest]\naddopts = -q --import-mode=importlib -p no:cacheprovider\n')
    git_run(repo, 'add', '.')
    git_run(repo, 'commit', '-qm', 'tests')
    home = tmp_path / 'home'
    home.mkdir()
    env = dict(os.environ, HOME=str(home), TMPDIR=str(tmp_path),
               XDG_CONFIG_HOME=str(home / 'config'), XDG_CACHE_HOME=str(home / 'cache'),
               XDG_DATA_HOME=str(home / 'data'), RAPTOR_REGISTRY_HOME=str(tmp_path / 'registry'),
               RAPTOR_OUT_DIR=str(tmp_path / 'out'), PYTHONDONTWRITEBYTECODE='1',
               PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTEST_PLUGINS='core.testing.llm_tripwire',
               PYTHONPATH=str(_SCRIPT.parents[2]), GITHUB_OUTPUT=str(tmp_path / 'output'))
    for name in ('PYTEST_ADDOPTS', 'PYTEST_XDIST_WORKER', 'PYTEST_XDIST_WORKER_COUNT',
                 'PYTEST_XDIST_TESTRUNUID', 'RAPTOR_TEST_LIVE_LLM', 'RAPTOR_RANDOMISE_TESTS',
                 'RAPTOR_EGRESS_LEAK_DIR', 'RAPTOR_MAX_TEST_SECONDS', 'RAPTOR_MAX_SESSION_SECONDS'):
        env.pop(name, None)
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), '--repo', str(repo), '--base', base, '--run'],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == int(failing), result.stdout + result.stderr
    assert ('2 failed' if failing else '2 passed') in result.stdout
    assert (tmp_path / 'output').read_text() == 'run=true\n'


def test_workflow_uses_local_git_ranges_and_retains_all_simulations():
    import yaml

    path = _SCRIPT.parents[1] / 'workflows/preflight.yml'
    workflow = yaml.safe_load(path.read_text())
    jobs = workflow['jobs']
    assert jobs['changes']['outputs'] == {'run': '${{ steps.scope.outputs.run }}'}
    for name in ('changes', 'preflight'):
        checkout = next(step for step in jobs[name]['steps']
                        if step.get('uses', '').startswith('actions/checkout@'))
        assert checkout['with']['fetch-depth'] == 2
    scope = next(step for step in jobs['changes']['steps'] if step.get('id') == 'scope')
    run = next(step for step in jobs['preflight']['steps']
               if step.get('name') == 'Run changed tests under simulation')
    for step in (scope, run):
        assert step['env']['BASE_SHA'] == '${{ github.event.pull_request.base.sha }}'
        assert '--base "$BASE_SHA" --repo .' in step['run']
    assert '--run' in run['run']
    assert 'TEST_FILES' not in run['env']
    assert 'gh api --paginate' not in '\n'.join(step.get('run', '') for step in jobs['changes']['steps'])
    assert {row['sim'] for row in jobs['preflight']['strategy']['matrix']['include']} == {
        'hidden-optional-deps', 'hidden-tree-sitter', 'duration-guard',
        'tree-hygiene', 'shuffle-a', 'shuffle-b',
    }
    assert jobs['preflight-passed']['if'] == 'always()'
    assert jobs['preflight-passed']['needs'] == ['changes', 'preflight']
