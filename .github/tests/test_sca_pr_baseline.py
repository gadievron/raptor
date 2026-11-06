"""The SCA PR gate compares the tested merge with its immutable base tree."""
from pathlib import Path
import json
import os
import subprocess
import sys

import pytest
import yaml

from core.testing.gitrepo import git_run, init_scratch_repo

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/sca-pr-gate.yml'


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def baseline_step():
    steps = workflow()['jobs']['diff']['steps']
    return next(step for step in steps if step['name'] == 'Scan PR base tree')


def scanner(label):
    return f'''#!{sys.executable}
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
pathlib.Path(os.environ['SCAN_RECORD']).write_text(json.dumps({{
    'scanner': {label!r}, 'content': (root / 'package.json').read_text(),
    'args': sys.argv[1:], 'tree': str(root),
}}))
raise SystemExit(int(os.environ['SCAN_EXIT']))
'''


def write(repo, name, content):
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


@pytest.fixture(scope='module')
def history_cache():
    # Shuffle may interleave parameter groups. Keep both immutable fixture
    # histories instead of rebuilding one whenever pytest switches groups.
    return {}


@pytest.fixture(params=['main', 'release/v1'])
def history(tmp_path_factory, request, history_cache):
    if request.param in history_cache:
        return history_cache[request.param]
    source = init_scratch_repo(tmp_path_factory.mktemp('sca-history'))
    write(source, 'package.json', 'old')
    tool = write(source, 'bin/raptor-sca', scanner('base-tool'))
    tool.chmod(0o755)
    git_run(source, 'add', '.')
    git_run(source, 'commit', '-qm', 'initial')
    write(source, 'package.json', 'base')
    git_run(source, 'add', '.')
    git_run(source, 'commit', '-qm', 'base')
    base = git_run(source, 'rev-parse', 'HEAD')
    if request.param != 'main':
        git_run(source, 'checkout', '-qb', request.param)
    git_run(source, 'checkout', '-qb', 'feature')
    write(source, 'package.json', 'PR')
    write(source, 'bin/raptor-sca', scanner('merge-tool'))
    git_run(source, 'add', '.')
    git_run(source, 'commit', '-qm', 'feature')
    git_run(source, 'checkout', '-q', request.param)
    git_run(source, 'merge', '--no-ff', '-qm', 'merge', 'feature')
    merge = git_run(source, 'rev-parse', 'HEAD')
    git_run(source, 'branch', 'tested-merge')
    git_run(source, 'checkout', '-q', 'main')
    write(source, 'package.json', 'newer-main')
    git_run(source, 'add', '.')
    git_run(source, 'commit', '-qm', 'main advances')
    history_cache[request.param] = source, base, merge
    return history_cache[request.param]


def checkout(history, tmp_path, *, depth=2, branch='tested-merge'):
    source, _, _ = history
    repo = tmp_path / 'checkout'
    git_run(source, 'clone', '--quiet', '--depth', str(depth), '--branch', branch,
            source.as_uri(), str(repo))
    return repo


def run_baseline(repo, tmp_path, *, status=0):
    runner_temp = tmp_path / 'runner temp with spaces'
    runner_temp.mkdir()
    record = tmp_path / 'scan.json'
    env = dict(os.environ, RUNNER_TEMP=str(runner_temp), SCAN_RECORD=str(record),
               SCAN_EXIT=str(status), HOME=str(tmp_path),
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null')
    for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR'):
        env.pop(name, None)
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c',
         baseline_step()['run']], cwd=repo, env=env, capture_output=True,
        text=True, timeout=10,
    )
    assert list(runner_temp.iterdir()) == [], result.stderr
    return result, record


@pytest.mark.parametrize('status', [0, 2, 130])
def test_shallow_merge_uses_exact_base_and_cleans_worktree(history, tmp_path, status):
    repo = checkout(history, tmp_path)
    _, base, merge = history
    assert git_run(repo, 'rev-list', '--count', 'HEAD') == '3'
    # Make the moving main ref available too: selecting it must still be wrong.
    git_run(repo, 'fetch', '--quiet', '--depth=1', 'origin',
            'main:refs/remotes/origin/main')
    before = git_run(repo, 'worktree', 'list', '--porcelain')
    refs = git_run(repo, 'show-ref')
    result, record = run_baseline(repo, tmp_path, status=status)
    assert result.returncode == status, result.stdout + result.stderr
    observed = json.loads(record.read_text())
    assert observed['content'] == 'base'
    assert observed['scanner'] == 'merge-tool'  # Both scans use the PR's tool.
    assert observed['args'][1:] == ['--out', '/tmp/sca-base', '--no-image-scanning']
    assert not Path(observed['tree']).exists()
    assert git_run(repo, 'rev-parse', 'HEAD') == merge
    assert git_run(repo, 'rev-parse', 'HEAD^1') == base
    assert git_run(repo, 'show-ref') == refs
    assert git_run(repo, 'worktree', 'list', '--porcelain') == before
    assert (repo / 'package.json').read_text() == 'PR'


@pytest.mark.parametrize('depth,branch', [(1, 'tested-merge'), (2, 'feature')])
def test_missing_merge_parents_refuse_before_scanning(history, tmp_path, depth, branch):
    repo = checkout(history, tmp_path, depth=depth, branch=branch)
    before = git_run(repo, 'worktree', 'list', '--porcelain')
    result, record = run_baseline(repo, tmp_path)
    assert result.returncode != 0
    assert not record.exists()
    assert git_run(repo, 'worktree', 'list', '--porcelain') == before


def test_workflow_keeps_merge_checkout_and_shallow_history():
    steps = workflow()['jobs']['diff']['steps']
    checkout_step = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
    assert checkout_step['with']['fetch-depth'] == 2
    assert 'ref' not in checkout_step['with']
    assert checkout_step['with']['persist-credentials'] is False
    step = baseline_step()
    assert step['shell'] == 'bash'
    assert 'git fetch' not in step['run']
    assert step['run'].index('trap cleanup_baseline EXIT') < step['run'].index('git worktree add')


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('failure', ['', 'list', 'post'])
def test_comment_file_handoff_preserves_body_and_nonfatal_failures(tmp_path, existing, failure):
    # Exceeds Linux's single-argument limit; no live GitHub request is made.
    report = ('finding with spaces and unicode \u03bb\n' * 6000) + 'last line\n'
    diff = write(tmp_path, 'sca-diff.md', report)
    runner_temp = tmp_path / 'runner temp'
    runner_temp.mkdir()
    output = write(tmp_path, 'github-output', '')
    calls = tmp_path / 'gh-calls.jsonl'
    gh = write(tmp_path, 'tools/gh', f'''#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
assert max(map(len, args)) < 4096, 'report must not travel through argv'
with pathlib.Path(os.environ['GH_CALLS']).open('a') as stream:
    stream.write(json.dumps(args) + '\\n')
if '--paginate' in args:
    if os.environ['GH_FAILURE'] == 'list':
        raise SystemExit(1)
    if os.environ['GH_EXISTING'] == '1':
        print('123')
else:
    if '-F' in args:
        field = args[args.index('-F') + 1]
        assert field.startswith('body=@')
        path = field.removeprefix('body=@')
    else:
        assert '--body-file' in args
        path = args[args.index('--body-file') + 1]
    expected = '<!-- raptor-sca-pr-gate -->\\n\\n' + pathlib.Path(os.environ['GH_REPORT']).read_text()
    assert pathlib.Path(path).read_text() == expected
    pathlib.Path(os.environ['GH_BODY_CHECKED']).touch()
    if os.environ['GH_FAILURE'] == 'post':
        raise SystemExit(1)
''')
    gh.chmod(0o755)
    body_checked = tmp_path / 'body-checked'
    step = next(step for step in workflow()['jobs']['diff']['steps']
                if step['name'] == 'Post PR comment')
    assert step['continue-on-error'] is True
    # Relocate only the fixed report fixture; execute the actual shell block.
    script = step['run'].replace('/tmp/sca-diff.md', '"$GH_REPORT"')
    env = dict(os.environ, PATH=str(gh.parent) + os.pathsep + os.environ['PATH'],
               RUNNER_TEMP=str(runner_temp), GITHUB_OUTPUT=str(output),
               REPO='fixture/owned', PR='42', GH_CALLS=str(calls),
               GH_FAILURE=failure, GH_EXISTING=str(int(existing)),
               GH_REPORT=str(diff), GH_BODY_CHECKED=str(body_checked))
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_text() == f"posted={str(not failure).lower()}\n"
    assert body_checked.exists() == (failure != 'list')
    assert list(runner_temp.iterdir()) == []
    invocations = [json.loads(line) for line in calls.read_text().splitlines()]
    assert len(invocations) == (1 if failure == 'list' else 2)
    assert '--paginate' in invocations[0] and '--slurp' in invocations[0]
    assert 'github-actions[bot]' in invocations[0][-1]
    if failure != 'list':
        if existing:
            assert invocations[1][:3] == ['api', '-X', 'PATCH']
            assert invocations[1][3] == '/repos/fixture/owned/issues/comments/123'
        else:
            assert invocations[1][:3] == ['pr', 'comment', '42']
