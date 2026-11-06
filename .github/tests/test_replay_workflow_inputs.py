"""Replay jobs keep their coverage while absent private cases stay lightweight."""
from pathlib import Path
import os
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def workflow():
    return (ROOT / '.github/workflows/replay-determinism.yml').read_text()


def job(workflow, name):
    jobs = workflow.split('\njobs:\n', 1)[1]
    match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:|\Z)',
                      jobs, re.M | re.S)
    assert match is not None, f'missing literal job: {name}'
    return match[1]


def workflow_steps(workflow, name):
    # Read only this workflow's flat literal steps, matching the existing CI
    # checks. The ci-lint runner installs pytest alone, not a YAML library.
    result = []
    for body in re.split(r'^      - ', job(workflow, name), flags=re.M)[1:]:
        first = body.splitlines()[0]
        assert first.startswith('name: '), 'expected a named literal step'
        fields = {'name': first.removeprefix('name: ')}
        for key in ('id', 'if'):
            match = re.search(r'^        ' + key + r': (.+)$', body, re.M)
            if match:
                fields[key] = match[1]
        run = re.search(r'^        run: ([|>])\n((?:          .*\n|\n)+)', body, re.M)
        if run:
            script = textwrap.dedent(run[2]).rstrip() + '\n'
            fields['run'] = (script if run[1] == '|'
                             else ' '.join(line.strip() for line in script.splitlines()))
        else:
            run = re.search(r'^        run: (.+)$', body, re.M)
            if run:
                fields['run'] = run[1]
        result.append(fields)
    return result


def step(workflow, name):
    matches = [item for item in workflow_steps(workflow, 'replay-eval-private')
               if item['name'] == name]
    assert len(matches) == 1, f'expected one step: {name}'
    return matches[0]


def event(workflow, name):
    events = workflow.split('\non:\n', 1)[1].split('\nconcurrency:', 1)[0]
    match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:|\Z)',
                      events, re.M | re.S)
    assert match is not None, f'missing literal event: {name}'
    return match[1]


def test_pr_and_push_include_execution_and_gate_inputs(workflow):
    paths = re.findall(r"^      - '([^']+)'$", event(workflow, 'pull_request'), re.M)
    assert paths
    assert paths == re.findall(r"^      - '([^']+)'$", event(workflow, 'push'), re.M)
    assert len(paths) == len(set(paths))
    assert {
        'pyproject.toml', 'uv.lock', 'uv.toml', '.python-version', 'pytest.ini',
        'conftest.py', 'core/__init__.py', 'packages/__init__.py',
        'core/testing/__init__.py', 'core/testing/param_ids.py',
        'core/testing/git_hermeticity.py', 'core/testing/llm_env.py',
        'core/testing/state_isolation.py', 'core/testing/module_state.py',
        '.github/scripts/runtime_universe.py', '.github/scripts/check_skip_budget.py',
        '.github/scripts/skip_budget_baseline.json',
    } <= set(paths)
    assert re.findall(r"^    - cron: '([^']+)'$", event(workflow, 'schedule'), re.M) == ['50 5 * * *']
    assert re.search(r'^  workflow_dispatch:$', workflow, re.M)


def test_confirmed_absence_is_the_only_lightweight_install_arm(workflow):
    private = job(workflow, 'replay-eval-private')
    steps = workflow_steps(workflow, 'replay-eval-private')
    discover = step(workflow, 'Discover local replay cases')
    assert discover['id'] == 'cases'
    assert 'if' not in discover
    minimal = step(workflow, 'Install pytest for the absent-case check')
    assert minimal['if'] == "steps.cases.outputs.present == 'false'"
    assert 'python -m pip install --disable-pip-version-check' in minimal['run']
    assert "grep -oE 'pytest==[0-9.]+' pyproject.toml" in minimal['run']
    assert len(re.findall(r'pytest==[0-9.]+', (ROOT / 'pyproject.toml').read_text())) == 1
    for name in ('Install uv', 'Install deps'):
        full = step(workflow, name)
        assert full['if'] == "steps.cases.outputs.present != 'false'"
        assert steps.index(discover) < steps.index(full)
    assert not re.search(r'^    if:', private, re.M)


def test_real_private_collection_and_skip_budget_remain_unconditional(workflow):
    run = step(workflow, 'Run private-case replay-eval lane')
    budget = step(workflow, "Check skip count against the lane's recorded budget")
    assert 'if' not in run and 'if' not in budget
    assert '.github/evals/test_replay_eval_lane.py' in run['run']
    assert '--junitxml="$RUNNER_TEMP/replay-eval.xml"' in run['run']
    assert '--lane replay-eval --full' in budget['run']
    assert '--junit-xml "$RUNNER_TEMP/replay-eval.xml"' in budget['run']
    public = workflow_steps(workflow, 'replay-determinism')
    install = next(item for item in public if item.get('name') == 'Install deps')
    assert 'if' not in install
    assert 'uv export --locked --no-hashes' in install['run']


def discovery_code(workflow):
    lines = step(workflow, 'Discover local replay cases')['run'].splitlines()
    assert lines[0] == "python3 - <<'PY'" and lines[-1] == 'PY'
    return '\n'.join(lines[1:-1])


def run_discovery(workflow, tmp_path, helper):
    repo = tmp_path / 'repo'
    destination = repo / '.github/evals/replay_eval.py'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(helper)
    output = tmp_path / 'github-output'
    env = dict(os.environ, GITHUB_OUTPUT=str(output), PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None)
    code = discovery_code(workflow) + "\nassert 'packages.llm_analysis.agent' not in sys.modules\nassert 'core.llm.client' not in sys.modules\n"
    result = subprocess.run([sys.executable, '-I', '-c', code], cwd=repo, env=env,
                            capture_output=True, text=True, timeout=10)
    return result, output


@pytest.mark.parametrize('paths,present', [
    ([], False),
    (['core/audit/corpus/replay-cases/'], False),
    (['core/audit/corpus/replay-cases/one/notes.txt'], False),
    (['core/audit/corpus/replay-cases/one/llm-transcript.jsonl'], True),
    (['core/audit/corpus/replay-cases/group/one/llm-transcript.jsonl'], True),
    (['core/audit/corpus/replay-cases/one/llm-transcript.jsonl/'], False),
    (['unrelated/llm-transcript.jsonl'], False),
])
def test_native_discovery_reuses_the_lane_case_contract(workflow, tmp_path, paths, present):
    for name in paths:
        path = tmp_path / 'repo' / name
        if name.endswith('/'):
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Even an invalid transcript must request full deps, never be
            # mistaken for absence and hidden behind the expected skip.
            path.write_text('invalid transcript fixture')
    result, output = run_discovery(workflow, tmp_path,
                                   (ROOT / '.github/evals/replay_eval.py').read_text())
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_text() == f'present={str(present).lower()}\n'


def test_discovery_failure_cannot_publish_an_absent_corpus(workflow, tmp_path):
    result, output = run_discovery(workflow, tmp_path,
                                   "def discover_cases():\n    raise OSError('owned discovery failure')\n")
    assert result.returncode != 0
    assert 'owned discovery failure' in result.stderr
    assert not output.exists()
