"""Recover allocation failures without retrying tests or executing source-run code."""
from copy import deepcopy
import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('macos_allocation_recovery', ROOT / '.github/scripts/retry_macos_allocation.py')
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


class API:
    repository = 'owner/raptor'

    def __init__(self):
        self.run = dict(id=100, workflow_id=10, path='.github/workflows/tests.yml',
                        repository={'full_name': self.repository},
                        head_repository={'id': 20, 'owner': {'login': 'contributor'}},
                        head_sha='a' * 40, head_branch='feature/topic', event='pull_request',
                        status='completed', conclusion='failure', run_attempt=1)
        self.recent = [deepcopy(self.run)]
        self.pulls = [dict(state='open', head={'sha': self.run['head_sha'], 'repo': {'id': 20}},
                           base={'repo': {'full_name': self.repository}})]
        self.refs = [dict(ref='refs/heads/' + self.run['head_branch'], object={'sha': self.run['head_sha']})]
        self.jobs = [dict(id=200, run_id=100, run_attempt=1, name='python-unit-tests-sandbox-macos',
                         labels=['macos-latest'], status='completed', conclusion='cancelled',
                         steps=[], runner_id=0, runner_name='',
                         check_run_url='https://api.github.com/repos/owner/raptor/check-runs/300')]
        self.annotations = [dict(annotation_level='notice', message='macOS arm64 capacity constraints'),
                            dict(annotation_level='failure', message=recovery.ALLOCATION_FAILURE)]
        self.calls = []
        self.before_final_read = lambda: None
        self.run_reads = 0

    @property
    def posts(self):
        return [path for method, path in self.calls if method == 'POST']

    def request(self, path, *, method='GET'):
        self.calls.append((method, path))
        if method == 'POST':
            assert path == 'actions/jobs/200/rerun'
            return None
        if path == 'actions/runs/100':
            self.run_reads += 1
            if self.run_reads == 2:
                self.before_final_read()
            return deepcopy(self.run)
        if path.startswith('actions/workflows/10/runs?'):
            query = parse_qs(urlsplit(path).query)
            assert query == dict(branch=[self.run['head_branch']], event=[self.run['event']], per_page=['100'])
            return {'workflow_runs': deepcopy(self.recent)}
        if path.startswith('pulls?'):
            query = parse_qs(urlsplit(path).query)
            assert query['state'] == ['open']
            assert query['head'] == ['contributor:' + self.run['head_branch']]
            return deepcopy(self.pulls)
        if path.startswith('git/matching-refs/heads/'):
            return deepcopy(self.refs)
        raise AssertionError('Unexpected API read: ' + path)

    def rows(self, path, key=None):
        self.calls.append(('GET', path))
        if path == 'actions/runs/100/attempts/1/jobs?per_page=100':
            assert key == 'jobs'
            return deepcopy(self.jobs)
        if path == 'check-runs/300/annotations?per_page=100':
            assert key is None
            return deepcopy(self.annotations)
        raise AssertionError('Unexpected paginated read: ' + path)


@pytest.fixture
def api():
    return API()


def decide(api):
    return recovery.recover(api, deepcopy(api.run), apply=True)


@pytest.mark.parametrize('workflow', recovery.MACOS_JOBS)
def test_confirmed_allocation_failure_requeues_only_expected_job(api, workflow):
    api.run['path'] = workflow
    api.jobs[0]['name'] = recovery.MACOS_JOBS[workflow]
    # A separate failed Linux job remains untouched, as do successful jobs.
    api.jobs += [dict(api.jobs[0], id=201, labels=['ubuntu-latest'], name='linux', steps=[{'name': 'tests'}]),
                 dict(api.jobs[0], id=202, conclusion='success')]
    result = decide(api)
    assert result['retried'] is True
    assert result['job_id'] == 200
    assert api.posts == ['actions/jobs/200/rerun']
    assert all('/rerun-failed-jobs' not in path for _, path in api.calls)


@pytest.mark.parametrize(('key', 'value'), [
    ('run_attempt', 2), ('run_attempt', True), ('status', 'in_progress'),
    ('conclusion', 'success'), ('conclusion', 'cancelled'),
    ('path', '.github/workflows/unknown.yml'), ('repository', {'full_name': 'other/repo'}),
    ('repository', None), ('head_repository', None), ('event', 'workflow_run'),
    ('id', '../jobs/200/rerun'), ('workflow_id', False), ('head_sha', 'not-a-sha'),
    ('head_branch', ''),
])
def test_ineligible_sources_do_not_even_read_the_api(api, key, value):
    api.run[key] = value
    assert decide(api)['retried'] is False
    assert api.calls == []


@pytest.mark.parametrize(('key', 'value'), [
    ('run_attempt', 2), ('run_attempt', True), ('run_id', 999), ('id', '200'),
    ('name', 'another-macos-job'), ('labels', ['ubuntu-latest']),
    ('runner_name', 'GitHub Actions 123'), ('runner_id', 123),
    ('status', 'queued'), ('conclusion', 'skipped'),
    ('steps', [{'name': 'Set up job', 'conclusion': 'failure'}]),
    ('steps', [{'name': 'tests', 'conclusion': 'timed_out'}]),
])
def test_executed_or_unexpected_jobs_cannot_be_retried(api, key, value):
    api.jobs[0][key] = value
    assert decide(api)['retried'] is False
    assert not api.posts


@pytest.mark.parametrize('missing', ['steps', 'runner_id', 'runner_name', 'run_attempt'])
def test_missing_allocation_evidence_is_not_assumed(api, missing):
    del api.jobs[0][missing]
    assert decide(api)['retried'] is False
    assert not api.posts


@pytest.mark.parametrize('annotations', [
    [], [{'annotation_level': 'notice', 'message': recovery.ALLOCATION_FAILURE}],
    [{'annotation_level': 'failure', 'message': 'The operation was canceled.'}],
    [{'annotation_level': 'failure', 'message': 'Due to capacity constraints, jobs may queue.'}],
])
def test_cancellation_or_capacity_notice_alone_is_not_enough(api, annotations):
    api.annotations = annotations
    assert decide(api)['reason'] == 'no confirmed runner allocation failure'
    assert not api.posts


def test_ambiguous_duplicate_jobs_are_not_retried(api):
    api.jobs.append(dict(api.jobs[0], id=201))
    assert decide(api)['retried'] is False
    assert not api.posts


@pytest.mark.parametrize('change', ['newer-run', 'missing-run', 'closed-pr', 'updated-pr', 'different-head-repo'])
def test_stale_pull_request_work_is_not_revived(api, change):
    if change == 'newer-run':
        api.recent.append(dict(api.run, id=101))
    elif change == 'missing-run':
        api.recent = []
    elif change == 'closed-pr':
        api.pulls = []
    elif change == 'updated-pr':
        api.pulls[0]['head']['sha'] = 'b' * 40
    else:
        api.pulls[0]['head']['repo']['id'] = 21
    assert decide(api)['reason'] == 'source run is stale'
    assert not api.posts


def test_unrelated_fork_with_same_branch_does_not_supersede_run(api):
    api.recent.append(dict(api.run, id=101, head_repository={'id': 21}))
    assert decide(api)['retried'] is True


@pytest.mark.parametrize('event', ['push', 'merge_group'])
@pytest.mark.parametrize('ref_state', ['current', 'advanced', 'deleted', 'prefix-collision'])
def test_branch_and_queue_refs_must_still_identify_the_tested_commit(api, event, ref_state):
    api.run['event'] = event
    api.recent = [deepcopy(api.run)]
    if ref_state == 'advanced':
        api.refs[0]['object']['sha'] = 'b' * 40
    elif ref_state == 'deleted':
        api.refs = []
    elif ref_state == 'prefix-collision':
        api.refs[0]['ref'] += '-other'
    assert decide(api)['retried'] is (ref_state == 'current')
    assert bool(api.posts) is (ref_state == 'current')


@pytest.mark.parametrize('event', ['schedule', 'workflow_dispatch'])
def test_scheduled_and_manual_snapshots_remain_useful_until_superseded(api, event):
    api.run['event'] = event
    api.recent = [deepcopy(api.run)]
    api.refs = []
    api.pulls = []
    assert decide(api)['retried'] is True


@pytest.mark.parametrize('race', ['manual-retry', 'newer-run', 'pr-update', 'metadata-change'])
def test_recheck_before_write_refuses_races(api, race):
    def mutate():
        if race == 'manual-retry':
            api.run['run_attempt'] = 2
        elif race == 'newer-run':
            api.recent.append(dict(api.run, id=101))
        elif race == 'pr-update':
            api.pulls[0]['head']['sha'] = 'b' * 40
        else:
            api.run['updated_at'] = 'changed'

    api.before_final_read = mutate
    assert decide(api)['retried'] is False
    assert not api.posts


def test_old_event_cannot_retry_a_run_that_someone_already_retried(api):
    event = deepcopy(api.run)
    api.run['run_attempt'] = 2
    assert recovery.recover(api, event)['retried'] is False
    assert not api.posts


def test_api_failure_before_write_cannot_requeue_work(api, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('owned API outage')

    monkeypatch.setattr(api, 'rows', fail)
    with pytest.raises(RuntimeError, match='owned API outage'):
        decide(api)
    assert not api.posts


def test_gh_uses_argument_vector_bounded_timeout_and_all_pages(monkeypatch):
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout=json.dumps([{'jobs': [{'id': 1}]}, {'jobs': [{'id': 2}]}]))

    monkeypatch.setattr(recovery, 'subprocess', SimpleNamespace(run=execute))
    client = recovery.GitHub('owner/raptor')
    assert client.rows('actions/runs/100/attempts/1/jobs?per_page=100', 'jobs') == [{'id': 1}, {'id': 2}]
    command, options = calls[0]
    assert command == ['gh', 'api', '--method', 'GET',
                       'repos/owner/raptor/actions/runs/100/attempts/1/jobs?per_page=100', '--paginate', '--slurp']
    assert options == dict(check=True, capture_output=True, text=True, timeout=45)
    assert client.request('check-runs/200/annotations?per_page=100', paginate=True) == [
        {'jobs': [{'id': 1}]}, {'jobs': [{'id': 2}]}]


def test_request_failure_is_not_swallowed(monkeypatch):
    def fail(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(recovery, 'subprocess', SimpleNamespace(run=fail))
    with pytest.raises(subprocess.CalledProcessError):
        recovery.GitHub('owner/raptor').request('actions/runs/100')


def test_cli_writes_auditable_summary_without_mutating_existing_content(api, monkeypatch, tmp_path):
    source = tmp_path / 'event.json'
    source.write_text(json.dumps({'workflow_run': api.run}))
    summary = tmp_path / 'summary.md'
    summary.write_text('Earlier summary\n')
    monkeypatch.setenv('GITHUB_EVENT_PATH', str(source))
    monkeypatch.setenv('GITHUB_REPOSITORY', api.repository)
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary))
    monkeypatch.setattr(recovery, 'GitHub', lambda _: api)
    assert recovery.main(['--apply']) == 0
    assert summary.read_text().startswith('Earlier summary\n')
    assert '"job_id": 200' in summary.read_text()
    assert api.posts == ['actions/jobs/200/rerun']


def test_recovery_workflow_matches_sources_and_only_loads_trusted_code():
    workflow = (ROOT / '.github/workflows/macos-runner-recovery.yml').read_text()
    names = ast.literal_eval(re.search(r'(?m)^    workflows: (\[[^\n]+\])$', workflow)[1])
    expected = []
    for source in recovery.MACOS_JOBS:
        text = (ROOT / source).read_text()
        expected.append(re.search(r'(?m)^name: (.+)$', text)[1].strip('"\''))
    assert set(names) == set(expected)
    assert 'types: [completed]' in workflow
    assert 'github.event.workflow_run.run_attempt == 1' in workflow
    assert "github.event.workflow_run.conclusion == 'failure'" in workflow
    assert "github.event.workflow_run.conclusion == 'timed_out'" in workflow
    assert 'permissions: {}' in workflow
    assert 'runs-on: ubuntu-latest' in workflow
    assert 'ref: ${{ github.sha }}' in workflow
    assert 'persist-credentials: false' in workflow
    assert 'uses: actions/cache' not in workflow
    assert 'uses: actions/download-artifact' not in workflow
    assert 'ref: ${{ github.event.workflow_run.head_sha }}' not in workflow
    assert workflow.count('        run:') == 1
    assert '          python3 .github/scripts/retry_macos_allocation.py --apply' in workflow


def test_inspection_is_read_only_by_default(api):
    result = recovery.recover(api, deepcopy(api.run))
    assert result['retried'] is False
    assert result['would_retry'] is True
    assert not api.posts


@pytest.mark.parametrize('url', [
    '', 'https://other.example/repos/owner/raptor/check-runs/300',
    'https://api.github.com/repos/another/repository/check-runs/300',
    'https://api.github.com/repos/owner/raptor/actions/jobs/200/rerun',
])
def test_check_evidence_must_belong_to_this_repository(api, url):
    api.jobs[0]['check_run_url'] = url
    assert decide(api)['retried'] is False
    assert not api.posts


def test_deleted_unrelated_fork_metadata_does_not_break_freshness_check(api):
    api.recent.append(dict(api.run, id=101, head_repository=None))
    assert decide(api)['retried'] is True
