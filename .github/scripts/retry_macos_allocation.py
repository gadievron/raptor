#!/usr/bin/env python3
"""Retry an unallocated macOS job once; never retry executed test failures."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote, urlencode

# These are workflow paths and job names, not labels supplied by a PR artifact.
MACOS_JOBS = {
    '.github/workflows/tests.yml': 'python-unit-tests-sandbox-macos',
    '.github/workflows/sandbox-wrappers.yml': 'wrappers-macos-latest',
    '.github/workflows/nightly.yml': 'intentional-crashes (macos-latest)',
    '.github/workflows/codeql.yml': 'Analyze (swift)',
}
ALLOCATION_FAILURE = 'The job was not acquired by Runner of type hosted even after multiple attempts'


class GitHub:
    """Use the runner's gh authentication without executing code from the source run."""

    def __init__(self, repository: str):
        if not re.fullmatch(r'[\w.-]+/[\w.-]+', repository):
            raise ValueError('invalid repository')
        self.repository = repository
        self.prefix = f'repos/{repository}/'

    def request(self, path: str, *, method: str = 'GET', paginate: bool = False):
        command = ['gh', 'api', '--method', method, self.prefix + path]
        if paginate:
            command += ['--paginate', '--slurp']
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=45)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def rows(self, path: str, key: str | None = None) -> list:
        pages = self.request(path, paginate=True)
        return [row for page in pages for row in (page[key] if key else page)]


def eligible_run(run: dict, repository: str) -> bool:
    if not isinstance(run.get('head_repository'), dict) or not isinstance(run.get('repository'), dict):
        return False
    return (
        run['repository'].get('full_name') == repository
        and run.get('path') in MACOS_JOBS
        and run.get('status') == 'completed'
        and run.get('conclusion') in ('failure', 'timed_out')
        and type(run.get('run_attempt')) is int and run['run_attempt'] == 1
        and type(run.get('id')) is int and run['id'] > 0
        and type(run.get('workflow_id')) is int and run['workflow_id'] > 0
        and run.get('event') in ('push', 'pull_request', 'merge_group', 'schedule', 'workflow_dispatch')
        and isinstance(run.get('head_branch'), str) and bool(run['head_branch'])
        and isinstance(run.get('head_sha'), str)
        and re.fullmatch(r'[0-9a-f]{40}', run['head_sha']) is not None
        and type(run.get('head_repository', {}).get('id')) is int
    )


def unallocated_job(job: dict, run: dict) -> bool:
    return (
        job.get('run_id') == run['id']
        and type(job.get('run_attempt')) is int and job['run_attempt'] == 1
        and type(job.get('id')) is int and job['id'] > 0
        and job.get('name') == MACOS_JOBS[run['path']]
        and job.get('labels') == ['macos-latest']
        and job.get('status') == 'completed'
        and job.get('conclusion') in ('failure', 'cancelled', 'timed_out')
        and job.get('steps') == []
        and job.get('runner_name') == ''
        and job.get('runner_id') == 0
    )


def still_current(api: GitHub, run: dict) -> bool:
    """Refuse superseded runs, closed/updated PRs, and deleted queue refs."""
    query = urlencode(dict(branch=run['head_branch'], event=run['event'], per_page=100))
    recent = api.request(f"actions/workflows/{run['workflow_id']}/runs?{query}")['workflow_runs']
    related = [row for row in recent if (row.get('head_repository') or {}).get('id') == run['head_repository']['id']
               and row.get('head_branch') == run['head_branch'] and row.get('event') == run['event']]
    if not any(row.get('id') == run['id'] for row in related):
        return False  # An old run outside this bounded window is not worth reviving.
    if any(row['id'] > run['id'] for row in related):
        return False
    if run['event'] == 'pull_request':
        owner = run['head_repository']['owner']['login']
        query = urlencode(dict(state='open', head=f"{owner}:{run['head_branch']}", per_page=100))
        pulls = api.request('pulls?' + query)
        return any(pr.get('state') == 'open'
                   and pr.get('head', {}).get('sha') == run['head_sha']
                   and (pr.get('head', {}).get('repo') or {}).get('id') == run['head_repository']['id']
                   and (pr.get('base', {}).get('repo') or {}).get('full_name') == api.repository
                   for pr in pulls)
    if run['event'] in ('push', 'merge_group'):
        refs = api.request('git/matching-refs/heads/' + quote(run['head_branch'], safe=''))
        return any(ref['ref'] == 'refs/heads/' + run['head_branch']
                   and ref['object']['sha'] == run['head_sha'] for ref in refs)
    return True  # Scheduled/manual snapshots remain useful until superseded.


def recover(api: GitHub, event_run: dict, *, apply: bool = False) -> dict:
    """Return an auditable decision; all writes target one validated job ID."""
    skipped = {'retried': False}
    if not eligible_run(event_run, api.repository):
        return dict(skipped, reason='source run is ineligible')
    run = api.request(f"actions/runs/{event_run['id']}")
    if (not eligible_run(run, api.repository)
            or any(run.get(key) != event_run.get(key) for key in ('id', 'path', 'workflow_id', 'head_sha', 'event'))):
        return dict(skipped, reason='source run changed or has already been retried')
    if not still_current(api, run):
        return dict(skipped, reason='source run is stale')
    jobs = api.rows(f"actions/runs/{run['id']}/attempts/1/jobs?per_page=100", 'jobs')
    candidates = [job for job in jobs if unallocated_job(job, run)]
    if len(candidates) != 1:
        return dict(skipped, reason='no unique unallocated macOS job')
    job = candidates[0]
    check = re.fullmatch(r'https://api\.github\.com/repos/' + re.escape(api.repository)
                         + r'/check-runs/([1-9][0-9]*)', job.get('check_run_url', ''))
    if check is None:
        return dict(skipped, reason='no repository-owned check run for allocation evidence')
    annotations = api.rows(f'check-runs/{check[1]}/annotations?per_page=100')
    if not any(row.get('annotation_level') == 'failure' and row.get('message') == ALLOCATION_FAILURE
               for row in annotations):
        return dict(skipped, reason='no confirmed runner allocation failure')
    # Recheck after reading evidence: a manual rerun or newer commit may have arrived.
    latest = api.request(f"actions/runs/{run['id']}")
    if latest != run or not still_current(api, run):
        return dict(skipped, reason='source run changed during inspection')
    if apply:
        api.request(f"actions/jobs/{job['id']}/rerun", method='POST')
    return dict(retried=apply, would_retry=True, run_id=run['id'], job_id=job['id'], job=job['name'],
                reason='confirmed allocation failure; one job and its dependents'
                + (' requeued' if apply else ' would be requeued'))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='requeue the validated job; default is inspection only')
    args = parser.parse_args(argv)
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    decision = recover(GitHub(os.environ['GITHUB_REPOSITORY']), event.get('workflow_run', {}), apply=args.apply)
    text = json.dumps(decision, indent=2) + '\n'
    print(text)
    with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as summary:
        summary.write('### macOS runner recovery\n\n```json\n' + text + '```\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
