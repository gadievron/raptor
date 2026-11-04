import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

import pytest


@pytest.fixture(params=['tests.yml', 'preflight.yml', 'sandbox-wrappers.yml'])
def gate_script(request):
    workflow = (Path(__file__).resolve().parents[1] / 'workflows' / request.param).read_text()
    body = workflow.rsplit('        run: |\n', 1)[1]
    script = ''.join(line[10:] if line.startswith('          ') else line
                     for line in body.splitlines(True))
    return compile(script, request.param, 'exec')


def run(script, needs, pages=None, error=None):
    with tempfile.TemporaryDirectory() as d:
        summary = Path(d) / 'summary.md'
        env = dict(NEEDS_JSON=json.dumps(needs), GITHUB_SERVER_URL='https://github.com',
                   GITHUB_REPOSITORY='owner/repo', GITHUB_RUN_ID='123',
                   GITHUB_RUN_ATTEMPT='2', GITHUB_STEP_SUMMARY=str(summary))
        result = subprocess.CompletedProcess([], 0, json.dumps(pages or []), '')
        output = io.StringIO()
        with patch.dict(os.environ, env), patch('subprocess.run', return_value=result, side_effect=error) as api, contextlib.redirect_stdout(output):
            try:
                exec(script, {})
            except SystemExit as e:
                status = e.code
        return status, output.getvalue(), summary.read_text(), api


def test_gate_reports_failures_without_changing_verdict(gate_script):
    status, out, summary, api = run(gate_script, {'scope': {'result':'success'}, 'acceptance': {'result':'skipped'}})
    assert status == 0 and not api.called and '| acceptance | skipped |' in summary
    job = dict(name='wrappers-macos-latest', conclusion='failure', labels=['macos-latest'], runner_name='', steps=[], html_url='https://github.com/owner/repo/actions/runs/123/job/456')
    status, out, summary, api = run(gate_script, {'scope':{'result':'success'}, 'acceptance':{'result':'failure'}}, [{'jobs':[]},{'jobs':[job]}])
    assert status == 1 and 'Required job acceptance reported failure' in out
    assert 'macos-latest' in out and 'runner=not assigned' in out
    assert 'No failing step was reported' in out and job['html_url'] in summary
    assert '/attempts/2/jobs' in api.call_args.args[0][-1]
    job['steps'] = [{'name':'Run tests', 'conclusion':'failure'}]
    status, out, _, _ = run(gate_script, {'acceptance':{'result':'failure'}}, [{'jobs':[job]}])
    assert status == 1 and 'Failed/cancelled steps: Run tests' in out
    for error in (FileNotFoundError(), subprocess.TimeoutExpired(['gh'],30), subprocess.CalledProcessError(1,['gh'])):
        status, out, summary, _ = run(gate_script, {'acceptance':{'result':'cancelled'}}, error=error)
        assert status == 1 and 'Could not retrieve' in out and '| acceptance | cancelled |' in summary
