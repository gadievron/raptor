import contextlib
import builtins
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

WORKFLOWS = ['tests.yml', 'preflight.yml', 'sandbox-wrappers.yml']


def workflow_source(name):
    return (Path(__file__).resolve().parents[1] / 'workflows' / name).read_text()


def source_script(workflow):
    body = workflow.rsplit('        run: |\n', 1)[1]
    return ''.join(line[10:] if line.startswith('          ') else line
                   for line in body.splitlines(True))


@pytest.fixture(params=WORKFLOWS)
def gate_script(request):
    return compile(source_script(workflow_source(request.param)), request.param, 'exec')


def needs_spec(workflow):
    block = list(re.finditer(r'(?m)^  [\w-]+:\n', workflow))[-1]
    gate = workflow[block.start():]
    declared = re.search(r'(?m)^    needs: \[([^\n]+)\]', gate)
    if declared:
        names = [name.strip() for name in declared[1].split(',')]
    else:
        declared = re.search(r'(?m)^    needs:\n((?:      - [\w-]+\n)+)', gate)
        assert declared, 'aggregate prerequisites must be explicit'
        names = re.findall(r'(?m)^      - ([\w-]+)$', declared[1])
    payload = re.search(r'(?m)^          NEEDS_JSON: >-\n((?:            [^\n]*\n)+)', gate)
    assert payload, 'the full needs object must not enter the process environment'
    spec = json.loads(' '.join(line.strip() for line in payload[1].splitlines()))
    assert set(spec) == set(names), 'result mapping drifted from declared prerequisites'
    for name, fields in spec.items():
        assert set(fields) == {'result'}, 'prerequisite outputs must not be forwarded'
        reference = re.fullmatch(r"\$\{\{ needs\['([^']+)'\]\.result \}\}", fields['result'])
        assert reference and reference[1] == name, 'result mapped to the wrong prerequisite'
    return spec


def run(script, needs, pages=None, error=None):
    with tempfile.TemporaryDirectory() as d:
        summary = Path(d) / 'summary.md'
        env = dict(NEEDS_JSON=json.dumps(needs), GITHUB_SERVER_URL='https://github.com',
                   GITHUB_REPOSITORY='owner/repo', GITHUB_RUN_ID='123',
                   GITHUB_RUN_ATTEMPT='2', GITHUB_STEP_SUMMARY=str(summary))
        result = subprocess.CompletedProcess([], 0, json.dumps(pages or []), '')
        api = Mock(return_value=result, side_effect=error)
        process = SimpleNamespace(run=api, SubprocessError=subprocess.SubprocessError)
        real_import = builtins.__import__

        def owned_import(name, *args, **kwargs):
            return process if name == 'subprocess' else real_import(name, *args, **kwargs)

        namespace = {'__builtins__': dict(vars(builtins), __import__=owned_import)}
        output = io.StringIO()
        with patch.dict(os.environ, env), contextlib.redirect_stdout(output):
            try:
                exec(script, namespace)
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


@pytest.mark.parametrize('name', WORKFLOWS)
def test_real_gate_process_starts_with_oversized_prerequisite_outputs(tmp_path, name):
    workflow = workflow_source(name)
    spec = needs_spec(workflow)
    context = {job: {'result': 'success', 'outputs': {}} for job in spec}
    first = next(iter(context))
    context[first]['outputs']['files'] = 'core/example/tests/test_case.py ' * 8000
    assert len(json.dumps(context).encode()) > 128 * 1024
    results = {job: {'result': data['result']} for job, data in context.items()}
    payload = json.dumps(results)
    assert len(payload.encode()) < 64 * 1024
    summary = tmp_path / 'summary.md'
    env = dict(os.environ, NEEDS_JSON=payload, GITHUB_SERVER_URL='https://github.com',
               GITHUB_REPOSITORY='owner/repo', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2',
               GITHUB_STEP_SUMMARY=str(summary), GH_TOKEN='owned-token')
    result = subprocess.run([sys.executable, '-I', '-c', source_script(workflow)],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(f'| {job} | success |' in summary.read_text() for job in spec)


@pytest.mark.parametrize('name', WORKFLOWS)
def test_every_mapped_prerequisite_can_fail_the_gate(name):
    workflow = workflow_source(name)
    spec = needs_spec(workflow)
    script = compile(source_script(workflow), name, 'exec')
    for job in spec:
        results = {key: {'result': 'skipped'} for key in spec}
        results[job]['result'] = 'cancelled'
        status, _, summary, _ = run(script, results)
        assert status == 1 and f'| {job} | cancelled |' in summary
