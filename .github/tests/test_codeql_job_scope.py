"""CodeQL allocates analysis runners only when their outputs are needed."""

import ast
import json
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

from core.testing.processes import run_in_process_group


WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/codeql.yml'


def _job(name):
    match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:|\Z)',
                      WORKFLOW.read_text(), re.M | re.S)
    assert match is not None
    return match[1]


def _condition(name):
    match = re.search(r'^    if: >-\n((?:      .+\n)+)', _job(name), re.M)
    assert match is not None, f'{name} lacks its job-level output gate'
    return ast.parse(' '.join(match[1].split()).replace('||', ' or '), mode='eval').body


def _reference(node):
    if isinstance(node, ast.Name):
        return node.id
    assert isinstance(node, ast.Attribute)
    return _reference(node.value) + '.' + node.attr


def _evaluate(node, values):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BoolOp):
        assert isinstance(node.op, ast.Or)
        return any(_evaluate(value, values) for value in node.values)
    if isinstance(node, ast.Compare):
        assert len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
        return _evaluate(node.left, values) == _evaluate(node.comparators[0], values)
    return values[_reference(node)]


def _runs(event, force='false', flags=('false', 'false', 'false')):
    values = {'github.event_name': event, 'needs.changes.outputs.force_full': force}
    values.update({f'needs.changes.outputs.codeql_{language}': flag
                   for language, flag in zip(('python', 'cpp', 'actions'), flags)})
    return _evaluate(_condition('analyze'), values)


def test_docs_push_has_no_analysis_runner():
    assert not _runs('push')


@pytest.mark.parametrize('event,force,flags', [
    ('push', 'false', ('true', 'false', 'false')),
    ('push', 'false', ('false', 'true', 'false')),
    ('push', 'false', ('false', 'false', 'true')),
    ('push', 'false', ('true', 'true', 'true')),
    ('push', 'true', ('false', 'false', 'false')),
    ('schedule', 'true', ('false', 'false', 'false')),
    ('workflow_dispatch', 'true', ('false', 'false', 'false')),
    ('pull_request', 'false', ('false', 'false', 'false')),
    ('merge_group', 'false', ('false', 'false', 'false')),
], ids=['python', 'cpp', 'actions', 'unknown-scope', 'forced-push', 'schedule',
        'manual', 'pr-stubs', 'merge-stubs'])
def test_needed_analysis_and_proposed_ref_stubs_keep_runners(event, force, flags):
    assert _runs(event, force, flags)


def test_analysis_and_upload_jobs_share_the_output_gate():
    assert ast.dump(_condition('analyze')) == ast.dump(_condition('upload'))


@pytest.mark.parametrize('results,code', [
    ('success skipped skipped', 0),
    ('success failure skipped', 1),
    ('success cancelled skipped', 1),
])
def test_required_status_accepts_intentional_skips_and_refuses_failures(tmp_path, results, code):
    match = re.search(r'^        run: \|\n((?:          .*\n|\n)+)',
                      _job('codeql-passed'), re.M)
    assert match is not None
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c',
         textwrap.dedent(match[1])], cwd=tmp_path,
        env={'PATH': '/usr/bin:/bin', 'RESULTS': results},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == code, result.stdout + result.stderr


def _cleanup_script():
    lines = _job('analyze').splitlines()
    start = lines.index('      - name: Free disk space for overlay analysis') + 1
    end = next(i for i in range(start, len(lines))
               if lines[i].startswith('      - '))
    step = lines[start:end]
    assert step[0] == "        if: steps.gate.outputs.run == 'true' && matrix.language == 'python'"
    body = step.index('        run: |') + 1
    return textwrap.dedent('\n'.join(step[body:]) + '\n')


@pytest.mark.parametrize('before_failure,cleanup_failure,after_failure,expected', [
    (False, False, False, 0),
    (False, True, False, 7),
    (True, False, False, 0),
    (True, True, False, 7),
    (False, False, True, 13),
], ids=['success', 'cleanup-failure', 'before-df-failure', 'both-fail', 'after-df-failure'])
def test_cleanup_measurement_keeps_all_roots_and_status(
    tmp_path, before_failure, cleanup_failure, after_failure, expected,
):
    tools = tmp_path / 'tools'
    tools.mkdir()
    log = tmp_path / 'commands.jsonl'
    fake = f'#!{sys.executable} -I\n' + r'''
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['COMMAND_LOG'], 'a') as stream:
    stream.write(json.dumps([tool, args]) + '\n')
if tool == 'sudo':
    assert args[:3] == ['rm', '-rf', '--'] and len(args) == 4
    assert args[3] in ['/usr/share/dotnet', '/usr/local/lib/android', '/opt/ghc']
    sys.exit(7 if os.environ['CLEANUP_FAILURE'] == '1' and args[3] == '/usr/local/lib/android' else 0)
assert tool == 'df' and args in [['-B1', '/'], ['-h', '/']]
failure = 'BEFORE_FAILURE' if args[0] == '-B1' else 'AFTER_FAILURE'
sys.exit(13 if os.environ[failure] == '1' else 0)
'''
    for name in ('sudo', 'df'):
        executable = tools / name
        executable.write_text(fake)
        executable.chmod(0o755)
    # Only inert tools are reachable; sudo records arguments without running rm.
    result = run_in_process_group(
        ['/bin/bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', _cleanup_script()],
        timeout=5, cwd=tmp_path, env={
            'PATH': str(tools), 'COMMAND_LOG': str(log),
            'BEFORE_FAILURE': str(int(before_failure)),
            'CLEANUP_FAILURE': str(int(cleanup_failure)),
            'AFTER_FAILURE': str(int(after_failure)),
        }, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert commands[0] == ['df', ['-B1', '/']]
    assert [args for tool, args in commands if tool == 'sudo'] == [
        ['rm', '-rf', '--', '/usr/share/dotnet'],
        ['rm', '-rf', '--', '/usr/local/lib/android'],
        ['rm', '-rf', '--', '/opt/ghc'],
    ]
    assert sum(tool == 'df' and args == ['-h', '/'] for tool, args in commands) == int(not cleanup_failure)
    assert result.stdout.count('CodeQL cleanup path=') == 3
    for line in result.stdout.splitlines():
        assert re.fullmatch(r'CodeQL cleanup path=/\S+ seconds=\d+ exit=(0|7)', line)
    assert ('::warning::CodeQL pre-cleanup disk measurement failed' in result.stderr) == before_failure
