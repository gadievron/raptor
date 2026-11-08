"""CodeQL allocates analysis runners only when their outputs are needed."""

import ast
from pathlib import Path
import re
import subprocess
import textwrap

import pytest


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
