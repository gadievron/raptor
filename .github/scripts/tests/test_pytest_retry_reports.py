"""Targeted retries preserve successes, skips, failures and complete coverage."""

import importlib.util
import os
import re
from pathlib import Path
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.github/scripts/pytest_retry_reports.py'
spec = importlib.util.spec_from_file_location('retry_reports_under_test', SCRIPT)
reports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)


def report(path, rows):
    suite = ET.Element('testsuite', name='pytest', time='1.5')
    for name, outcomes in rows:
        case = ET.SubElement(suite, 'testcase', classname='owned.tests', name=name, time='0.1')
        for outcome in outcomes:
            ET.SubElement(case, outcome, message='owned outcome')
    suite.attrib.update({key: str(value) for key, value in reports._counts(suite.findall('testcase')).items()})
    suite.set('tests', str(len(rows)))
    root = ET.Element('testsuites')
    root.append(suite)
    ET.ElementTree(root).write(path)
    return path


@pytest.mark.parametrize('outcomes, expected', [([], 0), (['skipped'], 0), (['failure'], 1), (['error'], 1)])
def test_eligibility_uses_case_failures(tmp_path, outcomes, expected):
    path = report(tmp_path / 'first.xml', [('case', outcomes)])
    assert reports.eligible(path) == expected


@pytest.mark.parametrize('payload', ['<broken', '<root/>', '<testsuite/>',
    '<testsuite tests="1" failures="1" errors="0" skipped="0"><testcase name="ambiguous"><failure/></testcase></testsuite>'])
def test_bad_reports_cannot_authorize_retry(tmp_path, payload):
    path = tmp_path / 'first.xml'
    path.write_text(payload)
    assert reports.main(['eligible', str(path), str(tmp_path / 'cache')]) == 1


def test_missing_report_cannot_authorize_retry(tmp_path):
    assert reports.main(['eligible', str(tmp_path / 'missing.xml'), str(tmp_path / 'cache')]) == 1


def test_merge_retains_first_pass_successes_and_skips(tmp_path):
    first = report(tmp_path / 'first.xml', [('passed', []), ('skipped', ['skipped']), ('retry', ['failure'])])
    retry = report(tmp_path / 'retry.xml', [('retry', [])])
    originals = first.read_bytes(), retry.read_bytes()
    output = tmp_path / 'effective.xml'
    assert reports.merge(first, retry, output)
    _, suite, groups = reports._read(output)
    assert set(groups) == {('owned.tests', name) for name in ('passed', 'skipped', 'retry')}
    assert suite.get('skipped') == '1'
    assert suite.get('failures') == '0'
    assert suite.get('tests') == '3'
    assert float(suite.get('time')) == 3
    assert (first.read_bytes(), retry.read_bytes()) == originals


@pytest.mark.parametrize('retry_rows', [[('one', [])], [('one', []), ('two', []), ('extra', [])], []])
def test_missing_or_unexpected_retry_cases_refuse_effective_report(tmp_path, retry_rows):
    first = report(tmp_path / 'first.xml', [('one', ['failure']), ('two', ['error'])])
    retry = report(tmp_path / 'retry.xml', retry_rows)
    output = tmp_path / 'effective.xml'
    output.write_bytes(first.read_bytes())
    with pytest.raises(ValueError, match='exactly'):
        reports.merge(first, retry, output)
    assert output.read_bytes() == first.read_bytes()


def test_retry_to_skip_is_not_recovered_coverage(tmp_path):
    first = report(tmp_path / 'first.xml', [('retry', ['failure'])])
    retry = report(tmp_path / 'retry.xml', [('retry', ['skipped'])])
    with pytest.raises(ValueError, match='skipped on retry'):
        reports.merge(first, retry, tmp_path / 'effective.xml')


def test_remaining_failure_still_fails_and_keeps_full_report(tmp_path):
    first = report(tmp_path / 'first.xml', [('passed', []), ('retry', ['failure'])])
    retry = report(tmp_path / 'retry.xml', [('retry', ['error'])])
    output = tmp_path / 'effective.xml'
    assert reports.main(['merge', str(first), str(retry), str(output)]) == 1
    _, suite, groups = reports._read(output)
    assert len(groups) == 2
    assert suite.get('errors') == '1'


def test_duplicate_failed_phase_records_are_replaced_together(tmp_path):
    first = report(tmp_path / 'first.xml', [('retry', ['failure']), ('retry', ['error']), ('passed', [])])
    retry = report(tmp_path / 'retry.xml', [('retry', [])])
    output = tmp_path / 'effective.xml'
    assert reports.merge(first, retry, output)
    _, suite, groups = reports._read(output)
    assert len(groups) == 2 and suite.get('errors') == '0'


def test_ambiguous_passed_duplicate_identity_is_refused(tmp_path):
    path = report(tmp_path / 'first.xml', [('same', []), ('same', ['failure'])])
    with pytest.raises(ValueError, match='ambiguous duplicate'):
        reports.eligible(path)


@pytest.mark.parametrize('field,value', [('failures', '99'), ('errors', '-1'), ('skipped', 'bad'), ('tests', '-1'), ('tests', '0'), ('tests', '99'), ('time', 'nan')])
def test_inconsistent_summary_is_refused(tmp_path, field, value):
    path = report(tmp_path / 'first.xml', [('case', ['failure'])])
    tree = ET.parse(path)
    tree.find('testsuite').set(field, value)
    tree.write(path)
    with pytest.raises(ValueError):
        reports.eligible(path)


def test_raw_attempt_cannot_be_overwritten(tmp_path):
    first = report(tmp_path / 'first.xml', [('case', ['failure'])])
    retry = report(tmp_path / 'retry.xml', [('case', [])])
    with pytest.raises(ValueError, match='overwrite'):
        reports.merge(first, retry, first)


@pytest.mark.parametrize('payload', [None, '{}', '{"wrong": false}', '{broken', '[]'])
def test_missing_or_inconsistent_cache_cannot_authorize_retry(tmp_path, payload):
    path = report(tmp_path / 'first.xml', [('case', ['failure'])])
    cache = tmp_path / 'cache'
    if payload is not None:
        (cache / 'v/cache').mkdir(parents=True)
        (cache / 'v/cache/lastfailed').write_text(payload)
    assert reports.main(['eligible', str(path), str(cache)]) == 1


def test_matching_failed_cache_authorizes_targeted_retry(tmp_path):
    path = report(tmp_path / 'first.xml', [('case', ['failure'])])
    cache = tmp_path / 'cache'
    (cache / 'v/cache').mkdir(parents=True)
    (cache / 'v/cache/lastfailed').write_text('{"owned/test_case.py::case": true}')
    assert reports.main(['eligible', str(path), str(cache)]) == 0


def integration_step():
    # This CI lane installs pytest only. Read the concrete literal shell block
    # without importing a YAML parser (or evaluating workflow expressions).
    source = (ROOT / '.github/workflows/nightly.yml').read_text()
    jobs = source.split('\njobs:\n', 1)[1]
    job = re.search(r'^  slow-integration:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)',
                    jobs, re.M | re.S)
    assert job is not None, 'slow-integration job missing'
    steps = re.split(r'^      - ', job[1], flags=re.M)[1:]
    integration = next(step for step in steps
                       if re.search(r'^        id: integration_tests$', step, re.M))
    body = re.search(r'^        run: \|\n((?:          .*\n|\n)+)', integration, re.M)
    assert body is not None, 'integration command must remain a literal shell block'
    return textwrap.dedent(body[1]), steps


def test_workflow_uses_isolated_cache_and_complete_effective_report():
    body, steps = integration_step()
    assert body.count('cache_dir=$RUNNER_TEMP/integration-pytest-cache') == 2
    assert body.count('--cache-clear') == 1
    assert body.count('--lf --last-failed-no-failures=none') == 1
    assert '"$rc" -ne 1' in body
    assert 'pytest_retry_reports.py eligible' in body
    assert 'pytest_retry_reports.py merge' in body
    assert 'exit "$retry_rc"' in body
    budget = next(step for step in steps if step.startswith('name: Check integration skip count'))
    assert '--junit-xml "$RUNNER_TEMP/integration.xml"' in budget
    assert "steps.integration_tests.outcome == 'failure'" in budget
    upload = next(step for step in steps if step.startswith('name: Upload test results\n'))
    assert 'integration-attempt-*.xml' in upload
    assert '/integration.xml' in upload


@pytest.mark.slow
@pytest.mark.parametrize('scenario', ['call-and-teardown', 'teardown-only', 'session-failure'])
def test_real_workflow_retries_only_failed_cases_and_preserves_global_failures(tmp_path, scenario):
    session_failure = scenario == 'session-failure'
    for directory in ('core', 'packages', 'engine', '.github/scripts', 'artifacts', 'bin'):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)
    (tmp_path / '.github/scripts/pytest_retry_reports.py').write_bytes(SCRIPT.read_bytes())
    (tmp_path / 'pytest.ini').write_text('[pytest]\naddopts = --import-mode=importlib\nmarkers =\n    integration: owned workflow smoke\n')
    (tmp_path / 'core/test_cases.py').write_text('''
from pathlib import Path
import pytest
pytestmark = pytest.mark.integration
HERE = Path(__file__).parent

def test_passed_once():
    path = HERE / 'passed'
    assert not path.exists(), 'a first-pass success was needlessly rerun'
    path.write_text('once')

@pytest.fixture
def phase_error():
    yield
    path = HERE / 'teardown'
    if not SESSION_FAILURE and not path.exists():
        path.write_text('once')
        raise RuntimeError('owned first-attempt teardown failure')

def test_retry_case(phase_error):
    path = HERE / 'retried'
    if not path.exists():
        path.write_text('once')
        assert not CALL_FAILURE, 'owned transient failure'

def test_existing_skip():
    pytest.skip('owned existing skip')
'''.replace('SESSION_FAILURE', repr(session_failure)).replace('CALL_FAILURE', repr(scenario == 'call-and-teardown')))
    if session_failure:
        (tmp_path / 'conftest.py').write_text('def pytest_sessionfinish(session):\n    session.exitstatus = 1\n')
    sleep = tmp_path / 'bin/sleep'
    sleep.write_text('#!/bin/sh\nexit 0\n')
    sleep.chmod(0o700)
    body, _ = integration_step()
    env = dict(os.environ, VENV_PATH=str(Path(sys.executable).parent.parent),
               RUNNER_TEMP=str(tmp_path / 'artifacts'),
               PATH=str(tmp_path / 'bin') + os.pathsep + os.environ.get('PATH', ''),
               PYTHONPATH=str(ROOT), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',
               PYTEST_ADDOPTS='-p core.testing.llm_tripwire')
    process = subprocess.run(['/bin/bash', '-e', '-c', body], cwd=tmp_path,
                             env=env, capture_output=True, text=True, timeout=60)
    assert process.returncode == (1 if session_failure else 0), process.stdout + process.stderr
    artifacts = tmp_path / 'artifacts'
    assert (artifacts / 'integration-attempt-2.xml').exists() is not session_failure
    _, suite, groups = reports._read(artifacts / 'integration.xml')
    assert len(groups) == 3
    assert suite.get('failures') == '0' and suite.get('skipped') == '1'
    assert (tmp_path / 'core/passed').read_text() == 'once'
