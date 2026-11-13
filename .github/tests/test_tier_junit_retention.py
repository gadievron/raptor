"""Check tier report-publication policy without executing workflows or actions."""

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/_tier.yml'
UPLOAD = 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9'
TIERS = {'source_intel', 'engine', 'codeql', 'llm_analysis', 'cve_diff',
         'fuzzing', 'sage', 'orchestration'}


def job_steps(branch):
    text = WORKFLOW.read_text()
    body = text.split(f'  {branch}:\n', 1)[1]
    body = re.split(r'^  [a-z][a-z_-]*:\n', body, maxsplit=1, flags=re.M)[0]
    return re.split(r'^      - name: ', body, flags=re.M)[1:]


def publication(branch):
    steps = job_steps(branch)
    uploads = [step for step in steps if 'uses: actions/upload-artifact@' in step]
    assert len(uploads) == 1, f'{branch} must retain its existing JUnit reports'
    return uploads[0]


def field(step, name):
    match = re.search(rf'^\s+{re.escape(name)}: (.+)$', step, re.M)
    assert match is not None, name
    return match[1]


def report_paths(step, runner_temp):
    """Resolve only the declared report inputs, not the upload action itself."""
    match = re.search(r'^          path: \|\n((?:            [^\n]+\n)+)', step, re.M)
    assert match is not None
    paths = [line.strip() for line in match[1].splitlines()]
    assert paths == ['${{ runner.temp }}/pytest-junit.xml',
                     '${{ runner.temp }}/pytest-native-junit.xml']
    return [Path(path.replace('${{ runner.temp }}', str(runner_temp))) for path in paths]


@pytest.mark.parametrize('branch', ['image', 'runner'])
def test_each_path_retains_reports_after_failure(branch):
    step = publication(branch)
    assert field(step, 'if') == 'always()'
    assert field(step, 'uses') == UPLOAD + ' # v7.0.2'
    assert field(step, 'if-no-files-found') == 'error'
    # Publication is deliberately fallible: missing reports, transport or
    # action timeout can fail an otherwise successful job.
    assert 'continue-on-error:' not in step
    assert 'overwrite:' not in step
    steps = job_steps(branch)
    assert steps.index(step) > next(i for i, s in enumerate(steps)
                                    if s.startswith("Check skip count against the lane's recorded budget\n"))


@pytest.mark.parametrize('branch', ['image', 'runner'])
@pytest.mark.parametrize('present', [
    pytest.param((), id='both-missing'),
    pytest.param(('pytest-junit.xml',), id='default-only'),
    pytest.param(('pytest-native-junit.xml',), id='native-only-not-completeness'),
    pytest.param(('pytest-junit.xml', 'pytest-native-junit.xml'), id='both-present'),
])
def test_owned_report_inputs_keep_partitions_optional_without_broad_upload(tmp_path, branch, present):
    step = publication(branch)
    for name in present:
        (tmp_path / name).write_text('<testsuite/>')
    # Unrelated logs and XML must not get swept into the artifact.
    (tmp_path / 'unrelated.xml').write_text('owned non-report sentinel')
    (tmp_path / 'diagnostic.log').write_text('owned log sentinel')
    selected = [path.name for path in report_paths(step, tmp_path) if path.is_file()]
    assert selected == list(present)
    # This pins input availability and the configured missing-file policy.
    # It does not emulate upload transport or prove all partition coverage.
    assert field(step, 'if-no-files-found') == 'error'
    assert bool(selected) == bool(present)


def test_artifact_names_distinguish_existing_callers_paths_and_attempts():
    callers = []
    for workflow in (ROOT / '.github/workflows').glob('*.yml'):
        for block in re.split(r'(?=^  [a-z][a-z0-9_-]*:\n)', workflow.read_text(), flags=re.M):
            if 'uses: ./.github/workflows/_tier.yml' in block:
                callers.append(field(block, 'tier'))
    assert set(callers) == TIERS
    assert len(callers) == len(TIERS)
    names = []
    for branch in ('image', 'runner'):
        template = field(publication(branch), 'name')
        for tier in callers:
            for attempt in ('1', '2'):
                name = template.replace('${{ inputs.tier }}', tier)
                name = name.replace('${{ github.job }}', branch)
                name = name.replace('${{ github.run_attempt }}', attempt)
                assert '${{' not in name
                names.append(name)
    assert len(set(names)) == 2 * len(TIERS) * 2


@pytest.mark.parametrize('branch', ['image', 'runner'])
def test_publication_keeps_test_failure_precedence_and_profile_guards(branch):
    step = next(step for step in job_steps(branch) if step.startswith('Run tests\n'))
    assert 'RAPTOR_MAX_TEST_SECONDS: "10"' in step
    assert 'exec python -m pytest $TEST_PATH $PYTEST_EXTRA' in step
    assert 'RAPTOR_MAX_TEST_SECONDS="" python -m pytest $TEST_PATH $PYTEST_EXTRA' in step
    assert '-m "$NATIVE_PYTEST_MARKERS"' in step
    assert '--junitxml="$RUNNER_TEMP/pytest-junit.xml"' in step
    assert '--junitxml="$RUNNER_TEMP/pytest-native-junit.xml"' in step
    assert 'exit "$fast_status"' in step and 'exit "$native_status"' in step
    assert 'if [ "$fast_status" -eq 5 ] && [ "$native_status" -eq 5 ]; then' in step
    assert 'exit 5' in step
    assert 'continue-on-error:' not in step


def test_publication_keeps_reusable_only_entry_and_read_permissions():
    text = WORKFLOW.read_text()
    header = text.split('jobs:\n', 1)[0]
    assert '  workflow_call:\n' in header
    assert not re.search(r'^  (?:push|pull_request|schedule|workflow_dispatch):', header, re.M)
    assert re.search(r'^permissions:\n  contents: read\n  packages: read\n', header, re.M)
    assert not re.search(r'^\s+(?:contents|packages|actions): write$', text, re.M)
