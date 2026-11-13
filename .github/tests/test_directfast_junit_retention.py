"""Inspect direct fast-shard retention without executing a shell or action."""

from pathlib import Path
import re
import shlex

import pytest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/tests.yml'
UPLOAD = 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9'


def fast_job():
    body = WORKFLOW.read_text().split('  python-unit-tests-fast:\n', 1)[1]
    return re.split(r'^  [a-z][a-z0-9_-]*:\n', body, maxsplit=1, flags=re.M)[0]


def steps():
    return re.split(r'^      - name: ', fast_job(), flags=re.M)[1:]


def field(step, name):
    match = re.search(rf'^\s+{re.escape(name)}: (.+)$', step, re.M)
    assert match is not None, name
    return match[1]


def publication():
    matches = [s for s in steps() if s.startswith('Upload fast-tier test results\n')]
    assert len(matches) == 1
    return matches[0]


def test_retention_is_strict_and_eligible_after_test_failure():
    step = publication()
    assert field(step, 'uses') == UPLOAD + '  # v7.0.2'
    assert field(step, 'if') == 'always()'
    assert field(step, 'if-no-files-found') == 'error'
    assert field(step, 'retention-days') == '7'
    assert 'continue-on-error:' not in step
    assert 'overwrite:' not in step
    # Missing XML and upload failures can fail a previously successful job.
    # always() does not promise publication after runner loss or hard cancel.
    assert steps().index(step) > next(
        i for i, s in enumerate(steps()) if s.startswith('Upload LLM tripwire evidence\n')
    )


def test_generated_and_uploaded_report_paths_match_without_changing_pytest_status():
    step = next(s for s in steps() if s.startswith('Run unit tests (batch '))
    command = re.search(r'^          python -m pytest .*?\|\| rc=\$\?$', step, re.M | re.S)
    assert command is not None
    argv = shlex.split(command[0].replace('\\\n', ' '))
    assert argv == [
        'python', '-m', 'pytest', '-p', 'core.testing.llm_tripwire',
        '--llm-tripwire-dir', '$RUNNER_TEMP/llm-tripwire',
        '--llm-tripwire-host-dir', '$RUNNER_TEMP/llm-hosts',
        '--junitxml=$RUNNER_TEMP/pytest-fast.xml',
        '-n', 'auto', '--dist', 'worksteal', '$TEST_FILES', '||', 'rc=$?',
    ]
    assert field(publication(), 'path') == '${{ runner.temp }}/pytest-fast.xml'
    assert 'TEST_FILES: ${{ matrix.files }}' in step
    assert 'set -f  # word-split $TEST_FILES without glob expansion' in step
    assert 'rc=0' in step
    assert 'if [ "$rc" -eq 5 ]; then\n' in step
    assert '            exit 0\n          fi\n          exit "$rc"' in step
    assert 'continue-on-error:' not in step


@pytest.mark.parametrize('report_present', [False, True], ids=['missing', 'present'])
def test_only_the_expected_owned_report_is_selected(tmp_path, report_present):
    template = field(publication(), 'path')
    report = Path(template.replace('${{ runner.temp }}', str(tmp_path)))
    (tmp_path / 'unrelated.xml').write_text('<testsuite/>')
    (tmp_path / 'tripwire.jsonl').write_text('{}\n')
    if report_present:
        report.write_text('<testsuite tests="0"/>')
    selected = [report] if report.is_file() else []
    assert selected == ([tmp_path / 'pytest-fast.xml'] if report_present else [])
    assert field(publication(), 'if-no-files-found') == 'error'
    # An empty pytest report remains a report (including accepted pytest rc5).
    # Presence is not evidence that every intended test partition executed.


def test_artifact_names_separate_shards_jobs_and_attempts():
    template = field(publication(), 'name')
    names = []
    for batch in range(1, 9):
        for job in ('python-unit-tests-fast', 'other-fast-job'):
            for attempt in (1, 2):
                name = template.replace('${{ matrix.batch }}', str(batch))
                name = name.replace('${{ github.job }}', job)
                name = name.replace('${{ github.run_attempt }}', str(attempt))
                assert '${{' not in name
                names.append(name)
    assert len(set(names)) == 32


def test_retention_keeps_tripwire_publication_separate():
    step = next(s for s in steps() if s.startswith('Upload LLM tripwire evidence\n'))
    assert field(step, 'if') == 'always()'
    assert field(step, 'name') == 'llm-tripwire-${{ matrix.batch }}'
    assert field(step, 'if-no-files-found') == 'ignore'
    assert field(step, 'retention-days') == '7'
    assert '${{ runner.temp }}/llm-tripwire/**/*.jsonl' in step
    assert '${{ runner.temp }}/llm-hosts/server.log' in step
    assert 'pytest-fast.xml' not in step
