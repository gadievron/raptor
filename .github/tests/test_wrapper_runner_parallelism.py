"""Exercise runner scheduling without launching native confinement probes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest


@pytest.fixture
def runner(monkeypatch, tmp_path):
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    with patch.object(sys, 'path', [str(scripts), *sys.path]):
        spec = importlib.util.spec_from_file_location('parallel_wrapper_runner', scripts / 'run_sandbox_wrapper_tests.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    registry = {'wrappers': [{'contracts': ['owned::contract']}], 'native': [
        {'id': f'family-{index}', 'platforms': {
            platform: {'tests': [f'owned::case_{index}'], 'expected': 1}
            for platform in ('linux', 'darwin')}} for index in range(4)]}
    monkeypatch.setattr(module, 'load_registry', lambda: registry)
    monkeypatch.setattr(module, 'registry_errors', lambda *_: [])
    monkeypatch.setattr(module, 'os', SimpleNamespace(**(vars(module.os) | {
        'confstr': lambda _: str(tmp_path)})))
    return module


def invoke(runner, monkeypatch, tmp_path, fake_run, *options):
    monkeypatch.setattr(runner, 'subprocess', SimpleNamespace(
        run=fake_run, STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
    monkeypatch.setattr(sys, 'argv', ['runner', '--lane', 'native', '--report-dir', str(tmp_path / 'reports'), *options])
    return runner.main()


def report(command, body='<testcase name="owned"/>'):
    xml = next(value.split('=', 1)[1] for value in command if value.startswith('--junitxml='))
    Path(xml).write_text('<testsuite>' + body + '</testsuite>')


def test_two_workers_keep_all_groups_isolated(runner, monkeypatch, tmp_path):
    barrier = threading.Barrier(2, timeout=4)
    homes = []
    lock = threading.Lock()
    active = peak = 0

    def execute(command, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            homes.append(kwargs['env']['HOME'])
        for key in ('HOME', 'TMPDIR', 'RAPTOR_OUT_DIR', 'RAPTOR_REGISTRY_HOME'):
            assert Path(kwargs['env'][key]).is_dir()
        barrier.wait()
        report(command)
        with lock:
            active -= 1
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, execute, '--jobs', '2') == 0
    assert peak == 2
    assert len(homes) == len(set(homes)) == 4
    assert all(not Path(home).exists() for home in homes)
    summary = json.loads((tmp_path / 'reports/summary.json').read_text())
    assert [row['family'] for row in summary['results']] == [f'family-{index}' for index in range(4)]
    assert all(not row['coverage_errors'] for row in summary['results'])


def test_default_remains_serial(runner, monkeypatch, tmp_path):
    calls = []

    def execute(command, **kwargs):
        calls.append(command[5])
        report(command)
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, execute) == 0
    assert calls == [f'owned::case_{index}' for index in range(4)]


def test_failure_stops_queued_groups_and_reaps_active_groups(runner, monkeypatch, tmp_path):
    started = threading.Barrier(2, timeout=4)
    failed = threading.Event()
    calls = []
    homes = []
    original = runner.check_report

    def checked(path, **kwargs):
        if path.stem == 'family-0':
            failed.set()
        return original(path, **kwargs)

    monkeypatch.setattr(runner, 'check_report', checked)

    def execute(command, **kwargs):
        calls.append(command[5])
        homes.append(kwargs['env']['HOME'])
        started.wait()
        if command[5] != 'owned::case_0':
            assert failed.wait(4)
        report(command)
        return SimpleNamespace(returncode=13 if command[5] == 'owned::case_0' else 0)

    assert invoke(runner, monkeypatch, tmp_path, execute, '--jobs', '2') == 13
    assert sorted(calls) == ['owned::case_0', 'owned::case_1']
    assert all(not Path(home).exists() for home in homes)
    assert len(json.loads((tmp_path / 'reports/summary.json').read_text())['results']) == 2


@pytest.mark.parametrize('body', ['', '<testcase><skipped/></testcase>', '<testcase/><testcase/>'])
def test_successful_process_still_requires_exact_coverage(runner, monkeypatch, tmp_path, body):
    def execute(command, **kwargs):
        report(command, body)
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, execute) == 1
    summary = json.loads((tmp_path / 'reports/summary.json').read_text())
    assert len(summary['results']) == 1
    assert summary['results'][0]['coverage_errors']


def test_timeout_keeps_failure_and_cleans_private_home(runner, monkeypatch, tmp_path):
    homes = []

    def execute(command, **kwargs):
        homes.append(kwargs['env']['HOME'])
        assert 0 < kwargs['timeout'] <= 600
        raise subprocess.TimeoutExpired(command, kwargs['timeout'])

    assert invoke(runner, monkeypatch, tmp_path, execute) == 124
    assert len(homes) == 1
    assert not Path(homes[0]).exists()


@pytest.mark.parametrize('jobs', ['0', '3'])
def test_worker_limit_rejects_unbounded_values(runner, monkeypatch, tmp_path, jobs):
    with pytest.raises(SystemExit) as error:
        invoke(runner, monkeypatch, tmp_path, None, '--jobs', jobs)
    assert error.value.code == 2


def test_contracts_remain_one_group(runner, monkeypatch, tmp_path):
    calls = []

    def execute(command, **kwargs):
        calls.append(command[5])
        report(command)
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, execute, '--lane', 'contracts', '--jobs', '2') == 0
    assert calls == ['owned::contract']


def test_unexpected_launch_error_cleans_up_and_cannot_pass(runner, monkeypatch, tmp_path):
    homes = []

    def execute(command, **kwargs):
        homes.append(kwargs['env']['HOME'])
        raise OSError('owned launch failure')

    with pytest.raises(OSError, match='owned launch failure'):
        invoke(runner, monkeypatch, tmp_path, execute)
    assert len(homes) == 1
    assert not Path(homes[0]).exists()


@pytest.fixture
def browser_runner(runner, monkeypatch):
    registry = runner.load_registry()
    registry['native'][-1]['id'] = 'playwright-browser'
    for index, family in enumerate(registry['native']):
        family['env'] = {'OWNED_FAMILY': str(index)}
    monkeypatch.setattr(runner, 'sys', SimpleNamespace(**(vars(sys) | {'platform': 'linux'})))
    return runner


def browser_invoke(runner, monkeypatch, tmp_path, execute, *options):
    monkeypatch.setattr(runner, 'subprocess', SimpleNamespace(
        run=execute, STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired))
    argv = ['runner', '--lane', 'native', '--jobs', '2',
            '--report-dir', str(tmp_path / 'reports'), *options]
    # argparse reads its own sys module, not the runner's platform facade.
    monkeypatch.setattr(sys, 'argv', argv)
    monkeypatch.setattr(runner.sys, 'argv', argv)
    return runner.main()


@pytest.mark.parametrize(('platform', 'jobs', 'lane', 'browser', 'expected'), [
    pytest.param('linux', '2', 'native', True, [3, 0, 1, 2], id='linux-two-browser-first'),
    pytest.param('linux', '2', 'native', False, [0, 1, 2, 3], id='browser-absent'),
    pytest.param('linux', '1', 'native', True, [0, 1, 2, 3], id='linux-serial-unchanged'),
    pytest.param('darwin', '2', 'native', True, [0, 1, 2, 3], id='macos-unchanged'),
    pytest.param('linux', '2', 'contracts', True, ['contract'], id='contracts-unchanged'),
])
def test_browser_submission_preserves_work_and_report_order(
        browser_runner, monkeypatch, tmp_path, platform, jobs, lane, browser, expected):
    runner = browser_runner
    runner.sys.platform = platform
    if not browser:
        runner.load_registry()['native'][-1]['id'] = 'family-3'
    submitted, roots, environments = [], [], []
    original_pool = runner.ThreadPoolExecutor

    class RecordingPool:
        def __init__(self, *, max_workers):
            assert max_workers == (1 if lane == 'contracts' else int(jobs))
            self.pool = original_pool(max_workers=max_workers)

        def __enter__(self):
            self.pool.__enter__()
            return self

        def __exit__(self, *args):
            return self.pool.__exit__(*args)

        def submit(self, function, group):
            submitted.append(group)
            return self.pool.submit(function, group)

    monkeypatch.setattr(runner, 'ThreadPoolExecutor', RecordingPool)

    def execute(command, **kwargs):
        env = kwargs['env']
        paths = [Path(env[key]) for key in ('HOME', 'TMPDIR', 'RAPTOR_OUT_DIR', 'RAPTOR_REGISTRY_HOME')]
        assert all(path.is_dir() for path in paths)
        assert len(set(paths)) == 4
        roots.append(paths)
        environments.append((command[5], env.get('OWNED_FAMILY')))
        report(command)
        return SimpleNamespace(returncode=0)

    assert browser_invoke(runner, monkeypatch, tmp_path, execute, '--lane', lane, '--jobs', jobs) == 0
    assert [group[1][0] for group in submitted] == [f'owned::case_{i}' if i != 'contract'
                                                 else 'owned::contract' for i in expected]
    if lane == 'native':
        assert sorted(environments) == [(f'owned::case_{i}', str(i)) for i in range(4)]
        assert all(group[2] == group[4] == 1 for group in submitted)
    assert len({str(paths[0].parent) for paths in roots}) == len(roots)
    assert all(not path.exists() for paths in roots for path in paths)
    summary = json.loads((tmp_path / 'reports/summary.json').read_text())
    plan = json.loads((tmp_path / 'reports/plan.json').read_text())
    names = ['contracts'] if lane == 'contracts' else [family['id'] for family in runner.load_registry()['native']]
    assert [group['family'] for group in plan['selected']] == names
    assert [result['family'] for result in summary['results']] == names
    assert all(result['returncode'] == 0 and not result['coverage_errors'] for result in summary['results'])


@pytest.mark.parametrize(('fault', 'failing_selector'), [
    pytest.param('returncode', 'owned::case_3', id='browser-failure'),
    pytest.param('returncode', 'owned::case_0', id='companion-failure'),
    pytest.param('exception', 'owned::case_3', id='launch-exception'),
    pytest.param('timeout', 'owned::case_3', id='timeout'),
    pytest.param('missing', 'owned::case_3', id='missing-coverage'),
    pytest.param('malformed', 'owned::case_3', id='malformed-coverage'),
    pytest.param('count', 'owned::case_3', id='wrong-count'),
    pytest.param('skipped', 'owned::case_3', id='skipped-case'),
    pytest.param('failure', 'owned::case_3', id='failed-case'),
    pytest.param('error', 'owned::case_3', id='error-case'),
])
def test_browser_failure_prefix_stops_pending_work_and_cleans_active_roots(
        browser_runner, monkeypatch, tmp_path, fault, failing_selector):
    runner = browser_runner
    started = threading.Barrier(2, timeout=4)
    stopped = threading.Event()
    monkeypatch.setattr(runner, 'threading', SimpleNamespace(Event=lambda: stopped))
    calls, homes, completed = [], [], []

    def execute(command, **kwargs):
        selector = command[5]
        calls.append(selector)
        homes.append(Path(kwargs['env']['HOME']))
        started.wait()
        if selector != failing_selector:
            assert stopped.wait(4)
            assert Path(kwargs['env']['HOME']).is_dir()
            completed.append(selector)
            report(command)
            return SimpleNamespace(returncode=0)
        if fault == 'exception':
            raise OSError('owned browser launch failure')
        if fault == 'timeout':
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        if fault == 'malformed':
            report(command, '<broken')
        elif fault == 'count':
            report(command, '<testcase/><testcase/>')
        elif fault in ('skipped', 'failure', 'error'):
            report(command, f'<testcase><{fault}/></testcase>')
        elif fault != 'missing':
            report(command)
        return SimpleNamespace(returncode=13 if fault == 'returncode' else 0)

    if fault == 'exception':
        with pytest.raises(OSError, match='owned browser launch failure'):
            browser_invoke(runner, monkeypatch, tmp_path, execute)
    else:
        expected_code = 13 if fault == 'returncode' else 124 if fault == 'timeout' else 1
        assert browser_invoke(runner, monkeypatch, tmp_path, execute) == expected_code
        summary = json.loads((tmp_path / 'reports/summary.json').read_text())
        assert {row['family'] for row in summary['results']} == {'family-0', 'playwright-browser'}
    assert stopped.is_set()
    # Reordering deliberately changes the attempted subset after a failure.
    assert sorted(calls) == ['owned::case_0', 'owned::case_3']
    assert completed == [selector for selector in calls if selector != failing_selector]
    assert len(set(homes)) == 2
    assert all(not home.exists() for home in homes)


def test_browser_order_retains_global_deadline_and_timeout_clamping(browser_runner, monkeypatch, tmp_path):
    from concurrent.futures import Future

    runner = browser_runner
    clock = iter([100, 700, 1000, 1299.5, 1400])
    monkeypatch.setattr(runner, 'time', SimpleNamespace(monotonic=lambda: next(clock)))

    class InlinePool:
        """Deterministic clock control, not a concurrency simulation."""
        def __init__(self, *, max_workers):
            assert max_workers == 2

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def submit(self, function, group):
            future = Future()
            future.set_result(function(group))
            return future

    monkeypatch.setattr(runner, 'ThreadPoolExecutor', InlinePool)
    allocations = []

    def execute(command, **kwargs):
        allocations.append((command[5], kwargs['timeout']))
        report(command)
        return SimpleNamespace(returncode=0)

    assert browser_invoke(runner, monkeypatch, tmp_path, execute) == 0
    assert allocations == [('owned::case_3', 600), ('owned::case_0', 300),
                           ('owned::case_1', 1), ('owned::case_2', 1)]


@pytest.mark.parametrize('prior', ['missing', 'file', 'symlink'])
def test_current_attempt_requires_its_own_report(runner, monkeypatch, tmp_path, prior):
    report_root = tmp_path / 'reports'
    report_root.mkdir()
    xml = report_root / 'family-0.xml'
    outside = tmp_path / 'outside.xml'
    sentinel = '<testsuite><testcase name="borrowed"/></testsuite>'
    outside.write_text(sentinel)
    if prior == 'file':
        xml.write_text('<testsuite><testcase name="previous-attempt"/></testsuite>')
    elif prior == 'symlink':
        xml.symlink_to(outside)
    homes = []

    def no_current_report(command, **kwargs):
        homes.append(Path(kwargs['env']['HOME']))
        # No report is written by this fake current child.
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, no_current_report,
                  '--family', 'family-0') == 1
    summary = json.loads((report_root / 'summary.json').read_text())
    assert summary['results'] == [dict(
        family='family-0', returncode=0,
        coverage_errors=['pytest did not produce JUnit coverage'],
    )]
    assert len(homes) == 1 and not homes[0].exists()
    assert not xml.exists() and not xml.is_symlink()
    assert outside.read_text() == sentinel


@pytest.mark.parametrize('prior', ['file', 'symlink'])
def test_fresh_report_replaces_only_owned_prior_report(runner, monkeypatch, tmp_path, prior):
    report_root = tmp_path / 'reports'
    report_root.mkdir()
    xml = report_root / 'family-0.xml'
    outside = tmp_path / 'outside.xml'
    sentinel = '<testsuite><testcase name="borrowed"/></testsuite>'
    outside.write_text(sentinel)
    if prior == 'file':
        xml.write_text('<testsuite><testcase name="previous-attempt"/></testsuite>')
    else:
        xml.symlink_to(outside)
    homes = []

    def current_report(command, **kwargs):
        assert not xml.exists() and not xml.is_symlink()
        homes.append(Path(kwargs['env']['HOME']))
        report(command, '<testcase name="current-attempt"/>')
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, current_report,
                  '--family', 'family-0') == 0
    assert xml.read_text() == '<testsuite><testcase name="current-attempt"/></testsuite>'
    assert outside.read_text() == sentinel
    assert len(homes) == 1 and not homes[0].exists()
    summary = json.loads((report_root / 'summary.json').read_text())
    assert summary['results'] == [dict(family='family-0', returncode=0, coverage_errors=[])]


def test_report_retirement_refusal_stops_before_child_and_cleans_root(runner, monkeypatch, tmp_path):
    report_root = tmp_path / 'reports'
    report_root.mkdir()
    xml = report_root / 'family-0.xml'
    prior = '<testsuite><testcase name="previous-attempt"/></testsuite>'
    xml.write_text(prior)
    stopped = threading.Event()
    monkeypatch.setattr(runner, 'threading', SimpleNamespace(Event=lambda: stopped))

    class RefusingReportPath(type(tmp_path)):
        def unlink(self, *args, **kwargs):
            if self.name == 'family-0.xml':
                raise OSError('owned report retirement refusal')
            return super().unlink(*args, **kwargs)

    monkeypatch.setattr(runner, 'Path', RefusingReportPath)
    calls = []

    def not_called(command, **kwargs):
        calls.append(command)
        raise AssertionError('child reached after report retirement refusal')

    with pytest.raises(OSError, match='owned report retirement refusal'):
        invoke(runner, monkeypatch, tmp_path, not_called, '--family', 'family-0')
    assert calls == [] and stopped.is_set()
    assert xml.read_text() == prior
    assert not list(tmp_path.rglob('raptor-wrapper-ci-*'))


@pytest.mark.parametrize('fault', ['nonzero', 'timeout', 'exception'])
def test_current_report_does_not_hide_child_failure(runner, monkeypatch, tmp_path, fault):
    report_root = tmp_path / 'reports'
    report_root.mkdir()
    xml = report_root / 'family-0.xml'
    xml.write_text('<testsuite><testcase name="previous-attempt"/></testsuite>')
    homes = []
    stopped = threading.Event()
    monkeypatch.setattr(runner, 'threading', SimpleNamespace(Event=lambda: stopped))

    def failing_child(command, **kwargs):
        assert not xml.exists()
        homes.append(Path(kwargs['env']['HOME']))
        report(command, '<testcase name="current-attempt"/>')
        if fault == 'exception':
            raise OSError('owned current child exception')
        if fault == 'timeout':
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        return SimpleNamespace(returncode=13)

    if fault == 'exception':
        with pytest.raises(OSError, match='owned current child exception'):
            invoke(runner, monkeypatch, tmp_path, failing_child, '--family', 'family-0')
    else:
        assert invoke(runner, monkeypatch, tmp_path, failing_child,
                      '--family', 'family-0') == (124 if fault == 'timeout' else 13)
        summary = json.loads((report_root / 'summary.json').read_text())
        assert summary['results'][0]['coverage_errors'] == []
    assert stopped.is_set()
    assert len(homes) == 1 and not homes[0].exists()


def test_parallel_families_retire_only_their_own_reports(runner, monkeypatch, tmp_path):
    registry = runner.load_registry()
    registry['native'] = registry['native'][:2]
    report_root = tmp_path / 'reports'
    report_root.mkdir()
    for family in ('family-0', 'family-1'):
        (report_root / (family + '.xml')).write_text(
            '<testsuite><testcase name="previous-attempt"/></testsuite>')
    sentinels = {'unselected-family.xml': 'unselected report', 'unrelated.log': 'borrowed log'}
    for name, text in sentinels.items():
        (report_root / name).write_text(text)
    barrier = threading.Barrier(2, timeout=4)
    homes = []
    calls = []

    def current_child(command, **kwargs):
        selector = command[5]
        calls.append(selector)
        xml = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('--junitxml=')))
        assert not xml.exists()
        homes.append(Path(kwargs['env']['HOME']))
        assert all((report_root / name).read_text() == text for name, text in sentinels.items())
        barrier.wait()
        report(command, f'<testcase name="{selector}"/>')
        kwargs['stdout'].write('owned current ' + selector)
        return SimpleNamespace(returncode=0)

    assert invoke(runner, monkeypatch, tmp_path, current_child, '--jobs', '2') == 0
    assert sorted(calls) == ['owned::case_0', 'owned::case_1']
    assert len(set(homes)) == 2 and all(not home.exists() for home in homes)
    assert all((report_root / name).read_text() == text for name, text in sentinels.items())
    summary = json.loads((report_root / 'summary.json').read_text())
    assert [row['family'] for row in summary['results']] == ['family-0', 'family-1']
    assert all(row['returncode'] == 0 and not row['coverage_errors'] for row in summary['results'])
    for family in ('family-0', 'family-1'):
        assert 'current ' in (report_root / (family + '.log')).read_text()
