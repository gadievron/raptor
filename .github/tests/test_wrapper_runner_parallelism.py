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
