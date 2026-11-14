"""Caller pytest controls cannot narrow the registered wrapper checks."""
from concurrent.futures import Future
import importlib.util
from pathlib import Path
import shlex
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
import xml.etree.ElementTree as ET


class InlinePool:
    """Exercise the real scheduling path without starting worker threads."""

    def __init__(self, *, max_workers):
        assert max_workers == 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, function, *args):
        future = Future()
        try:
            future.set_result(function(*args))
        except BaseException as error:
            future.set_exception(error)
        return future


def exercise(monkeypatch, tmp_path, inherited, *, lane='contracts', returncode=0):
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    with patch.object(sys, 'path', [str(scripts), *sys.path]):
        spec = importlib.util.spec_from_file_location(
            'wrapper_environment_runner', scripts / 'run_sandbox_wrapper_tests.py',
        )
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)

    selectors = ['owned::expanded', 'owned::second', 'owned::third']
    registry = {
        'wrappers': [{'contracts': selectors}],
        'native': [{'id': 'owned-family', 'env': {'OWNED_FAMILY': 'retained'},
                    'platforms': {'linux': {'tests': ['owned::native'], 'expected': 1}}}],
    }
    monkeypatch.setattr(runner, 'load_registry', lambda: registry)
    monkeypatch.setattr(runner, 'registry_errors', lambda *_: [])
    monkeypatch.setattr(runner, 'ThreadPoolExecutor', InlinePool)
    monkeypatch.setattr(runner, 'sys', SimpleNamespace(
        **(vars(sys) | {'platform': 'linux'}),
    ))
    monkeypatch.setattr(runner, 'os', SimpleNamespace(
        **(vars(runner.os) | {'environ': inherited}),
    ))
    observed = {}

    def fake_pytest(command, *, env, **kwargs):
        selected = command[5:command.index('-o')]
        cases = [f'{selector}[{index}]' for selector in selected
                 for index in range(5 if selector == 'owned::expanded' else 1)]
        # Model pytest's environment-option deselection, not a real child.
        options = shlex.split(env.get('PYTEST_ADDOPTS', ''))
        if '--deselect' in options:
            prefix = options[options.index('--deselect') + 1]
            cases = [case for case in cases if not case.startswith(prefix)]
        if env.get('PYTEST_PLUGINS') == 'owned_drop_plugin':
            cases = [case for case in cases if not case.startswith('owned::third')]
        observed.update(command=command, env=env, selectors=selected, cases=cases)
        suite = ET.Element('testsuite')
        for case in cases:
            ET.SubElement(suite, 'testcase', name=case)
        output = next(arg.split('=', 1)[1] for arg in command
                      if arg.startswith('--junitxml='))
        ET.ElementTree(suite).write(output)
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(runner, 'subprocess', SimpleNamespace(
        run=fake_pytest, STDOUT=subprocess.STDOUT,
        TimeoutExpired=subprocess.TimeoutExpired,
    ))
    monkeypatch.setattr(sys, 'argv', [
        'runner', '--lane', lane, '--report-dir', str(tmp_path / 'reports'),
    ])
    return runner.main(), observed


def test_inherited_options_cannot_remove_a_registered_contract(monkeypatch, tmp_path):
    inherited = {'PYTEST_ADDOPTS': '--deselect owned::second', 'PATH': '/owned/tools'}
    before = inherited.copy()
    result, child = exercise(monkeypatch, tmp_path, inherited)
    assert result == 0
    assert child['selectors'] == ['owned::expanded', 'owned::second', 'owned::third']
    assert child['cases'] == [
        *(f'owned::expanded[{index}]' for index in range(5)),
        'owned::second[0]', 'owned::third[0]',
    ]
    assert 'PYTEST_ADDOPTS' not in child['env']
    assert inherited == before


def test_inherited_plugin_cannot_change_registered_collection(monkeypatch, tmp_path):
    inherited = {'PYTEST_PLUGINS': 'owned_drop_plugin', 'PATH': '/owned/tools'}
    before = inherited.copy()
    result, child = exercise(monkeypatch, tmp_path, inherited)
    assert result == 0
    assert child['cases'][-1] == 'owned::third[0]'
    assert len(child['cases']) == 7
    assert 'PYTEST_PLUGINS' not in child['env']
    assert inherited == before


def test_control_scrubbing_keeps_family_environment_and_failure_cleanup(monkeypatch, tmp_path):
    inherited = {'PYTEST_ADDOPTS': '-k unrelated', 'PYTEST_PLUGINS': 'unrelated',
                 'PATH': '/owned/tools', 'RETAINED_CALLER_VALUE': 'owned'}
    before = inherited.copy()
    result, child = exercise(monkeypatch, tmp_path, inherited, lane='native', returncode=13)
    assert result == 13
    assert child['selectors'] == ['owned::native']
    assert child['env']['OWNED_FAMILY'] == 'retained'
    assert child['env']['RETAINED_CALLER_VALUE'] == 'owned'
    assert child['env']['PATH'].endswith('/owned/tools')
    assert child['env']['RAPTOR_MAX_TEST_SECONDS'] == ''
    assert not {'PYTEST_ADDOPTS', 'PYTEST_PLUGINS'} & child['env'].keys()
    assert inherited == before
    for name in ('HOME', 'TMPDIR', 'RAPTOR_OUT_DIR', 'RAPTOR_REGISTRY_HOME'):
        assert not Path(child['env'][name]).exists()
