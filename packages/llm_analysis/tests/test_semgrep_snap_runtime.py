"""The complete patch-gate factory retains its scratch and network boundary."""

import ast
import os
from pathlib import Path
import subprocess
from typing import Callable

import pytest

from packages.semgrep.runtime import SnapRuntime


SOURCE = Path(__file__).resolve().parents[1] / 'patch_gate.py'


def _factory():
    node, = [n for n in ast.parse(SOURCE.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == '_make_runner']
    namespace = {'Path': Path, 'Callable': Callable}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    return namespace['_make_runner']


def _runtime(tmp_path):
    class OwnedRuntime(SnapRuntime):
        def validate(self):
            pass

    return OwnedRuntime('/snap/bin/semgrep', tmp_path / 'app', tmp_path / 'base',
                        tmp_path / 'base/usr/bin/python3.10', tmp_path / 'app/bin/pysemgrep',
                        tmp_path / 'app/lib/python3.10/site-packages',
                        tmp_path / 'base/usr/lib/python3.10', '1.56.0', ('owned',))


def test_patch_gate_runtime_adapter_preserves_scoped_policy_and_original(tmp_path):
    calls = []

    def sandbox(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, 'owned', '')

    factory = _factory()
    globals_before = dict(factory.__globals__)
    environment_before = dict(os.environ)
    original = factory(sandbox, tmp_path)
    spec = _runtime(tmp_path)
    adapted = original.with_semgrep_runtime(spec)
    assert adapted is not original
    supplied = {'PATH': '/host/bin', 'PYTHONPATH': '/host/injection', 'BASH_ENV': '/host/hook'}
    command = [*spec.command_prefix, 'scan']
    adapted(command, env=supplied, capture_output=True, text=True, timeout=3, shell=True)
    argv, policy = calls[0]
    assert argv == command and policy['target'] == policy['output'] == str(tmp_path)
    assert policy['block_network'] is True and policy['fake_home'] is True
    assert policy['caller_label'] == 'patch-gate' and policy['env_caller_filtered'] is True
    assert policy['tool_paths'] == list(spec.tool_paths)
    assert policy['env']['PYTHONPATH'] == str(spec.site_packages)
    assert 'BASH_ENV' not in policy['env'] and 'shell' not in policy
    assert supplied['PYTHONPATH'] == '/host/injection'
    original(['owned-ordinary-command'], env={'PATH': '/usr/bin'}, text=True)
    assert 'tool_paths' not in calls[1][1] and calls[1][1]['env'] == {'PATH': '/usr/bin'}
    assert os.environ == environment_before and factory.__globals__ == globals_before


def test_patch_gate_runtime_mismatch_refuses_before_execution(tmp_path):
    original = _factory()(lambda *a, **k: pytest.fail('mismatched command executed'), tmp_path)
    adapted = original.with_semgrep_runtime(_runtime(tmp_path))
    with pytest.raises(ValueError, match='does not match'):
        adapted(['unrelated-command'], env={})
