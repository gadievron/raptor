"""Full owned factory/closure bodies retain hypothesis confinement on adaptation."""

import ast
import builtins
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from packages.semgrep.runtime import SnapRuntime


SOURCE = Path(__file__).resolve().parents[3] / 'packages/hypothesis_validation/adapters/base.py'


def _factory(sandbox, grants):
    nodes = [n for n in ast.parse(SOURCE.read_text()).body
             if (isinstance(n, ast.FunctionDef)
                 and n.name in {'make_sandbox_runner', '_cmd_file_grants'})
             or (isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == '_SHARED_TMP_ROOTS'
                         for t in n.targets))]

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.sandbox':
            return SimpleNamespace(run=sandbox)
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = {'Path': Path, 'Callable': Callable, 'Any': Any,
                 '__builtins__': dict(vars(builtins), __import__=imported),
                 '_toolchain_read_dirs': lambda command: ['owned-ordinary-toolchain']}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), namespace)
    if grants is not None:
        namespace['_cmd_file_grants'] = lambda command, **kwargs: list(grants)
    return namespace['make_sandbox_runner']


def _runtime(tmp_path):
    class OwnedRuntime(SnapRuntime):
        def validate(self):
            pass  # The resolver's trust checks have separate focused controls.

    return OwnedRuntime('/snap/bin/semgrep', tmp_path / 'app', tmp_path / 'base',
                        tmp_path / 'base/usr/bin/python3.10', tmp_path / 'app/bin/pysemgrep',
                        tmp_path / 'app/lib/python3.10/site-packages',
                        tmp_path / 'base/usr/lib/python3.10', '1.56.0', ('owned',))


def test_hypothesis_runtime_adaptation_preserves_policy_and_original_closure(tmp_path):
    calls = []

    def sandbox(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, 'owned', '')

    rule = tmp_path / 'rule.yaml'
    rule.write_text('owned metadata; never parsed\n')
    factory = _factory(sandbox, [str(rule)])
    globals_before = dict(factory.__globals__)
    environment_before = dict(os.environ)
    target, output = tmp_path / 'target', tmp_path / 'output'
    original = factory(target=target, output=output, readable_paths=['owned-cache'],
                       caller_label='owned-hypothesis')
    spec = _runtime(tmp_path)
    adapted = original.with_semgrep_runtime(spec)
    assert adapted is not original
    supplied = {'PATH': '/host/bin', 'PYTHONPATH': '/host/injection', 'LD_PRELOAD': '/host/evil.so'}
    command = [*spec.command_prefix, 'scan', '--config', str(rule)]
    adapted(command, env=supplied, capture_output=True, text=True, timeout=4, shell=True)
    argv, policy = calls[0]
    assert argv == command and policy['target'] == str(target) and policy['output'] == str(output)
    assert policy['block_network'] is True and policy['restrict_reads'] is True
    assert policy['fake_home'] is True and policy['caller_label'] == 'owned-hypothesis'
    assert policy['readable_paths'] == ['owned-cache']
    assert policy['tool_paths'] == [*spec.tool_paths, str(rule)]
    assert policy['env']['PYTHONPATH'] == str(spec.site_packages)
    assert 'LD_PRELOAD' not in policy['env'] and 'shell' not in policy
    assert supplied['PYTHONPATH'] == '/host/injection'
    original(['owned-ordinary-command'], env={'PATH': '/usr/bin'}, text=True)
    assert calls[1][1]['tool_paths'] == ['owned-ordinary-toolchain', str(rule)]
    assert calls[1][1]['env'] == {'PATH': '/usr/bin'}
    assert os.environ == environment_before
    assert factory.__globals__ == globals_before


def test_hypothesis_runtime_command_mismatch_never_reaches_sandbox(tmp_path):
    factory = _factory(lambda *a, **k: pytest.fail('mismatched command executed'), [])
    original = factory(target=tmp_path, output=tmp_path / 'output')
    adapted = original.with_semgrep_runtime(_runtime(tmp_path))
    with pytest.raises(ValueError, match='does not match'):
        adapted(['unrelated-command'], env={})


def test_actual_input_grants_do_not_expand_the_runtime_frontend(tmp_path):
    calls = []

    def sandbox(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, '', '')

    spec = _runtime(tmp_path)
    spec.frontend.parent.mkdir(parents=True)
    spec.frontend.write_text('owned frontend metadata; never executed\n')
    rule = tmp_path / 'rules' / 'owned.yaml'
    rule.parent.mkdir()
    rule.write_text('owned rule metadata; never parsed\n')
    original = _factory(sandbox, None)(target=tmp_path / 'target',
                                       output=tmp_path / 'output')
    adapted = original.with_semgrep_runtime(spec)
    adapted([*spec.command_prefix, 'scan', '--config', str(rule)], env={})
    assert calls[0]['tool_paths'] == [*spec.tool_paths, str(rule.parent)]
    assert str(spec.frontend.parent) not in calls[0]['tool_paths']
