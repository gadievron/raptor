"""Actual scanner function bodies with owned execution and import boundaries.

The module entrypoint primes a platform parent-death helper. These tests load
only the complete selected functions, so collection cannot perform that probe.
"""

import ast
import builtins
from collections.abc import Callable
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages import semgrep
from packages.semgrep import runtime


SOURCE = Path(__file__).resolve().parents[3] / 'packages/static-analysis/scanner.py'


def _functions(names, namespace, imports):
    nodes = [n for n in ast.parse(SOURCE.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes} == set(names)

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if name in imports:
            if name == 'importlib.util' and not fromlist:
                return SimpleNamespace(util=imports[name])
            return imports[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    env = dict(namespace, __builtins__=dict(vars(builtins), __import__=imported))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), env)
    return SimpleNamespace(**{name: env[name] for name in names})


def _runtime(tmp_path):
    class OwnedRuntime(runtime.SnapRuntime):
        def validate(self):
            return None  # Resolver trust is exercised in its own focused tests.

    return OwnedRuntime('/snap/bin/semgrep', tmp_path / 'app', tmp_path / 'base',
                        tmp_path / 'base/usr/bin/python3.10', tmp_path / 'app/bin/pysemgrep',
                        tmp_path / 'app/lib/python3.10/site-packages',
                        tmp_path / 'base/usr/lib/python3.10', '1.56.0', ('owned',))


def test_scanner_wrapper_keeps_runtime_environment_and_grants_local(tmp_path):
    spec = _runtime(tmp_path)
    calls = []

    def sandbox(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=1, stdout='owned-output', stderr='')

    config = SimpleNamespace(DEFAULT_TIMEOUT=30, get_safe_env=lambda: {'PATH': '/usr/bin:/bin'})
    wrapper = _functions(['run'], {'RaptorConfig': config},
                         {'core.sandbox': SimpleNamespace(run=sandbox)}).run
    supplied = {'PYTHONPATH': '/host/injection', 'PYTHONINSPECT': '1', 'PATH': '/host/bin',
                'LD_PRELOAD': '/host/evil.so', 'BASH_ENV': '/host/hook',
                'UNKNOWN_SECRET': 'secret'}
    command = [*spec.command_prefix, 'scan']
    assert wrapper(command, target=str(tmp_path), output=str(tmp_path / 'output'),
                   fake_home=True, env=supplied, semgrep_runtime=spec) == (1, 'owned-output', '')
    assert supplied['PYTHONPATH'] == '/host/injection'
    _, options = calls[0]
    assert options['env']['PYTHONPATH'] == str(spec.site_packages)
    assert not ({'PYTHONINSPECT', 'LD_PRELOAD', 'BASH_ENV', 'UNKNOWN_SECRET'} & options['env'].keys())
    assert options['env_caller_filtered'] is True and 'strict_env' not in options
    assert options['tool_paths'] == list(spec.tool_paths)
    assert options['block_network'] is True and options['fake_home'] is True


@pytest.mark.parametrize("version", ["1.56.0", "9.9.9"])
def test_scanner_converts_one_json_scan_and_preserves_actual_metadata(tmp_path, monkeypatch, version):
    monkeypatch.delenv("RAPTOR_SEMGREP_OFFLINE", raising=False)
    spec = _runtime(tmp_path)
    payload = json.dumps({'version': version, 'errors': [],
                          'paths': {'scanned': ['unsafe.py', 'safe.py']},
                          'results': [{'check_id': 'owned-eval', 'path': 'unsafe.py',
                                       'start': {'line': 2, 'col': 9},
                                       'end': {'line': 2, 'col': 25},
                                       'extra': {'message': 'Owned finding', 'severity': 'WARNING',
                                                 'metadata': {}}}]})
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return 1, payload, ''

    class ProxyLoader:
        def exec_module(self, module):
            module.proxy_hosts_for_semgrep = lambda: ['unused.invalid']

    util = SimpleNamespace(spec_from_file_location=lambda *a: SimpleNamespace(loader=ProxyLoader()),
                           module_from_spec=lambda spec: SimpleNamespace())
    package = SimpleNamespace(resolve_snap_runtime=lambda selected: spec,
                              SnapRuntimeError=runtime.SnapRuntimeError,
                              scope_isolation_available=lambda selected: False,
                              build_cmd=semgrep.build_cmd,
                              convert_semgrep_json_to_sarif=semgrep.convert_semgrep_json_to_sarif)
    config = SimpleNamespace(SEMGREP_OFFLINE=False, SEMGREP_RULE_TIMEOUT=5,
                             SEMGREP_PACK_TIMEOUT=30, get_safe_env=lambda: {'PATH': '/usr/bin:/bin'})
    env = {'RaptorConfig': config, 'Path': Path, 'Callable': Callable,
           'semgrep_pkg': package, 'shutil': SimpleNamespace(which=lambda name: '/snap/bin/semgrep'),
           'logger': logging.getLogger('owned-scanner-snap'), 'run': execute,
           '__file__': str(SOURCE), '_MAX_TOOL_JSON_BYTES': 1024 * 1024,
           'validate_sarif': lambda path: json.loads(path.read_text())['version'] == '2.1.0',
           'SandboxSetupError': RuntimeError, 'os': __import__('os'), 're': __import__('re')}
    functions = _functions(['run_single_semgrep', '_sanitize_pack_name'], env,
                           {'importlib.util': util,
                            'packages.semgrep.runner': SimpleNamespace(
                                _warn_scope_isolation_once=lambda *a: None)})
    out = tmp_path / 'output'
    out.mkdir()
    target = tmp_path / 'target'
    target.mkdir()
    rule = tmp_path / 'rule.yaml'
    rule.write_text('owned local rule; never executed\n')
    sarif, success = functions.run_single_semgrep('owned', str(rule), target, out, 30)
    assert len(calls) == 1
    if version != spec.version:
        assert not success and not (out / 'semgrep_owned.json').exists()
        assert (out / 'semgrep_owned.json.rejected').read_text() == payload
        assert 'version does not match' in (out / 'semgrep_owned.stderr.log').read_text()
        return
    assert success
    command, options = calls[0]
    assert command[:2] == list(spec.command_prefix)
    assert '--json' in command and '--json-output' not in command
    assert options['semgrep_runtime'] is spec and options['proxy_hosts'] is None
    assert (out / 'semgrep_owned.json').read_text() == payload
    converted = json.loads(Path(sarif).read_text())
    assert len(converted['runs'][0]['results']) == 1
