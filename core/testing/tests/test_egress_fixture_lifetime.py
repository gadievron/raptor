"""Real fixture stacks restore egress routes after undo, errors and interrupts."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.slow
ROOT = Path(__file__).resolve().parents[3]
STACKS = {
    'root': None,
    'llm': 'core/llm/conftest.py',
    'audit': 'core/audit/tests/conftest.py',
    'dataflow': 'core/dataflow/tests/conftest.py',
}


@pytest.mark.parametrize('stack', STACKS)
@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('enabled', [False, True])
def test_real_fixture_stack_preserves_caller(stack, mode, enabled, tmp_path):
    job = tmp_path / 'child'
    job.mkdir()
    sources = [('root_guards', ROOT / 'conftest.py')]
    if STACKS[stack]:
        sources.append(('directory_guards', ROOT / STACKS[stack]))
    for name, source in sources:
        (job / (name + '.py')).write_text(
            'from pathlib import Path\n__file__ = ' + repr(str(source))
            + "\nexec(compile(Path(__file__).read_text(), __file__, 'exec'), globals())\n")
    (job / 'caller.py').write_text('''import json
import os
from pathlib import Path
import pytest
from core.llm import egress
from core.run import pin
from core.testing.llm_env import PROXY_ENV_VARS, DEFAULT_OLLAMA_HOST
JOB = Path(__file__).resolve().parent
LOCAL = LOCAL_VALUE
MODE = MODE_VALUE
ENABLED = ENABLED_VALUE
SEEN = 0

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global ORIGINAL, ROUTE, LOCK, FROZEN
    ORIGINAL = {'HTTPS_PROXY': 'http://caller.invalid:3128'}
    egress._enabled = ENABLED
    egress._original_proxy_env = ORIGINAL
    LOCK = egress._STATE_LOCK
    for index, name in enumerate(PROXY_ENV_VARS):
        if index % 3 == 0:
            os.environ.pop(name, None)
        else:
            os.environ[name] = '' if index % 3 == 1 else 'http://127.0.0.1:9'
    os.environ['OLLAMA_HOST'] = 'http://caller.invalid:11434'
    ROUTE = {name: (name in os.environ, os.environ.get(name)) for name in (*PROXY_ENV_VARS, 'OLLAMA_HOST')}
    FROZEN = {}
    pin._frozen_pins = FROZEN
    pin.set_process_project('borrowed', threaded=True)

def expected():
    return {name: (False, None) if LOCAL and name != 'OLLAMA_HOST' else
            (True, DEFAULT_OLLAMA_HOST) if LOCAL else ROUTE[name]
            for name in (*PROXY_ENV_VARS, 'OLLAMA_HOST')}

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    report = {
        'enable_flag': egress._enabled is ENABLED,
        'cache_identity': egress._original_proxy_env is ORIGINAL,
        'cache_contents': ORIGINAL == {'HTTPS_PROXY': 'http://caller.invalid:3128'},
        'lock_identity': egress._STATE_LOCK is LOCK,
        'lock_released': not LOCK.locked(),
        'environment': {name: (name in os.environ, os.environ.get(name)) for name in ROUTE} == ROUTE,
        'process_guard_preserved': pin._frozen_pins is FROZEN and pin._process_project == 'borrowed' and pin._process_project_set and pin._process_project_threaded,
        'expected_bodies': SEEN == (1 if MODE == 'interrupt' else 2),
    }
    (JOB / 'restoration.json').write_text(json.dumps(report))
'''.replace('LOCAL_VALUE', repr(stack != 'root')).replace('MODE_VALUE', repr(mode)).replace('ENABLED_VALUE', repr(enabled)))
    (job / 'test_scope.py').write_text('''import json
import os
import subprocess
import sys
import caller
from core.llm import egress
from core.run import pin

def route():
    return {name: (name in os.environ, os.environ.get(name)) for name in caller.ROUTE}

def test_01_scope(monkeypatch):
    caller.SEEN += 1
    assert egress._enabled is False
    assert egress._original_proxy_env is None
    assert route() == caller.expected()
    assert pin._process_project is None
    assert pin._process_project_set is False
    monkeypatch.setattr(egress, '_enabled', True)
    monkeypatch.setattr(egress, '_original_proxy_env', {'HTTPS_PROXY': 'body'})
    monkeypatch.setenv('NO_PROXY', 'body')
    monkeypatch.undo()
    assert egress._enabled is False
    assert egress._original_proxy_env is None
    assert route() == caller.expected()
    assert pin._process_project is None
    with egress._STATE_LOCK:
        egress._original_proxy_env = {'NO_PROXY': 'local-only'}
    os.environ['NO_PROXY'] = 'owned.invalid'
    egress._enabled = False
    if caller.MODE == 'error':
        raise AssertionError('intentional egress body failure')
    if caller.MODE == 'interrupt':
        raise KeyboardInterrupt('intentional egress interruption')

def test_02_fresh():
    caller.SEEN += 1
    assert egress._enabled is False
    assert egress._original_proxy_env is None
    assert route() == caller.expected()
    code = "import os,json; print(json.dumps({k:[k in os.environ,os.environ.get(k)] for k in KEYS}))"
    code = code.replace('KEYS', repr(list(caller.ROUTE)))
    child = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == {k:list(v) for k,v in caller.expected().items()}
''')
    env = dict(os.environ)
    for key in ('RAPTOR_RANDOMISE_TESTS', 'RAPTOR_TEST_LIVE_LLM'):
        env.pop(key, None)
    for key, leaf in [('HOME', 'home'), ('TMPDIR', 'tmp'), ('XDG_DATA_HOME', 'data'),
                      ('XDG_CONFIG_HOME', 'config'), ('XDG_CACHE_HOME', 'cache'),
                      ('RAPTOR_OUT_DIR', 'out')]:
        path = job / leaf
        path.mkdir()
        env[key] = str(path)
    env['PYTHONPATH'] = str(job) + os.pathsep + str(ROOT)
    args = [sys.executable, '-m', 'pytest', '--noconftest', '-c', str(ROOT / 'pytest.ini'),
            '-p', 'core.testing.llm_tripwire']
    for name, _ in sources:
        args += ['-p', name]
    args += ['-p', 'caller', str(job / 'test_scope.py'), '-q', '-m', '', '--tb=short']
    result = subprocess.run(args, cwd=job, env=env, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    assert result.returncode == {'normal':0, 'error':1, 'interrupt':2}[mode], output
    if mode != 'normal':
        assert 'intentional egress' in output
    report = json.loads((job / 'restoration.json').read_text())
    assert all(report.values()), report
