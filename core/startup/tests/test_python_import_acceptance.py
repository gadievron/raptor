"""Opt-in real helper and dependency checks in disposable protected sessions."""
import os
from pathlib import Path
import subprocess
import sys
import venv

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow, pytest.mark.skipif(
    os.environ.get('RAPTOR_INSTALL_PROTECTION_ACCEPTANCE') != '1',
    reason='explicit installation-protection host acceptance')]


def test_real_helpers_dependencies_and_cache_poisoning(tmp_path, require_install_mounts):
    root = Path(__file__).resolve().parents[3]
    home, output, scratch = (tmp_path/name for name in ('home', 'output', 'scratch'))
    for directory in (home, output, scratch):
        directory.mkdir()
    executable = sys.executable
    poison = output / 'poison'
    poison.mkdir()
    (poison/'_raptor_writable_probe.py').write_text('VALUE = 99\n')
    # The same selected interpreter can use an ordinary writable search path.
    baseline = subprocess.run([executable, '-I', '-c',
        'import sys; sys.path.insert(0, sys.argv[1]); '
        'import _raptor_writable_probe; assert _raptor_writable_probe.VALUE == 99', str(poison)],
        capture_output=True, text=True, timeout=15)
    assert baseline.returncode == 0, baseline.stderr
    env = dict(os.environ, HOME=str(home), TMPDIR=str(scratch), RAPTOR_WORK_DIR=str(scratch),
               RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root), _RAPTOR_TRUSTED='1',
               XDG_CACHE_HOME=str(home/'cache'), XDG_DATA_HOME=str(home/'data'),
               XDG_CONFIG_HOME=str(home/'config'), XDG_STATE_HOME=str(home/'state'),
               PATH=str(Path(executable).parent)+os.pathsep+os.environ.get('PATH', os.defpath))
    for variable in ('RAPTOR_REGISTRY_HOME', 'CI', 'RAPTOR_CI', '_RAPTOR_DEP_CHECK',
                     'PYTHONPATH', 'PYTHONPYCACHEPREFIX', 'PYTHONHOME'):
        env.pop(variable, None)
    code = r'''
import importlib.util, json, os, pathlib, subprocess, sys
root, poison, output = map(pathlib.Path, sys.argv[1:4])
# Construct real malicious bytecode for a legitimate module's cache filename.
# It must not execute when normal imports resume after the helper bootstrap.
import fractions
source = pathlib.Path(fractions.__file__)
sys.modules.pop('fractions')
sys.pycache_prefix = str(output/'hostile-cache')
cache = pathlib.Path(importlib.util.cache_from_source(str(source)))
cache.parent.mkdir(parents=True)
from importlib._bootstrap_external import _code_to_timestamp_pyc
payload = compile('raise AssertionError("writable bytecode cache executed")', str(source), 'exec')
metadata = source.stat()
cache.write_bytes(_code_to_timestamp_pyc(payload, int(metadata.st_mtime), metadata.st_size))
control = subprocess.run([sys.executable, '-I', '-c',
    'import sys; sys.pycache_prefix = sys.argv[1]; import fractions', sys.pycache_prefix],
    capture_output=True, text=True, timeout=15)
assert control.returncode != 0 and 'writable bytecode cache executed' in control.stderr, control.stderr
os.environ['PYTHONPYCACHEPREFIX'] = sys.pycache_prefix
sys.path[:0] = [str(poison), str(root)]
import core.startup.process_init
assert sys.pycache_prefix is None and sys.dont_write_bytecode
assert str(poison) not in sys.path
assert 'PYTHONPYCACHEPREFIX' not in os.environ
import fractions
assert fractions.Fraction(1, 2).denominator == 2
try: import _raptor_writable_probe
except ModuleNotFoundError: pass
else: raise AssertionError('writable module remained importable')
# Load actual installed dependencies and their native/stdlib dependencies.
import requests, pydantic, openai, yaml, sqlite3, ssl, ctypes
assert requests.Request('GET', 'https://example.invalid/').prepare().url.endswith('/')
assert pydantic.TypeAdapter(int).validate_python('42') == 42
assert yaml.safe_load('value: 42')['value'] == 42
assert openai.OpenAI
assert ssl.OPENSSL_VERSION and ctypes.sizeof(ctypes.c_int) > 0
from core.understand_graph.store import open_graph
from core.understand_graph.queries import graph_summary
connection = open_graph(output/'graph/raptor.graph.sqlite')
connection.close()
assert graph_summary(output/'graph/raptor.graph.sqlite')['exists']
helpers = ('raptor-project-manager', 'raptor-self-test', 'raptor-graph-query',
           'raptor-audit', 'raptor-describe')
for name in helpers:
    reply = subprocess.run([str(root/'libexec'/name), '--help'], cwd=poison,
                           capture_output=True, text=True, timeout=45)
    assert reply.returncode == 0, (name, reply.stdout, reply.stderr)
    assert 'usage:' in reply.stdout.lower(), (name, reply.stdout)
    print('PASS helper '+name, flush=True)
fixture = output/'fixture'
fixture.mkdir()
(fixture/'main.c').write_text('int main(void) { return 0; }\n')
for arguments in (['create', 'import-hygiene-acceptance', '--target', str(fixture)], ['status']):
    reply = subprocess.run([str(root/'libexec/raptor-project-manager'), *arguments], cwd=poison,
                           capture_output=True, text=True, timeout=30)
    assert reply.returncode == 0, (arguments, reply.stdout, reply.stderr)
    assert 'import-hygiene-acceptance' in reply.stdout, reply.stdout
# An isolated interpreter missing application packages must report the normal
# dependency diagnostic, not succeed through a writable substitute package.
missing = subprocess.run([sys.executable, '-I', '-S', '-c',
    'import sys; sys.path.insert(0, sys.argv[1]); import core.startup.process_init', str(root)],
    capture_output=True, text=True, timeout=30)
assert missing.returncode == 1, (missing.returncode, missing.stderr)
assert 'missing dependencies:' in missing.stderr, missing.stderr
assert 'Traceback' not in missing.stderr, missing.stderr
assert os.statvfs(root).f_flag & os.ST_RDONLY, 'installation is no longer read-only'
print(json.dumps({'helpers': list(helpers), 'dependencies': 'passed',
                  'cache_poisoning': 'blocked', 'project_lifecycle': 'passed',
                  'graph': 'passed', 'missing_dependencies': 'diagnosed'}), flush=True)
'''
    reply = subprocess.run([executable, '-I', '-S', '-B', str(root/'core/startup/install_guard.py'),
                            '--', executable, '-c', code, str(root), str(poison), str(output)],
                           env=env, cwd=output, capture_output=True, text=True, timeout=240)
    (tmp_path/'protected.stdout.log').write_text(reply.stdout)
    (tmp_path/'protected.stderr.log').write_text(reply.stderr)
    assert reply.returncode == 0, (reply.stdout, reply.stderr)
    assert '"cache_poisoning": "blocked"' in reply.stdout


@pytest.mark.parametrize('system_packages', [False, True], ids=['isolated-venv', 'system-site-venv'])
def test_virtualenv_dependency_and_stdlib_paths(tmp_path, require_install_mounts, system_packages):
    import sysconfig
    root = Path(__file__).resolve().parents[3]
    environment = tmp_path/'venv with spaces'
    venv.EnvBuilder(with_pip=False, system_site_packages=system_packages).create(environment)
    executable = environment/'bin/python3'
    # A dependency actually installed in the new venv, without pip or network.
    layout = subprocess.check_output([str(executable), '-I', '-c',
        'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True, timeout=15).strip()
    dependency = Path(layout)/'_raptor_venv_dependency.py'
    dependency.write_text('VALUE = 42\n')
    home, output, scratch = (tmp_path/name for name in ('home', 'output', 'scratch'))
    for directory in (home, output, scratch):
        directory.mkdir()
    userbase = tmp_path/'user base'
    user_site = Path(sysconfig.get_path('purelib', scheme='posix_user', vars={'userbase': str(userbase)}))
    user_site.mkdir(parents=True)
    (user_site/'_raptor_user_dependency.py').write_text('VALUE = 7\n')
    env = dict(os.environ, HOME=str(home), TMPDIR=str(scratch), RAPTOR_WORK_DIR=str(scratch),
               RAPTOR_OUT_DIR=str(output), RAPTOR_DIR=str(root), _RAPTOR_DEP_CHECK='0',
               PYTHONUSERBASE=str(userbase),
               PATH=str(executable.parent)+os.pathsep+os.environ.get('PATH', os.defpath))
    for variable in ('RAPTOR_REGISTRY_HOME', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONPYCACHEPREFIX'):
        env.pop(variable, None)
    code = r'''
import os, pathlib, sys
sys.path.insert(0, os.environ['RAPTOR_DIR'])
import core.startup.process_init
import _raptor_venv_dependency, fractions, sqlite3, ssl, ctypes
assert _raptor_venv_dependency.VALUE == 42
assert fractions.Fraction(1, 3).denominator == 3
assert ssl.OPENSSL_VERSION and ctypes.sizeof(ctypes.c_int) > 0
assert sqlite3.connect(':memory:').execute('select 42').fetchone() == (42,)
assert pathlib.Path(_raptor_venv_dependency.__file__).is_relative_to(pathlib.Path(sys.prefix))
assert os.statvfs(_raptor_venv_dependency.__file__).f_flag & os.ST_RDONLY
if sys.argv[1] == 'enabled':
    import _raptor_user_dependency
    assert _raptor_user_dependency.VALUE == 7
else:
    try: import _raptor_user_dependency
    except ModuleNotFoundError: pass
    else: raise AssertionError('isolated venv unexpectedly enabled user packages')
'''
    reply = subprocess.run([str(executable), '-I', '-S', '-B', str(root/'core/startup/install_guard.py'),
                            '--', str(executable), '-c', code, 'enabled' if system_packages else 'disabled'],
                           env=env, cwd=output, capture_output=True, text=True, timeout=120)
    (tmp_path/'protected.stdout.log').write_text(reply.stdout)
    (tmp_path/'protected.stderr.log').write_text(reply.stderr)
    assert reply.returncode == 0, (reply.stdout, reply.stderr)
