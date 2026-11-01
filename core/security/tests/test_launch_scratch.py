"""Session-authenticated scratch, independent of mutable tool environment."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from core.config import RaptorConfig
from core.project import sessions
from core.security import env_sanitisation, launch_scratch

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX launcher metadata')
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def bound(tmp_path, monkeypatch):
    root = tmp_path / f'raptor-{os.geteuid()}' / 'session-12345-678'
    root.mkdir(parents=True, mode=0o700)
    metadata = launch_scratch.create(root)
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    monkeypatch.delitem(sessions.__dict__, 'SESSIONS_DIR', raising=False)
    monkeypatch.setenv('RAPTOR_SESSION_PID', '12345')
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'credential')
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', '')
    monkeypatch.setattr(launch_scratch, '_metadata_path', None)
    monkeypatch.setattr(launch_scratch, '_refresh_delegation', lambda entry: None)
    monkeypatch.setattr(sessions, '_identity_for', lambda pid: {'starttime': '1', 'boot_id': 'boot'})
    monkeypatch.setattr(sessions, '_identity_matches', lambda pid, fields: True)
    assert sessions.record_session('project', 12345, 'credential') == 12345
    entry = sessions._sessions_dir() / '12345'
    fields = sessions._parse_entry(entry)
    fields['scratch_metadata'] = str(metadata)
    sessions._atomic_write(entry, sessions._entry_content('project', fields))
    monkeypatch.setattr(launch_scratch, '_restored', False)
    monkeypatch.setattr(env_sanitisation, '_subprocess_tmpdir', None)
    return root, metadata


def test_session_record_wins_over_both_injected_environment_paths(bound, monkeypatch):
    root, metadata = bound
    monkeypatch.setenv('TMPDIR', '/attacker/tmp')
    monkeypatch.setenv('_RAPTOR_LAUNCH_METADATA', '/attacker/metadata.json')
    launch_scratch.restore()
    assert RaptorConfig.get_safe_env()['TMPDIR'] == str(root / 'tmp')
    monkeypatch.setenv('TMPDIR', '/changed/later')
    assert RaptorConfig.get_safe_env()['TMPDIR'] == str(root / 'tmp')
    assert sessions.record_session('changed-project', 12345) == 12345
    assert sessions._parse_entry(sessions._sessions_dir() / '12345')['scratch_metadata'] == str(metadata)


def test_missing_context_never_adopts_a_plausibly_named_tmpdir(tmp_path, monkeypatch):
    root = tmp_path / f'raptor-{os.geteuid()}' / 'attacker-chosen'
    root.mkdir(parents=True, mode=0o700)
    monkeypatch.setenv('TMPDIR', str(root))
    monkeypatch.delenv('_RAPTOR_SCRATCH_AUTH', raising=False)
    monkeypatch.setattr(sessions, 'resolve_session_pid', lambda: None)
    monkeypatch.setattr(launch_scratch, '_restored', False)
    monkeypatch.setattr(env_sanitisation, '_subprocess_tmpdir', None)
    launch_scratch.restore()
    assert RaptorConfig.get_safe_env()['TMPDIR'] == env_sanitisation._default_subprocess_tmpdir
    assert RaptorConfig.get_safe_env()['TMPDIR'] != str(root)
    assert not list(root.iterdir())


@pytest.mark.parametrize('component', ['metadata', 'launch.json', 'tmp'])
def test_metadata_and_scratch_symlinks_are_refused(bound, component):
    root, metadata = bound
    target = metadata if component == 'launch.json' else root / component
    original = target.with_name(target.name + '.original')
    target.rename(original)
    target.symlink_to(original, target_is_directory=component != 'launch.json')
    with pytest.raises(OSError):
        launch_scratch.restore()


@pytest.mark.parametrize('kind', ['oversized', 'redirect', 'hardlink', 'public', 'unsealed'])
def test_invalid_metadata_is_not_silently_replaced_by_tmp(bound, kind):
    root, metadata = bound
    if kind == 'oversized': metadata.write_text(' ' * 4097)
    elif kind == 'redirect': metadata.write_text(json.dumps({'v': 1, 'tmpdir': '/attacker', 'protected': False}))
    elif kind == 'hardlink': os.link(metadata, root / 'alias')
    elif kind == 'public': metadata.chmod(0o644)
    else: metadata.write_text(json.dumps({'v': 1, 'tmpdir': str(root / 'tmp'), 'protected': True}))
    with pytest.raises((OSError, ValueError)):
        launch_scratch.restore()


def test_recorded_scratch_is_usable_by_a_child_after_helper_exit(tmp_path):
    root = tmp_path / f'raptor-{os.geteuid()}' / 'session-12345-890'
    root.mkdir(parents=True, mode=0o700)
    launch_scratch.create(root)
    report = tmp_path / 'report'
    child = "import os,pathlib,sys,time; time.sleep(.3); " \
            "p=pathlib.Path(os.environ['TMPDIR'])/'probe'; p.write_text('ok'); " \
            "pathlib.Path(sys.argv[1]).write_text('ok')"
    parent = "import os,subprocess,sys; " \
             "subprocess.Popen([sys.executable,'-I','-c',sys.argv[1],sys.argv[2]], " \
             "env={**os.environ,'TMPDIR':sys.argv[3]}, stdin=subprocess.DEVNULL, " \
             "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
    result = subprocess.run([sys.executable, '-I', '-c', parent, child, str(report),
                             str(root / 'tmp')], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    deadline = time.monotonic() + 5
    while not report.exists() and time.monotonic() < deadline:
        time.sleep(.02)
    assert report.read_text() == 'ok'


def test_darwin_default_uses_os_private_directory(monkeypatch):
    called = []
    def confstr(key):
        called.append(key)
        return '/private/var/folders/example/T/'
    monkeypatch.setattr(os, 'confstr', confstr)
    monkeypatch.setenv('TMPDIR', '/attacker/tmp')
    assert env_sanitisation._system_tmpdir('darwin') == '/private/var/folders/example/T/'
    assert called == [65537]


@pytest.mark.parametrize('answer', [None, '', '/tmp', '/private/tmp/', 'relative'])
def test_darwin_private_default_failure_never_becomes_public_tmp(monkeypatch, answer):
    monkeypatch.setattr(os, 'confstr', lambda key: answer)
    with pytest.raises(OSError):
        env_sanitisation._system_tmpdir('darwin')


def test_parallel_instances_keep_operator_base_and_separate_child_contexts(tmp_path):
    base = tmp_path / 'chosen tmp base'
    base.mkdir()
    home = tmp_path / 'home'
    home.mkdir()
    registry = tmp_path / 'registry'
    code = r'''
import json,os,pathlib,subprocess,sys
sys.path.insert(0,sys.argv[1])
from core.project import sessions
from core.security import launch_scratch
pid=os.getpid()
root=pathlib.Path(os.environ['TMPDIR'])/('raptor-'+str(os.geteuid()))/('session-'+str(pid)+'-123')
root.mkdir(parents=True,mode=0o700)
metadata=launch_scratch.create(root)
# A Python proxy stands in for the real frontend's process name on both OSes.
sessions._comm=lambda p:'claude'
assert sessions.record_session('project',pid,'credential-'+str(pid))==pid
entry=sessions._sessions_dir()/str(pid)
fields=sessions._parse_entry(entry)
fields['scratch_metadata']=str(metadata)
sessions._atomic_write(entry,sessions._entry_content('project',fields))
os.environ.update(RAPTOR_SESSION_PID=str(pid),RAPTOR_SESSION_TOKEN=fields['token'])
import core.startup.process_init
core.startup.process_init.init()
from core.config import RaptorConfig
expected=str(root/'tmp')
os.environ['TMPDIR']='/late/attacker/value'
assert RaptorConfig.get_safe_env()['TMPDIR']==expected
print('ready',flush=True)
sys.stdin.readline()
# Match self-test isolation: keep scratch credentials but no project identity.
env=RaptorConfig.get_safe_env()
for key in ('RAPTOR_SESSION_PID','RAPTOR_SESSION_TOKEN'):env.pop(key,None)
env.update(HOME=str(root/'isolated-home'),RAPTOR_REGISTRY_HOME=str(root/'isolated-registry'))
child=r"""
import json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
import core.startup.process_init
from core.config import RaptorConfig
env=RaptorConfig.get_safe_env()
assert env['TMPDIR']==sys.argv[2],env['TMPDIR']
assert not os.environ.get('RAPTOR_SESSION_TOKEN')
(pathlib.Path(env['TMPDIR'])/'child-probe').write_text('ok')
print(env['TMPDIR'])
"""
result=subprocess.run([sys.executable,'-I','-c',child,sys.argv[1],expected],env=env,capture_output=True,text=True)
assert result.returncode==0,result.stderr
print(result.stdout.strip(),flush=True)
'''
    env = dict(os.environ, HOME=str(home), TMPDIR=str(base), RAPTOR_REGISTRY_HOME=str(registry), CI='1')
    for key in ('_RAPTOR_SCRATCH_AUTH', 'RAPTOR_SESSION_PID', 'RAPTOR_SESSION_TOKEN'):
        env.pop(key, None)
    processes = [subprocess.Popen([sys.executable, '-I', '-c', code, str(ROOT)],
                                 env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True) for _ in range(2)]
    try:
        for process in processes:
            assert process.stdout.readline().strip() == 'ready'
        paths = []
        for process in processes:
            output, error = process.communicate('go\n', timeout=15)
            assert process.returncode == 0, error
            path = Path(output.strip())
            assert base in path.parents
            assert (path / 'child-probe').read_text() == 'ok'
            paths.append(path)
        assert paths[0] != paths[1]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


@pytest.mark.parametrize('mutation', ['token', 'identity', 'issuer', 'symlink', 'hardlink'])
def test_scratch_authorization_rejects_tampering(tmp_path, mutation):
    metadata = launch_scratch.allocate(tmp_path, os.getpid())
    raw = launch_scratch.issue(tmp_path / 'authorities', metadata, os.getpid())
    value = json.loads(raw)
    entry = Path(value['entry'])
    if mutation == 'token':
        value['token'] = 'wrong'
    elif mutation == 'identity':
        data = json.loads(entry.read_text())
        data['identity'] = {}
        entry.write_text(json.dumps(data))
    elif mutation == 'issuer':
        # A syntactically valid entry belonging to a non-ancestor cannot bind us.
        value['pid'] = 2**30
        value['entry'] = str(entry.with_name(str(value['pid'])))
    elif mutation == 'symlink':
        original = entry.with_name('original')
        entry.rename(original)
        entry.symlink_to(original)
    else:
        os.link(entry, entry.with_name('alias'))
    with pytest.raises((OSError, ValueError)):
        launch_scratch._restore_authorized(json.dumps(value))


def test_launcher_darwin_base_selection_never_substitutes_tmp(monkeypatch, tmp_path):
    launcher = (ROOT / 'bin/raptor').read_text()
    start = launcher.index('_raptor_tmp_base() {')
    end = launcher.index('\n}\n', start) + 3
    function = launcher[start:end]
    script = '''
_rp() {
    case "$1" in
        uname) printf '%s\\n' Darwin ;;
        getconf) [ -n "$PRIVATE_TEMP" ] && printf '%s\\n' "$PRIVATE_TEMP" ;;
        *) return 1 ;;
    esac
}
''' + function + '\n_raptor_tmp_base\n'
    env = {key: value for key, value in os.environ.items()
           if key not in {'TMPDIR', 'RAPTOR_WORK_DIR', 'BASH_ENV', 'ENV'}}
    private = '/private/var/folders/example/T/'
    result = subprocess.run(['/bin/bash', '-c', script], env={**env, 'PRIVATE_TEMP': private},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and result.stdout.strip() == private
    result = subprocess.run(['/bin/bash', '-c', script], env={**env, 'PRIVATE_TEMP': ''},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode != 0 and not result.stdout
    chosen = str(tmp_path / 'operator base')
    result = subprocess.run(['/bin/bash', '-c', script], env={**env, 'TMPDIR': chosen},
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and result.stdout.strip() == chosen


def test_unusable_explicit_base_does_not_allocate_elsewhere(tmp_path):
    with pytest.raises(FileNotFoundError):
        launch_scratch.allocate(tmp_path / 'missing-base', os.getpid())
    assert not (tmp_path / 'missing-base').exists()


@pytest.mark.parametrize('relative', [False, True])
def test_direct_process_preserves_initial_tmpdir_after_environment_changes(tmp_path, relative):
    base = tmp_path / 'operator scratch'
    base.mkdir()
    env = {'PATH': os.defpath, 'HOME': str(tmp_path), 'CI': '1',
           'TMPDIR': base.name if relative else str(base),
           'RAPTOR_REGISTRY_HOME': str(tmp_path / 'registry')}
    code = r'''
import os,pathlib,sys
sys.path.insert(0,sys.argv[1])
import core.startup.process_init
from core.config import RaptorConfig
from core.security.env_sanitisation import safe_subprocess_env
expected=sys.argv[2]
os.environ['TMPDIR']='/changed/after/startup'
os.chdir('/')
assert RaptorConfig.get_safe_env()['TMPDIR']==expected
assert safe_subprocess_env()['TMPDIR']==expected
def broken_config(): raise ImportError('simulate an unavailable config')
RaptorConfig.get_safe_env=staticmethod(broken_config)
assert safe_subprocess_env()['TMPDIR']==expected
with __import__('tempfile').TemporaryFile(dir=expected) as stream: stream.write(b'ok')
'''
    result = subprocess.run([sys.executable, '-I', '-c', code, str(ROOT), str(base.resolve())],
                            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not list(base.iterdir())


@pytest.mark.parametrize('kind', ['missing', 'file', 'controls'])
def test_direct_process_rejects_unusable_tmpdir_without_fallback(tmp_path, kind):
    base = tmp_path / 'operator-scratch'
    if kind == 'file':
        base.write_text('not a directory')
    elif kind == 'controls':
        base = tmp_path / 'invalid\npath'
        base.mkdir()
    env = {'PATH': os.defpath, 'HOME': str(tmp_path), 'CI': '1', 'TMPDIR': str(base),
           'RAPTOR_REGISTRY_HOME': str(tmp_path / 'registry')}
    code = 'import sys;sys.path.insert(0,sys.argv[1]);import core.startup.process_init'
    result = subprocess.run([sys.executable, '-I', '-c', code, str(ROOT)], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'check TMPDIR' in result.stderr
    assert 'Traceback' not in result.stderr


def test_allocated_sessions_have_independent_random_root_and_record_ids(tmp_path, monkeypatch):
    import re
    from core.security import scratch_lifecycle
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    first = launch_scratch.allocate(tmp_path, os.getpid())
    second = launch_scratch.allocate(tmp_path, os.getpid())
    assert first.parent.parent != second.parent.parent
    for metadata in (first, second):
        root = metadata.parent.parent
        assert re.fullmatch(r'session-[a-f0-9]{32}', root.name)
        session_id = scratch_lifecycle.register(metadata, os.getpid())
        assert session_id == root.name.removeprefix('session-')
