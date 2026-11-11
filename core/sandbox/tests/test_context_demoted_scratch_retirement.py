"""Context-owned scratch directories retire independently after interruption."""

import builtins
from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

from core.sandbox import context, probes, _spawn, state, landlock, seccomp
from core.sandbox import job_budget, summary, activity
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux mountless routing')
@pytest.mark.parametrize('body_failure', [False, True])
@pytest.mark.parametrize('stage', ['remove', 'unregister'])
@pytest.mark.parametrize('route', ['demoted', 'single'])
def test_demoted_scratch_cleanup_attempts_each_directory(tmp_path, body_failure, stage, route):
    owned, registered, retired, dispatched = [], set(), [], []
    identities = {}
    interruption = KeyboardInterrupt('owned scratch cleanup interruption')
    original = ValueError('owned context body failure')

    def forbidden(*args, **kwargs):
        pytest.fail('unexpected native dispatch or probe')

    def allocate(**kwargs):
        assert kwargs['prefix'] == '.scr-'
        path = tempfile.mkdtemp(dir=tmp_path, **kwargs)
        owned.append(path)
        info = Path(path).stat()
        identities[path] = (info.st_dev, info.st_ino)
        assert info.st_mode & 0o777 == 0o700
        return path

    def register(path):
        assert path in owned
        registered.add(path)

    def unregister(path):
        assert path in owned
        registered.remove(path)
        if path == owned[0] and stage == 'unregister':
            raise interruption

    def remove(path, **kwargs):
        assert path in owned
        info = Path(path).stat()
        assert (info.st_dev, info.st_ino) == identities[path]
        retired.append(path)
        shutil.rmtree(path, **kwargs)
        if len(retired) == 1 and stage == 'remove':
            raise interruption

    def dispatch(cmd, **kwargs):
        assert kwargs['skip_mount_ns'] is True
        assert kwargs['env']['TMPDIR'] in owned
        dispatched.append(kwargs['env']['TMPDIR'])
        result = subprocess.CompletedProcess(cmd, 0, '', '')
        result._setup_status = None
        return result

    private_probes = module_function_view(probes, bindings={
        'check_unshare_engages': lambda flags: (True, ''),
        'unshare_supports_cgroup': lambda: False,
    })
    private_spawn = module_function_view(_spawn, bindings={'run_sandboxed': dispatch})
    private_state = module_function_view(state, bindings={
        '_speculative_failure_cache': {}, '_mountless_backend_warned': False,
        'warn_once': lambda *args: False,
    })
    private_landlock = module_function_view(landlock, bindings={
        'check_landlock_available': lambda: True, '_get_landlock_abi': lambda: 6,
    })
    private_seccomp = module_function_view(seccomp, bindings={
        'check_seccomp_available': lambda: True,
    })
    class Job:
        def __init__(self, *args, **kwargs):
            self.record = {}

        def ensure_lane(self, *args, **kwargs):
            pass

        def ensure_exports(self, *args, **kwargs):
            pass

        def close(self):
            pass

    relative = {
        'probes': private_probes, '_spawn': private_spawn,
        'landlock': private_landlock, 'seccomp': private_seccomp,
        'job_budget': module_function_view(job_budget, bindings={'Job': Job}),
        'summary': module_function_view(summary, bindings={
            'get_active_run_dir': lambda: None,
            'record_run_posture': lambda *args, **kwargs: None,
        }),
        'activity': module_function_view(activity, bindings={
            'record_execution': lambda *args, **kwargs: None,
        }),
    }
    absolute = {
        'tempfile': module_function_view(tempfile, bindings={'mkdtemp': allocate}),
        'shutil': module_function_view(shutil, bindings={'rmtree': remove}),
        'core.run.scratch': SimpleNamespace(
            keepalive_register=register, keepalive_unregister=unregister,
        ),
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name in relative:
            return relative[name]
        if level == 1 and not name and any(n in relative for n in fromlist):
            return SimpleNamespace(**{n: relative[n] for n in fromlist if n in relative})
        if level == 0 and name in absolute:
            return absolute[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__, 'state': private_state,
        '_probes': private_probes, '_landlock': private_landlock,
        '_seccomp': private_seccomp,
        'check_net_available': lambda: route == 'demoted',
        'check_mount_available': lambda: route == 'demoted',
        'check_landlock_available': lambda: True, '_get_landlock_abi': lambda: 6,
        'check_seccomp_available': lambda: True, 'check_seatbelt_available': lambda: False,
        '_make_preexec_fn': lambda *args, **kwargs: None,
        '_run_teardown_first_timeout': forbidden, '_sweep_marked_processes': forbidden,
    }, import_hook=imports)
    try:
        with pytest.raises(ValueError if body_failure else KeyboardInterrupt) as caught:
            with contextmanager(private.sandbox)(
                    block_network=route == 'demoted',
                    target=str(tmp_path), output=str(tmp_path),
                    restrict_reads=True) as run:
                if route == 'demoted':
                    for _ in range(2):
                        result = run([sys.executable], timeout=1, skip_mount_ns=True)
                        assert result.sandbox_info['private_scratch'] is True
                else:
                    assert len(owned) == 1
                    assert registered == set(owned)
                if body_failure:
                    raise original
        assert caught.value is (original if body_failure else interruption)
        assert len(owned) == len(set(owned)) == (2 if route == 'demoted' else 1)
        assert dispatched == (owned if route == 'demoted' else [])
        assert retired == owned
        assert not registered
        assert all(not Path(path).exists() for path in owned)
    finally:
        for path in owned:
            if Path(path).exists():
                info = Path(path).stat()
                if (info.st_dev, info.st_ino) == identities[path]:
                    shutil.rmtree(path)
        registered.clear()
