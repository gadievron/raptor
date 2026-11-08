"""Trusted tracer startup, independent of cwd and ambient checkout settings."""

import json
import os
from pathlib import Path
import sys

import pytest

from core.sandbox import _tracer_launch as launch
from core.testing.standalone_cli import run_standalone_cli
from core.testing.state_isolation import pin_user_state_dirs


@pytest.mark.parametrize('ambient', [None, '', 'relative-checkout', '/nonexistent/stale-checkout'])
@pytest.mark.parametrize('config_arg', [None, '', '/proc/self/fd/19'])
def test_launch_preserves_arguments_with_a_minimal_owned_environment(monkeypatch, ambient, config_arg):
    if ambient is None:
        monkeypatch.delenv('RAPTOR_DIR', raising=False)
    else:
        monkeypatch.setenv('RAPTOR_DIR', ambient)
    before = dict(os.environ)
    argv, env = launch.prepare_tracer_launch('/owned/python', 321, 'run dir', 18, config_arg)
    assert argv == ['/owned/python', '-P', '-s', '-m', 'core.sandbox.tracer',
                    '321', 'run dir', '18', *([] if config_arg is None else [config_arg])]
    assert env == {'PYTHONPATH': str(Path(launch.__file__).resolve().parents[2]),
                   'PATH': '/usr/bin:/bin'}
    assert dict(os.environ) == before
    argv.clear()
    env.clear()
    again, fresh = launch.prepare_tracer_launch('/owned/python', 321, 'run dir', 18, config_arg)
    assert again and fresh  # Specifications are per call, never shared mutable state.


@pytest.mark.slow
@pytest.mark.parametrize('cwd_kind', ['checkout', 'unrelated'])
def test_interpreter_excludes_cwd_and_user_site_without_discarding_checkout(tmp_path, cwd_kind):
    """Inspect interpreter startup only; native confinement is tested below."""
    argv, env = launch.prepare_tracer_launch(sys.executable, 321, 'unused', 18)
    cwd = Path(launch.__file__).resolve().parents[2] if cwd_kind == 'checkout' else tmp_path
    probe = """
import core, json, os, site, sys
print(json.dumps({'safe_path': sys.flags.safe_path,
                  'no_user_site': sys.flags.no_user_site,
                  'user_site_enabled': site.ENABLE_USER_SITE,
                  'paths': sys.path, 'core': core.__file__, 'cwd': os.getcwd()}))
"""
    result = run_standalone_cli([*argv[:3], '-c', probe], env=env, cwd=cwd,
                                capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data['safe_path'] is True
    assert data['no_user_site'] == 1
    assert data['user_site_enabled'] is False
    assert '' not in data['paths']
    root = Path(env['PYTHONPATH'])
    assert Path(data['core']).resolve().parent == root / 'core'
    assert data['paths'][0] == str(root)
    if cwd_kind == 'unrelated':
        assert str(cwd) not in data['paths']


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('backend', ['landlock', 'namespaces'])
@pytest.mark.parametrize('ambient', ['', '/nonexistent/stale-checkout'])
def test_native_tracer_uses_parent_checkout_and_retains_read_confinement(
        tmp_path, monkeypatch, backend, ambient):
    if sys.platform != 'linux':
        pytest.skip('Linux tracer backends require a native Linux kernel')
    from core.sandbox import _landlock_audit, _spawn, evidence, landlock, ptrace_probe, seccomp
    from core.sandbox.python_paths import python_runtime_tool_paths
    from core.sandbox.tests.test_spawn_audit import _audit_prereqs_ok

    if not landlock.check_landlock_available():
        pytest.skip('Landlock unavailable')
    if not ptrace_probe.check_ptrace_available() or not seccomp.check_seccomp_available():
        pytest.skip('ptrace/libseccomp unavailable')
    if backend == 'namespaces':
        ready, reason = _audit_prereqs_ok()
        if not ready:
            pytest.skip(reason)
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('RAPTOR_DIR', ambient)
    cwd = tmp_path / 'unrelated-cwd'
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    run = tmp_path / 'run'
    run.mkdir()
    denied = tmp_path / 'outside-policy'
    denied.write_text('owned read-denial witness')
    readable = ['/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc',
                *python_runtime_tool_paths()]
    # The existing file is readable before confinement; the target must hit
    # the actual read boundary while its executable/stdlib remain granted.
    assert denied.read_text() == 'owned read-denial witness'
    probe = """
import errno, os, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM), error
else:
    os.close(fd)
    raise AssertionError('outside-policy read was admitted')
print('READ-DENIED')
"""
    cmd = [sys.executable, '-I', '-S', '-c', probe, str(denied)]
    module = _landlock_audit if backend == 'landlock' else _spawn
    verified = []
    close_evidence = evidence.EvidenceFile.close
    def record_close(self, *args, **kwargs):
        result = close_evidence(self, *args, **kwargs)
        verified.append(result)
        return result
    monkeypatch.setattr(evidence.EvidenceFile, 'close', record_close)
    captured = []
    prepare = module.prepare_tracer_launch
    def record(*args):
        result = prepare(*args)
        captured.append((os.getpid(), args, result))
        return result
    monkeypatch.setattr(module, 'prepare_tracer_launch', record)
    parent = os.getpid()
    common = dict(audit_run_dir=str(run), writable_paths=[str(run)],
                  readable_paths=readable, restrict_reads=True,
                  env={'PATH': '/usr/bin:/bin'}, cwd=str(cwd), timeout=30,
                  capture_output=True, text=True)
    if backend == 'landlock':
        result = module.run_landlock_audit(
            cmd, **common,
            landlock_preexec=landlock._make_landlock_preexec(
                [str(run)], readable_paths=readable, fail_raise=True),
            seccomp_preexec=seccomp._make_seccomp_preexec('full', audit_mode=True),
        )
    else:
        result = module.run_sandboxed(
            cmd, **common, target=None, output=None, block_network=False,
            nproc_limit=0, limits={}, allowed_tcp_ports=None,
            seccomp_profile='full', seccomp_block_udp=False,
            audit_mode=True, audit_required=True,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'READ-DENIED'
    assert verified and all(value is True for value in verified)
    if backend == 'landlock':
        assert result.evidence_verified is True
    else:
        assert result._setup_status is None
    assert len(captured) == 1
    owner, args, (argv, env) = captured[0]
    assert owner == parent  # Filesystem resolution occurred before tracer fork.
    assert args[0] == sys.executable
    assert argv[1:5] == ['-P', '-s', '-m', 'core.sandbox.tracer']
    assert env['PYTHONPATH'] == str(Path(launch.__file__).resolve().parents[2])
    assert args[4].startswith('/proc/self/fd/')


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt])
def test_parent_launch_preparation_failure_reaps_waiting_target(tmp_path, monkeypatch, failure_type):
    """Preparation fails before target exec; production must release its child."""
    if sys.platform != 'linux':
        pytest.skip('Linux audit fork lifecycle')
    from contextlib import ExitStack
    from core.sandbox import _landlock_audit as audit
    from core.testing.module_bindings import patch_module_attribute

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    failure = failure_type('owned parent preparation failure')
    fork, reap = os.fork, audit._kill_and_reap
    children = []
    with ExitStack() as owner:
        def own_fork():
            pid = fork()
            if pid > 0:
                # Register before the following preparation can fail. This
                # backstop runs only after the production-cleanup assertion.
                owner.callback(reap, pid)
                children.append(pid)
            return pid
        def refuse(*args):
            assert len(children) == 1  # Target exists, tracer not forked yet.
            raise failure
        patch_module_attribute(monkeypatch, audit, 'os', 'fork', own_fork)
        monkeypatch.setattr(audit, 'prepare_tracer_launch', refuse)
        with pytest.raises(BaseException) as caught:
            audit.run_landlock_audit(
                ['/bin/true'], audit_run_dir=str(run),
                env={'PATH': '/usr/bin:/bin'}, timeout=10,
            )
        assert caught.value is failure
        assert len(children) == 1
        with pytest.raises(ChildProcessError):
            os.waitpid(children[0], os.WNOHANG)
