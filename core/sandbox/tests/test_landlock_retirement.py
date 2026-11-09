"""Current Landlock owners retire across setup and child cleanup faults."""
from contextlib import ExitStack
import os
import sys
import pytest
from core.sandbox import evidence
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('cleanup_type', [None, OSError, KeyboardInterrupt])
def test_first_fork_error_attempts_all_metadata_retirement(tmp_path, monkeypatch, primary_type, cleanup_type):
    if sys.platform != "linux":
        pytest.skip("Linux audit metadata lifecycle")
    from core.sandbox import _landlock_audit as audit
    from core.sandbox import ptrace_probe, seccomp
    if not ptrace_probe.check_ptrace_available() or not seccomp.check_seccomp_available():
        pytest.skip("ptrace/libseccomp unavailable")
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    run = tmp_path / "run"
    run.mkdir()
    primary = primary_type("owned first-fork failure")
    secondary = cleanup_type("owned pipe-retirement failure") if cleanup_type else None
    close, pipe, anonymous = os.close, os.pipe, evidence.anonymous_fd
    open_evidence, close_evidence = evidence.EvidenceFile.open, evidence.EvidenceFile.close
    owned, opened = set(), []
    injected = False
    with ExitStack() as owner:
        def retire_remaining():
            for fd in tuple(owned):
                owned.remove(fd)
                close(fd)
        owner.callback(retire_remaining)
        def record_open(cls, *args, **kwargs):
            handle = open_evidence(*args, **kwargs)
            opened.append(handle)
            owner.callback(close_evidence, handle, verify=False)
            return handle
        def record_pipe():
            fds = pipe()
            owned.update(fds)
            return fds
        def record_config(*args, **kwargs):
            fd = anonymous(*args, **kwargs)
            owned.add(fd)
            return fd
        def fail_fork():
            raise primary
        def interrupt_close(fd):
            nonlocal injected
            close(fd)
            owned.discard(fd)
            caller = sys._getframe(1)
            within_cleanup = False
            while caller is not None:
                if caller.f_code.co_name == '_cleanup_fds':
                    within_cleanup = True
                    break
                caller = caller.f_back
            if not injected and within_cleanup and secondary is not None:
                injected = True
                raise secondary
        with monkeypatch.context() as patch:
            patch.setattr(evidence.EvidenceFile, "open", classmethod(record_open))
            patch.setattr(evidence, "anonymous_fd", record_config)
            patch_module_attribute(patch, audit, "os", "pipe", record_pipe)
            patch_module_attribute(patch, audit, "os", "fork", fail_fork)
            patch_module_attribute(patch, audit, "os", "close", interrupt_close)
            caught = None
            try:
                audit.run_landlock_audit(["/bin/true"], audit_run_dir=str(run),
                                        env={"PATH": "/usr/bin:/bin"}, timeout=30)
            except BaseException as error:
                caught = error
        assert injected is (cleanup_type is not None)
        assert len(opened) == 1
        assert opened[0]._fd_released, "evidence owner skipped after pipe cleanup interrupt"
        assert not owned, "remaining pipes/config skipped after cleanup interrupt"
        assert caught is primary


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('cleanup_type', [None, OSError, KeyboardInterrupt])
def test_live_target_reap_error_does_not_skip_metadata(tmp_path, monkeypatch, primary_type, cleanup_type):
    if sys.platform != 'linux':
        pytest.skip('Linux audit target lifecycle')
    from core.sandbox import _landlock_audit as audit, ptrace_probe, seccomp
    if not ptrace_probe.check_ptrace_available() or not seccomp.check_seccomp_available():
        pytest.skip('ptrace/libseccomp unavailable')
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    parent = os.getpid()
    primary = primary_type('owned tracer preparation failure')
    secondary = cleanup_type('owned reap acknowledgement failure') if cleanup_type else None
    fork, reap, close = os.fork, audit._kill_and_reap, os.close
    anonymous = evidence.anonymous_fd
    open_evidence, close_evidence = evidence.EvidenceFile.open, evidence.EvidenceFile.close
    children, opened, configs, reap_calls = [], [], [], []
    config_released = False
    with ExitStack() as owner:
        def record_open(cls, *args, **kwargs):
            handle = open_evidence(*args, **kwargs)
            opened.append(handle)
            owner.callback(close_evidence, handle, verify=False)
            return handle
        def record_config(*args, **kwargs):
            fd = anonymous(*args, **kwargs)
            configs.append(fd)
            def release_config():
                nonlocal config_released
                if not config_released:
                    config_released = True
                    close(fd)
            owner.callback(release_config)
            return fd
        def record_fork():
            pid = fork()
            if pid > 0:
                children.append(pid)
                owner.callback(reap, pid)
            return pid
        def record_close(fd):
            nonlocal config_released
            close(fd)
            if os.getpid() == parent and configs and fd == configs[0]:
                config_released = True
        def fail_prepare(*args, **kwargs):
            assert len(children) == 1
            # The real child is still ours and cannot exec before the go byte.
            assert os.waitpid(children[0], os.WNOHANG) == (0, 0)
            raise primary
        def reap_then_fail(pid):
            reap(pid)
            reap_calls.append(pid)
            if secondary is not None:
                raise secondary
        with monkeypatch.context() as patch:
            patch.setattr(evidence.EvidenceFile, 'open', classmethod(record_open))
            patch.setattr(evidence, 'anonymous_fd', record_config)
            patch.setattr(audit, 'prepare_tracer_launch', fail_prepare)
            patch.setattr(audit, '_kill_and_reap', reap_then_fail)
            patch_module_attribute(patch, audit, 'os', 'fork', record_fork)
            patch_module_attribute(patch, audit, 'os', 'close', record_close)
            caught = None
            try:
                audit.run_landlock_audit(['/bin/true'], audit_run_dir=str(run),
                                        env={'PATH': '/usr/bin:/bin'}, timeout=30)
            except BaseException as error:
                caught = error
        assert len(children) == len(opened) == len(configs) == 1
        assert reap_calls == children
        assert opened[0]._fd_released
        assert config_released
        assert caught is primary
        with pytest.raises(ChildProcessError):
            os.waitpid(children[0], os.WNOHANG)


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit setup')
@pytest.mark.parametrize('stage', ['config_path', 'environment', 'libc'])
@pytest.mark.parametrize('primary_type', [RuntimeError, KeyboardInterrupt])
def test_pre_fork_setup_failure_retires_all_acquired_owners(
    tmp_path, monkeypatch, stage, primary_type,
):
    import core.config as config
    from core.sandbox import _landlock_audit as audit, ptrace_probe, seccomp
    from core.testing.module_views import scoped_function_imports

    if not ptrace_probe.check_ptrace_available() or not seccomp.check_seccomp_available():
        pytest.skip('ptrace/libseccomp unavailable')
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    primary = primary_type('owned pre-fork setup failure')
    real_pipe, real_close = os.pipe, os.close
    anonymous = evidence.anonymous_fd
    open_evidence = evidence.EvidenceFile.open
    close_evidence = evidence.EvidenceFile.close
    owned, handles, forks = set(), [], []

    def fail(*args, **kwargs):
        raise primary

    class Config:
        get_safe_env = staticmethod(fail)

    with ExitStack() as owner:
        def release_remaining():
            for fd in tuple(owned):
                owned.remove(fd)
                real_close(fd)
        owner.callback(release_remaining)

        def pipe():
            pair = real_pipe()
            owned.update(pair)
            return pair

        def close(fd):
            real_close(fd)
            owned.discard(fd)

        def config_fd(*args, **kwargs):
            fd = anonymous(*args, **kwargs)
            owned.add(fd)
            return fd

        def record_open(cls, *args, **kwargs):
            handle = open_evidence(*args, **kwargs)
            handles.append(handle)
            owner.callback(close_evidence, handle, verify=False)
            return handle

        def unexpected_fork():
            forks.append(True)
            raise AssertionError('setup fault did not reach its intended boundary')

        monkeypatch.setattr(evidence.EvidenceFile, 'open', classmethod(record_open))
        monkeypatch.setattr(evidence, 'anonymous_fd', config_fd)
        patch_module_attribute(monkeypatch, audit, 'os', 'pipe', pipe)
        patch_module_attribute(monkeypatch, audit, 'os', 'close', close)
        patch_module_attribute(monkeypatch, audit, 'os', 'fork', unexpected_fork)
        if stage == 'config_path':
            monkeypatch.setattr(evidence, 'fd_path', fail)
        if stage == 'libc':
            patch_module_attribute(monkeypatch, audit, 'ctypes.util', 'find_library', fail)
        with scoped_function_imports(
            audit, ['run_landlock_audit'], {'core.config': config},
        ) as imports:
            monkeypatch.setattr(getattr(imports, 'core.config'), 'RaptorConfig', Config)
            with pytest.raises(BaseException) as caught:
                audit.run_landlock_audit(
                    ['/bin/true'], audit_run_dir=str(run), timeout=30,
                    env=None if stage == 'environment' else {'PATH': '/usr/bin:/bin'},
                )
        assert caught.value is primary
        assert not forks
        assert len(handles) == 1
        assert handles[0]._fd_released
        assert not owned


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux audit child ownership')
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_timeout_reap_acknowledgement_cannot_retry_consumed_pid(
    tmp_path, monkeypatch, error_type,
):
    from core.sandbox import _landlock_audit as audit, ptrace_probe, seccomp

    if not ptrace_probe.check_ptrace_available() or not seccomp.check_seccomp_available():
        pytest.skip('ptrace/libseccomp unavailable')
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    fork, reap = os.fork, audit._kill_and_reap
    opened, children, reaps = [], [], []
    original_open = evidence.EvidenceFile.open
    original_close = evidence.EvidenceFile.close
    primary = error_type('owned post-reap acknowledgement failure')
    injected = False

    with ExitStack() as owner:
        def record_open(cls, *args, **kwargs):
            handle = original_open(*args, **kwargs)
            opened.append(handle)
            owner.callback(original_close, handle, verify=False)
            return handle

        def record_fork():
            pid = fork()
            if pid > 0:
                children.append(pid)
                owner.callback(reap, pid)
            return pid

        def reap_then_fail(pid):
            nonlocal injected
            reap(pid)
            reaps.append(pid)
            if pid == children[0] and not injected:
                injected = True
                with pytest.raises(ChildProcessError):
                    os.waitpid(pid, os.WNOHANG)
                raise primary

        with monkeypatch.context() as patch:
            patch.setattr(evidence.EvidenceFile, 'open', classmethod(record_open))
            patch.setattr(audit, '_kill_and_reap', reap_then_fail)
            patch_module_attribute(patch, audit, 'os', 'fork', record_fork)
            caught = None
            try:
                audit.run_landlock_audit(
                    ['/bin/sleep', '30'], audit_run_dir=str(run),
                    env={'PATH': '/usr/bin:/bin'}, timeout=0, capture_output=False,
                )
            except BaseException as error:
                caught = error
        assert caught is primary
        assert injected
        assert len(children) == 2
        assert reaps == children, 'a consumed child PID was retried by final cleanup'
        assert len(opened) == 1 and opened[0]._fd_released
