"""Current namespace owners retire across setup and completion failures."""
from contextlib import ExitStack
import os
import sys
import pytest
from core.sandbox import _spawn as spawn, evidence
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('fault_site', ['status', 'tracer'])
@pytest.mark.parametrize('failure_type', [None, OSError, KeyboardInterrupt])
def test_final_cleanup_retires_evidence(tmp_path, monkeypatch, fault_site, failure_type):
    if sys.platform != 'linux':
        pytest.skip('Native namespace audit cleanup')
    from core.sandbox.tests.test_spawn_audit import _audit_prereqs_ok
    available, reason = _audit_prereqs_ok()
    if not available:
        pytest.skip(reason)
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    primary = failure_type('owned late retirement failure') if failure_type else None
    original_reap = spawn._reap_tracer
    original_drain = spawn._drain_status_pipe
    original_open, original_close = evidence.EvidenceFile.open, evidence.EvidenceFile.close
    fork = os.fork
    opened, children, status, tracer_reaps = [], [], [], []
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
                owner.callback(spawn._kill_and_reap, pid)
            return pid
        def interrupt_after_status(*args, **kwargs):
            verdict = original_drain(*args, **kwargs)
            status.append(verdict)
            if fault_site == 'status' and primary is not None:
                raise primary
            return verdict
        def interrupt_after_reap(pid, *args, **kwargs):
            result = original_reap(pid, *args, **kwargs)
            tracer_reaps.append(pid)
            if fault_site == 'tracer' and primary is not None:
                raise primary
            return result
        with monkeypatch.context() as patch:
            patch.setattr(evidence.EvidenceFile, 'open', classmethod(record_open))
            patch.setattr(spawn, '_drain_status_pipe', interrupt_after_status)
            patch.setattr(spawn, '_reap_tracer', interrupt_after_reap)
            patch_module_attribute(patch, spawn, 'os', 'fork', record_fork)
            caught = result = None
            try:
                result = spawn.run_sandboxed(
                    ['/bin/true'], target=None, output=None, block_network=False,
                    nproc_limit=0, limits={}, writable_paths=[str(run)],
                    readable_paths=['/usr','/lib','/lib64','/bin','/sbin','/etc'],
                    restrict_reads=True, allowed_tcp_ports=None, seccomp_profile='full',
                    seccomp_block_udp=False, env={'PATH':'/usr/bin:/bin'}, cwd=None,
                    timeout=30, audit_mode=True, audit_required=True, audit_run_dir=str(run))
            except BaseException as error:
                caught = error
        assert caught is primary
        if primary is None:
            assert result.returncode == 0, result.stderr
        assert len(tracer_reaps) == 1
        assert children and status == [None]
        assert len(opened) == 1
        assert opened[0]._fd_released, 'evidence skipped after status retirement interrupt'


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('primary_type', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('secondary_type', [None, OSError, KeyboardInterrupt])
def test_startup_target_cleanup_preserves_error_and_evidence(tmp_path, monkeypatch, primary_type, secondary_type):
    if sys.platform != 'linux':
        pytest.skip('Native namespace startup cleanup')
    from core.sandbox.tests.test_spawn_audit import _audit_prereqs_ok
    available, reason = _audit_prereqs_ok()
    if not available:
        pytest.skip(reason)
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    primary = primary_type('owned startup callback interrupt')
    secondary = secondary_type('owned target retirement failure') if secondary_type else None
    original_open, original_close = evidence.EvidenceFile.open, evidence.EvidenceFile.close
    teardown, reap = spawn._teardown_target, spawn._kill_and_reap
    children, opened, retired = [], [], []
    with ExitStack() as owner:
        def record_open(cls, *args, **kwargs):
            handle = original_open(*args, **kwargs)
            opened.append(handle)
            owner.callback(original_close, handle, verify=False)
            return handle
        def fail_callback(pid):
            children.append(pid)
            owner.callback(reap, pid)
            assert os.waitpid(pid, os.WNOHANG) == (0, 0)
            raise primary
        def fail_after_teardown(pid, *args, **kwargs):
            result = teardown(pid, *args, **kwargs)
            retired.append(pid)
            if secondary is not None:
                raise secondary
            return result
        with monkeypatch.context() as patch:
            patch.setattr(evidence.EvidenceFile, 'open', classmethod(record_open))
            patch.setattr(spawn, '_teardown_target', fail_after_teardown)
            caught = None
            try:
                spawn.run_sandboxed(
                    ['/bin/true'], target=None, output=None, block_network=False,
                    nproc_limit=0, limits={}, writable_paths=[str(run)],
                    readable_paths=['/usr','/lib','/lib64','/bin','/sbin','/etc'],
                    restrict_reads=True, allowed_tcp_ports=None, seccomp_profile='full',
                    seccomp_block_udp=False, env={'PATH':'/usr/bin:/bin'}, cwd=None,
                    timeout=30, audit_mode=True, audit_required=True, audit_run_dir=str(run),
                    child_pid_callback=fail_callback)
            except BaseException as error:
                caught = error
        assert caught is primary
        assert len(children) == len(opened) == 1
        assert retired == children
        assert opened[0]._fd_released
        with pytest.raises(ChildProcessError):
            os.waitpid(children[0], os.WNOHANG)


@pytest.mark.parametrize('primary_type', [None, OSError, KeyboardInterrupt])
@pytest.mark.parametrize('secondary_type', [OSError, KeyboardInterrupt, SystemExit])
def test_retirement_attempts_every_owner_and_preserves_first_error(
    primary_type, secondary_type,
):
    primary = primary_type('owned operation failure') if primary_type else None
    secondary = secondary_type('owned retirement failure')
    later = RuntimeError('later retirement failure')
    calls = []

    def fail_first():
        calls.append('first')
        raise secondary

    def fail_later():
        calls.append('later')
        raise later

    def retire():
        spawn._retire_parent_resources(fail_first, fail_later,
                                       lambda: calls.append('last'))

    if primary is None:
        with pytest.raises(BaseException) as caught:
            retire()
        assert caught.value is secondary
    else:
        try:
            raise primary
        except BaseException:
            retire()
            assert sys.exc_info()[1] is primary
    assert calls == ['first', 'later', 'last']


@pytest.mark.skipif(sys.platform != 'linux', reason='owned child waitid control')
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_target_reaped_after_death_endpoint_close_error(monkeypatch, error_type):
    real_close = spawn.close_death_w
    with ExitStack() as owner:
        read_fd, write_fd = spawn.open_death_pipe()
        owner.callback(os.close, read_fd)
        owner.callback(real_close, write_fd)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(write_fd)
                os.read(read_fd, 1)
            finally:
                os._exit(0)
        owner.callback(spawn._kill_and_reap, pid)
        failure = error_type('owned death endpoint close failure')
        parent_fds = {write_fd}
        closed = []

        def fail_close(fd):
            assert real_close(fd)
            closed.append(fd)
            raise failure

        monkeypatch.setattr(spawn, 'close_death_w', fail_close)
        with pytest.raises(BaseException) as caught:
            spawn._teardown_target(pid, write_fd, parent_fds, grace_s=0)
        assert caught.value is failure
        assert closed == [write_fd]
        assert not parent_fds
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


@pytest.mark.parametrize('active', [False, True])
def test_retirement_annotation_failure_cannot_replace_primary(active):
    class Failure(RuntimeError):
        def add_note(self, note):
            raise KeyboardInterrupt('owned diagnostic failure')

    primary = Failure('owned operation failure')

    def fail():
        raise primary

    def later():
        raise OSError('owned later cleanup failure')

    if active:
        try:
            raise primary
        except BaseException:
            spawn._retire_parent_resources(later)
            assert sys.exc_info()[1] is primary
    else:
        with pytest.raises(Failure) as caught:
            spawn._retire_parent_resources(fail, later)
        assert caught.value is primary


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('secondary_type', [OSError, KeyboardInterrupt])
def test_config_handoff_failure_retires_descriptor_evidence_and_root(
    tmp_path, monkeypatch, secondary_type,
):
    import errno
    import shutil
    import tempfile
    from core.testing.module_views import scoped_function_imports
    from core.sandbox.tests.test_spawn_audit import _audit_prereqs_ok

    available, reason = _audit_prereqs_ok()
    if not available:
        pytest.skip(reason)
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    run = tmp_path / 'run'
    run.mkdir()
    primary = KeyboardInterrupt('owned config handoff failure')
    secondary = secondary_type('owned evidence retirement failure')
    anonymous = evidence.anonymous_fd
    original_open = evidence.EvidenceFile.open
    original_close = evidence.EvidenceFile.close
    roots, handles, descriptors = [], [], []

    def close_if_owned(fd, identity):
        try:
            info = os.fstat(fd)
        except OSError as error:
            if error.errno == errno.EBADF:
                return
            raise
        if (info.st_dev, info.st_ino) == identity:
            os.close(fd)

    with ExitStack() as owner:
        def owned_root(prefix):
            root = tempfile.mkdtemp(prefix=prefix, dir=tmp_path)
            roots.append(root)
            owner.callback(shutil.rmtree, root, ignore_errors=True)
            return root

        def open_evidence(cls, *args, **kwargs):
            handle = original_open(*args, **kwargs)
            handles.append(handle)
            owner.callback(original_close, handle, verify=False)
            return handle

        def config_fd(*args, **kwargs):
            fd = anonymous(*args, **kwargs)
            info = os.fstat(fd)
            descriptors.append(fd)
            owner.callback(close_if_owned, fd, (info.st_dev, info.st_ino))
            return fd

        def fail_path(fd):
            raise primary

        def fail_close(handle, *args, **kwargs):
            original_close(handle, *args, **kwargs)
            raise secondary

        monkeypatch.setattr(evidence.EvidenceFile, 'open', classmethod(open_evidence))
        monkeypatch.setattr(evidence.EvidenceFile, 'close', fail_close)
        monkeypatch.setattr(evidence, 'anonymous_fd', config_fd)
        monkeypatch.setattr(evidence, 'fd_path', fail_path)
        with scoped_function_imports(
            spawn, ['run_sandboxed'], {'tempfile': tempfile},
        ) as imports:
            monkeypatch.setattr(imports.tempfile, 'mkdtemp', owned_root)
            with pytest.raises(KeyboardInterrupt) as caught:
                spawn.run_sandboxed(
                    ['/bin/true'], target=None, output=None, block_network=False,
                    nproc_limit=0, limits={}, writable_paths=[str(tmp_path)],
                    readable_paths=['/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc'],
                    restrict_reads=True, allowed_tcp_ports=None, seccomp_profile='full',
                    seccomp_block_udp=False, env={'PATH': '/usr/bin:/bin'}, cwd=None,
                    timeout=30, audit_mode=True, audit_required=True,
                    audit_run_dir=str(run),
                )
        assert caught.value is primary
        assert len(roots) == len(handles) == len(descriptors) == 1
        assert handles[0]._fd_released
        assert not os.path.exists(roots[0])
        with pytest.raises(OSError) as closed:
            os.fstat(descriptors[0])
        assert closed.value.errno == errno.EBADF


def test_status_endpoint_consumed_before_interrupted_close(monkeypatch):
    import errno

    reader, writer = os.pipe()
    identity = os.fstat(reader)
    real_close = os.close
    primary = KeyboardInterrupt('owned status close interrupt')
    parent_fds = {reader}
    os.write(writer, b'G')
    real_close(writer)

    def close(fd):
        real_close(fd)
        assert fd not in parent_fds
        raise primary

    try:
        with monkeypatch.context() as patch:
            patch_module_attribute(patch, spawn, 'os', 'close', close)
            with pytest.raises(KeyboardInterrupt) as caught:
                spawn._drain_status_pipe(reader, parent_fds)
        assert caught.value is primary
        assert not parent_fds
    finally:
        try:
            current = os.fstat(reader)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                real_close(reader)
