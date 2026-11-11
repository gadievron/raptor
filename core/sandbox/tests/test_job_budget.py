"""Budget admission/control tests. File-backed controls do not prove kernel limits."""
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import job_budget


def test_budget_roundtrip_and_invalid_caps():
    raw = {'memory_max': 4096 * 1024, 'cpu_max': [50000, 100000], 'pids_max': 16,
           'required': True, 'parent': '/sys/fs/cgroup/owned'}
    budget = job_budget.Budget.parse(raw)
    assert budget.as_dict() == raw
    assert dict(budget.controls) == {'memory.max': '4194304', 'memory.swap.max': '0', 'cpu.max': '50000 100000', 'pids.max': '16'}
    for bad in ({}, {'memory_max': True}, {'pids_max': 0}, {'cpu_max': [True, 100000]},
                {'cpu_max': [1000, 0]}, {'memory_max': 4096, 'required': 1},
                {'pids_max': 10, 'parent': '/sys/fs/cgroup/../other'}, {'unlimited': True}):
        with pytest.raises(ValueError):
            job_budget.Budget.parse(bad)


def test_required_unsupported_lane_refuses_and_optional_is_explicit(caplog):
    with pytest.raises(job_budget.JobBudgetError) as caught:
        job_budget.Job(job_budget.Budget.parse({'pids_max': 16}), namespace_backend=False)
    assert caught.value.job_budget['status'] == 'unavailable'
    assert caught.value.job_budget['effective'] == {}
    job = job_budget.Job(job_budget.Budget.parse({'pids_max': 16, 'required': False}),
                         namespace_backend=False)
    assert job.record['required'] is False
    assert job.record['effective'] == {}
    assert 'optional' in caplog.text
    job.close()


def test_budget_config_uses_existing_file_and_refuses_malformed(tmp_path):
    path = tmp_path / 'sandbox.json'
    assert job_budget.load_budget(None, config_path=path) is None
    path.write_text('{"memory_mb":0,"job_budget":{"memory_max":8192,"pids_max":8}}')
    budget = job_budget.load_budget(None, config_path=path)
    assert dict(budget.controls) == {'memory.max': '8192', 'memory.swap.max': '0', 'pids.max': '8'}
    path.write_text('{"job_budget":{"pids_max":8,"pids_max":9}}')
    with pytest.raises(ValueError):
        job_budget.load_budget(None, config_path=path)
    # Explicit per-call policy never silently merges a standing policy.
    assert job_budget.load_budget({'pids_max': 4}, config_path=path).as_dict() == {'pids_max': 4, 'required': True}


class Scope:
    def __init__(self, directory):
        import os
        self.path = directory
        self.node = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.parent = None
        self.identity = [os.fstat(self.node).st_dev, os.fstat(self.node).st_ino]
        self.closed = False
        self.released = False
        self.members = []

    def attach(self, pid):
        self.members.append(pid)
        (self.path / 'cgroup.procs').write_text(str(pid))

    def close_admission(self):
        self.closed = True

    def stop(self, **kwargs):
        assert self.closed
        self.members.clear()
        return False

    def release(self):
        assert self.closed and not self.members
        self.released = True

    def close(self):
        import os
        if self.node is not None:
            os.close(self.node)
            self.node = None


@pytest.fixture
def controls(tmp_path, monkeypatch):
    # This fixture owns a file-backed Linux controller model, not host admission.
    monkeypatch.setattr(job_budget, "sys", SimpleNamespace(platform="linux"))
    scope = Scope(tmp_path)
    for name, value in [('pids.max', 'max'), ('cpu.max', 'max 100000'),
                        ('memory.max', 'max'), ('cgroup.procs', '')]:
        (tmp_path / name).write_text(value)
    monkeypatch.setattr(job_budget.cgroup_scope.Scope, 'create', lambda parent: scope)
    monkeypatch.setattr(job_budget, 'find_delegation', lambda controls: tmp_path)
    monkeypatch.setattr(job_budget.Job, '_start_watcher', lambda self: None)
    def write(node, name, data):
        assert node == scope.node
        (tmp_path / name).write_text(data)
    monkeypatch.setattr(job_budget.cgroup_scope, '_write', write)
    try:
        yield scope
    finally:
        scope.close()


def test_controls_applied_read_back_before_admission(controls):
    job = job_budget.Job(job_budget.Budget.parse({'pids_max': 16, 'cpu_max': [10000, 100000]}),
                         namespace_backend=True)
    assert job.record['status'] == 'prepared'
    assert not controls.members
    job.attach(12345)
    assert controls.members == [12345]
    assert job.record['status'] == 'applied'
    job.ensure_lane('mount-ns spawn', namespace_isolated=True)
    with pytest.raises(job_budget.JobBudgetError):
        job.ensure_lane('mountless namespace backend')
    with pytest.raises(job_budget.JobBudgetError):
        job.ensure_lane('mount-ns spawn', namespace_isolated=False)
    with pytest.raises(job_budget.JobBudgetError):
        job.ensure_lane('Landlock-only subprocess')
    assert not controls.released


def test_readback_failure_retires_scope_and_never_attaches(controls, monkeypatch):
    original = job_budget.cgroup_scope._read
    def read(node, name):
        return 'max' if name == 'pids.max' else original(node, name)
    monkeypatch.setattr(job_budget.cgroup_scope, '_read', read)
    with pytest.raises(job_budget.JobBudgetError) as caught:
        job_budget.Job(job_budget.Budget.parse({'pids_max': 16}), namespace_backend=True)
    assert not controls.members
    assert controls.released
    assert caught.value.job_budget['effective'] == {}
    assert caught.value.job_budget['cleanup'] == 'complete'


def test_real_host_rejects_scratch_as_delegated_cgroup(tmp_path):
    # Real admission checks must not accept an ordinary directory of controls.
    budget = job_budget.Budget.parse({'pids_max': 16, 'parent': str(tmp_path)})
    with pytest.raises(job_budget.JobBudgetError) as caught:
        job_budget.Job(budget, namespace_backend=True)
    assert caught.value.job_budget['status'] == 'unavailable'
    assert caught.value.job_budget['effective'] == {}


def test_public_none_profile_cannot_silently_drop_required_job_budget(tmp_path):
    from core.sandbox import sandbox
    canary = tmp_path / 'never-started'
    with sandbox(profile='none', job_budget={'pids_max': 16}) as run:
        with pytest.raises(job_budget.JobBudgetError) as caught:
            run(['/bin/touch', str(canary)])
    assert not canary.exists()
    assert caught.value.job_budget['effective'] == {}


def test_optional_budget_records_native_trusted_noop_downgrade():
    from core.sandbox import run
    result = run([sys.executable, "-c", "pass"], profile='none', job_budget={'pids_max': 16, 'required': False},
                 capture_output=True, timeout=5)
    assert result.returncode == 0
    assert result.sandbox_info['job_budget']['status'] == 'unavailable'
    assert result.sandbox_info['job_budget']['required'] is False
    assert result.sandbox_info['job_budget']['effective'] == {}


def test_job_cleanup_failure_cannot_turn_into_success(controls, monkeypatch):
    import os
    job = job_budget.Job(job_budget.Budget.parse({'pids_max': 16}), namespace_backend=True)
    reader, writer = os.pipe()
    job.reader = reader
    job.writer = None
    job.watcher = None
    os.close(writer)
    with pytest.raises(job_budget.JobBudgetError) as caught:
        job.close()
    assert caught.value.job_budget['cleanup'] == 'failed'
    assert controls.released


@pytest.mark.parametrize("owner_alive,write_failure", [(False, False), (True, False), (False, True)])
def test_watcher_owner_death_or_explicit_stop_retire_once(controls, owner_alive, write_failure):
    import signal
    from types import SimpleNamespace
    from core.testing.module_views import module_function_view
    calls = []
    class Exit(BaseException):
        pass
    def stop(scope):
        calls.append('stop')
        return {'cleanup': 'complete'}
    def write(fd, raw):
        calls.append('write')
        if write_failure:
            raise BrokenPipeError('owned reader gone')
        return len(raw)
    def exit_process(code):
        calls.append(('exit', code))
        raise Exit()
    def read(fd, count):
        calls.append('read-stop-byte')
        return b'S'
    signals = SimpleNamespace(SIGINT=signal.SIGINT, SIGTERM=signal.SIGTERM,
                              SIGHUP=signal.SIGHUP, SIG_IGN=signal.SIG_IGN,
                              signal=lambda *args: None)
    view = module_function_view(job_budget, bindings={
        'os': SimpleNamespace(getppid=lambda: 123 if owner_alive else 456,
                              read=read, write=write, _exit=exit_process, set_blocking=lambda *args: None),
        'signal': signals, '_finish_scope': stop,
        'select': SimpleNamespace(select=lambda *args: ([1], [], [])),
    })
    with pytest.raises(Exit):
        view._watch(controls, 1, 2, lambda keep: calls.append('fd-sweep'), 123)
    assert calls.count('stop') == 1
    assert ('read-stop-byte' in calls) == owner_alive
    assert calls[-1] == ('exit', 1 if write_failure else 0)


def test_admission_cancellation_preserves_original_exception(controls, monkeypatch):
    failure = KeyboardInterrupt('owned attach cancellation')
    def interrupted(pid):
        raise failure
    monkeypatch.setattr(controls, 'attach', interrupted)
    job = job_budget.Job(job_budget.Budget.parse({'pids_max': 16}), namespace_backend=True)
    with pytest.raises(KeyboardInterrupt) as caught:
        job.attach(12345)
    assert caught.value is failure


def test_budget_cannot_export_control_files_or_sys_grants(controls, tmp_path):
    job = job_budget.Job(job_budget.Budget.parse({'pids_max': 16}), namespace_backend=True)
    with pytest.raises(job_budget.JobBudgetError):
        job.ensure_exports(['/sys'], [])
    alias = tmp_path / 'sys-alias'
    alias.symlink_to('/sys', target_is_directory=True)
    with pytest.raises(job_budget.JobBudgetError):
        job.ensure_exports([alias], [])
    with pytest.raises(job_budget.JobBudgetError):
        job.ensure_exports([], [controls.node])


def test_control_sealing_failure_never_claims_success(monkeypatch):
    import builtins
    from types import SimpleNamespace
    from core.sandbox import mount_ns
    from core.testing.module_views import module_function_view
    failure = PermissionError('owned sealing refusal')
    calls = []
    def mount(*args):
        calls.append(args)
        raise failure
    module = SimpleNamespace(_mount=mount, MS_RDONLY=mount_ns.MS_RDONLY)
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'mount_ns' and level == 1:
            return module
        return builtins.__import__(name, globals, locals, fromlist, level)
    view = module_function_view(job_budget, bindings={
        'os': SimpleNamespace(path=SimpleNamespace(isdir=lambda path: True))}, import_hook=imports)
    seal = view._prepare_control_sealer()
    with pytest.raises(PermissionError) as caught:
        seal()
    assert caught.value is failure
    assert calls[0][0:3] == ('tmpfs', '/sys/fs/cgroup', 'tmpfs')
    assert calls[0][3] & mount_ns.MS_RDONLY
