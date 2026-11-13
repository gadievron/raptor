"""A started group process stays owned until handle construction succeeds."""
from types import SimpleNamespace

import pytest

from core.sandbox import supervised as sup
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, RuntimeError])
@pytest.mark.parametrize('cleanup_failure', [False, True])
def test_constructor_failure_retires_started_group(error_type, cleanup_failure):
    primary = error_type('owned handle failure')
    private, events, _ = _view(primary, cleanup_failure)
    with pytest.raises(error_type) as raised:
        private._spawn_group_tier(['owned-target'], {}, None, None, None, False, None)
    assert raised.value is primary
    assert events == [('kill', 71), ('wait', sup._KILL_REAP_BUDGET_S)]


def test_success_transfers_popen_without_retirement():
    private, events, process = _view(None)
    handle = private._spawn_group_tier(['owned-target'], {}, None, None, None, False, None)
    assert handle.popen is process and handle.pid == 71
    assert events == []


def test_popen_failure_has_no_acquired_process_to_retire():
    primary = OSError('owned Popen refusal')
    private, events, _ = _view(primary, launch_failure=True)
    with pytest.raises(sup.SandboxSetupError) as raised:
        private._spawn_group_tier(['owned-target'], {}, None, None, None, False, None)
    assert raised.value.__cause__ is primary
    assert events == []


def _view(primary, cleanup_failure=False, launch_failure=False):
    events = []

    def wait(*, timeout):
        events.append(('wait', timeout))
        return 0

    process = SimpleNamespace(pid=71, wait=wait)

    def popen(cmd, **kwargs):
        assert cmd == ['owned-target'] and kwargs['start_new_session'] is True
        if launch_failure:
            raise primary
        return process

    def handle(**kwargs):
        if primary:
            raise primary
        return SimpleNamespace(**kwargs)

    def kill(pid, signum):
        assert signum == sup.signal.SIGKILL
        events.append(('kill', pid))
        if cleanup_failure:
            raise OSError('owned cleanup failure')

    private = module_function_view(sup, bindings={
        'subprocess': SimpleNamespace(Popen=popen),
        'SupervisedHandle': handle, 'os': SimpleNamespace(killpg=kill),
    })
    return private, events, process
