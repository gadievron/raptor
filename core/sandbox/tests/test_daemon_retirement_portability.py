"""Terminal-group recovery accepts only confirmed absence, never signal denial."""
import errno
import signal
import subprocess
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view


def control(*, platform='darwin', retained=True, owner=True, observed=0,
            signal_errno=errno.EPERM, absence='absent', wait_error=None,
            probe_error=None, failed=False):
    # Every operation involving this synthetic identity is a private binding.
    calls = []
    request = SimpleNamespace(pid=424242, returncode=None, _retain_request_group=owner,
                              _request_group_retired=False, _request_exit_status=observed)
    initial = PermissionError(signal_errno, 'owned initial signal failure')

    def observe(which, pid, flags):
        assert pid == request.pid
        calls.append('observe')
        return None

    def reap(*, timeout):
        assert 0 <= timeout <= 1
        calls.append('reap')
        if wait_error is not None:
            raise wait_error
        request.returncode = observed
        return observed

    def group_signal(pid, sig):
        assert pid == request.pid
        calls.append(('signal', sig))
        if sig == signal.SIGKILL:
            raise initial
        assert sig == 0, 'no destructive retry after consuming the leader'
        if probe_error is not None:
            raise probe_error
        if absence == 'absent':
            raise ProcessLookupError(errno.ESRCH, 'owned absent group')
        if absence == 'denied':
            raise PermissionError(errno.EPERM, 'owned group query denied')
        if absence == 'io':
            raise OSError(errno.EIO, 'owned group query unavailable')
        if absence == 'untyped-lookup':
            raise ProcessLookupError('lookup without an ESRCH result')
        assert absence == 'present'

    request.wait = reap
    request.poll = lambda: request.returncode
    private_os = SimpleNamespace(P_PID=1, WEXITED=4, WNOHANG=1, WNOWAIT=0x1000000,
                                 waitid=observe, killpg=group_signal)
    private = module_function_view(daemon, bindings={
        'os': private_os, 'sys': SimpleNamespace(platform=platform),
        'time': SimpleNamespace(monotonic=lambda: 100.0),
        '_RETAIN_REQUEST_GROUP': retained, '_REQUEST_CLEANUP_FAILED': failed,
    })
    assert private.os.killpg is group_signal and private.os.waitid is observe
    return private, request, calls, initial


def test_terminal_darwin_group_requires_esrch_after_reap():
    private, request, calls, _ = control()
    private._kill_request_group(request)
    assert calls == ['observe', ('signal', signal.SIGKILL), 'reap', ('signal', 0)]
    assert request.returncode == 0 and request._request_group_retired
    assert not private._REQUEST_CLEANUP_FAILED
    before = list(calls)
    private._kill_request_group(request)
    assert calls == before, 'consumed retirement must not signal a numeric group again'


@pytest.mark.parametrize('options', [
    {'platform': 'linux'}, {'retained': False}, {'owner': False},
    {'observed': None}, {'observed': True}, {'signal_errno': errno.EIO},
], ids=['other-platform', 'no-retention', 'not-request-owner', 'live-leader',
        'invalid-terminal-status', 'other-signal-error'])
def test_unconfirmed_ownership_does_not_enter_recovery(options):
    private, request, calls, initial = control(**options)
    with pytest.raises(private._RequestCleanupError) as caught:
        private._kill_request_group(request)
    assert caught.value.__cause__ is initial
    assert 'reap' not in calls and ('signal', 0) not in calls
    assert private._REQUEST_CLEANUP_FAILED
    assert not request._request_group_retired


@pytest.mark.parametrize('absence', ['present', 'denied', 'io', 'untyped-lookup'])
def test_presence_or_ambiguous_absence_remains_cleanup_failure(absence):
    private, request, calls, initial = control(absence=absence)
    with pytest.raises(private._RequestCleanupError) as caught:
        private._kill_request_group(request)
    assert caught.value.__cause__ is initial
    assert calls == ['observe', ('signal', signal.SIGKILL), 'reap', ('signal', 0)]
    assert private._REQUEST_CLEANUP_FAILED and not request._request_group_retired
    before = list(calls)
    with pytest.raises(private._RequestCleanupError, match='reaped before group retirement'):
        private._kill_request_group(request)
    assert calls == before


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
@pytest.mark.parametrize('stage', ['reap', 'absence'])
def test_recovery_cancellation_preserves_identity_and_failed_latch(stage, error_type):
    failure = error_type('owned recovery cancellation')
    options = {'wait_error' if stage == 'reap' else 'probe_error': failure}
    private, request, calls, _ = control(**options)
    with pytest.raises(error_type) as caught:
        private._kill_request_group(request)
    assert caught.value is failure
    assert private._REQUEST_CLEANUP_FAILED and not request._request_group_retired
    assert [value for value in calls if isinstance(value, tuple) and value[1] == signal.SIGKILL] == [
        ('signal', signal.SIGKILL),
    ]


@pytest.mark.parametrize('failure', [OSError(errno.EIO, 'owned reap failure'),
                                    subprocess.TimeoutExpired('owned request', 1)],
                         ids=['io', 'deadline'])
def test_failed_reap_cannot_claim_group_absence(failure):
    private, request, calls, initial = control(wait_error=failure)
    with pytest.raises(private._RequestCleanupError) as caught:
        private._kill_request_group(request)
    assert caught.value.__cause__ is initial
    assert ('signal', 0) not in calls
    assert private._REQUEST_CLEANUP_FAILED and not request._request_group_retired


def test_confirmed_retirement_never_clears_an_existing_failed_latch():
    private, request, _, _ = control(failed=True)
    private._kill_request_group(request)
    assert request._request_group_retired
    assert private._REQUEST_CLEANUP_FAILED
