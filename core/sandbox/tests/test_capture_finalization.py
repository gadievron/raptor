"""Tracer finalisation retains parent-known loss without changing records."""

from contextlib import ExitStack
import os
import sys

import pytest

from core.sandbox import evidence, observe_profile, summary
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_capture_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setattr(summary, '_evidence_write_failures', dict(summary._evidence_write_failures))
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', dict(summary._evidence_inode_mismatches))


@pytest.fixture
def capture_handle(tmp_path):
    run = tmp_path / 'run'
    run.mkdir()
    with ExitStack() as owner:
        handle = evidence.EvidenceFile.open(run, 'owned.jsonl')
        owner.callback(handle.close)
        yield handle, run


def test_clean_finalization_does_not_publish_loss(capture_handle):
    handle, run = capture_handle
    assert handle.write_record({'type': 'owned-control'})
    assert evidence.finalize_capture(handle) is True
    assert evidence.finalize_capture(handle) is True
    assert handle._fd_released is True
    assert summary.get_evidence_write_failure(run) is False


def test_cached_verification_failure_is_sticky_without_rearming_publication(capture_handle, monkeypatch):
    handle, run = capture_handle
    monkeypatch.setattr(handle, 'verify', lambda: False)
    assert evidence.finalize_capture(handle) is False
    assert summary.get_evidence_write_failure(run) is True
    key = str(run.resolve())
    # Existing summary publication consumes the pending value but retains the
    # key as an in-process loss floor. A cached close must not re-arm it.
    monkeypatch.setitem(summary._evidence_write_failures, key, False)
    assert evidence.finalize_capture(handle) is False
    assert summary._evidence_write_failures[key] is False
    assert summary.get_evidence_write_failure(run) is True
    assert summary.get_evidence_write_failure(run.parent / 'other-run') is False
    assert handle._fd_released is True


def test_close_io_failure_reaches_parent_memory_after_descriptor_release(capture_handle, monkeypatch):
    handle, run = capture_handle
    close = os.close
    def fail_after_close(fd):
        close(fd)
        raise OSError('owned close acknowledgement failed')
    patch_module_attribute(monkeypatch, evidence, 'os', 'close', fail_after_close)
    assert evidence.finalize_capture(handle) is False
    assert handle._fd_released is True
    assert summary.get_evidence_write_failure(run) is True


@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt])
def test_verification_exception_is_preserved_after_loss_publication(capture_handle, monkeypatch, failure_type):
    handle, run = capture_handle
    failure = failure_type('owned verification error')
    def fail():
        raise failure
    monkeypatch.setattr(handle, 'verify', fail)
    with pytest.raises(BaseException) as caught:
        evidence.finalize_capture(handle)
    assert caught.value is failure
    assert handle._fd_released is True
    assert summary.get_evidence_write_failure(run) is True


@pytest.mark.parametrize('secondary_type', [OSError, KeyboardInterrupt])
def test_publication_error_does_not_replace_verification_interrupt(capture_handle, monkeypatch, secondary_type):
    handle, _ = capture_handle
    primary = KeyboardInterrupt('owned verification interrupt')
    secondary = secondary_type('owned publication error')
    def fail_verify():
        raise primary
    def fail_publish(run):
        raise secondary
    monkeypatch.setattr(handle, 'verify', fail_verify)
    monkeypatch.setattr(summary, '_record_evidence_write_failure', fail_publish)
    with pytest.raises(BaseException) as caught:
        evidence.finalize_capture(handle)
    assert caught.value is primary
    assert caught.value.__cause__ is secondary
    assert handle._fd_released is True


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.parametrize('backend', ['landlock', 'namespaces'])
@pytest.mark.parametrize('failed_verification', [False, True])
def test_native_capture_finalization_reaches_current_reader(tmp_path, monkeypatch, backend, failed_verification):
    if sys.platform != 'linux':
        pytest.skip('Native Linux tracer capture')
    from core.sandbox import _landlock_audit, _spawn, landlock, ptrace_probe, seccomp
    from core.sandbox.tests.test_spawn_audit import _audit_prereqs_ok
    if not landlock.check_landlock_available():
        pytest.skip('Landlock unavailable')
    if not ptrace_probe.check_ptrace_available() or not seccomp.check_seccomp_available():
        pytest.skip('ptrace/libseccomp unavailable')
    if backend == 'namespaces':
        available, reason = _audit_prereqs_ok()
        if not available:
            pytest.skip(reason)
    run = tmp_path / 'run'
    run.mkdir()
    close = evidence.EvidenceFile.close
    observed = []
    def close_with_verdict(self, *args, **kwargs):
        actual = close(self, *args, **kwargs)
        observed.append(actual)
        # Release the real descriptor and leave all records intact. Only the
        # parent-side verification verdict is fault-injected.
        assert actual is True
        return not failed_verification
    monkeypatch.setattr(evidence.EvidenceFile, 'close', close_with_verdict)
    nonce = 'owned-capture-finalization'
    readable = ['/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc']
    common = dict(audit_run_dir=str(run), observe_mode=True, observe_nonce=nonce,
                  writable_paths=[str(run)], readable_paths=readable,
                  restrict_reads=True, env={'PATH': '/usr/bin:/bin'}, timeout=30)
    if backend == 'landlock':
        result = _landlock_audit.run_landlock_audit(
            ['/bin/true'], **common,
            landlock_preexec=landlock._make_landlock_preexec(
                [str(run)], readable_paths=readable, fail_raise=True),
            seccomp_preexec=seccomp._make_seccomp_preexec('full', audit_mode=True, observe_mode=True),
        )
        assert result.evidence_verified is (not failed_verification)
    else:
        result = _spawn.run_sandboxed(
            ['/bin/true'], **common, target=None, output=None,
            block_network=False, nproc_limit=0, limits={}, allowed_tcp_ports=None,
            seccomp_profile='full', seccomp_block_udp=False, cwd=None,
            audit_mode=True, audit_required=True,
        )
        assert result._setup_status is None
    assert result.returncode == 0, result.stderr
    assert observed
    assert summary.get_evidence_write_failure(run) is failed_verification
    profile = observe_profile.parse_observe_log(
        run, expected_nonce=nonce, sandbox_info={'nonce_delivery': 'anonymous_fd'},
        current_run=True,
    )
    assert profile.nonce_trusted is True
    assert profile.budget_truncated is False
    assert profile.capture_incomplete is failed_verification
    # An offline parse has no current parent-memory guarantee. Its own record
    # validation remains independent of the simulated close verdict.
    offline = observe_profile.parse_observe_log(run, expected_nonce=nonce)
    assert offline.capture_incomplete is False


@pytest.mark.slow
@pytest.mark.linux_native
def test_finally_retry_preserves_original_verification_interrupt(tmp_path, monkeypatch):
    from core.sandbox import _landlock_audit as audit
    if sys.platform != 'linux':
        pytest.skip('Native Linux tracer cleanup')
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    if not check_ptrace_available() or not check_seccomp_available():
        pytest.skip('ptrace/libseccomp unavailable')
    run = tmp_path / 'run'
    run.mkdir()
    primary = KeyboardInterrupt('owned verification interrupt')
    secondary = OSError('owned failure-publication error')
    def verify(self):
        raise primary
    def publish(run):
        raise secondary
    monkeypatch.setattr(evidence.EvidenceFile, 'verify', verify)
    monkeypatch.setattr(summary, '_record_evidence_write_failure', publish)
    with pytest.raises(BaseException) as caught:
        audit.run_landlock_audit(
            ['/bin/true'], audit_run_dir=str(run),
            env={'PATH': '/usr/bin:/bin'}, timeout=30,
        )
    assert caught.value is primary


@pytest.mark.parametrize('secondary_type', [OSError, KeyboardInterrupt])
def test_cached_close_publication_keeps_active_caller_error(capture_handle, monkeypatch, secondary_type):
    handle, _ = capture_handle
    monkeypatch.setattr(handle, 'verify', lambda: False)
    assert handle.close() is False
    primary = ValueError('owned caller error')
    secondary = secondary_type('owned cached publication failure')
    def fail_publish(run):
        raise secondary
    monkeypatch.setattr(summary, '_record_evidence_write_failure', fail_publish)
    try:
        raise primary
    except ValueError:
        with pytest.raises(BaseException) as caught:
            evidence.finalize_capture(handle)
    assert caught.value is primary
    assert caught.value.__cause__ is secondary
    assert handle._fd_released is True
