"""Linux backend metadata parity must not imply macOS cgroup enforcement."""

from types import SimpleNamespace

import pytest

from core.sandbox import _macos_spawn as mac
from core.sandbox.errors import SandboxSetupError
from core.sandbox.job_budget import Job


def test_active_job_controller_is_refused_before_launch():
    # Only the active-scope producer field is inspected on this unsupported
    # platform. No cgroup or child is created by this refusal control.
    controller = SimpleNamespace(scope=object())
    with pytest.raises(SandboxSetupError, match='Job budgets require the Linux'):
        mac.run_sandboxed(['unused'], job_controller=controller)


@pytest.mark.parametrize('disabled', [False, True], ids=['none', 'inactive-job'])
def test_inactive_metadata_preserves_existing_rootfs_refusal(disabled):
    job = Job(None, namespace_backend=False) if disabled else None
    callbacks = []
    try:
        with pytest.raises(SandboxSetupError, match='rootfs'):
            mac.run_sandboxed(['unused'], rootfs='/unused-rootfs',
                              execution_committed_callback=lambda: callbacks.append(True),
                              job_controller=job)
        assert callbacks == []
        if job is not None:
            assert job.scope is None and job.record['status'] == 'not_requested'
    finally:
        if job is not None:
            job.close()
