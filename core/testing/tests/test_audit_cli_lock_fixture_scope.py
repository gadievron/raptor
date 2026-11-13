"""CLI wiring tests release their real locks while preserving borrowed handles."""
from contextlib import contextmanager, nullcontext
import os
import errno

import pytest

from core.audit import run_lock
from core.audit.tests import test_audit_cli_lifecycle as native


@pytest.mark.parametrize("name", ["test_explicit_out_goes_through_lifecycle_start", "test_no_out_still_resolves_via_lifecycle"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_cli_fixture_releases_only_owned_locks(tmp_path, name, failure):
    registry = run_lock._HELD
    before = tuple(registry)
    acquire = run_lock.acquire_run_lock
    inherited_dir = tmp_path / "inherited"
    inherited_dir.mkdir()
    borrowed = acquire(inherited_dir, "run")
    borrowed_fd = borrowed.fd
    owned = []
    owned_fds = []
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    try:
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                with contextmanager(native._owned_run_locks.__wrapped__)(patch):
                    getattr(native, name)(tmp_path, patch)
                    owned = [h for h in registry if all(h is not b for b in (*before, borrowed))]
                    assert len(owned) == 1
                    owned_fds = [h.fd for h in owned]
                    assert owned[0].held
                    assert borrowed.held
                    if failure:
                        raise failure("owned body failure")
        assert run_lock._HELD is registry
        assert tuple(registry) == (*before, borrowed)
        assert all(not h.held and h.fd == -1 for h in owned)
        for fd in owned_fds:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
        assert borrowed.fd == borrowed_fd and borrowed.held
        os.fstat(borrowed_fd)
        assert run_lock.acquire_run_lock is acquire
    finally:
        for handle in tuple(registry):
            if all(handle is not b for b in before):
                handle.release()
    assert tuple(registry) == before
