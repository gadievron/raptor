"""Checklist authority fixtures preserve unrelated runners and real locks."""
from contextlib import contextmanager, nullcontext
import errno
import inspect
import os
import subprocess

import pytest

from core.audit import run_lock
from core.audit.tests import test_checklist_target_mismatch as native


@pytest.mark.parametrize("name", ["test_mismatch_discards_and_rebuilds", "test_matching_checklist_kept_no_rebuild"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_checklist_fixture_owns_only_its_resources(tmp_path, capsys, name, failure):
    runner = subprocess.run
    acquire = run_lock.acquire_run_lock
    registry = run_lock._HELD
    before = tuple(registry)
    directory = tmp_path / "borrowed"
    directory.mkdir()
    borrowed = acquire(directory, "run")
    borrowed_fd = borrowed.fd
    originals = []
    calls = []
    token = object()
    owned = []
    fds = []

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    try:
        with pytest.MonkeyPatch.context() as owner:
            owner.setattr(subprocess, "run", unrelated)
            with expected:
                with pytest.MonkeyPatch.context() as patch:
                    with contextmanager(native._private_cli_runtime.__wrapped__)(patch) as install:
                        def checked(mod, fake_run):
                            originals.append((mod, mod.cmd_run))
                            install(mod, fake_run)
                            assert subprocess.run is unrelated

                        method = getattr(native.TestCmdRunChecklistGate(), name)
                        args = {"tmp_path": tmp_path, "monkeypatch": patch,
                                "capsys": capsys, "_private_cli_runtime": checked}
                        method(**{k: args[k] for k in inspect.signature(method).parameters})
                        assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                        assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                        owned = [h for h in registry if all(h is not b for b in (*before, borrowed))]
                        assert len(owned) == 1 and owned[0].held
                        fds = [h.fd for h in owned]
                        if failure:
                            raise failure("owned body failure")
            assert len(originals) == 1
            assert all(mod.cmd_run is function for mod, function in originals)
            assert run_lock.acquire_run_lock is acquire
            assert run_lock._HELD is registry
            assert tuple(registry) == (*before, borrowed)
            assert all(not h.held and h.fd == -1 for h in owned)
            for fd in fds:
                with pytest.raises(OSError) as closed:
                    os.fstat(fd)
                assert closed.value.errno == errno.EBADF
            assert borrowed.fd == borrowed_fd and borrowed.held
            os.fstat(borrowed_fd)
            assert subprocess.run is unrelated
    finally:
        for handle in tuple(registry):
            if all(handle is not b for b in before):
                handle.release()
    assert tuple(registry) == before
    assert subprocess.run is runner
