"""Checklist timeout wiring owns fakes and real locks across failure exits."""
from contextlib import contextmanager, nullcontext
import errno
import inspect
import os
import subprocess

import pytest

from core.audit import run_lock
from core.audit.tests import test_checklist_build_timeout as native


_CASES = [
    "test_gaps_checklist_build_timeout_reported",
    "test_run_checklist_build_timeout_fails_lifecycle",
    "TestRunPathWiring.test_small_target_keeps_the_floor_bound",
    "TestGapsPathWiring.test_invalid_override_refused_before_spawn",
]


@pytest.mark.parametrize("name", _CASES)
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_timeout_wiring_restores_borrowed_resources(tmp_path, capsys, name, failure):
    runner = subprocess.run
    acquire = run_lock.acquire_run_lock
    registry = run_lock._HELD
    before = tuple(registry)
    cache = native._CLI_MOD
    directory = tmp_path / "borrowed"
    directory.mkdir()
    borrowed = acquire(directory, "run")
    borrowed_fd = borrowed.fd
    calls = []
    token = object()
    originals = []
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
                    with contextmanager(native._no_override.__wrapped__)(patch) as install:
                        def checked(mod, fake_run):
                            originals.append((mod, mod.cmd_run, mod.cmd_gaps))
                            install(mod, fake_run)
                            assert subprocess.run is unrelated

                        if "." in name:
                            cls, method = name.split(".")
                            function = getattr(getattr(native, cls)(), method)
                        else:
                            function = getattr(native, name)
                        args = {"tmp_path": tmp_path, "monkeypatch": patch,
                                "capsys": capsys, "_no_override": checked}
                        function(**{k: args[k] for k in inspect.signature(function).parameters})
                        assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                        assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                        owned = [h for h in registry if all(h is not b for b in (*before, borrowed))]
                        assert len(owned) == (1 if name in _CASES[1:3] else 0)
                        assert all(h.held for h in owned)
                        fds = [h.fd for h in owned]
                        if failure:
                            raise failure("owned body failure")
            assert len(originals) == 1
            assert all(mod.cmd_run is run and mod.cmd_gaps is gaps for mod, run, gaps in originals)
            assert native._CLI_MOD is cache
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
