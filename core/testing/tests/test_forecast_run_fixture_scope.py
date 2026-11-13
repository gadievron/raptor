"""Forecast-run fixture owns process fakes and real lock handle lifetimes."""
from contextlib import contextmanager, nullcontext
import errno
import os
import subprocess

import pytest

from core.audit import run_lock
from core.audit.tests import test_audit_forecast_cli as native
from core.audit import codeql_provision


@pytest.mark.parametrize("name", ["test_forecast_exits_zero_spend", "test_forecast_without_inventory_fails_loudly", "test_capped_run_skips_band"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_forecast_fixture_preserves_borrowed_resources(tmp_path, capsys, name, failure):
    runner = subprocess.run
    provision = codeql_provision.provision_codeql_dbs
    acquire = run_lock.acquire_run_lock
    registry = run_lock._HELD
    before = tuple(registry)
    directory = tmp_path / "borrowed"
    directory.mkdir()
    borrowed = acquire(directory, "run")
    borrowed_fd = borrowed.fd
    loads = []
    raw_load = native._load_cli
    calls = []
    token = object()
    owned = []
    fds = []

    def load():
        mod = raw_load()
        loads.append((mod, mod.cmd_run))
        return mod

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    try:
        with pytest.MonkeyPatch.context() as owner:
            owner.setattr(native, "_load_cli", load)
            owner.setattr(subprocess, "run", unrelated)
            with expected:
                with pytest.MonkeyPatch.context() as patch:
                    with contextmanager(native.cli_env.__wrapped__)(tmp_path, patch) as env:
                        getattr(native, name)(env, capsys)
                        assert codeql_provision.provision_codeql_dbs is provision
                        if name == "test_capped_run_skips_band":
                            assert env.provision_calls == [(env.target.resolve(), env.out_dir)]
                        else:
                            assert env.provision_calls == []
                        assert subprocess.run is unrelated
                        assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                        assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                        owned = [h for h in registry if all(h is not b for b in (*before, borrowed))]
                        assert len(owned) == 1 and owned[0].held
                        fds = [h.fd for h in owned]
                        if failure:
                            raise failure("owned body failure")
            assert len(loads) == 1
            assert all(mod.cmd_run is function for mod, function in loads)
            assert codeql_provision.provision_codeql_dbs is provision
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
    assert native._load_cli is raw_load
