"""Audit CLI recorders own local imports without intercepting other callers."""
from contextlib import contextmanager, nullcontext
import inspect
import subprocess

import pytest

from core.audit.tests import test_audit_cli_lifecycle as native


_CASES = [
    "test_explicit_out_goes_through_lifecycle_start",
    "test_no_out_still_resolves_via_lifecycle",
    "test_project_pin_forwarded_to_lifecycle_child",
    "test_explicitly_projectless_dash_forwarded_verbatim",
    "test_no_project_flag_forwards_nothing",
    "test_project_pin_forwarded_alongside_explicit_out",
    "test_surface_run_project_reaches_lifecycle_child_argv",
    "test_surface_invalid_project_is_one_line_error",
]


@pytest.mark.parametrize("name", _CASES)
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_cli_recorder_restores_import_scope(tmp_path, capsys, name, failure):
    runner = subprocess.run
    calls = []
    originals = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "run", unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                with contextmanager(native._owned_run_locks.__wrapped__)(patch):
                    with contextmanager(native._private_cli_run.__wrapped__)(patch) as install:
                        def checked(mod, fake_run):
                            originals.append((mod, mod.cmd_run))
                            install(mod, fake_run)
                            assert mod.cmd_run is not originals[-1][1]
                            assert subprocess.run is unrelated

                        function = getattr(native, name)
                        args = {"tmp_path": tmp_path, "monkeypatch": patch,
                                "capsys": capsys, "_private_cli_run": checked}
                        function(**{key: args[key] for key in inspect.signature(function).parameters})
                        assert len(originals) == 1
                        assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                        assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                        if failure:
                            raise failure("owned body failure")
        assert all(mod.cmd_run is original for mod, original in originals)
        assert subprocess.run is unrelated
    assert subprocess.run is runner
