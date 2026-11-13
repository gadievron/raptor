"""PoC security fixtures keep failure imports and process recorders private."""
import builtins
from contextlib import nullcontext
import subprocess
import sys

import pytest

from core.run.tests import test_validation_helper_poc_build as native


@pytest.mark.parametrize("case", ["refusal", "optout", "setup"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_security_cases_preserve_other_consumers(tmp_path, caplog, case, failure):
    runner, importer = subprocess.run, builtins.__import__
    originals = []
    calls = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "run", unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                install = native._private_poc_runtime.__wrapped__(patch)

                def checked(mod, import_hook=None):
                    original = mod._build_standalone_pocs
                    originals.append((mod, original))
                    process = install(mod, import_hook)
                    assert mod._build_standalone_pocs.__code__ is original.__code__
                    assert process is not subprocess
                    assert process.CompletedProcess is subprocess.CompletedProcess
                    assert builtins.__import__ is importer
                    return process

                if case == "refusal":
                    native.test_missing_sandbox_refuses_before_any_compiler_call(tmp_path, patch, None, checked)
                elif case == "optout":
                    native.test_missing_sandbox_explicit_optout_logs_and_keeps_filtered_env(tmp_path, patch, caplog, checked)
                else:
                    native.test_sandbox_setup_failure_never_retries_as_bare_compile(tmp_path, patch, checked)
                assert len(originals) == 1
                assert builtins.__import__ is importer
                assert __import__("core.sandbox", fromlist=["run"]) is sys.modules["core.sandbox"]
                assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                if failure:
                    raise failure("owned body failure")
        assert all(mod._build_standalone_pocs is original for mod, original in originals)
        assert subprocess.run is unrelated
        assert builtins.__import__ is importer
    assert subprocess.run is runner
