"""SCA self-test bare-run guards stay on the hardening consumer."""
from contextlib import nullcontext
import subprocess

import pytest

from packages.sca import harden
from packages.sca.tests import test_harden_self_test_sandbox as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_self_test_guard_restores_consumer_binding(tmp_path, failure):
    namespace, runner = harden.subprocess, subprocess.run
    calls = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, 'run', unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.test_self_test_does_not_use_unsandboxed_subprocess_run(tmp_path, patch)
                assert harden.subprocess is not namespace
                assert harden.subprocess.SubprocessError is subprocess.SubprocessError
                assert subprocess.run(['unrelated-owned-sentinel'], timeout=7) is token
                assert calls == [(['unrelated-owned-sentinel'], {'timeout': 7})]
                if failure:
                    raise failure('owned body failure')
        assert harden.subprocess is namespace
        assert subprocess.run is unrelated
    assert subprocess.run is runner


def test_actual_self_test_guard_still_rejects_bare_run(tmp_path, monkeypatch):
    def unsafe(**kwargs):
        return harden.subprocess.run(['owned-negative-control']).returncode

    monkeypatch.setattr(native, '_run_self_test', unsafe)
    with pytest.MonkeyPatch.context() as patch:
        with pytest.raises(AssertionError, match='must route through core.sandbox.context.run_untrusted'):
            native.test_self_test_does_not_use_unsandboxed_subprocess_run(tmp_path, patch)
