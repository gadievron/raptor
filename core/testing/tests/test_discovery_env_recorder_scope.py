"""Stage E environment recorder does not replace unrelated subprocess users."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from packages.exploitability_validation.tests import test_discover_executables_env as native


@pytest.mark.parametrize("method", [
    "test_safe_env_failure_never_leaks_ambient_environ",
    "test_safe_env_failure_warns_loudly",
    "test_safe_env_failure_emits_security_event",
    "test_no_security_event_on_healthy_safe_env",
    "test_emission_failure_never_breaks_the_fail_closed_path",
    "test_healthy_safe_env_is_used_unchanged",
])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_environment_fixture_restores_discovery(tmp_path, method, failure):
    runner = subprocess.run
    discover = native._helper._discover_executables
    scope = native._discovery_run
    entered = []

    @contextmanager
    def checked(*args, **kwargs):
        with scope(*args, **kwargs) as recorder:
            entered.append(recorder)
            assert native._helper._discover_executables is not discover
            assert subprocess.run is runner
            yield recorder
            recorder.assert_called_once()
            argv = recorder.call_args.args[0]
            assert argv[0] == "find"
            assert isinstance(recorder.call_args.kwargs["env"], dict)
            assert subprocess.run is runner
            if failure:
                raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "_discovery_run", checked)
        with expected:
            getattr(native.DiscoverExecutablesEnvTests(), method)()
        assert len(entered) == 1
        assert native._helper._discover_executables is discover
        assert subprocess.run is runner
    assert native._discovery_run is scope
