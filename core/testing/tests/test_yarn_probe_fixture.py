"""The Yarn env fixture owns the version probe it intends to replace."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from packages.sca.resolvers import _proxy_hosts, yarn
from packages.sca.resolvers.tests import test_resolvers as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_yarn_env_fixture_replaces_actual_version_probe(failure, tmp_path):
    original_probe, original_run = yarn._detect_major_version, yarn._run
    original_check, original_subprocess = yarn._check_tool, yarn.subprocess
    absent = object()
    class_probe = vars(yarn.YarnResolver).get("_detect_major_version", absent)
    attempted, installs = [], []

    def denied(command, **kwargs):
        attempted.append(list(command))
        raise AssertionError("unexpected native version probe")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(yarn, "subprocess", SimpleNamespace(**(vars(original_subprocess) | {"run": denied})))
        patch.setattr(_proxy_hosts, "_calibrated_profile", lambda *a, **k: None)

        class Recorder:
            def setattr(self, owner, name, value, raising=True):
                if owner is yarn and name == "_run":
                    original = value

                    def record(command, **kwargs):
                        installs.append(list(command))
                        result = original(command, **kwargs)
                        if failure:
                            raise failure("owned resolver body failure")
                        return result

                    value = record
                patch.setattr(owner, name, value, raising=raising)

        expected = pytest.raises(failure, match="owned resolver body failure") if failure else nullcontext()
        with expected:
            native.test_yarn_env_overlays_safe_env(Recorder(), tmp_path)
        assert attempted == []
        assert len(installs) == 1
        assert "--mode=update-lockfile" in installs[0]
        assert "--ignore-scripts" not in installs[0]
        assert yarn._detect_major_version() == 3
        assert vars(yarn.YarnResolver).get("_detect_major_version", absent) is class_probe
    assert yarn._detect_major_version is original_probe
    assert yarn._run is original_run
    assert yarn._check_tool is original_check
    assert yarn.subprocess is original_subprocess
    assert vars(yarn.YarnResolver).get("_detect_major_version", absent) is class_probe
