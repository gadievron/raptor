"""Coverage hook fixture homes retire even when registry setup aborts."""

import os
from pathlib import Path

import pytest

from core.coverage.tests import test_record as native


@pytest.mark.parametrize("phase,error", [(phase, error)
    for phase in ("factory", "started")
    for error in (OSError, KeyboardInterrupt, SystemExit)] + [(None, None)])
def test_native_hook_setup_cleanup_restores_environment_and_home(monkeypatch, phase, error):
    before = dict(os.environ)
    original = native.patch
    failure = error("owned hook registry setup failure") if error else None
    fired = False

    class View:
        def dict(self, *a, **k):
            nonlocal fired
            if phase == "factory":
                fired = True
                raise failure
            scope = original.dict(*a, **k)

            class Registry:
                def stop(self):
                    return scope.stop()

                def start(self):
                    nonlocal fired
                    value = scope.start()
                    if phase == "started":
                        fired = True
                        raise failure
                    return value

            return Registry()

    case = native.TestTrackReadHook("test_skips_without_active_project")
    with monkeypatch.context() as patch:
        patch.setattr(native, "patch", View())
        try:
            if error:
                with pytest.raises(error) as caught:
                    case.setUp()
                assert caught.value is failure
                assert fired
            else:
                case.setUp()
                home = Path(case._home_tmp.name)
                assert home.is_dir()
                assert os.environ["HOME"] == str(home)
                assert Path(os.environ["RAPTOR_REGISTRY_HOME"]) == home / ".raptor"
                # Preserve the original normal teardown, followed by unittest's
                # registered cleanup phase; TemporaryDirectory is idempotent.
                case.tearDown()
            assert case.doCleanups(), "native unittest cleanup failed"
            assert not Path(case._home_tmp.name).exists()
            restored = set(os.environ) == set(before) and all(
                os.environ.get(key) == value for key, value in before.items()
            )
            assert restored, "borrowed environment was not restored"
        finally:
            case.doCleanups()
            if hasattr(case, "_home_tmp"):
                case._home_tmp.cleanup()
    assert native.patch is original
