"""Metadata project-run fixtures restore borrowed process-pin provenance."""

import pytest

from core.run import pin
from core.run.tests import test_metadata as native
from core.testing.module_state import isolated_module_state

pytest_plugins = ["core.run.tests.test_metadata"]
FIELDS = ("_process_project", "_process_project_set", "_process_project_threaded")


@pytest.mark.parametrize("value,threaded", [("caller-owned", True), ("-", False), (None, False)])
@pytest.mark.parametrize("error", [None, OSError, KeyboardInterrupt, SystemExit])
def test_project_run_fixture_restores_caller_after_body_undo(value, threaded, error):
    borrowed = dict(zip(FIELDS, (value, value is not None, threaded)))
    with isolated_module_state(pin, borrowed):
        case = native.TestRunCoverageSnapshot("test_completion_snapshots_project_run_coverage")
        failure = error("owned metadata body failure") if error else None
        cleanups = []

        def invoke():
            try:
                case.setUp()
                assert tuple(getattr(pin, field) for field in FIELDS) == (None, False, False)
                with pytest.MonkeyPatch.context() as body:
                    body.setattr(pin, "_process_project", "body-owned")
                    body.setattr(pin, "_process_project_set", True)
                    body.setattr(pin, "_process_project_threaded", True)
                    body.undo()
                    assert tuple(getattr(pin, field) for field in FIELDS) == (None, False, False)
                    # Full native project/start/completion/coverage assertions.
                    case.test_completion_snapshots_project_run_coverage()
                    if error:
                        pin.set_process_project("fixture-owned", threaded=True)
                        raise failure
            finally:
                cleanups.append(case.doCleanups())

        try:
            if error:
                with pytest.raises(error) as caught:
                    invoke()
                assert caught.value is failure
            else:
                invoke()
            assert cleanups == [True]
            restored = tuple(getattr(pin, field) for field in FIELDS)
            assert all(actual is original for actual, original in zip(restored, borrowed.values()))
            assert pin.get_process_project() == value
            assert not native.Path(case._registry_tmp.name).exists()
        finally:
            case.doCleanups()
