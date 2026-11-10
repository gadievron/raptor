"""Native pin fixtures borrow caller process state and restore it after undo."""

import pytest

from core.run import pin
from core.run.tests import test_pin as native
from core.testing.module_state import isolated_module_state

FIELDS = ("_process_project", "_process_project_set", "_process_project_threaded")


@pytest.mark.parametrize("value,threaded", [("caller-owned", True), ("-", False), (None, False)])
@pytest.mark.parametrize("error", [None, OSError, KeyboardInterrupt, SystemExit])
def test_native_fixture_restores_borrowed_process_pin(value, threaded, error):
    borrowed = dict(zip(FIELDS, (value, value is not None, threaded)))
    with isolated_module_state(pin, borrowed):
        case = native.ResolveForStartTest("test_argv_beats_binding_beats_symlink")
        failure = error("owned native fixture body failure") if error else None
        try:
            case.setUp()
            assert tuple(getattr(pin, field) for field in FIELDS) == (None, False, False)
            with pytest.MonkeyPatch.context() as body:
                body.setattr(pin, "_process_project", "body-owned")
                body.setattr(pin, "_process_project_set", True)
                body.setattr(pin, "_process_project_threaded", True)
                body.undo()
                assert tuple(getattr(pin, field) for field in FIELDS) == (None, False, False)
                # Execute the full original precedence scenario with the real
                # project registry, session ledger and resolver assertions.
                case.test_argv_beats_binding_beats_symlink()
                if error:
                    with pytest.raises(error) as caught:
                        pin.set_process_project("fixture-owned", threaded=True)
                        raise failure
                    assert caught.value is failure
            assert case.doCleanups(), "native unittest cleanup failed"
            restored = tuple(getattr(pin, field) for field in FIELDS)
            assert all(actual is original for actual, original in zip(restored, borrowed.values()))
            assert pin.get_process_project() == value
            assert not case.root.exists()
        finally:
            case.doCleanups()
