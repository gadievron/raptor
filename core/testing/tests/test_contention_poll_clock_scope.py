"""A contention fixture's polling shortcut leaves the shared clock untouched."""
from contextlib import contextmanager, nullcontext
import time

import pytest

from core.run import metadata, provenance
from core.run.tests import test_run_contention as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_wait_fixture_restores_clock(tmp_path, failure):
    sleep = time.sleep
    gate = metadata._project_run_gate
    lookup = metadata._live_conflicting_run
    git = provenance._git
    helper = native.scoped_function_imports
    entered, clocks = [], []

    def observed(*args, **kwargs):
        assert time.sleep is sleep
        clock = entered[0].time.sleep
        if not clocks:
            clocks.append(clock)
        return lookup(*args, **kwargs)

    @contextmanager
    def checked(consumer, functions, imports):
        assert consumer is not metadata
        assert functions == ('_owned_gate',)
        assert imports == {'time': time}
        assert consumer._owned_gate.__code__ is gate.__wrapped__.__code__
        with helper(consumer, functions, imports) as private:
            entered.append(private)
            try:
                yield private
                assert metadata._project_run_gate is gate
                assert provenance._git is git
                if failure:
                    raise failure('owned body failure')
            finally:
                assert time.sleep is sleep
                assert metadata._project_run_gate is gate
                assert provenance._git is git

    state = native._user_state_in_tmp.__wrapped__(tmp_path)
    next(state)
    case = native.StartRunGateTest('test_wait_queues_until_holder_finishes')
    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    try:
        case.setUp()
        with pytest.MonkeyPatch.context() as owner:
            owner.setattr(native, 'scoped_function_imports', checked)
            owner.setattr(metadata, '_live_conflicting_run', observed)
            with expected:
                case.test_wait_queues_until_holder_finishes()
            assert len(entered) == len(clocks) == 1
            assert clocks[0].call_count > 0
            assert all(call.args == (2.0,) for call in clocks[0].call_args_list)
            assert time.sleep is sleep
            assert metadata._project_run_gate is gate
            assert provenance._git is git
        assert native.scoped_function_imports is helper
    finally:
        case.doCleanups()
        state.close()
