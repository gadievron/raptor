"""Flag-inference discovery fakes leave unrelated tool lookup untouched."""
from contextlib import contextmanager, nullcontext
import shutil

import pytest

from core.build.tests import test_synthesised_javac_hardening as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_flag_fixture_restores_discovery(tmp_path, failure):
    which = shutil.which
    method = native.BuildDetector._cc_suggest_flags
    runner = native.build_detector._sandbox_run
    helper = native.scoped_function_imports
    entered, dispatched = [], []

    @contextmanager
    def checked(consumer, functions, imports):
        assert consumer is not native.build_detector
        assert functions == ('_owned_cc_suggest_flags',)
        assert imports == {'shutil': shutil}
        selected = consumer._owned_cc_suggest_flags
        assert selected.__code__ is method.__code__
        assert consumer._sandbox_run is not runner
        sandbox = consumer._sandbox_run

        def observed(*args, **kwargs):
            dispatched.append((args, kwargs))
            return sandbox(*args, **kwargs)

        consumer._sandbox_run = observed
        try:
            with helper(consumer, functions, imports) as private:
                entered.append(private)
                assert shutil.which is which
                yield private
                assert native.BuildDetector._cc_suggest_flags is method
                assert shutil.which is which
                if failure:
                    raise failure('owned body failure')
        finally:
            assert native.BuildDetector._cc_suggest_flags is method

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'scoped_function_imports', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                native.test_cc_suggest_flags_passes_read_confinement(tmp_path, body)
        assert len(entered) == len(dispatched) == 1
        args, kwargs = dispatched[0]
        assert args[0][0] == '/usr/bin/claude'
        assert kwargs['restrict_reads'] is True
        assert kwargs['readable_paths'] == ['/opt/cc-floor']
        assert native.BuildDetector._cc_suggest_flags is method
        assert native.build_detector._sandbox_run is runner
        assert shutil.which is which
    assert native.scoped_function_imports is helper
