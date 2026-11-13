"""Version display fixtures keep Git outcomes local to the classmethod."""
from contextlib import contextmanager, nullcontext
from pathlib import Path
import subprocess

import pytest

from core.config.tests import test_config as native


@pytest.mark.parametrize('method', [
    'test_falls_back_to_VERSION_on_git_error',
    'test_falls_back_to_VERSION_on_nonzero_exit',
    'test_uses_git_describe_and_strips_leading_v',
])
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_version_fixture_restores_transport(method, failure):
    run = subprocess.run
    descriptor = vars(native.RaptorConfig)['effective_version']
    function = descriptor.__func__
    factory = native.module_function_view
    helper = native._version_runner
    entered, calls = [], []

    def checked_view(module, *, bindings):
        assert module is native._config
        assert bindings == {'_owned_version': function}
        view = factory(module, bindings=bindings)
        assert view._owned_version.__code__ is function.__code__
        entered.append(view)
        return view

    @contextmanager
    def checked(**kwargs):
        try:
            with helper(**kwargs) as runner:
                assert subprocess.run is run
                assert vars(native.RaptorConfig)['effective_version'] is not descriptor
                yield runner
                assert runner.call_count == 1
                calls.append(runner.call_args)
                if failure:
                    raise failure('owned body failure')
        finally:
            assert vars(native.RaptorConfig)['effective_version'] is descriptor
            assert subprocess.run is run

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as body:
        body.setattr(native, 'module_function_view', checked_view)
        body.setattr(native, '_version_runner', checked)
        with expected:
            getattr(native.TestEffectiveVersion(), method)()
        assert len(entered) == len(calls) == 1
        repo = Path(native._config.__file__).resolve().parents[2]
        assert calls[0].args == (['git', '-C', str(repo), 'describe',
                                 '--tags', '--dirty=-local', '--always'],)
        assert calls[0].kwargs == {'capture_output': True, 'text': True,
                                   'timeout': 2, 'check': False}
        assert vars(native.RaptorConfig)['effective_version'] is descriptor
        assert native.RaptorConfig.effective_version.__func__ is function
        assert subprocess.run is run
    assert native.module_function_view is factory
    assert native._version_runner is helper
