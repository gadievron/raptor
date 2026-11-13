"""SDK import outcomes are simulated only in the detection consumer."""
from contextlib import contextmanager, nullcontext
import importlib
import json

import pytest

from core.llm import config, detection
from core.llm.tests import test_lazy_sdk_availability as native

CASES = [(flag, module, available)
         for flag, module in detection._SDK_IMPORTS.items()
         for available in (True, False)] + [('selected-missing', 'openai', False)]


@pytest.mark.parametrize('flag,module,available', CASES)
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_sdk_fixture_restores_imports(flag, module, available, failure):
    importer = importlib.import_module
    function = detection._sdk_available
    alias = config._sdk_available
    cache = detection._SDK_AVAILABILITY
    contents = cache.copy()
    missing = object()
    slots = {key: vars(detection).get(key, missing) for key in detection._SDK_IMPORTS}
    helper = native.scoped_function_imports
    entered = []

    @contextmanager
    def checked(consumer, functions, imports):
        assert consumer is detection
        assert functions == ('_sdk_available',)
        assert imports == {'importlib': importlib}
        try:
            with helper(consumer, functions, imports) as private:
                entered.append(private)
                assert detection._sdk_available is not function
                assert importlib.import_module is importer
                yield private
                # The inner monkeypatch scope must restore the captured alias first.
                assert config._sdk_available is alias
                assert importlib.import_module('json') is json
                if failure:
                    raise failure('owned body failure')
        finally:
            assert detection._sdk_available is function
            assert config._sdk_available is alias

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'scoped_function_imports', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                if flag == 'selected-missing':
                    native.test_missing_selected_sdk_is_not_advertised(body)
                    assert detection._SDK_AVAILABILITY == {'OPENAI_SDK_AVAILABLE': False}
                else:
                    native.test_lazy_flags_validate_real_import_once(body, flag, module, available)
                    assert detection._SDK_AVAILABILITY == {flag: available}
        assert len(entered) == 1
        assert detection._SDK_AVAILABILITY is cache
        assert cache == contents
        assert all(vars(detection).get(key, missing) is value for key, value in slots.items())
        assert detection._sdk_available is function
        assert config._sdk_available is alias
        assert importlib.import_module is importer
    assert native.scoped_function_imports is helper
