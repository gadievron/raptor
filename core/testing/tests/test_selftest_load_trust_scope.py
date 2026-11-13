"""The self-test fixture grants import trust only while its loader executes."""
from contextlib import nullcontext
import importlib.machinery
import os
import sys
from types import ModuleType

import pytest

from core.testing.module_bindings import patch_module_attribute
from core.testing.tests import test_selftest_harness as native


@pytest.mark.parametrize('trust', [None, '', 'caller-marker'], ids=['absent', 'empty', 'set'])
@pytest.mark.parametrize('alias', ['absent', 'none', 'module'])
@pytest.mark.parametrize('mode', ['normal', 'load-error', 'load-interrupt',
                                'body-error', 'body-interrupt'])
def test_actual_fixture_limits_trust_to_loader(tmp_path, trust, alias, mode):
    loader = importlib.machinery.SourceFileLoader
    namespace = native.importlib
    script = native.SCRIPT
    missing = object()
    entered = []
    error = KeyboardInterrupt if 'interrupt' in mode else RuntimeError
    stub = tmp_path / 'owned_loader.py'
    stub.write_text(
        "import os, sys\n"
        "assert os.environ['_RAPTOR_TRUSTED'] == '1'\n"
        "sys.path.append('owned-loader-entry')\n"
        "loaded = True\n"
    )

    class Loader(loader):
        def exec_module(self, module):
            assert os.environ['_RAPTOR_TRUSTED'] == '1'
            super().exec_module(module)
            assert module.loaded is True
            entered.append(module)
            if mode.startswith('load-'):
                raise error('owned load failure')

    with pytest.MonkeyPatch.context() as owner:
        if trust is None:
            owner.delenv('_RAPTOR_TRUSTED', raising=False)
        else:
            owner.setenv('_RAPTOR_TRUSTED', trust)
        if alias == 'absent':
            owner.delitem(sys.modules, 'raptor_self_test', raising=False)
        else:
            prior = None if alias == 'none' else ModuleType('caller_selftest')
            owner.setitem(sys.modules, 'raptor_self_test', prior)
        inherited = sys.modules.get('raptor_self_test', missing)
        path, contents = sys.path, sys.path.copy()
        owner.setattr(native, 'SCRIPT', stub)
        patch_module_attribute(owner, native, 'importlib.machinery', 'SourceFileLoader', Loader)
        fixture = native.selftest.__wrapped__()
        try:
            if mode.startswith('load-'):
                with pytest.raises(error, match='owned load failure'):
                    next(fixture)
            else:
                module = next(fixture)
                assert module is entered[0]
                assert sys.modules['raptor_self_test'] is module
                assert os.environ.get('_RAPTOR_TRUSTED') == trust
                assert ('_RAPTOR_TRUSTED' in os.environ) is (trust is not None)
                assert sys.path is path and sys.path == contents
                expected = (pytest.raises(error, match='owned body failure')
                            if mode.startswith('body-') else nullcontext())
                with expected:
                    if mode.startswith('body-'):
                        raise error('owned body failure')
        finally:
            fixture.close()
        assert len(entered) == 1
        assert sys.modules.get('raptor_self_test', missing) is inherited
        assert os.environ.get('_RAPTOR_TRUSTED') == trust
        assert ('_RAPTOR_TRUSTED' in os.environ) is (trust is not None)
        assert sys.path is path and sys.path == contents
        assert importlib.machinery.SourceFileLoader is loader
    assert native.importlib is namespace
    assert native.SCRIPT == script
