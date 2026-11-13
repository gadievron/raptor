"""CodeQL override tests own their fallback lookup without sharing fakes."""
from contextlib import nullcontext
import os
import shutil

import pytest

from packages.codeql.tests import test_cli_resolution as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_override_fixture_restores_lookup(tmp_path, caplog, failure):
    which = shutil.which
    namespace = native.codeql.shutil
    resolver = native.codeql._resolve_cli
    helper = native.patch_module_attribute
    missing = object()
    override = os.environ.get('CODEQL_CLI', missing)
    entered, calls = [], []

    def checked(patch, consumer, binding, name, value):
        assert consumer is native.codeql
        assert (binding, name) == ('shutil', 'which')

        def lookup(name):
            calls.append(name)
            assert shutil.which is which
            return value(name)

        private = helper(patch, consumer, binding, name, lookup)
        entered.append(private)
        return private

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'patch_module_attribute', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                native.test_invalid_codeql_cli_override_warns(tmp_path, body, caplog)
                assert calls == ['codeql']
                caplog.clear()
                native.test_valid_override_wins_silently(tmp_path, body, caplog)
                assert calls == ['codeql']
                assert len(entered) == 1
                assert native.codeql.shutil is not namespace
                assert shutil.which is which
                if failure:
                    raise failure('owned body failure')
        assert native.codeql.shutil is namespace
        assert native.codeql._resolve_cli is resolver
        assert native._resolve_cli is resolver
        assert os.environ.get('CODEQL_CLI', missing) == override
        assert shutil.which is which
    assert native.patch_module_attribute is helper
