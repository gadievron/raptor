"""Offline scanner fixtures own loader paths and probe guards."""
from contextlib import contextmanager, nullcontext
import socket
import sys

import pytest

from packages.semgrep.tests import test_offline as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_offline_fixture_restores_path_and_socket(tmp_path, failure):
    connect, scope = socket.create_connection, native.scoped_function_imports
    path, values = sys.path, list(sys.path)
    calls = []
    token = object()
    entered = []

    def unrelated(*args, **kwargs):
        calls.append((args, kwargs))
        return token

    @contextmanager
    def checked(module, functions, imports):
        original = module._drop_unreachable_registry_packs
        dropped = module._dropped_registry_packs
        contents = list(dropped)
        entered.append(module)
        try:
            with scope(module, functions, imports) as private:
                assert sys.path is not path
                assert socket.create_connection is unrelated
                yield private
                assert socket.create_connection(('unrelated-owned.invalid', 1), timeout=7) is token
                assert calls == [((('unrelated-owned.invalid', 1),), {'timeout': 7})]
                if failure:
                    raise failure('owned body failure')
        finally:
            assert module._drop_unreachable_registry_packs is original
            assert module._dropped_registry_packs is dropped
            assert dropped == contents

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(socket, 'create_connection', unrelated)
        owner.setattr(native, 'scoped_function_imports', checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                cache = native.cache.__wrapped__(tmp_path, patch)
                native.test_scanner_never_probes_or_drops_missing_packs(cache, patch)
        assert len(entered) == 1
        assert sys.path is path and sys.path == values
        assert socket.create_connection is unrelated
    assert socket.create_connection is connect
    assert native.scoped_function_imports is scope


def test_actual_offline_tripwire_rejects_injected_probe(tmp_path):
    scope = native.scoped_function_imports
    path, values = sys.path, list(sys.path)
    connect = socket.create_connection

    @contextmanager
    def unsafe(module, functions, imports):
        with scope(module, functions, imports) as private:
            original = module._drop_unreachable_registry_packs
            with pytest.MonkeyPatch.context() as patch:
                def regression(configs):
                    private.socket.create_connection(('owned-negative.invalid', 443))
                    return original(configs)
                patch.setattr(module, '_drop_unreachable_registry_packs', regression)
                yield private

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, 'scoped_function_imports', unsafe)
        cache = native.cache.__wrapped__(tmp_path, patch)
        with pytest.raises(AssertionError, match='must not probe'):
            native.test_scanner_never_probes_or_drops_missing_packs(cache, patch)
    assert sys.path is path and sys.path == values
    assert socket.create_connection is connect
