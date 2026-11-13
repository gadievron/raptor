"""Actual credential-warning cases keep optional imports and path hints private."""

import builtins
from contextlib import contextmanager
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from core.llm.dispatcher import auth
from core.llm.dispatcher.tests import test_bedrock_signing as native
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs

METHODS = ['test_bedrock_session_warnings_sigv4_intent_without_botocore',
           'test_bedrock_session_warnings_bearer_only_no_botocore_warning']

@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('phase', ['normal', 'error', 'interrupt'])
def test_actual_warning_caller_keeps_shared_import_and_path_unchanged(tmp_path, method, phase):
    importer, predicate = builtins.__import__, Path.is_file
    original = auth.CredentialStore.bedrock_session_warnings
    original_path = auth.Path
    imports, observed = [], []
    error = KeyboardInterrupt if phase == 'interrupt' else RuntimeError

    @contextmanager
    def scoped(*args, **kwargs):
        with native._without_botocore(*args, **kwargs):
            function = auth.CredentialStore.bedrock_session_warnings
            assert function.__code__ is original.__code__
            private_builtins = function.__globals__['__builtins__']
            hook = private_builtins['__import__']
            assert hook is not importer
            def count(name, *args, **kwargs):
                if name == 'botocore' or name.startswith('botocore.'):
                    imports.append(name)
                return hook(name, *args, **kwargs)
            def warnings(self, *args, **kwargs):
                assert builtins.__import__ is importer
                assert Path.is_file is predicate
                assert auth.Path is original_path
                private_path = function.__globals__['Path']
                assert (private_path is original_path) == (method == METHODS[0])
                result = function(self, *args, **kwargs)
                observed.append(result)
                if phase != 'normal':
                    raise error('owned warning body failure')
                return result
            with pytest.MonkeyPatch.context() as scope:
                scope.setitem(private_builtins, '__import__', count)
                scope.setattr(auth.CredentialStore, 'bedrock_session_warnings', warnings)
                yield

    view = module_function_view(native, bindings={'_without_botocore': scoped})
    with patch.dict(os.environ, {'AWS_EC2_METADATA_DISABLED': 'true'}, clear=True), pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / 'state')
        if phase == 'normal':
            getattr(view, method)(owner)
        else:
            with pytest.raises(error, match='owned warning body failure'):
                getattr(view, method)(owner)
        assert len(observed) == 1
        assert imports == (['botocore'] if method == METHODS[0] else [])
        assert any('botocore' in warning for warning in observed[0]) == (method == METHODS[0])
        assert auth.CredentialStore.bedrock_session_warnings is original
        assert Path.is_file is predicate
        assert builtins.__import__ is importer
        assert auth.Path is original_path
