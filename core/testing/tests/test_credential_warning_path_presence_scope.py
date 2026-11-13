"""Native credential-file hint cases keep Path and SDK registry bindings borrowed."""

import builtins
from contextlib import contextmanager
import os
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import patch

import pytest

from core.llm.dispatcher import auth
from core.llm.dispatcher.tests import test_bedrock_signing as native
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs

@pytest.mark.parametrize('case', ['unmanaged', 'silent-absent', 'silent-none', 'silent-present'])
@pytest.mark.parametrize('phase', ['normal', 'error', 'interrupt'])
def test_actual_warning_caller_preserves_path_and_sdk_registry(tmp_path, case, phase):
    predicate, importer = Path.is_file, builtins.__import__
    original = auth.CredentialStore.bedrock_session_warnings
    original_path = auth.Path
    absent = object()
    observed, imports = [], []
    error = KeyboardInterrupt if phase == 'interrupt' else RuntimeError

    with patch.dict(os.environ, {'AWS_EC2_METADATA_DISABLED': 'true'}, clear=True), pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / 'state')
        if case == 'silent-absent':
            owner.delitem(sys.modules, 'botocore', raising=False)
        elif case == 'silent-none':
            owner.setitem(sys.modules, 'botocore', None)
        elif case == 'silent-present':
            owner.setitem(sys.modules, 'botocore', ModuleType('botocore'))
        registry = sys.modules.get('botocore', absent)

        @contextmanager
        def scoped(*args, **kwargs):
            with native._without_credential_file(*args, **kwargs) as private:
                function = auth.CredentialStore.bedrock_session_warnings
                assert function.__code__ is original.__code__
                assert function.__globals__['Path'] is native._NoCredentialsPath
                hook = function.__builtins__['__import__']
                assert (hook is importer) == (case == 'unmanaged')
                def count(name, *args, **kwargs):
                    if name == 'botocore':
                        imports.append(name)
                    return hook(name, *args, **kwargs)
                counted = module_function_view(private, import_hook=count)
                def warnings(self, *args, **kwargs):
                    assert Path.is_file is predicate
                    assert builtins.__import__ is importer
                    assert auth.Path is original_path
                    assert sys.modules.get('botocore', absent) is registry
                    result = counted._owned_warnings(self, *args, **kwargs)
                    observed.append(result)
                    assert sys.modules.get('botocore', absent) is registry
                    if phase != 'normal':
                        raise error('owned warning body failure')
                    return result
                with pytest.MonkeyPatch.context() as scope:
                    scope.setattr(auth.CredentialStore, 'bedrock_session_warnings', warnings)
                    yield

        view = module_function_view(native, bindings={'_without_credential_file': scoped})
        method = 'test_bedrock_session_warnings_unmanaged_asia_env' if case == 'unmanaged' else 'test_bedrock_session_warnings_silent_for_long_term_setup'
        if phase == 'normal':
            getattr(view, method)(owner)
        else:
            with pytest.raises(error, match='owned warning body failure'):
                getattr(view, method)(owner)
        assert imports == ['botocore']
        assert len(observed) == 1
        if case == 'unmanaged':
            assert any('short-lived' in warning and 'aws configure sso' in warning for warning in observed[0])
        else:
            assert observed == [[]]
        assert sys.modules.get('botocore', absent) is registry
        assert auth.CredentialStore.bedrock_session_warnings is original
        assert Path.is_file is predicate
        assert builtins.__import__ is importer
        assert auth.Path is original_path
