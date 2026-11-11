"""Apple-tool preparation respects env's declared executable search path."""
import builtins
import os
import shutil

import pytest

from core.sandbox import _macos_spawn as spawn
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX executable path semantics')

SYSTEM = '/usr/bin:/bin'
CUSTOM = '/owned/toolchain/bin'
COMPILER = '/Library/Developer/CommandLineTools/usr/bin/clang'
SDK = '/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk'


@pytest.fixture
def preparation():
    lookups, queries = [], []

    def which(name, *, path):
        assert name == 'cc'
        lookups.append((name, path))
        # Private lookup metadata: no filesystem discovery or tool execution.
        return {SYSTEM: '/usr/bin/cc', CUSTOM: CUSTOM + '/cc', '': None}[path]

    def query(*args):
        queries.append(args)
        assert args in (('--find', 'cc'), ('--show-sdk-path',))
        return SDK if args == ('--show-sdk-path',) else COMPILER

    private_shutil = module_function_view(shutil, bindings={'which': which})

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'shutil' and level == 0:
            return private_shutil
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(spawn, bindings={'_xcrun_path': query},
                                   import_hook=import_local)
    return private._prepare_apple_tool, lookups, queries


@pytest.mark.parametrize('prefix', [
    pytest.param(['/usr/bin/env', 'PATH=' + CUSTOM], id='inline-custom'),
    pytest.param(['/bin/env', 'PATH=' + CUSTOM], id='bin-env-custom'),
    pytest.param(['/usr/bin/env', 'PATH=' + SYSTEM, 'PATH=' + CUSTOM], id='last-custom'),
    pytest.param(['/usr/bin/env', 'OTHER=retained', 'PATH=' + CUSTOM], id='other-assignment'),
])
def test_inline_custom_path_does_not_select_system_compiler(preparation, prefix):
    prepare, lookups, queries = preparation
    command = prefix + ['cc', 'owned.c']
    original = list(command)
    environment = {'PATH': SYSTEM, 'OTHER': 'retained'}
    assert prepare(command, environment) == original
    assert command == original
    assert lookups == [('cc', CUSTOM)]
    assert queries == []
    assert environment == {'PATH': SYSTEM, 'OTHER': 'retained'}


@pytest.mark.parametrize('wrapped', [False, True], ids=['direct-system', 'inline-system'])
def test_selected_system_path_keeps_system_preparation(preparation, wrapped):
    prepare, lookups, queries = preparation
    prefix = ['/usr/bin/env', 'PATH=' + SYSTEM] if wrapped else []
    command = prefix + ['cc', 'owned.c']
    original = list(command)
    environment = {'PATH': CUSTOM if wrapped else SYSTEM}
    assert prepare(command, environment) == prefix + [COMPILER, 'owned.c']
    assert command == original
    assert lookups == [('cc', SYSTEM)]
    assert queries == [('--find', 'cc'), ('--show-sdk-path',)]
    assert environment['SDKROOT'] == SDK


def test_empty_inline_path_does_not_fall_back_to_parent_path(preparation):
    prepare, lookups, queries = preparation
    command = ['/usr/bin/env', 'PATH=', 'cc', 'owned.c']
    environment = {'PATH': SYSTEM}
    assert prepare(command, environment) == command
    assert lookups == [('cc', '')]
    assert queries == []
    assert environment == {'PATH': SYSTEM}


def test_absolute_custom_tool_remains_independent_of_search_path(preparation):
    prepare, lookups, queries = preparation
    command = ['/usr/bin/env', 'PATH=' + SYSTEM, CUSTOM + '/cc', 'owned.c']
    environment = {'PATH': CUSTOM}
    assert prepare(command, environment) == command
    assert lookups == queries == []
    assert environment == {'PATH': CUSTOM}
