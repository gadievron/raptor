"""Startup uses the selected installed runtime, not Snap or host pip metadata."""

import builtins
from types import SimpleNamespace

import pytest

from core.startup import init
from core.testing.module_views import module_function_view
from packages.semgrep.runtime import SnapRuntimeError


def _view(resolve):
    shutil = SimpleNamespace(which=lambda name: '/snap/bin/semgrep')
    metadata = SimpleNamespace(PackageNotFoundError=LookupError,
                               version=lambda name: pytest.fail('host package metadata queried'))
    runtime = SimpleNamespace(resolve_snap_runtime=resolve, SnapRuntimeError=SnapRuntimeError)

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'shutil':
            return shutil
        if name == 'importlib.metadata':
            return metadata
        if name == 'packages.semgrep.runtime':
            return runtime
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(init, import_hook=imported,
                                bindings={'_cached_cli_version': lambda name:
                                          pytest.fail('Snap dispatcher executed')})


def test_startup_uses_snap_package_version_without_probing():
    calls = []

    def resolve(selected):
        calls.append(selected)
        return SimpleNamespace(version='1.56.0')

    assert _view(resolve)._semgrep_version() == '1.56.0'
    assert calls == ['/snap/bin/semgrep']


def test_unsafe_snap_layout_never_uses_host_metadata_or_dispatcher():
    def resolve(selected):
        raise SnapRuntimeError('owned unsupported runtime')

    assert _view(resolve)._semgrep_version() is None
