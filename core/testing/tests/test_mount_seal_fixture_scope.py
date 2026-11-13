"""Sealing ABI fakes belong only to the mocked mount consumer."""
from contextlib import contextmanager, nullcontext
import ctypes
import platform
from types import SimpleNamespace

import pytest

from core.sandbox.tests import test_mount_ns_etc_locked_fallback as native

pytestmark = native.pytestmark


@pytest.mark.parametrize('result', [0, -1])
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_sealing_fixture_restores_interfaces(result, failure):
    machine, get_errno = platform.machine, ctypes.get_errno
    function = native.mount_ns._recursive_bind_system_ro
    namespace = native.mount_ns.ctypes
    mount, syscall = native.mount_ns._mount, native.mount_ns._libc.syscall
    imports_helper = native.scoped_function_imports
    errno_helper = native.mock_module_attribute
    mock = native.mock
    arch_calls, errno_calls = [], []

    @contextmanager
    def imports(consumer, functions, modules):
        assert consumer is native.mount_ns
        assert functions == ('_recursive_bind_system_ro',)
        assert modules == {'platform': platform}
        try:
            with imports_helper(consumer, functions, modules) as private:
                yield private
                if failure:
                    raise failure('owned body failure')
        finally:
            assert native.mount_ns._recursive_bind_system_ro is function

    @contextmanager
    def errno_scope(consumer, binding, name, **kwargs):
        assert consumer is native.mount_ns
        assert (binding, name) == ('ctypes', 'get_errno')
        with errno_helper(consumer, binding, name, **kwargs) as probe:
            assert ctypes.get_errno is get_errno
            yield probe
            errno_calls.append(probe.call_count)

    @contextmanager
    def object_scope(target, name, *args, **kwargs):
        with mock.patch.object(target, name, *args, **kwargs) as probe:
            if name == 'machine':
                assert target is not platform
                assert platform.machine is machine
            yield probe
            if name == 'machine':
                arch_calls.append(probe.call_count)

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'scoped_function_imports', imports)
        owner.setattr(native, 'mock_module_attribute', errno_scope)
        owner.setattr(native, 'mock', SimpleNamespace(patch=SimpleNamespace(object=object_scope)))
        with expected:
            native.test_recursive_system_bind_seals_every_mount_without_clearing_flags(result)
        assert arch_calls == [1]
        assert errno_calls == [int(result != 0)]
        assert platform.machine is machine
        assert ctypes.get_errno is get_errno
        assert native.mount_ns.ctypes is namespace
        assert native.mount_ns._mount is mount
        assert native.mount_ns._libc.syscall is syscall
        assert native.mount_ns._recursive_bind_system_ro is function
    assert native.mock is mock
    assert native.mock_module_attribute is errno_helper
    assert native.scoped_function_imports is imports_helper
