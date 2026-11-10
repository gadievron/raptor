"""Scope descriptor retirement with ordinary owned directory handles."""

from contextlib import ExitStack
import errno
import os
import sys

import pytest

from core.security import cgroup_scope
from core.testing.module_views import module_function_view


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux cgroup descriptor owner')


@pytest.mark.parametrize('stage,error_type', [
    pytest.param(stage, kind, id=f'{stage}-{name}')
    for stage in ('node', 'parent', 'both')
    for name, kind in [('io', OSError), ('interrupt', KeyboardInterrupt)]
] + [pytest.param(None, None, id='success')])
def test_close_consumes_both_owners_before_return(tmp_path, stage, error_type):
    with ExitStack() as owners:
        handles = {}

        def open_owned(role):
            descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
            info = os.fstat(descriptor)
            handles[role] = descriptor

            def safety_close():
                try:
                    current = os.fstat(descriptor)
                except OSError as error:
                    assert error.errno == errno.EBADF
                    return
                if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                    os.close(descriptor)
            owners.callback(safety_close)
            return descriptor

        scope = cgroup_scope.Scope(tmp_path, open_owned('node'), open_owned('parent'))
        faults = ({role: error_type('owned after-close ' + role) for role in handles}
                  if error_type is not None else {})
        calls = []

        def close(descriptor):
            role = next(role for role, fd in handles.items() if fd == descriptor)
            os.close(descriptor)
            calls.append(role)
            if stage == role or stage == 'both':
                raise faults[role]

        private = module_function_view(cgroup_scope, bindings={
            'close_scope': cgroup_scope.Scope.close,
            'os': module_function_view(os, bindings={'close': close}),
        })
        caught = None
        try:
            private.close_scope(scope)
        except BaseException as error:
            caught = error
        live = []
        for role, descriptor in handles.items():
            try:
                os.fstat(descriptor)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                live.append(role)
        assert not live, f'Scope.close left native owners live: {live}'
        assert scope.node is None and scope.parent is None
        assert calls == ['node', 'parent']
        assert caught is (faults['node' if stage == 'both' else stage] if stage else None)
        private.close_scope(scope)
        assert calls == ['node', 'parent'], 'a second close retried consumed numbers'


def test_secondary_note_failure_does_not_replace_first_close_error(tmp_path):
    # The ordinary descriptor controls above prove physical retirement.
    # This independent metadata seam proves diagnostic failure precedence.
    primary = OSError('first owned close error')
    secondary = OSError('second owned close error')
    reached = []

    def note(text):
        reached.append('note')
        raise MemoryError('owned diagnostic failure')

    primary.add_note = note
    scope = object.__new__(cgroup_scope.Scope)
    scope.node, scope.parent = 101, 102
    calls = []

    def close(descriptor):
        calls.append(descriptor)
        raise primary if descriptor == 101 else secondary

    private = module_function_view(cgroup_scope, bindings={
        'close_scope': cgroup_scope.Scope.close,
        'os': module_function_view(os, bindings={'close': close}),
    })
    assert private.close_scope.__globals__['os'].close is close
    with pytest.raises(OSError) as caught:
        private.close_scope(scope)
    assert caught.value is primary
    assert calls == [101, 102] and reached == ['note']
    assert scope.node is None and scope.parent is None
