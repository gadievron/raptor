"""The public CLI passes active exceptions into its real mutation lock."""
import contextlib
import errno
import os
from types import SimpleNamespace

import pytest

from core.project import oplock
from core.project.tests.test_binary_pin_cleanup import pin as pin
from core.testing.module_views import module_function_view


@pytest.fixture
def locked(pin):
    fcntl = pytest.importorskip('fcntl')
    state = SimpleNamespace(fd=None, acquired=0, unlocked=0, closes=0, cleanup=None)
    private_os = SimpleNamespace(**vars(os))
    private_fcntl = SimpleNamespace(**vars(fcntl))

    def flock(fd, operation):
        result = fcntl.flock(fd, operation)
        if operation == fcntl.LOCK_UN:
            assert fd == state.fd
            state.unlocked += 1
        else:
            info = os.fstat(fd)
            path = pin.manager.load('pin-owned').output_path / '.op.lock'
            expected = path.stat()
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            state.fd = fd
            state.acquired += 1
        return result

    def close(fd):
        os.close(fd)
        assert fd == state.fd
        state.closes += 1
        if state.cleanup is not None:
            raise state.cleanup

    private_os.close = close
    private_fcntl.flock = flock
    view = module_function_view(oplock, bindings={'os': private_os, 'fcntl': private_fcntl})
    generator = oplock.project_op_lock.__wrapped__
    from types import FunctionType
    owned_generator = FunctionType(generator.__code__, vars(view), generator.__name__,
                                   generator.__defaults__, generator.__closure__)
    owned_generator.__kwdefaults__ = generator.__kwdefaults__
    pin.run.__globals__['project_op_lock'] = contextlib.contextmanager(owned_generator)
    state.pin = pin
    yield state
    assert state.acquired == state.unlocked == state.closes == 1
    with pytest.raises(OSError) as caught:
        os.fstat(state.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [MemoryError, SystemExit])
def test_public_cli_preserves_exit_during_consumed_lock_close(locked, primary, cleanup):
    locked.pin.primary = primary('after actual binary read')
    locked.cleanup = cleanup('after actual mutation lock close')
    with pytest.raises(SystemExit if primary is KeyboardInterrupt else primary) as caught:
        locked.pin.run()
    if primary is KeyboardInterrupt:
        assert caught.value.code == 130
        assert caught.value.__context__ is locked.pin.primary
    else:
        assert caught.value is locked.pin.primary
    assert locked.pin.record.read_bytes() == locked.pin.original_record


@pytest.mark.parametrize('cleanup', [OSError, MemoryError, KeyboardInterrupt])
def test_public_cli_fresh_lock_close_policy(locked, cleanup):
    locked.cleanup = cleanup('after actual mutation lock close')
    if cleanup is OSError:
        locked.pin.run()
    else:
        with pytest.raises(cleanup) as caught:
            locked.pin.run()
        assert caught.value is locked.cleanup
    project = locked.pin.manager.load('pin-owned')
    assert project.binaries == [str(locked.pin.path)]


def test_public_cli_healthy_mutation_lock(locked):
    locked.pin.run()
    assert locked.pin.manager.load('pin-owned').binaries == [str(locked.pin.path)]


def test_success_inside_caller_exception_keeps_fresh_close_visible(locked):
    locked.cleanup = MemoryError('fresh lock close during successful CLI')
    try:
        raise RuntimeError('unrelated caller handler')
    except RuntimeError:
        with pytest.raises(MemoryError) as caught:
            locked.pin.run()
    assert caught.value is locked.cleanup
    assert locked.pin.manager.load('pin-owned').binaries == [str(locked.pin.path)]
