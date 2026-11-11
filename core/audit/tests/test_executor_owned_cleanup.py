"""Owned executor resources retire without replacing an active failure."""
import asyncio
import logging
from types import SimpleNamespace

import pytest

from core.audit import executor
from core.llm import throttle as throttle_module
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('body_error', [False, True])
@pytest.mark.parametrize('log_error', [False, True])
@pytest.mark.parametrize('close_error', [False, True])
def test_owned_throttle_cleanup(monkeypatch, body_error, log_error, close_error):
    primary = KeyboardInterrupt('body cancelled')
    captured = []
    real_close = throttle_module.AdaptiveThrottle.close

    async def body(*args, **kwargs):
        owned = args[6]
        captured.append(owned)
        owned._signal_count = 1
        if body_error:
            raise primary
        return executor.ExecutorStats()

    def close(resource):
        real_close(resource)
        if close_error:
            raise OSError('after retirement')

    class FailingHandler(logging.Handler):
        def emit(self, record):
            if log_error:
                raise OSError('log transport failed')

    logger = logging.Logger('owned-executor-test', logging.INFO)
    logger.addHandler(FailingHandler())
    view = module_function_view(executor, bindings={'_run_async_body': body, 'logger': logger})
    monkeypatch.setattr(throttle_module.AdaptiveThrottle, 'close', close)
    loop = asyncio.new_event_loop()
    caught = None
    try:
        try:
            loop.run_until_complete(view._run_async([], None, None, None, None,
                                                   executor.ExecutorConfig(max_workers=2),
                                                   review_one_fn=lambda: None))
        except BaseException as exc:
            caught = exc
        assert len(captured) == 1
        assert captured[0] not in throttle_module._active_throttles
        assert not captured[0]._registered
        if body_error:
            assert caught is primary
        elif log_error or close_error:
            assert isinstance(caught, OSError)
        else:
            assert caught is None
    finally:
        for resource in captured:
            real_close(resource)
        loop.close()


@pytest.mark.parametrize('body_error', [False, True])
@pytest.mark.parametrize('close_error', [False, True])
def test_owned_loop_cleanup(body_error, close_error):
    primary = KeyboardInterrupt('body cancelled')
    loops = []
    descriptors = []

    class OwnedLoop(asyncio.SelectorEventLoop):
        def __init__(self):
            super().__init__()
            loops.append(self)
            descriptors.append(self._selector.fileno())
            self.close_calls = 0

        def close(self):
            self.close_calls += 1
            super().close()
            if close_error:
                raise OSError('after loop close')

    async def body(*args, **kwargs):
        if body_error:
            raise primary
        return executor.ExecutorStats()

    view = module_function_view(executor, bindings={
        '_run_async': body,
        'asyncio': SimpleNamespace(new_event_loop=OwnedLoop),
    })
    caught = None
    try:
        view.run_executor_sync([], None, None, None, None,
                               executor.ExecutorConfig(max_workers=2),
                               review_one_fn=lambda: None)
    except BaseException as exc:
        caught = exc
    assert len(loops) == 1
    assert loops[0].is_closed()
    assert loops[0].close_calls == 1
    import errno
    import os
    with pytest.raises(OSError) as retired:
        os.fstat(descriptors[0])
    assert retired.value.errno == errno.EBADF
    if body_error:
        assert caught is primary
    elif close_error:
        assert isinstance(caught, OSError)
    else:
        assert caught is None


def test_borrowed_throttle_remains_registered():
    borrowed = throttle_module.AdaptiveThrottle(2)

    async def body(*args, **kwargs):
        assert args[6] is borrowed
        return executor.ExecutorStats()

    view = module_function_view(executor, bindings={'_run_async_body': body})
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(view._run_async([], None, None, None, None,
                                               executor.ExecutorConfig(max_workers=2),
                                               throttle=borrowed, review_one_fn=lambda: None))
        assert borrowed in throttle_module._active_throttles
        assert borrowed._registered
    finally:
        borrowed.close()
        loop.close()


def test_fresh_loop_cleanup_error_inside_caller_handler():
    try:
        raise ValueError("already handled by caller")
    except ValueError:
        test_owned_loop_cleanup(body_error=False, close_error=True)
