"""Parent bind-pin collection retains its active failure during cleanup."""

import contextlib
import os
from types import SimpleNamespace

import pytest

from core.sandbox import _pathpin as pin
from core.sandbox import _spawn as spawn
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(not hasattr(os, 'O_PATH'), reason='requires Linux O_PATH')


@pytest.fixture
def owned_pins(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ('target', 'output', 'rootfs')]
    for path in paths:
        path.mkdir()
    real_pin, real_close = pin.open_pinned, os.close
    state = SimpleNamespace(
        paths=list(map(str, paths)), owned=set(), opened=[], closed=[],
        attempts=0, primary=None, cleanup=None,
    )

    def acquire(path):
        state.attempts += 1
        if state.primary is not None and state.attempts == 3:
            raise state.primary
        fd = real_pin(path)
        state.owned.add(fd)
        state.opened.append(fd)
        return fd

    def close(fd):
        assert fd in state.owned, 'never retry a consumed descriptor number'
        real_close(fd)
        state.owned.remove(fd)
        state.closed.append(fd)
        if state.cleanup is not None and len(state.closed) == 1:
            raise state.cleanup

    monkeypatch.setattr(pin, 'open_pinned', acquire)
    patch_module_attribute(monkeypatch, spawn, 'os', 'close', close)
    try:
        yield state
    finally:
        for fd in state.owned:
            with contextlib.suppress(OSError):
                real_close(fd)


@pytest.mark.parametrize('primary_type', [OSError, RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_failed_acquisition_retires_each_pin_without_replacing_primary(
    owned_pins, primary_type, cleanup_type,
):
    owned_pins.primary = primary_type('owned pin acquisition failure')
    owned_pins.cleanup = cleanup_type('owned pin cleanup failure')
    target, output, rootfs = owned_pins.paths
    with pytest.raises(primary_type) as caught:
        spawn._pin_bind_sources(target, output, rootfs, None)
    assert caught.value is owned_pins.primary
    assert owned_pins.owned == set()
    assert owned_pins.attempts == 3
    assert len(owned_pins.opened) == 2
    assert sorted(owned_pins.closed) == sorted(owned_pins.opened)


def test_success_transfers_map_pins_without_closing_them(owned_pins):
    target, output, _rootfs = owned_pins.paths
    result = spawn._pin_bind_sources(target, output, None, None)
    assert set(result) == {target, output}
    assert set(result.values()) == owned_pins.owned
    assert len(owned_pins.owned) == 2
    assert owned_pins.closed == []
