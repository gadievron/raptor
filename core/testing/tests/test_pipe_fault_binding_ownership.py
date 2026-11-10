"""Pipe fault views preserve shared factories, outer trackers and unrelated FDs."""
import os
from contextlib import contextmanager
from types import ModuleType

import pytest

from core.testing import pipes as pipe_support
from core.testing.tests import test_pipe_setup_cleanup as native
from packages.joern.tests import test_pidns_tier as tier

pytestmark = pytest.mark.skipif(os.name != "posix", reason="owned POSIX pipe fixture scopes")


def _record(pair, identities):
    for fd in pair:
        info = os.fstat(fd)
        identities[fd] = (info.st_dev, info.st_ino)
    return pair


@pytest.mark.parametrize("consumer", [pipe_support, tier], ids=["pipe-helper", "tier-reader"])
@pytest.mark.parametrize("state", ["ordinary", "borrowed"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_pipe_scope_owns_only_selected_consumer(monkeypatch, consumer, state, outcome):
    borrowed_view, borrowed_pipe, borrowed_write = consumer.os, os.pipe, os.write
    other = tier if consumer is pipe_support else pipe_support
    borrowed_other = other.os
    identities, outer_calls = {}, []
    selected = unrelated = None
    failure_type = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]
    failure = failure_type("owned pipe scope body fault") if failure_type else None

    def outer_pipe():
        value = borrowed_pipe()
        outer_calls.append(value)
        return value

    view = ModuleType("os")
    vars(view).update(vars(borrowed_view))
    view.pipe = outer_pipe
    expected_view = view if state == "borrowed" else borrowed_view
    try:
        with monkeypatch.context() as ambient:
            if state == "borrowed":
                ambient.setattr(consumer, "os", view)

            def exercise():
                nonlocal selected, unrelated
                with native._pipes(monkeypatch, OSError, consumer=consumer) as pairs:
                    assert consumer.os is not expected_view
                    assert consumer.os.pipe is not expected_view.pipe
                    assert consumer.os.write is expected_view.write
                    assert other.os is borrowed_other
                    assert os.pipe is borrowed_pipe and os.write is borrowed_write
                    selected = _record(consumer.os.pipe(), identities)
                    unrelated = _record(borrowed_pipe(), identities)
                    assert pairs == [selected] and unrelated not in pairs
                    if failure is not None:
                        raise failure
                    for fd in selected:
                        os.close(fd)

            if failure is None:
                exercise()
            else:
                with pytest.raises(failure_type) as caught:
                    exercise()
                assert caught.value is failure
            assert selected is not None and unrelated is not None
            assert all(not native._owned(fd, identities[fd]) for fd in selected)
            assert all(native._owned(fd, identities[fd]) for fd in unrelated)
            os.write(unrelated[1], b"other owner")
            assert os.read(unrelated[0], 11) == b"other owner"
            assert len(outer_calls) == int(state == "borrowed")
            assert consumer.os is expected_view and other.os is borrowed_other
            assert os.pipe is borrowed_pipe and os.write is borrowed_write
        assert consumer.os is borrowed_view
    finally:
        for fd, identity in identities.items():
            if native._owned(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_actual_tier_write_fault_keeps_outer_pipe_tracker(monkeypatch, outcome):
    borrowed_view, borrowed_pipe, borrowed_write = tier.os, os.pipe, os.write
    identities, calls, publications = {}, [], []
    failure_type = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]
    failure = failure_type("owned nested tier scope boundary") if failure_type else None
    scopes = 0

    def outer_pipe():
        pair = _record(borrowed_pipe(), identities)
        calls.append(pair)
        return pair

    view = ModuleType("os")
    vars(view).update(vars(borrowed_view))
    view.pipe = outer_pipe

    class Patch:
        def __getattr__(self, name):
            return getattr(monkeypatch, name)

        @contextmanager
        def context(self):
            nonlocal scopes
            scopes += 1
            position = scopes
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, name):
                        return getattr(actual, name)

                    def setitem(self, mapping, key, value):
                        actual.setitem(mapping, key, value)
                        if mapping is vars(tier) and key == "os":
                            publications.append((value, value.pipe, value.write))
                            if len(publications) == 2:
                                assert value.pipe is publications[0][1]
                                assert value.write is not publications[0][2]
                        assert os.pipe is borrowed_pipe and os.write is borrowed_write

                    def setattr(self, *args, **kwargs):
                        actual.setattr(*args, **kwargs)
                        assert os.pipe is borrowed_pipe and os.write is borrowed_write

                yield Scope()
                if position == 2 and failure is not None:
                    raise failure

    try:
        with monkeypatch.context() as ambient:
            ambient.setattr(tier, "os", view)
            if failure is None:
                native.test_tier_reader_closes_owned_pipe_ends(True, "write", OSError, Patch())
            else:
                with pytest.raises(failure_type) as caught:
                    native.test_tier_reader_closes_owned_pipe_ends(True, "write", OSError, Patch())
                assert caught.value is failure
            assert len(calls) == 1 and len(identities) == 2
            assert all(not native._owned(fd, identity) for fd, identity in identities.items())
            assert len(publications) == 2
            assert publications[1][1] is publications[0][1]
            assert publications[1][2] is not publications[0][2]
            assert tier.os is view
            assert os.pipe is borrowed_pipe and os.write is borrowed_write
        assert tier.os is borrowed_view
    finally:
        for fd, identity in identities.items():
            if native._owned(fd, identity):
                os.close(fd)
