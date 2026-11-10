"""Allocation and inert-launch hooks remain consumer-local."""
from contextlib import contextmanager
import os
import subprocess

import pytest

from core.testing import pipes as pipe_consumer
from core.testing.module_bindings import patch_module_attribute
from core.testing.tests import test_spawn_pipe_setup_cleanup as native


@pytest.mark.parametrize("kind", ["argv", "second-pipe", "pool"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt])
def test_spawn_pipe_binding_restores_after_exit(
    kind, error, outcome, monkeypatch, caplog
):
    borrowed_pipe, borrowed_popen = os.pipe, subprocess.Popen
    original = pipe_consumer.os
    recorded = []
    seen = []

    class Patch:
        @contextmanager
        def context(self):
            allocation = []
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, name):
                        return getattr(actual, name)

                    def setattr(self, target, name, value, *args, **kwargs):
                        assert os.pipe is borrowed_pipe
                        assert subprocess.Popen is borrowed_popen
                        if name == "pipe":
                            assert target is not os
                            cells = dict(zip(value.__code__.co_freevars,
                                             (c.cell_contents for c in value.__closure__)))
                            recorded.append(cells["descriptors"])
                            allocation.append(True)
                            seen.append("pipe")
                        if name == "Popen":
                            assert target is not subprocess
                            seen.append("Popen")
                        actual.setattr(target, name, value, *args, **kwargs)
                yield Scope()
                assert os.pipe is borrowed_pipe
                assert subprocess.Popen is borrowed_popen
                if allocation and outcome is not None:
                    raise outcome("outer pipe scope exit")

    def invoke():
        if kind == "pool":
            native.test_pool_preparation_or_construction_failure_releases_pipe(
                "context", error, Patch(), caplog
            )
        else:
            native.test_shim_preparation_or_spawn_failure_releases_pipes(
                native._SHIMS[0][0], 2, kind, error, Patch()
            )

    if outcome is None:
        invoke()
    else:
        with pytest.raises(outcome, match="outer pipe scope exit"):
            invoke()
    assert seen == (["pipe"] if kind == "pool" else ["pipe", "Popen"])
    assert len(recorded) == 1 and recorded[0]
    assert not any(native._owned(fd, identity) for fd, identity in recorded[0])
    assert pipe_consumer.os is original
    assert os.pipe is borrowed_pipe and subprocess.Popen is borrowed_popen


@pytest.mark.parametrize("kind", ["argv", "second-pipe", "pool"])
def test_allocation_scope_preserves_outer_consumer_tracker(kind, monkeypatch, caplog):
    real_pipe = pipe_consumer.os.pipe
    original = pipe_consumer.os
    tracked = []

    def pipe():
        pair = real_pipe()
        for fd in pair:
            stat = os.fstat(fd)
            tracked.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    try:
        with monkeypatch.context() as outer:
            private = patch_module_attribute(outer, pipe_consumer, "os", "pipe", pipe)
            if kind == "pool":
                native.test_pool_preparation_or_construction_failure_releases_pipe(
                    "context", OSError, monkeypatch, caplog
                )
            else:
                native.test_shim_preparation_or_spawn_failure_releases_pipes(
                    native._SHIMS[0][0], 2, kind, OSError, monkeypatch
                )
            assert pipe_consumer.os is private and private.pipe is pipe
            assert len(tracked) == (4 if kind == "argv" else 2)
            assert not any(native._owned(fd, identity) for fd, identity in tracked)
        assert pipe_consumer.os is original
    finally:
        for fd, identity in tracked:
            if native._owned(fd, identity):
                os.close(fd)
