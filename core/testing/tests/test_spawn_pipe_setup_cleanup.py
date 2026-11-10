"""Command preparation and failed launches retain pipe ownership."""

from contextlib import contextmanager
import errno
import os
from types import SimpleNamespace

import pytest

from core.testing import pipes as pipe_consumer
from core.testing.module_bindings import patch_module_attribute

_SHIMS = [
    ("test_status_byte_relayed_and_exit_mirrored", 2),
    ("test_target_does_not_inherit_status_fd", 1),
    ("test_target_does_not_inherit_raptor_markers", 1),
    ("test_normal_completion_with_death_pipe", 2),
    ("test_death_pipe_teardown", 2),
    ("test_env_restore_reapplied_at_target_exec", 1),
]
_CASES = [
    (name, count, fault) for name, count in _SHIMS for fault in ("argv", "env", "spawn")
]
_CASES += [(name, count, "second-pipe") for name, count in _SHIMS if count == 2]


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@contextmanager
def _record_pipes(monkeypatch, error, fault):
    descriptors, pairs = [], []
    real_pipe = pipe_consumer.os.pipe

    def pipe():
        if fault == "second-pipe" and pairs:
            raise error("injected second-pipe failure")
        pair = real_pipe()
        pairs.append(pair)
        for fd in pair:
            stat = os.fstat(fd)
            descriptors.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    try:
        with monkeypatch.context() as patcher:
            patch_module_attribute(patcher, pipe_consumer, "os", "pipe", pipe)
            yield pairs
        assert descriptors
        assert not any(_owned(fd, identity) for fd, identity in descriptors), (
            "failed setup left pipe descriptors open"
        )
    finally:
        for fd, identity in descriptors:
            if _owned(fd, identity):
                os.close(fd)


@pytest.mark.skipif(os.name != "posix", reason="owned shim pipe fixtures")
@pytest.mark.parametrize("name,count,fault", _CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_shim_preparation_or_spawn_failure_releases_pipes(
    name, count, fault, error, monkeypatch
):
    from core.sandbox.tests import test_seatbelt_shim as module

    calls = []

    def fail(stage):
        def raise_error(*args, **kwargs):
            calls.append(stage)
            raise error(f"injected {stage} failure")

        return raise_error

    with _record_pipes(monkeypatch, error, fault) as pairs:
        with monkeypatch.context() as patcher:
            # Every launch is inert in the failure matrix, including if an
            # expected argument/environment failure is accidentally bypassed.
            patch_module_attribute(patcher, module, "subprocess", "Popen", fail("spawn"))
            if fault == "argv":
                patcher.setattr(module, "_outer", fail("argv"))
            elif fault == "env":
                patcher.setattr(module, "_env", fail("env"))
            with pytest.raises(error, match=f"injected {fault} failure"):
                getattr(module.TestSeatbeltShim(), name)()
        assert len(pairs) == (1 if fault == "second-pipe" else count)
        assert calls == ([] if fault == "second-pipe" else [fault])


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork-pool pipe fixture")
@pytest.mark.parametrize("fault", ["context", "executor"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_pool_preparation_or_construction_failure_releases_pipe(
    fault, error, monkeypatch, caplog
):
    from core.inventory.tests import test_pool_teardown as module

    calls = []

    def fail(stage):
        def raise_error(*args, **kwargs):
            calls.append(stage)
            raise error(f"injected {stage} failure")

        return raise_error

    with _record_pipes(monkeypatch, error, fault) as pairs:
        with monkeypatch.context() as patcher:
            if fault == "context":
                patcher.setattr(
                    module,
                    "multiprocessing",
                    SimpleNamespace(get_context=fail("context")),
                )
            # Never construct a process pool or run its exit-wedge initializer.
            patcher.setattr(module, "ProcessPoolExecutor", fail("executor"))
            with pytest.raises(error, match=f"injected {fault} failure"):
                module.test_clean_shutdown_escalates_on_exit_wedge(caplog)
        assert len(pairs) == 1
        assert calls == [fault]
