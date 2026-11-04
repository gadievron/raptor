"""Descriptor snapshots must close and restore independently after failure."""

from contextlib import contextmanager, suppress
import errno
import importlib
import os
import signal
import sys
from types import SimpleNamespace

import pytest


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@contextmanager
def _intercept_descriptors(module, monkeypatch, error, fault):
    descriptors, duplicates, redirects = [], [], []
    real_pipe, real_dup = os.pipe, os.dup

    def fail():
        raise error("injected descriptor failure")

    def record(fd):
        stat = os.fstat(fd)
        descriptors.append((fd, (stat.st_dev, stat.st_ino)))
        return fd

    def pipe():
        pair = real_pipe()
        for fd in pair:
            record(fd)
        return pair

    def dup(fd):
        if fault == "dup" or (fault == "second-dup" and duplicates):
            return fail()
        result = record(real_dup(fd))
        duplicates.append(result)
        return result

    def dup2(source, target):
        # Never replace pytest's actual stdout or stderr in fault tests.
        restoring = source in duplicates
        redirects.append((source, target, restoring))
        if not restoring and fault == "install":
            return fail()
        if restoring and (fault == "restore" or fault == f"restore-{target}"):
            return fail()
        return target

    proxy = SimpleNamespace(**(vars(os) | {"pipe": pipe, "dup": dup, "dup2": dup2}))
    support = None
    with suppress(ModuleNotFoundError):
        support = importlib.import_module("core.testing.fds")
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "os", proxy)
            if support is not None:
                patcher.setattr(support, "os", proxy)
            yield SimpleNamespace(
                duplicates=duplicates, redirects=redirects, fail=fail, patcher=patcher
            )
        assert not any(_owned(fd, identity) for fd, identity in descriptors), (
            "descriptor failure stranded an owned handle"
        )
    finally:
        for fd, identity in descriptors:
            if _owned(fd, identity):
                os.close(fd)


_WARNS = [
    "test_warn_post_fork_writes_prefixed_line",
    "test_warn_post_fork_auto_prepends_prefix_when_missing",
    "test_warn_post_fork_no_double_prefix",
]


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX descriptor snapshots")
@pytest.mark.parametrize("name", _WARNS)
@pytest.mark.parametrize("fault", ["dup", "install", "body", "restore"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_warning_capture_failure_closes_descriptors(name, fault, error, monkeypatch):
    from core.sandbox.tests import test_fork_safe_warn as module
    from core.sandbox import _fork_safe_warn

    with _intercept_descriptors(module, monkeypatch, error, fault) as state:
        state.patcher.setattr(
            _fork_safe_warn,
            "warn_post_fork",
            lambda *args: state.fail() if fault == "body" else None,
        )
        with pytest.raises(error, match="injected descriptor failure"):
            getattr(module, name)()


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX descriptor snapshots")
@pytest.mark.parametrize("fault", ["second-dup", "body", "restore-1", "restore-2"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_initializer_failure_restores_signal_and_closes_snapshots(
    fault, error, monkeypatch
):
    from core.inventory.tests import test_pool_teardown as module

    prior = object()
    current = [prior]
    changes = []

    def change(signum, handler):
        changes.append(handler)
        current[0] = handler

    with _intercept_descriptors(module, monkeypatch, error, fault) as state:

        def initialize(*args):
            if fault == "body":
                state.fail()
            current[0] = signal.SIG_DFL

        proxy = SimpleNamespace(
            SIGTERM=signal.SIGTERM,
            SIG_DFL=signal.SIG_DFL,
            getsignal=lambda _: current[0],
            signal=change,
        )
        state.patcher.setattr(module, "signal", proxy)
        state.patcher.setattr(module, "_init_inventory_worker", initialize)
        with pytest.raises(error, match="injected descriptor failure"):
            module.test_init_inventory_worker_resets_sigterm()
        assert current[0] is prior, "descriptor cleanup skipped restoring SIGTERM"
        if fault != "second-dup":
            assert {
                target for _, target, restoring in state.redirects if restoring
            } == {1, 2}, "one restore failure skipped another snapshot"


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX descriptor snapshots")
@pytest.mark.parametrize("fault", ["dup", "install", "body", "restore"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_fd1_swap_failure_closes_snapshot(fault, error, monkeypatch):
    from core.sandbox.tests import test_fd12_readable_arm as module

    with _intercept_descriptors(module, monkeypatch, error, fault) as state:
        with pytest.raises(error, match="injected descriptor failure"):
            with module._Fd1Swap(12345):
                if fault == "body":
                    state.fail()


@pytest.mark.skipif(sys.platform != "linux", reason="controlled parser-jail fixture")
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_parser_fixture_restores_limit_after_stop_failure(error, monkeypatch):
    from core.sandbox.tests import test_parser_jail_io_reliability as module

    changes, workers = [], []
    real_jail = module.jail_mod.ParserJail

    def factory():
        jail = real_jail()
        workers.append(jail)
        stop = jail.stop

        def fail_stop():
            stop()
            raise error("injected jail stop failure")

        jail.stop = fail_stop
        return jail

    proxy = SimpleNamespace(
        RLIMIT_NOFILE=module.resource.RLIMIT_NOFILE,
        RLIM_INFINITY=module.resource.RLIM_INFINITY,
        getrlimit=lambda _: (1024, 4096),
        setrlimit=lambda _, limits: changes.append(limits),
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(module.jail_mod, "ParserJail", factory)
        patcher.setattr(module, "resource", proxy)
        with pytest.raises(error, match="injected jail stop failure"):
            module.test_high_descriptor_worker_still_parses(patcher)
    assert workers
    assert changes == [(2049, 4096), (1024, 4096)], (
        "jail stop failure skipped restoring the resource limit"
    )


@pytest.mark.skipif(os.name != "posix", reason="simulated POSIX signal masks")
@pytest.mark.parametrize("error", [None, OSError, KeyboardInterrupt])
def test_initializer_restores_signal_mask_even_when_handler_restore_fails(
    error, monkeypatch
):
    from core.inventory.tests import test_pool_teardown as module

    prior_handler = object()
    prior_mask = {signal.SIGTERM, signal.SIGINT}
    handler, mask = [prior_handler], [set(prior_mask)]

    def change(signum, value):
        if value is prior_handler and error is not None:
            raise error("injected handler restore failure")
        handler[0] = value

    def change_mask(action, signals):
        previous = set(mask[0])
        if action == signal.SIG_BLOCK:
            mask[0].update(signals)
        elif action == signal.SIG_SETMASK:
            mask[0] = set(signals)
        else:
            mask[0].difference_update(signals)
        return previous

    with _intercept_descriptors(module, monkeypatch, OSError, "none") as state:

        def initialize(*args):
            handler[0] = signal.SIG_DFL
            mask[0].discard(signal.SIGTERM)

        proxy = SimpleNamespace(
            SIGTERM=signal.SIGTERM,
            SIG_DFL=signal.SIG_DFL,
            SIG_BLOCK=signal.SIG_BLOCK,
            SIG_SETMASK=signal.SIG_SETMASK,
            getsignal=lambda _: handler[0],
            signal=change,
            pthread_sigmask=change_mask,
        )
        state.patcher.setattr(module, "signal", proxy)
        state.patcher.setattr(module, "_init_inventory_worker", initialize)
        if error is None:
            module.test_init_inventory_worker_resets_sigterm()
        else:
            with pytest.raises(error, match="injected handler restore failure"):
                module.test_init_inventory_worker_resets_sigterm()
        assert mask[0] == prior_mask, (
            "initializer fixture leaked its signal-mask change"
        )


@pytest.mark.skipif(os.name != "posix", reason="owned stdio redirection child")
def test_preserved_fds_restores_real_child_stdio(tmp_path):
    from pathlib import Path
    import subprocess

    root = str(Path(__file__).resolve().parents[3])
    output = tmp_path / "redirected"
    code = """import os,sys
sys.path.insert(0,sys.argv[1])
from core.testing.fds import preserved_fds
fd=os.open(sys.argv[2],os.O_CREAT|os.O_WRONLY,0o600)
try:
    with preserved_fds(1,2):
        os.dup2(fd,1)
        os.write(1,b'inside')
    os.write(1,b'outside')
finally:
    os.close(fd)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, root, str(output)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text() == "inside"
    assert result.stdout == "outside"
