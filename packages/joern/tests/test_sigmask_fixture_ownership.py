"""Signal-mask tests own setup resources and restore interrupted state."""

from contextlib import suppress
import os
from pathlib import Path
import shutil
import signal
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packages.joern.tests import test_netns_forwarder_sigmask as module


from core.testing.module_bindings import patch_module_attribute


pytestmark = pytest.mark.linux_native

NETWORK = [
    "upstream_ctor",
    "bind",
    "listen",
    "getsockname",
    "listener",
    "forwarder",
    "listdir",
    "start",
    "client_ctor",
    "client_timeout",
    "client_connect",
    "accept",
    "body",
    "close_client",
    "close_accepted",
    "close_upstream",
    "stop",
]
WATCHDOG = ["listener", "forwarder", "pipe", "watchdog", "body", "stop"]


@pytest.mark.parametrize(
    "kind,stage",
    [("network", s) for s in NETWORK] + [("watchdog", s) for s in WATCHDOG],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_mask_case_failure_releases_sockets_and_directory(
    kind, stage, error, uds_dir, monkeypatch
):
    root = Path(uds_dir)
    retained, pipes = [], []
    real_socket, real_pipe = socket.socket, os.pipe
    failure = error("injected mask fixture failure")
    listener = None
    lists = 0

    def fail():
        raise failure

    class OwnedSocket:
        def __init__(self, sock, role):
            self.sock, self.role = sock, role
            retained.append(self)

        def __getattr__(self, name):
            if name == stage and stage in ("bind", "listen", "getsockname"):
                return lambda *a, **kw: fail()
            return getattr(self.sock, name)

        def settimeout(self, value):
            if stage == "client_timeout" and self.role == "client":
                fail()
            self.sock.settimeout(value)

        def connect(self, path):
            if stage == "client_connect":
                fail()

        def accept(self):
            if stage == "accept":
                fail()
            return OwnedSocket(real_socket(), "accepted"), None

        def close(self):
            self.sock.close()
            if stage == "close_" + self.role:
                fail()

    def create_socket(*args, **kwargs):
        role = "upstream" if not retained else "client"
        if stage == role + "_ctor":
            fail()
        return OwnedSocket(real_socket(*args, **kwargs), role)

    def create_listener(path):
        nonlocal listener
        if stage == "listener":
            fail()
        raw = real_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.bind(path)
        raw.listen()
        listener = OwnedSocket(raw, "listener")
        return listener

    def stop():
        if stage == "stop":
            fail()
        if listener is not None:
            listener.sock.close()
        for name in ("f.sock", "w.sock"):
            (root / name).unlink(missing_ok=True)

    forwarder = SimpleNamespace(
        start=Mock(side_effect=failure if stage == "start" else None), stop=stop
    )

    def construct(*args, **kwargs):
        if stage == "forwarder":
            fail()
        return forwarder

    def listdir(path):
        nonlocal lists
        if stage == "listdir":
            fail()
        lists += 1
        return [] if lists == 1 else ["100", "101", "102"]

    def pipe():
        if stage == "pipe":
            fail()
        pair = real_pipe()
        for fd in pair:
            stat = os.fstat(fd)
            pipes.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = create_socket
    filesystem = SimpleNamespace(**vars(os))
    filesystem.listdir, filesystem.pipe = listdir, pipe
    # The watchdog is ALWAYS inert here: never launch its process-owned
    # worker in the pytest parent, even on an unfixed source tree.
    watchdog = Mock(
        side_effect=failure if stage == "watchdog" else None,
        return_value=SimpleNamespace(native_id=1),
    )
    try:
        with monkeypatch.context() as patcher:
            patch_module_attribute(patcher, module, 'tempfile', "mkdtemp", lambda **kw: str(root))
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(module, "os", filesystem)
            patcher.setattr(module, "create_listener", create_listener)
            patcher.setattr(module, "Forwarder", construct)
            patcher.setattr(
                module,
                "_blocks_handled",
                Mock(
                    side_effect=failure if stage == "body" else None, return_value=True
                ),
            )
            patcher.setattr(module, "_sig_blk", lambda tid: 0)
            patcher.setattr(module.netns_forwarder, "_start_orphan_watchdog", watchdog)
            call = (
                module._watchdog_signal_mask_case
                if kind == "watchdog"
                else module.test_forwarder_threads_block_handled_terminal_signals
            )
            if stage.startswith("close_") and error is OSError:
                call()  # Existing best-effort close semantics ignore OSError.
            else:
                with pytest.raises(error, match="injected mask fixture failure"):
                    call()
        assert all(owned.fileno() == -1 for owned in retained), (
            "mask fixture leaked socket"
        )
        assert not root.exists(), "mask fixture left its temporary directory"
    finally:
        for owned in retained:
            owned.sock.close()
        # These descriptors are intentionally private-child-owned in the
        # target helper. Our inert parent-side model owns its own copies.
        for fd, identity in pipes:
            with suppress(OSError):
                stat = os.fstat(fd)
                if (stat.st_dev, stat.st_ino) == identity:
                    os.close(fd)
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("stage", ["before", "after"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_probe_failure_releases_and_joins_its_thread(stage, error, monkeypatch):
    real_event, real_thread = threading.Event, threading.Thread
    real_shield = module.netns_forwarder._start_signal_shielded
    events, workers = [], []

    def event():
        owned = real_event()
        events.append(owned)
        return owned

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        workers.append(worker)
        return worker

    def shield(worker):
        if stage == "after":
            real_shield(worker)
            assert events[0].wait(2)
        raise error("injected probe start failure")

    threads = SimpleNamespace(**vars(threading))
    threads.Event, threads.Thread = event, thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            patcher.setattr(module.netns_forwarder, "_start_signal_shielded", shield)
            with pytest.raises(error, match="injected probe start failure"):
                module.test_start_signal_shielded_blocks_in_worker_restores_caller()
        assert workers and not workers[0].is_alive(), "probe escaped failed setup"
    finally:
        for owned in events:
            owned.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join(3)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_creator_mask_setup_failure_restores_original_mask(error, monkeypatch):
    real_mask = signal.pthread_sigmask
    original = real_mask(signal.SIG_BLOCK, ())
    baseline = (set(original) | {signal.SIGUSR2}) - {signal.SIGUSR1, signal.SIGTERM}
    real_mask(signal.SIG_SETMASK, baseline)
    raised = False

    def mask(how, signals):
        nonlocal raised
        previous = real_mask(how, signals)
        if how == signal.SIG_SETMASK and not raised:
            raised = True
            raise error("injected creator mask setup failure")
        return previous

    signals = SimpleNamespace(**vars(signal))
    signals.pthread_sigmask = mask
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "signal", signals)
            with pytest.raises(error, match="injected creator mask setup failure"):
                module.test_shield_masks_creator_around_start_and_restores_exactly()
        assert real_mask(signal.SIG_BLOCK, ()) == baseline, (
            "test left creator mask changed"
        )
    finally:
        real_mask(signal.SIG_SETMASK, original)
