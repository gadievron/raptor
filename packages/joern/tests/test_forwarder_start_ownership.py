"""Failed acceptor startup remains joinable through signal-mask restoration."""

from contextlib import suppress
import signal
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.joern import netns_forwarder as module

pytestmark = pytest.mark.linux_native


@pytest.mark.parametrize("stage", ["construct", "block", "start", "restore", "after_shield"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_acceptor_start_remains_owned(stage, error, uds_dir, monkeypatch):
    path = Path(uds_dir) / "start.sock"
    listener = module.create_listener(str(path))
    forwarder = module.Forwarder(listener, ("127.0.0.1", 1), socket_path=str(path))
    real_thread = threading.Thread
    real_mask = signal.pthread_sigmask
    real_shield = module._start_signal_shielded
    baseline_mask = real_mask(signal.SIG_BLOCK, ())
    workers, joined = [], []
    restored = False
    failure = error("injected acceptor startup failure")

    def thread(*args, **kwargs):
        if stage == "construct":
            raise failure
        worker = real_thread(*args, **kwargs)
        join = worker.join

        def observed_join(*args, **kwargs):
            joined.append(worker)
            return join(*args, **kwargs)

        worker.join = observed_join
        if stage == "start":
            def fail_start():
                raise failure
            worker.start = fail_start
        workers.append(worker)
        return worker

    def mask(how, signals):
        nonlocal restored
        if stage == "block" and how == signal.SIG_BLOCK:
            raise failure
        previous = real_mask(how, signals)
        if stage == "restore" and how == signal.SIG_SETMASK and not restored:
            # Simulate a pending handler raising as restoration completes;
            # never deliver a process signal or leave the creator masked.
            restored = True
            raise failure
        return previous

    def shield(worker):
        real_shield(worker)
        if stage == "after_shield":
            raise failure

    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    signals = SimpleNamespace(**vars(signal))
    signals.pthread_sigmask = mask
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            patcher.setattr(module, "signal", signals)
            patcher.setattr(module, "_start_signal_shielded", shield)
            with pytest.raises(error, match="injected acceptor startup failure"):
                forwarder.start()
            assert real_mask(signal.SIG_BLOCK, ()) == baseline_mask
            forwarder.stop()
        assert listener.fileno() == -1
        assert not path.exists()
        for worker in workers:
            if worker.ident is None:
                assert worker not in joined, "unstarted acceptor was joined"
            else:
                assert worker in joined, "failed startup abandoned its acceptor handle"
                assert not worker.is_alive()
    finally:
        try:
            forwarder.stop()
        finally:
            with suppress(OSError):
                listener.shutdown(2)
            listener.close()
            path.unlink(missing_ok=True)
            for worker in workers:
                if worker.ident is not None:
                    real_thread.join(worker, 3)
            real_mask(signal.SIG_SETMASK, baseline_mask)
