"""Failed startup must release the audit producer and its pipe."""

import io
import subprocess
from unittest.mock import Mock

import pytest

from core.sandbox import seatbelt_audit


from core.testing.module_bindings import patch_module_attribute

@pytest.fixture
def setup_streamer(tmp_path, monkeypatch):
    proc = Mock(stdout=io.StringIO())
    proc.wait.return_value = 0
    launch = Mock(return_value=proc)
    patch_module_attribute(monkeypatch, seatbelt_audit, "subprocess", "Popen", launch)
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    monkeypatch.setattr(streamer, "_warm_up_until_attached", lambda: True)
    return streamer, proc, launch


@pytest.mark.parametrize("stage", ["warmup", "construct", "start"])
@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_failed_startup_releases_process_and_pipe(setup_streamer, monkeypatch, stage, failure_type):
    streamer, proc, _ = setup_streamer
    failure = failure_type("startup failed")

    def fail(*args, **kwargs):
        raise failure

    if stage == "warmup":
        monkeypatch.setattr(streamer, "_warm_up_until_attached", fail)
    elif stage == "construct":
        patch_module_attribute(monkeypatch, seatbelt_audit, "threading", "Thread", fail)
    else:
        local_thread = type("FaultThread", (seatbelt_audit.threading.Thread,), {"start": fail})
        patch_module_attribute(monkeypatch, seatbelt_audit, "threading", "Thread", local_thread)
    with pytest.raises(failure_type) as raised:
        streamer.start()
    assert raised.value is failure
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=5)
    assert proc.stdout.closed
    assert streamer._reader is None
    assert streamer._proc is None


@pytest.mark.parametrize("signal", ["terminate", "kill"])
def test_signal_errors_do_not_skip_reaping(setup_streamer, monkeypatch, signal):
    streamer, proc, _ = setup_streamer
    failure = RuntimeError("warmup failed")
    monkeypatch.setattr(streamer, "_warm_up_until_attached", Mock(side_effect=failure))
    getattr(proc, signal).side_effect = ProcessLookupError()
    if signal == "kill":
        proc.wait.side_effect = [subprocess.TimeoutExpired("log", 5), 0]
    with pytest.raises(RuntimeError) as raised:
        streamer.start()
    assert raised.value is failure
    assert proc.wait.call_count == (2 if signal == "kill" else 1)
    assert proc.stdout.closed


def test_reap_failure_preserves_original_startup_exception(setup_streamer, monkeypatch):
    streamer, proc, _ = setup_streamer
    failure = KeyboardInterrupt("cancel warmup")
    monkeypatch.setattr(streamer, "_warm_up_until_attached", Mock(side_effect=failure))
    proc.wait.side_effect = RuntimeError("reaping failed")
    with pytest.raises(KeyboardInterrupt) as raised:
        streamer.start()
    assert raised.value is failure
    proc.kill.assert_called_once()
    assert proc.wait.call_count == 2
    assert proc.stdout.closed


def test_duplicate_start_keeps_original_process(setup_streamer, monkeypatch):
    streamer, proc, launch = setup_streamer
    reader = Mock()
    patch_module_attribute(monkeypatch, seatbelt_audit, "threading", "Thread", Mock(return_value=reader))
    streamer.start()
    with pytest.raises(RuntimeError, match="already been started"):
        streamer.start()
    launch.assert_called_once()
    assert streamer._proc is proc
    assert streamer._reader is reader
    proc.terminate.assert_not_called()
    assert not proc.stdout.closed
    proc.stdout.close()


def test_thread_start_failure_reaps_a_real_producer(tmp_path, monkeypatch):
    import sys

    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE, start_new_session=True,
    )
    try:
        patch_module_attribute(monkeypatch, seatbelt_audit, "subprocess", "Popen", Mock(return_value=proc))
        streamer = seatbelt_audit.LogStreamer(tmp_path)
        monkeypatch.setattr(streamer, "_warm_up_until_attached", lambda: True)
        local_thread = type("FaultThread", (seatbelt_audit.threading.Thread,), {"start": Mock(side_effect=RuntimeError("cannot start reader"))})
        patch_module_attribute(monkeypatch, seatbelt_audit, "threading", "Thread", local_thread)
        with pytest.raises(RuntimeError, match="cannot start reader"):
            streamer.start()
        assert proc.returncode is not None
        assert proc.stdout.closed
        assert streamer._proc is None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        proc.stdout.close()
