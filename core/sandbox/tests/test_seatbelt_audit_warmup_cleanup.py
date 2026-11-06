"""Every post-spawn warm-up exit owns bounded child cleanup."""

import select
import selectors
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import probes, seatbelt_audit as audit
from core.testing.streams import pipe_streams


from core.testing.module_bindings import patch_module_attribute

@pytest.fixture
def warmup_setup(tmp_path, monkeypatch):
    streamer = audit.LogStreamer(tmp_path)
    with pipe_streams() as (stream, writer):
        writer.close()
        streamer._proc = SimpleNamespace(stdout=stream)
        proc = Mock(pid=4242)
        proc.wait.return_value = 0
        selector = Mock()
        selector.select.return_value = []
        factory = Mock(return_value=selector)
        monkeypatch.setattr(probes, "_find_sandbox_binary", lambda name: sys.executable)
        patch_module_attribute(monkeypatch, audit, "subprocess", "Popen", Mock(return_value=proc))
        monkeypatch.setattr(selectors, "DefaultSelector", factory)
        yield streamer, proc, selector, factory


@pytest.mark.parametrize("stage", ["missing_streamer", "create", "register", "select"])
@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
def test_setup_and_wait_errors_still_reap(warmup_setup, stage, failure_type):
    streamer, proc, selector, factory = warmup_setup
    failure = failure_type("warm-up failed")
    if stage == "missing_streamer":
        streamer._proc = None
        expected = RuntimeError
    elif stage == "create":
        factory.side_effect = failure
        expected = failure_type
    else:
        getattr(selector, stage).side_effect = failure
        expected = failure_type
    with pytest.raises(expected):
        streamer._warm_up_until_attached()
    proc.wait.assert_called_once_with(timeout=1.0)
    if stage in ("register", "select"):
        selector.close.assert_called_once()


def test_missing_stdout_still_escalates_a_stubborn_probe(warmup_setup):
    streamer, proc, _, factory = warmup_setup
    streamer._proc.stdout = None
    proc.wait.side_effect = [
        subprocess.TimeoutExpired("warmup", 1),
        subprocess.TimeoutExpired("warmup", 1), 0,
    ]
    assert streamer._warm_up_until_attached() is False
    factory.assert_not_called()
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()
    assert proc.wait.call_count == 3


def test_selector_close_error_preserves_original_failure(warmup_setup):
    streamer, proc, selector, _ = warmup_setup
    failure = RuntimeError("registration failed")
    selector.register.side_effect = failure
    selector.close.side_effect = OSError("close failed")
    with pytest.raises(RuntimeError) as raised:
        streamer._warm_up_until_attached()
    assert raised.value is failure
    proc.wait.assert_called_once_with(timeout=1.0)


@pytest.mark.parametrize("signal", ["terminate", "kill"])
def test_signal_errors_do_not_skip_wait(signal):
    proc = Mock()
    getattr(proc, signal).side_effect = ProcessLookupError()
    proc.wait.side_effect = (
        [subprocess.TimeoutExpired("warmup", 1), 0] if signal == "terminate"
        else [subprocess.TimeoutExpired("warmup", 1),
              subprocess.TimeoutExpired("warmup", 1), 0]
    )
    audit._reap_warm_up(proc)
    assert proc.wait.call_count == (2 if signal == "terminate" else 3)


def test_reap_errors_are_logged_without_replacing_gate_failure(warmup_setup, caplog):
    streamer, proc, selector, _ = warmup_setup
    failure = RuntimeError("registration failed")
    selector.register.side_effect = failure
    proc.wait.side_effect = OSError("wait failed")
    with pytest.raises(RuntimeError) as raised:
        streamer._warm_up_until_attached()
    assert raised.value is failure
    proc.kill.assert_called_once()
    assert "could not reap warm-up process" in caplog.text


@pytest.mark.skipif(not hasattr(select, "poll"), reason="requires POSIX polling")
def test_real_probe_ignoring_terminate_is_killed_and_reaped():
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
         "print('ready', flush=True); time.sleep(60)"],
        stdout=subprocess.PIPE,
    )
    try:
        poller = select.poll()
        poller.register(proc.stdout, select.POLLIN)
        assert poller.poll(5000)
        assert proc.stdout.readline() == b"ready\n"
        audit._reap_warm_up(proc)
        assert proc.returncode is not None
        assert proc.returncode != 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()
