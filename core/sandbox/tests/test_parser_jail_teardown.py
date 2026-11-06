"""Worker cleanup failures must not corrupt parser-manager state."""

import socket
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import parser_jail as parser


from core.testing.module_bindings import patch_module_attribute

class TestParserWorkerTeardown:
    @pytest.mark.parametrize("stage", ["poll", "kill", "wait"])
    def test_os_error_still_attempts_bounded_reap(self, stage, caplog):
        proc = Mock(pid=1234)
        proc.poll.return_value = None
        getattr(proc, stage).side_effect = OSError("cleanup failed")
        parser.ParserJail._reap_locked(proc)
        proc.wait.assert_called_once_with(timeout=parser._READY_TIMEOUT_S)
        assert "worker pid 1234" in caplog.text

    def test_already_exited_worker_is_waited_without_signaling(self):
        proc = Mock(pid=1234)
        proc.poll.return_value = 0
        parser.ParserJail._reap_locked(proc)
        proc.kill.assert_not_called()
        proc.wait.assert_called_once_with(timeout=parser._READY_TIMEOUT_S)

    def test_timeout_remains_bounded_and_logged(self, caplog):
        proc = Mock(pid=1234)
        proc.poll.return_value = None
        proc.wait.side_effect = subprocess.TimeoutExpired("worker", 1)
        parser.ParserJail._reap_locked(proc)
        proc.wait.assert_called_once_with(timeout=parser._READY_TIMEOUT_S)
        assert "did not reap" in caplog.text

    def test_repeated_stop_does_not_reuse_failed_cleanup_state(self):
        jail = parser.ParserJail()
        proc = Mock(pid=1234)
        proc.poll.return_value = None
        proc.kill.side_effect = OSError("signal failed")
        proc.wait.side_effect = OSError("reap failed")
        sock = Mock()
        sock.close.side_effect = OSError("close failed")
        jail._proc, jail._sock = proc, sock
        jail.stop()
        jail.stop()
        assert jail._proc is None and jail._sock is None
        sock.close.assert_called_once()
        proc.kill.assert_called_once()
        proc.wait.assert_called_once()

    @pytest.mark.parametrize("failure", [OSError("broken pipe"), parser._ProtocolError("bad frame")])
    @pytest.mark.parametrize("cleanup_stage", ["poll", "kill", "wait"])
    def test_parse_still_returns_refusal(self, monkeypatch, failure, cleanup_stage):
        jail = parser.ParserJail()
        proc = Mock(pid=1234)
        proc.poll.return_value = None
        getattr(proc, cleanup_stage).side_effect = OSError("cleanup failed")
        jail._proc, jail._sock = proc, Mock()
        monkeypatch.setattr(jail, "_ensure_worker_locked", lambda: None)
        monkeypatch.setattr(jail, "_roundtrip_locked", Mock(side_effect=failure))
        verdict = jail.parse(b"request")
        assert isinstance(verdict, parser.ParseRefusal)
        assert jail._proc is None and jail._sock is None
        proc.wait.assert_called_once()

    def test_close_cancellation_still_reaps_and_clears_state(self):
        jail = parser.ParserJail()
        proc = Mock(pid=1234)
        proc.poll.return_value = None
        sock = Mock()
        failure = KeyboardInterrupt("cancel close")
        sock.close.side_effect = failure
        jail._proc, jail._sock = proc, sock
        with pytest.raises(KeyboardInterrupt) as raised:
            jail.stop()
        assert raised.value is failure
        assert jail._proc is None and jail._sock is None
        proc.kill.assert_called_once()
        proc.wait.assert_called_once()

    def test_handshake_diagnostic_errors_preserve_typed_failure(self, monkeypatch):
        jail = parser.ParserJail()
        proc = Mock(pid=1234)
        proc.poll.return_value = None
        proc.wait.side_effect = OSError("wait failed")
        proc.kill.side_effect = OSError("kill failed")
        patch_module_attribute(monkeypatch, parser, "subprocess", "Popen", Mock(return_value=proc))
        monkeypatch.setattr(
            jail, "_read_ready_frame", Mock(side_effect=parser._ProtocolError("bad ready frame")),
        )
        with pytest.raises(parser.ParserJailUnavailable, match="bad ready frame") as raised:
            jail.start()
        assert "exit status unavailable" in str(raised.value)
        assert jail._proc is None and jail._sock is None
        assert jail._spawn_failures == 1
        assert jail._next_spawn_attempt > 0


    def test_signal_error_still_reaps_real_child(self, monkeypatch):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        sock, peer = socket.socketpair()
        original_kill = proc.kill
        jail = parser.ParserJail()
        jail._proc, jail._sock = proc, sock

        def signal_race():
            original_kill()
            raise ProcessLookupError("worker disappeared during signal")

        monkeypatch.setattr(proc, "kill", signal_race)
        try:
            jail.stop()
            assert proc.returncode is not None
            assert jail._proc is None and jail._sock is None
            peer.settimeout(1)
            assert peer.recv(1) == b""
        finally:
            if proc.poll() is None:
                original_kill()
            proc.wait(timeout=5)
            sock.close()
            peer.close()
