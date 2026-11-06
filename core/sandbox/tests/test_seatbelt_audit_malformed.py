"""A malformed log line must not suppress subsequent audit evidence."""

from contextlib import ExitStack
import io
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from core.sandbox import probes, seatbelt_audit


from core.testing.module_bindings import patch_module_attribute

def entry(message="Sandbox: Python(4242) deny file-read-data /tmp/example"):
    return {
        "senderImagePath": seatbelt_audit.SANDBOX_KEXT_SENDER,
        "eventMessage": message,
    }


@pytest.fixture
def malformed_lines():
    digits = "9" * ((sys.get_int_max_str_digits() or 4300) + 1)
    lines = [
        "null", "[]", "true", '"text"', "{bad json",
        "[" * 2000 + "]" * 2000,
        *[json.dumps(entry(value)) for value in (None, [], {}, 42, False)],
    ]
    if sys.get_int_max_str_digits():
        lines.extend([
            '{"value":' + digits + '}',
            json.dumps(entry("Sandbox: Python(" + digits + ") deny file-read-data /tmp/x")),
            json.dumps(entry("Sandbox: Python(1111) deny file-read-data /tmp/x("
                             + digits + ") deny file-read-data /tmp/y")),
        ])
    return lines


def test_reader_continues_after_malformed_entries(tmp_path, monkeypatch, malformed_lines):
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    lines = malformed_lines + [json.dumps(entry())]
    streamer._proc = SimpleNamespace(stdout=io.StringIO("\n".join(lines) + "\n"))
    captured = []
    monkeypatch.setattr(streamer, "_filter_and_append", captured.append)
    streamer._read_loop()
    assert len(captured) == 1
    assert captured[0]["target_pid"] == 4242
    assert captured[0]["path"] == "/tmp/example"


@pytest.mark.parametrize("value", [None, [], True, 42, "message"])
def test_parser_rejects_non_object_entries(value):
    assert seatbelt_audit.parse_log_entry(value) is None


@pytest.mark.parametrize("value", [None, [], {}, 42, False])
def test_parser_rejects_non_string_messages(value):
    assert seatbelt_audit.parse_log_entry(entry(value)) is None


def test_warmup_continues_after_malformed_entries(tmp_path, monkeypatch, malformed_lines):
    streamer = seatbelt_audit.LogStreamer(tmp_path)
    warmup = SimpleNamespace(pid=4242, wait=lambda timeout: 0)
    monkeypatch.setattr(probes, "_find_sandbox_binary", lambda name: sys.executable)
    patch_module_attribute(monkeypatch, seatbelt_audit, "subprocess", "Popen", lambda *a, **kw: warmup)
    with ExitStack() as cleanup:
        reader, writer = socket.socketpair()
        cleanup.callback(writer.close)
        cleanup.callback(reader.close)
        reader.settimeout(5)
        writer.settimeout(5)

        def send_lines():
            writer.sendall(("\n".join(malformed_lines + [json.dumps(entry())]) + "\n").encode())
            writer.shutdown(socket.SHUT_WR)

        # Drain concurrently: the malformed payload can exceed the
        # socket buffer (notably on macOS), blocking a prefilled sendall.
        with ThreadPoolExecutor(max_workers=1) as executor:
            sent = executor.submit(send_lines)
            with reader.makefile("r") as stream:
                streamer._proc = SimpleNamespace(stdout=stream)
                assert streamer._warm_up_until_attached() is True
                assert stream.read() == ""
            sent.result(timeout=5)
