"""An unrelated handled exception must not hide a new timeout-mode failure."""
from types import SimpleNamespace

import pytest

from core.sandbox import parser_jail as parser
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('operation', ['recv', 'roundtrip'])
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt])
def test_successful_exchange_surfaces_restore_failure_in_exception_handler(
    monkeypatch, operation, failure_type,
):
    failure = failure_type('owned timeout restoration failure')
    payload = b'{"ok":true,"host":"owned.invalid","port":443}'
    response = (parser.FRAME_HEADER.pack(len(payload), 17) + payload
                if operation == 'roundtrip' else b'x')
    consumed, restored = [], []

    class Transport:
        timeout = 17

        def gettimeout(self):
            return self.timeout

        def settimeout(self, value):
            if value == 17:
                restored.append(True)
                raise failure
            assert value > 0
            self.timeout = value

        def recv(self, size):
            nonlocal response
            chunk, response = response[:size], response[size:]
            consumed.append(chunk)
            return chunk

        def send(self, view):
            return len(view)

    sock = Transport()
    jail = parser.ParserJail()
    jail._sock = sock
    monkeypatch.setattr(jail, '_new_req_id', lambda: 17)
    poller = SimpleNamespace(register=lambda *args: None, poll=lambda timeout: [])
    patch_module_attribute(monkeypatch, parser, 'select', 'poll', lambda: poller)
    try:
        raise ValueError('unrelated caller exception')
    except ValueError:
        with pytest.raises(BaseException) as caught:
            if operation == 'recv':
                parser.ParserJail._recv_exact(sock, 1, deadline=parser.time.monotonic() + 1)
            else:
                jail._roundtrip_locked(b'owned')
    assert caught.value is failure
    assert consumed and restored
