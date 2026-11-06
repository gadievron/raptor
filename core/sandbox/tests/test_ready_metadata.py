"""Validate consumed worker status fields over owned framed sockets."""
from contextlib import ExitStack
import json
import socket

import pytest

from core.sandbox import parser_jail as jail


def read_ready(value):
    payload = json.dumps(value).encode()
    with ExitStack() as cleanup:
        reader, writer = socket.socketpair()
        cleanup.callback(reader.close)
        cleanup.callback(writer.close)
        reader.settimeout(2)
        writer.settimeout(2)
        writer.sendall(jail.FRAME_HEADER.pack(len(payload), jail.READY_FRAME_ID) + payload)
        return jail.ParserJail()._read_ready_frame(reader)


@pytest.mark.parametrize('value', [
    {}, {'ready': 1}, {'ready': 'true'},
    {'ready': True}, {'ready': True, 'landlock': None},
    {'ready': True, 'landlock': 0}, {'ready': True, 'landlock': 'true'},
    *({'ready': True, 'landlock': True, 'rlimits_failed': bad}
      for bad in (None, False, 0, '', {}, [1])),
    {'ready': False, 'error': {'message': 'refused'}},
], ids=['missing-ready', 'integer-ready', 'string-ready', 'missing-landlock',
        'null-landlock', 'integer-landlock', 'string-landlock', 'null-limits',
        'bool-limits', 'integer-limits', 'string-limits', 'object-limits',
        'nonstring-limit', 'object-error'])
def test_ready_rejects_malformed_consumed_metadata(value):
    with pytest.raises(jail._ProtocolError):
        read_ready(value)


@pytest.mark.parametrize('value', [
    {'ready': True, 'landlock': True, 'pid': -1},
    {'ready': True, 'landlock': False},
    {'ready': True, 'landlock': True, 'rlimits_failed': []},
    {'ready': True, 'landlock': True, 'rlimits_failed': ['RLIMIT_AS']},
    {'ready': False}, {'ready': False, 'error': None},
    {'ready': False, 'error': 'refused'},
], ids=['confined', 'degraded', 'empty-limits', 'partial-limits',
        'refused', 'null-error', 'reason'])
def test_ready_preserves_supported_metadata(value):
    assert read_ready(value) == value
