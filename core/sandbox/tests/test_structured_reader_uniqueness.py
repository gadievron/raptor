"""Structured reader boundaries reject ambiguity before consuming values."""
from contextlib import ExitStack
import json
import socket

import pytest

from core.sandbox import egress_summary, parser_jail, seatbelt_audit, telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.parametrize('payload', [
    b'{"ok":false,"ok":true,"host":"example.test","port":443}',
    b'{"ok":true,"host":"first.test","host":"last.test","port":443}',
    b'{"ok":true,"host":"example.test","port":80,"port":443}',
    b'{"ok":true,"host":"example.test","port":443,"meta":{"x":1,"x":1}}',
])
def test_worker_verdict_rejects_duplicate_members(payload):
    with pytest.raises(parser_jail._ProtocolError):
        parser_jail._validate_verdict(payload)


def test_worker_ready_frame_rejects_duplicate_members():
    payload = b'{"ready":false,"ready":true,"landlock":true}'
    with ExitStack() as cleanup:
        reader, writer = socket.socketpair()
        cleanup.callback(reader.close)
        cleanup.callback(writer.close)
        reader.settimeout(2)
        writer.settimeout(2)
        writer.sendall(parser_jail.FRAME_HEADER.pack(len(payload), parser_jail.READY_FRAME_ID) + payload)
        owner = parser_jail.ParserJail()
        with pytest.raises(parser_jail._ProtocolError):
            owner._read_ready_frame(reader)


@pytest.mark.parametrize('field', ['host', 'result', 'nested'])
def test_egress_reader_skips_ambiguity_and_keeps_neighbors(tmp_path, field):
    good = {'host': 'example.test', 'port': 443, 'result': 'allowed'}
    if field == 'nested':
        bad = json.dumps(good)[:-1] + ',"meta":{"x":1,"x":2}}'
    else:
        bad = '{' + json.dumps(field) + ':"earlier",' + json.dumps(good)[1:]
    (tmp_path / 'proxy-events.jsonl').write_text(json.dumps(good) + '\n' + bad + '\n' + json.dumps(good) + '\n')
    value = egress_summary.finalize_egress_summary(tmp_path)
    assert value['total_connections'] == 2
    assert value['allowed'] == 2
    assert json.loads((tmp_path / egress_summary.EGRESS_SUMMARY_FILE).read_text()) == value


@pytest.mark.parametrize('nested', [False, True])
def test_tamper_history_skips_ambiguity_and_keeps_neighbors(tmp_path, monkeypatch, nested):
    path = tmp_path / 'tamper.jsonl'
    monkeypatch.setattr(mac, 'tamper_marker_path', lambda: path)
    bad = ('{"reason":"first","reason":"last"}' if not nested else
           '{"reason":"ambiguous","meta":{"x":1,"x":1}}')
    before, after = {'reason': 'before'}, {'reason': 'after'}
    path.write_text(json.dumps(before) + '\n' + bad + '\n' + json.dumps(after) + '\n')
    assert mac.tamper_events() == [before, after]


@pytest.mark.parametrize('field', ['eventMessage', 'senderImagePath', 'nested'])
def test_live_log_decoder_rejects_duplicate_members(field):
    entry = {'senderImagePath': seatbelt_audit.SANDBOX_KEXT_SENDER,
             'eventMessage': 'Sandbox: tool(123) deny file-read-data /tmp/valid'}
    bad = (json.dumps(entry)[:-1] + ',"meta":{"x":1,"x":2}}' if field == 'nested' else
           '{' + json.dumps(field) + ':"earlier",' + json.dumps(entry)[1:])
    assert seatbelt_audit._decode_log_entry(bad) is None


def test_unique_nested_members_remain_accepted():
    value = {'ok': True, 'host': 'example.test', 'port': 443,
             'meta': {'left': {'x': 1}, 'right': {'x': 2}}}
    verdict = parser_jail._validate_verdict(json.dumps(value).encode())
    assert (verdict.host, verdict.port) == ('example.test', 443)
    assert seatbelt_audit._decode_log_entry(json.dumps(value)) == value
