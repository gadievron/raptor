"""Live decoding preserves valid neighbors and reports discarded source rows."""
import json

import pytest

from core.sandbox import evidence, observe_profile as observe, seatbelt_audit as audit, summary
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.slow  # owned process stdout exercises the production reader


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        monkeypatch.setattr(summary, '_evidence_write_failures', dict(summary._evidence_write_failures))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def log_line(path):
    return (json.dumps({'senderImagePath': audit.SANDBOX_KEXT_SENDER,
                        'eventMessage': f'Sandbox: tool(123) deny(1) file-read-data {path}'},
                       ensure_ascii=False) + '\n').encode('utf-8')


@pytest.mark.parametrize('data,paths,incomplete', [
    (log_line('/tmp/first') + b'\xff\n' + log_line('/tmp/last'), ['/tmp/first', '/tmp/last'], True),
    (log_line('/tmp/MARKER').replace(b'MARKER', b'\xff') + log_line('/tmp/last'), ['/tmp/last'], True),
    (log_line('/tmp/caf\u00e9'), ['/tmp/caf\u00e9'], False),
    (log_line('/tmp/replacement-\ufffd'), ['/tmp/replacement-\ufffd'], False),
    (b'null\n' + log_line('/tmp/last'), ['/tmp/last'], True),
    (b'{bad json\n' + log_line('/tmp/last'), ['/tmp/last'], True),
    (b'{"eventMessage":"unrelated"}\n' + log_line('/tmp/last'), ['/tmp/last'], False),
    (b'\n \n' + log_line('/tmp/last'), ['/tmp/last'], False),
])
def test_live_capture_retains_valid_data_and_loss_state(owned_audit_source, data, paths, incomplete):
    owner, profile = owned_audit_source(data)
    assert profile.paths_read == paths
    assert profile.capture_incomplete is incomplete
    assert owner._reader_failed is incomplete
    assert owner._proc.stdout.closed
    path = evidence.evidence_write_path(owner._run_dir, observe.OBSERVE_FILENAME)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    tail = records[-1]
    assert tail['type'] == 'audit_summary'
    assert tail.get('reader_failed', False) is incomplete
    assert tail['reader_drained'] is (not incomplete)


def test_warmup_preserves_damage_until_per_line_validation():
    import socket
    import time
    data = log_line('/tmp/MARKER').replace(b'MARKER', b'\xff') + log_line('/tmp/last')
    reader, writer = socket.socketpair()
    try:
        reader.settimeout(2)
        writer.settimeout(2)
        writer.sendall(data)
        writer.shutdown(socket.SHUT_WR)
        with reader.makefile('r') as stream:
            lines = list(audit._warm_up_log_lines(stream, time.monotonic() + 2))
        entries = [entry for line in lines if (entry := audit._decode_log_entry(line)) is not None]
        assert len(entries) == 1
        assert '/tmp/last' in entries[0]['eventMessage']
    finally:
        reader.close()
        writer.close()
