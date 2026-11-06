"""Raw diagnostic registers preserve integer compatibility without truncation."""
import json
from enum import IntEnum

import pytest

from core.sandbox import evidence, summary, telemetry_mac as mac, triage
from core.sandbox.escalation_signatures import decode_syscall_args, hostile_arg_label
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


BAD_ARGS = [
    pytest.param('socket', [17.9, 3], id='fractional-family'),
    pytest.param('socket', [17, 3.9], id='fractional-type'),
    pytest.param('socket', [True, 3], id='boolean-family'),
    pytest.param('socket', [17, True], id='boolean-type'),
    pytest.param('ioctl', [0, 0x5412 + .75], id='fractional-command'),
    pytest.param('ioctl', [0, True], id='boolean-command'),
]


@pytest.mark.parametrize('syscall,args', BAD_ARGS)
def test_decoder_does_not_manufacture_integer_registers(syscall, args):
    assert decode_syscall_args(syscall, args) == {}
    assert hostile_arg_label(syscall, args) is None


@pytest.mark.parametrize('syscall,args', BAD_ARGS)
def test_summary_marks_malformed_registers_and_preserves_neighbors(tmp_path, syscall, args):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True)
    good = {'type': 'write', 'path': '/tmp/retained'}
    bad = {'type': 'seccomp', 'syscall': syscall, 'args': args}
    path.write_text('\n'.join(map(json.dumps, [good, bad, good])) + '\n')
    result = summary.summarize_and_write(run)
    assert result['corrupt_lines'] == 1
    assert result['total_denials'] == 2
    assert all(row['path'] == '/tmp/retained' for row in result['denials'])
    assert result['mac']
    assert triage.triage_run(run, allow_legacy=False)['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('stamped', [False, True], ids=['legacy', 'signed'])
@pytest.mark.parametrize('syscall,args', BAD_ARGS)
def test_reader_rejects_malformed_registers_even_with_valid_mac(tmp_path, stamped, syscall, args):
    run = tmp_path / 'run'
    binding = mac.run_binding(run)
    rows = [{'type': 'seccomp', 'syscall': syscall, 'args': args}]
    value = {'total_denials': 1, 'denials': rows}
    if stamped:
        value['mac'] = mac.mint(mac.summary_fields(1, triage._denials_sha256(rows), binding))
        assert value['mac']
    assert triage._verify_summary(value, binding, allow_legacy=True) == (None, triage._INTEGRITY_TAMPERED)


class Register(IntEnum):
    FAMILY = 17
    KIND = 3


@pytest.mark.parametrize('args', [
    [17, 3], ['17', '3'], [(1 << 32) | 17, 0x803],
    [str((1 << 32) | 17), '2051'], [Register.FAMILY, Register.KIND],
], ids=['integers', 'numeric-strings', 'masked', 'masked-strings', 'enum'])
def test_integer_compatibility_is_preserved(args):
    assert decode_syscall_args('socket', args) == {'socket_family': 'AF_PACKET', 'socket_type': 'SOCK_RAW'}
    assert hostile_arg_label('socket', args) == 'socket(AF_PACKET)'


@pytest.mark.parametrize('args', [None, [], [17], ['17', 3]], ids=['missing', 'empty', 'short', 'numeric-string'])
def test_supported_legacy_registers_remain_verifiable(tmp_path, args):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'type': 'seccomp', 'syscall': 'socket', 'args': args}) + '\n')
    result = summary.summarize_and_write(run)
    assert 'corrupt_lines' not in result
    assert result['total_denials'] == 1
    assert triage.triage_run(run, allow_legacy=False)['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_VERIFIED
