"""Malformed audit arguments cannot interrupt signature classification."""
import pytest

from core.sandbox.escalation_signatures import decode_syscall_args, hostile_arg_label


@pytest.mark.parametrize('args', [None, {}, {'0': 17, '1': 3}, {0: 17, '1': 3},
                                  '173', b'173', 17, True])
@pytest.mark.parametrize('syscall', ['socket', 'ioctl'])
def test_non_sequence_arguments_are_ignored(syscall, args):
    assert decode_syscall_args(syscall, args) == {}
    assert hostile_arg_label(syscall, args) is None


@pytest.mark.parametrize('value', [float('inf'), float('-inf'), float('nan'),
                                   {}, [], None, 'invalid'])
@pytest.mark.parametrize('syscall', ['socket', 'ioctl'])
def test_invalid_numeric_arguments_are_ignored(syscall, value):
    args = [value, 3] if syscall == 'socket' else [0, value]
    assert decode_syscall_args(syscall, args) == {}
    assert hostile_arg_label(syscall, args) is None


@pytest.mark.parametrize('container', [list, tuple])
def test_valid_sequences_preserve_masks_and_numeric_strings(container):
    assert decode_syscall_args('socket', container([str((1 << 32) | 17), 0x803])) == {
        'socket_family': 'AF_PACKET', 'socket_type': 'SOCK_RAW'}
    assert hostile_arg_label('ioctl', container([0, str((1 << 32) | 0x5412)])) == 'ioctl(TIOCSTI)'


def test_bad_record_does_not_prevent_later_record_classification():
    records = [{'0': 17, '1': 3}, [float('inf'), 3], [17, 3]]
    assert [hostile_arg_label('socket', args) for args in records] == [
        None, None, 'socket(AF_PACKET)']
