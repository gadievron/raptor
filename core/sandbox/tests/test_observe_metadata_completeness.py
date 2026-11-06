"""Consumed observation metadata cannot conceal capture or interpretation loss."""
import json

import pytest

from core.sandbox import evidence, observe_profile as observe
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(observe, '_connect_gap_last_warn', observe._connect_gap_last_warn)
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture
def load(tmp_path):
    def parse(records):
        run = tmp_path / 'run'
        path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
        path.parent.mkdir(parents=True, exist_ok=True)
        first = {'syscall': 'stat', 'path': '/tmp/retained', 'nonce': 'trusted'}
        tail = {'type': 'audit_summary', 'nonce': 'trusted',
                'reader_failed': False, 'reader_drained': True}
        path.write_text('\n'.join(map(json.dumps, [first, *records, tail])) + '\n')
        return observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
    return parse


@pytest.mark.parametrize('field', ['observe', 'parse_ambiguous'])
@pytest.mark.parametrize('value', [None, 0, 1, '', 'false', [], {}, [True]],
                         ids=['null', 'zero', 'one', 'empty', 'string', 'array', 'object', 'true-array'])
def test_malformed_stamps_are_loss_without_becoming_observations(load, field, value):
    profile = load([{'syscall': 'stat', 'path': '/tmp/malformed', 'nonce': 'trusted', field: value}])
    assert profile.paths_stat == ['/tmp/retained']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False
    assert profile.nonce_trusted is True


@pytest.mark.parametrize('field,value,kept,incomplete', [
    ('observe', True, True, False), ('observe', False, False, False),
    ('parse_ambiguous', False, True, False), ('parse_ambiguous', True, False, True),
], ids=['observe', 'other-mode', 'unambiguous', 'ambiguous'])
def test_boolean_stamps_preserve_existing_semantics(load, field, value, kept, incomplete):
    profile = load([{'syscall': 'stat', 'path': '/tmp/event', 'nonce': 'trusted', field: value}])
    assert profile.paths_stat == ['/tmp/retained'] + (['/tmp/event'] if kept else [])
    assert profile.capture_incomplete is incomplete


@pytest.mark.parametrize('syscall', ['open', 'openat'])
@pytest.mark.parametrize('args', [None, True, 7, {}, 'invalid', []],
                         ids=['null', 'boolean', 'integer', 'object', 'string', 'short'])
def test_unusable_flag_container_keeps_conservative_path_but_marks_loss(load, syscall, args):
    profile = load([{'syscall': syscall, 'path': '/tmp/unknown-flags',
                     'args': args, 'nonce': 'trusted'}])
    assert profile.paths_read == ['/tmp/unknown-flags']
    assert profile.paths_written == []
    assert profile.capture_incomplete is True
    assert profile.paths_stat == ['/tmp/retained']


@pytest.mark.parametrize('syscall', ['open', 'openat'])
@pytest.mark.parametrize('flags', [None, True, 1.5, '1'], ids=['null', 'boolean', 'fraction', 'string'])
def test_unusable_flag_value_keeps_conservative_path_but_marks_loss(load, syscall, flags):
    args = [0, flags] if syscall == 'open' else [-100, 0, flags]
    profile = load([{'syscall': syscall, 'path': '/tmp/unknown-flags',
                     'args': args, 'nonce': 'trusted'}])
    assert profile.paths_read == ['/tmp/unknown-flags']
    assert profile.paths_written == []
    assert profile.capture_incomplete is True


@pytest.mark.parametrize('syscall', ['open', 'openat'])
@pytest.mark.parametrize('flags', [0, 1], ids=['read', 'write'])
def test_integer_flags_remain_complete(load, syscall, flags):
    args = [0, flags] if syscall == 'open' else [-100, 0, flags]
    profile = load([{'syscall': syscall, 'path': '/tmp/known-flags',
                     'args': args, 'nonce': 'trusted'}])
    assert profile.paths_read == ([] if flags else ['/tmp/known-flags'])
    assert profile.paths_written == (['/tmp/known-flags'] if flags else [])
    assert profile.capture_incomplete is False


@pytest.mark.parametrize('syscall', ['open', 'openat', 'file-read-data'])
def test_legacy_absent_args_remain_complete(load, syscall):
    profile = load([{'syscall': syscall, 'path': '/tmp/legacy', 'nonce': 'trusted'}])
    assert profile.paths_read == ['/tmp/legacy']
    assert profile.capture_incomplete is False


def test_openat2_retains_conservative_write_handling(load):
    profile = load([{'syscall': 'openat2', 'path': '/tmp/openat2', 'args': [-100, 0, 1234],
                     'nonce': 'trusted'}])
    assert profile.paths_written == ['/tmp/openat2']
    assert profile.capture_incomplete is False


@pytest.mark.parametrize('destination', [None, '', 'unparsed', '192.0.2.1:not-a-port',
                                        '[::1]:not-a-port', '192.0.2.1:' + '9' * 5000],
                         ids=['missing', 'empty', 'unknown', 'bad-port', 'bad-ipv6-port', 'oversized-port'])
@pytest.mark.parametrize('with_valid', [False, True], ids=['all-lost', 'partial-loss'])
def test_macos_destination_loss_remains_visible_with_clean_tail(load, destination, with_valid):
    records = [{'syscall': 'network-outbound', 'path': destination, 'nonce': 'trusted'}]
    if with_valid:
        records.append({'syscall': 'network-outbound', 'path': '192.0.2.1:443', 'nonce': 'trusted'})
    profile = load(records)
    expected = [observe.ConnectTarget('192.0.2.1', 443, 'AF_INET')] if with_valid else []
    assert profile.connect_targets == expected
    assert profile.paths_stat == ['/tmp/retained']
    assert profile.capture_incomplete is True
    assert profile.budget_truncated is False


@pytest.mark.parametrize('destination,targets', [
    ('/tmp/owned.sock', []),
    ('192.0.2.1:443', [observe.ConnectTarget('192.0.2.1', 443, 'AF_INET')]),
    ('[::1]:443', [observe.ConnectTarget('::1', 443, 'AF_INET6')]),
], ids=['local-ipc', 'ipv4', 'ipv6'])
def test_supported_macos_destinations_remain_complete(load, destination, targets):
    profile = load([{'syscall': 'network-outbound', 'path': destination, 'nonce': 'trusted'}])
    assert profile.connect_targets == targets
    assert profile.capture_incomplete is False


@pytest.mark.parametrize('record', [
    {'syscall': 'stat', 'path': '/tmp/foreign', 'observe': 'false'},
    {'syscall': 'stat', 'path': '/tmp/foreign', 'parse_ambiguous': []},
    {'syscall': 'openat', 'path': '/tmp/foreign', 'args': []},
    {'syscall': 'network-outbound', 'path': 'unparsed'},
], ids=['observe', 'ambiguous', 'flags', 'destination'])
def test_foreign_nonce_cannot_set_metadata_loss(load, record):
    profile = load([{**record, 'nonce': 'foreign'}])
    assert profile.paths_stat == ['/tmp/retained']
    assert profile.paths_read == []
    assert profile.connect_targets == []
    assert profile.capture_incomplete is False


def test_absent_stamps_and_control_records_remain_supported(load):
    profile = load([{'syscall': 'stat', 'path': '/tmp/legacy', 'nonce': 'trusted'},
                    {'type': 'category_budget_exceeded', 'nonce': 'trusted'}])
    assert profile.paths_stat == ['/tmp/retained', '/tmp/legacy']
    assert profile.capture_incomplete is False
