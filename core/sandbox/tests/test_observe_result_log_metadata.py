"""Post-run display bounds must not alter result or denial evidence."""

import json
import logging
import os
import signal
import subprocess
import sys

import pytest

from core.sandbox import evidence, observe, summary
from core.security.log_sanitisation import escape_nonprintable
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
ROUTES = ['crash', 'resource', 'sigsys', 'terminated', 'asan', 'ubsan', 'msan', 'tsan',
          'network', 'degraded-network', 'write', 'udp', 'seccomp']
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX signal result vocabulary')


@pytest.fixture(autouse=True)
def owned_state(tmp_path, caplog):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        run = tmp_path / 'run'
        run.mkdir()
        summary.set_active_run_dir(run)
        caplog.set_level(logging.DEBUG, logger=observe.__name__)
        yield run


def call_route(route, command, *, extra=None):
    if route == 'seccomp' and sys.platform != 'linux':
        pytest.skip('stderr seccomp hints are Linux-only')
    signals = {'crash': 'SIGSEGV', 'resource': 'SIGXCPU', 'sigsys': 'SIGSYS',
               'terminated': 'SIGTERM'}
    if route in signals:
        number = getattr(signal, signals[route], None)
        if number is None:
            pytest.skip('required POSIX signal unavailable')
        result = subprocess.CompletedProcess(['owned-tool'], -number, b'', b'')
        observe.interpret_result(result, command)
        assert result.returncode == -number and result.stderr == b''
        info = result.sandbox_info
        assert info['signal_num'] == number
        assert info['signal_provenance'] == 'waitstatus'
        if route == 'crash':
            assert info['crashed'] is True
        elif route == 'resource':
            assert info['resource_exceeded'] is True
        elif route == 'sigsys':
            assert info['seccomp_killed'] is True
        else:
            assert info['crashed'] is False
        return info
    if route in {'asan', 'ubsan', 'msan', 'tsan'}:
        text = {'asan': 'ERROR: AddressSanitizer: ' + (extra or 'heap-buffer-overflow'),
                'ubsan': 'UndefinedBehaviorSanitizer', 'msan': 'MemorySanitizer',
                'tsan': 'ThreadSanitizer'}[route]
        stderr = text.encode()
        result = subprocess.CompletedProcess(['owned-tool'], 1, b'', stderr)
        observe.interpret_result(result, command)
        assert result.returncode == 1 and result.stderr is stderr
        info = result.sandbox_info
        assert info['sanitizer'] == route
        assert info['sanitizer_provenance'] == 'stderr_match'
        assert info['crashed'] is True
        return info
    info = {}
    if route in {'network', 'degraded-network'}:
        observe._check_blocked('Network is unreachable', command, 1, info,
                               network_engaged=True,
                               degraded_net_deny=route == 'degraded-network')
    elif route == 'write':
        path = extra or '/owned/outside'
        observe._check_blocked(f"cannot create '{path}': Permission denied", command,
                               1, info, landlock_engaged=True, writable_paths=[])
        assert path in info['blocked'][0]
    elif route == 'udp':
        observe._check_blocked('Could not determine a usable local IP', command,
                               1, info, udp_block_engaged=True)
    else:
        observe._check_blocked('Operation not permitted', command, 1, info,
                               seccomp_engaged=True, seccomp_profile='full')
    assert len(info['blocked']) == 1
    return info


def assert_display(caplog, route, variant):
    records = [r for r in caplog.records if r.name == observe.__name__]
    assert len(records) == 1
    rendered = logging.Formatter('%(message)s').format(records[0])
    assert all(c.isprintable() for c in rendered)
    assert len(rendered) < 1400
    assert records[0].exc_info is None
    level = (logging.WARNING if route == 'resource' else
             logging.DEBUG if route == 'terminated' else logging.INFO)
    assert records[0].levelno == level
    label = {'crash': '(crash)', 'resource': '(resource limit)', 'sigsys': 'SIGSYS',
             'terminated': 'SIGTERM', 'asan': 'ASAN', 'ubsan': 'UBSAN', 'msan': 'MSAN',
             'tsan': 'TSAN', 'network': 'network blocked', 'degraded-network': 'TCP connect',
             'write': 'write outside', 'udp': 'UDP/loopback', 'seccomp': 'Operation not permitted'}[route]
    assert label in rendered
    if variant == 'long':
        assert '...[+' in rendered
    elif variant == 'control':
        assert r'\x1b' in rendered
    else:
        assert 'owned-tool' in rendered


@pytest.mark.parametrize('route', ROUTES)
@pytest.mark.parametrize('variant', ['plain', 'control', 'long'])
def test_command_display_preserves_structured_outcomes(owned_state, caplog, route, variant):
    reference = call_route(route, 'owned-tool')
    caplog.clear()
    command = {'plain': 'owned-tool', 'control': CONTROL, 'long': 'owned-' + 'x' * 5000}[variant]
    actual = call_route(route, command)
    assert actual == reference
    if route in {'network', 'degraded-network', 'write', 'udp', 'seccomp'}:
        path = evidence.resolve_read_path(owned_state, summary.DENIALS_FILE)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        assert len(records) == 2
        stored_command = (command if len(command) <= summary.MAX_CMD_LEN else
                          command[:summary.MAX_CMD_LEN - 1] + '…')
        assert records[-1]['cmd'] == escape_nonprintable(stored_command)
        assert records[-1]['returncode'] == 1
        assert records[-1]['type'] == ('network' if route == 'degraded-network' else route)
        if variant == 'long':
            assert len(records[-1]['cmd']) > 256
            assert len(records[-1]['cmd']) == summary.MAX_CMD_LEN
        def without_display_and_time(row):
            return {k: v for k, v in row.items() if k not in {'cmd', 'ts'}}
        assert without_display_and_time(records[0]) == without_display_and_time(records[1])
    assert_display(caplog, route, variant)


@pytest.mark.parametrize('route', ['asan', 'write'])
def test_long_secondary_metadata_is_bounded_only_for_display(owned_state, caplog, route):
    value = ('owned-' if route == 'asan' else '/owned/') + 'x' * 5000
    info = call_route(route, 'owned-tool', extra=value)
    if route == 'asan':
        assert info['evidence'] == 'AddressSanitizer: ' + value
    else:
        assert info['blocked'] == [f'Attempted write to {value} (blocked by sandbox)']
        path = evidence.resolve_read_path(owned_state, summary.DENIALS_FILE)
        stored = json.loads(path.read_text())
        assert stored['path'] == value
        assert stored['cmd'] == 'owned-tool'
    assert_display(caplog, route, 'long')
