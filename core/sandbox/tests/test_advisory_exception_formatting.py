"""Advisory fallback and cleanup survive exceptions with broken messages."""
import json
import logging
import threading

import pytest

from core.sandbox import calibrate, calibrated_hosts, egress_summary, host, proxy
from core.sandbox.errors import SandboxSetupError


@pytest.fixture
def owned(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(calibrated_hosts, '_CACHE', {})
    monkeypatch.setattr(calibrated_hosts, '_CACHE_LOCK', threading.Lock())
    caplog.set_level(logging.DEBUG)
    binary = tmp_path / 'tool'
    binary.write_bytes(b'owned calibration input; never executed')
    output = tmp_path / 'output'
    output.mkdir()
    return binary, output


def _invoke(route, problem, owned, monkeypatch):
    binary, output = owned
    attempts = []

    def fail(*args, **kwargs):
        attempts.append(True)
        raise problem

    if route.startswith('calibration'):
        monkeypatch.setattr(calibrate, 'load_or_calibrate', fail)
        assert calibrated_hosts.calibrated_profile(str(binary), ()) is None
        entry = next(iter(calibrated_hosts._CACHE.values()))
        assert entry.ready.is_set() and entry.result is None
        assert calibrated_hosts.calibrated_profile(str(binary), ()) is None
        assert attempts == [True]
    elif route == 'egress':
        previous = output / egress_summary.EGRESS_SUMMARY_FILE
        previous.write_bytes(b'previous summary')
        original = egress_summary.summarise_egress
        monkeypatch.setattr(egress_summary, 'summarise_egress', fail)
        assert egress_summary.finalize_egress_summary(output) is None
        assert previous.read_bytes() == b'previous summary'
        monkeypatch.setattr(egress_summary, 'summarise_egress', original)
        event = {'host': 'example.test', 'port': 443, 'result': 'allowed'}
        (output / proxy.PROXY_EVENTS_FILENAME).write_text(json.dumps(event) + '\n')
        result = egress_summary.finalize_egress_summary(output)
        assert result['allowed'] == result['total_connections'] == 1
        assert json.loads(previous.read_text()) == result
    else:
        marker = output / 'keep'
        marker.write_bytes(b'owned output')
        owner = object.__new__(host.SandboxHost)
        owner._daemon_fds_lock = threading.Lock()
        owner._owned_output = str(output)
        original = host.rmtree_hardened
        monkeypatch.setattr(host, 'rmtree_hardened', fail)
        owner._cleanup_owned_output()
        assert owner._owned_output == str(output)
        assert marker.read_bytes() == b'owned output'
        monkeypatch.setattr(host, 'rmtree_hardened', original)
        owner._cleanup_owned_output()
        assert owner._owned_output is None and not output.exists()
    assert attempts == [True]


@pytest.mark.parametrize('route', ['calibration-failed', 'calibration-refused', 'egress', 'host-cleanup'])
@pytest.mark.parametrize('kind', ['runtime', 'value', 'type', 'nonstring'])
def test_broken_messages_keep_advisory_and_cleanup_results(owned, monkeypatch, caplog, route, kind):
    calls = []
    parent = SandboxSetupError if route == 'calibration-refused' else OSError

    class Broken(parent):
        def __str__(self):
            calls.append('str')
            if kind == 'nonstring':
                return None
            raise {'runtime': RuntimeError, 'value': ValueError, 'type': TypeError}[kind]('owned formatting failure')

        def __repr__(self):
            calls.append('repr')
            raise AssertionError('repr must not be used')

    _invoke(route, Broken('owned failure'), owned, monkeypatch)
    assert calls == ['str']
    names = {calibrated_hosts.logger.name, egress_summary.log.name, host.log.name}
    records = [record for record in caplog.records if record.name in names]
    assert any('exception message unavailable' in record.getMessage() for record in records)
    assert all(record.exc_info is None for record in records)


@pytest.mark.parametrize('route', ['calibration-failed', 'calibration-refused', 'egress', 'host-cleanup'])
@pytest.mark.parametrize('cancellation', [KeyboardInterrupt('cancel'), SystemExit(17)], ids=['interrupt', 'exit'])
def test_cancellation_from_message_conversion_keeps_identity(owned, monkeypatch, route, cancellation):
    parent = SandboxSetupError if route == 'calibration-refused' else OSError

    class Interrupted(parent):
        def __str__(self):
            raise cancellation

    binary, output = owned
    problem = Interrupted('owned failure')
    def fail(*args, **kwargs):
        raise problem
    if route.startswith('calibration'):
        monkeypatch.setattr(calibrate, 'load_or_calibrate', fail)
        invoke = lambda: calibrated_hosts.calibrated_profile(str(binary), ())
    elif route == 'egress':
        monkeypatch.setattr(egress_summary, 'summarise_egress', fail)
        invoke = lambda: egress_summary.finalize_egress_summary(output)
    else:
        monkeypatch.setattr(host, 'rmtree_hardened', fail)
        invoke = lambda: host._remove_owned_output(str(output))
    with pytest.raises(type(cancellation)) as caught:
        invoke()
    assert caught.value is cancellation
    if route.startswith('calibration'):
        entry = next(iter(calibrated_hosts._CACHE.values()))
        assert entry.ready.is_set() and entry.result is None
    assert output.exists()
