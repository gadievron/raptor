"""Native solver results and hostile-worker boundaries with owned fixtures."""
import socket
import sys
import time

import pytest

from core.audit import subproc_json as broker
from core.audit.condition_smt import _z3_child_env

ENTRY = 'core.audit.condition_smt:_z3_dispatch_json'
pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.linux_native, pytest.mark.darwin_native]


@pytest.fixture(autouse=True)
def native_delivery(monkeypatch):
    if sys.platform == 'linux':
        from core.sandbox.probes import check_mount_available, check_net_available
        if not check_mount_available() or not check_net_available():
            pytest.skip('native mount and PID/network namespaces required')
    elif sys.platform == 'darwin':
        from core.sandbox.probes import check_seatbelt_available
        if not check_seatbelt_available():
            pytest.skip('Seatbelt required')
    else:
        pytest.skip('Linux or macOS required')
    pytest.importorskip('z3')
    original = broker._sandbox_run
    def observe(command, **options):
        assert options['require_fresh_procfs'] is True
        result = original(command, **options)
        tier = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
        assert result.sandbox_info['containment_tier'] == tier, result.sandbox_info
        return result
    monkeypatch.setattr(broker, '_sandbox_run', observe)


@pytest.mark.parametrize('tag,args', [
    ('path_feasibility', {'constraints': [dict(variable='x', operator='<', bound_value=10, source_text='x < 10'), dict(variable='x', operator='>', bound_value=20, source_text='x > 20')]}),
    ('signed_mismatch', dict(variable='n', operator='<', bound=100, bit_width=32)),
    ('guard_sufficiency', {'constraints': [dict(variable='len', operator='<', bound_value=4096, source_text='len < 4096')], 'buffer_size': 256, 'sink_api': 'memcpy'}),
])
def test_native_solver_round_trip(tag, args):
    result = broker.run_json_child(ENTRY, {'tag': tag, 'args': args}, env=_z3_child_env(), timeout=20)
    assert result is not None
    if tag == 'path_feasibility':
        assert result[0] is False and result[2] is None
    elif tag == 'signed_mismatch':
        assert result['mismatch'] is True and result['witness']
    else:
        assert result[0] is True and isinstance(result[2], dict)


def test_native_sweep_keeps_kernel_vocabulary_without_read_grant(tmp_path):
    from core.audit.sweep import _smt_verb_in_subprocess
    kernel = tmp_path / 'kernel'
    kernel.mkdir()
    (kernel / 'Kbuild').write_text('obj-m += owned.o\n')
    result = _smt_verb_in_subprocess(file_path='owned.c', function_name='f', verb='check-lock-discipline',
        source='int f(void *sk, int val) {\nlock_sock(sk);\nif (val < 0)\nreturn -1;\nrelease_sock(sk);\nreturn 0;\n}',
        hypothesis='early return leaves socket locked', target_path=str(kernel), timeout=20)
    assert result.outcome == 'confirmed', result


def _replacement(tmp_path, monkeypatch, program):
    worker = tmp_path / 'owned-worker.py'
    worker.write_text(program)
    monkeypatch.setattr(broker, '_CHILD_SCRIPT_PATH', str(worker))


def test_native_worker_has_no_host_or_network_authority(tmp_path, monkeypatch):
    secret = tmp_path / 'secret'
    secret.write_text('owned secret')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        _replacement(tmp_path, monkeypatch, '''import os, pathlib, resource, socket, stat, sys
assert stat.S_ISREG(os.fstat(1).st_mode) and stat.S_ISREG(os.fstat(2).st_mode)
assert 0 <= resource.getrlimit(resource.RLIMIT_FSIZE)[1] <= 16 * 1024 * 1024
for name in (''' + repr(str(secret)) + ', ' + repr(str(secret.parent / 'outside-write')) + '''):
    try: pathlib.Path(name).write_text('changed')
    except OSError: pass
    else: raise AssertionError('outside write allowed')
try: pathlib.Path(''' + repr(str(secret)) + ''').read_text()
except OSError: pass
else: raise AssertionError('outside read allowed')
try:
    connection = socket.create_connection(('127.0.0.1', ''' + str(port) + '''), timeout=1)
except OSError: pass
else:
    connection.close()
    raise AssertionError('host network reachable')
for key in ('AWS_SECRET_ACCESS_KEY','OPENAI_API_KEY','PYTHONPATH','BOGUS_SECRET','_RAPTOR_TRUSTED','RAPTOR_INSTALL_PROTECTED','RAPTOR_DIR'):
    assert key not in os.environ, key
assert os.environ['HOME'] == os.getcwd() + '/.home'
assert os.environ['TMPDIR'] == os.getcwd()
pathlib.Path('owned-output').write_text('owned')
sys.stdout.write('{"owned":true}')
''')
        env = dict(_z3_child_env(), AWS_SECRET_ACCESS_KEY='owned', OPENAI_API_KEY='owned', BOGUS_SECRET='owned')
        result = broker.run_json_child(ENTRY, {'target_path': str(secret.parent)}, env=env)
    assert result == {'owned': True}
    assert secret.read_text() == 'owned secret' and not (secret.parent / 'outside-write').exists()


def test_native_timeout_returns_no_verdict(tmp_path, monkeypatch):
    _replacement(tmp_path, monkeypatch, 'import time\ntime.sleep(60)\n')
    started = time.monotonic()
    assert broker.run_json_child(ENTRY, {}, env=_z3_child_env(), timeout=2) is None
    assert time.monotonic() - started < 12


def test_native_memory_limit(tmp_path, monkeypatch):
    if sys.platform != 'linux':
        pytest.skip('macOS RLIMIT_AS is best effort')
    _replacement(tmp_path, monkeypatch, '''import resource, sys
assert 0 <= resource.getrlimit(resource.RLIMIT_AS)[1] <= 2048 * 1024 * 1024
assert 0 <= resource.getrlimit(resource.RLIMIT_CPU)[0] <= 10
try: data = bytearray(3 * 1024 * 1024 * 1024)
except MemoryError: sys.stdout.write('{"owned":true}')
else: raise AssertionError('memory cap missing')
''')
    assert broker.run_json_child(ENTRY, {}, env=_z3_child_env()) == {'owned': True}


def test_native_oversized_valid_prefix_cannot_be_accepted(tmp_path, monkeypatch):
    _replacement(tmp_path, monkeypatch, 'import sys\nsys.stdout.write(\'{"owned":true}\' + " " * (2 * 1024 * 1024))\n')
    assert broker.run_json_child(ENTRY, {}, env=_z3_child_env()) is None
