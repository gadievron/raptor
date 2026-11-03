"""Data-only SMT transport and fail-closed sandbox policy."""
import json
from pathlib import Path
import subprocess

import pytest

from core.audit import subproc_json as broker
from core.audit._json_protocol import MAX_REPLY_BYTES, MAX_REQUEST_BYTES, decode, encode

ENTRY = 'core.audit.condition_smt:_z3_dispatch_json'


@pytest.mark.parametrize('payload', [b'[]' * 2, b'\xff', b'{"x":1,"x":2}',
                                     b'NaN', b'1e999', b'[' * 10000 + b']' * 10000],
                         ids=['multiple-json-values', 'invalid-utf8', 'duplicate-keys',
                              'nan', 'numeric-overflow', 'excessive-nesting'])
def test_hostile_json_refused(payload):
    with pytest.raises((ValueError, RecursionError, UnicodeError)):
        decode(payload, MAX_REPLY_BYTES)


@pytest.mark.parametrize('value', [object(), float('inf'), {'x': object()}, {1: 'x'}, [[[[object()]]]]])
def test_nondata_requests_refused(value):
    with pytest.raises(ValueError):
        encode(value, MAX_REQUEST_BYTES)


def test_byte_and_depth_budgets():
    with pytest.raises(ValueError):
        decode(b'{}' + b' ' * MAX_REPLY_BYTES, MAX_REPLY_BYTES)
    with pytest.raises(ValueError):
        encode('x' * MAX_REQUEST_BYTES, MAX_REQUEST_BYTES)
    value = []
    for _ in range(34):
        value = [value]
    with pytest.raises(ValueError):
        encode(value, MAX_REQUEST_BYTES)


@pytest.mark.parametrize('mode', ['ok', 'nonzero', 'timeout', 'bad', 'floor'])
def test_policy_cleanup_and_no_bare_fallback(tmp_path, monkeypatch, mode):
    from core.config import RaptorConfig
    from core.sandbox import SandboxFloorError
    from core.sandbox.tiers import ContainmentTier
    from core.sandbox import context
    monkeypatch.setattr(context, 'untrusted_fresh_procfs_required', lambda: True)
    seen = []
    def run(command, **options):
        seen.append(options)
        assert command[0] == '/usr/bin/env' and '-I' in command and '-B' in command
        assert broker._CHILD_SCRIPT_PATH in command
        assert options['target'] == options['output'] == options['cwd']
        assert options['readable_paths'] == []
        assert options['require_fresh_procfs'] and options['_untrusted_workload']
        assert options['restrict_reads'] and options['block_network'] and options['fake_home']
        assert options['strip_trust_markers'] and options['strict_env'] and options['exclude_tmp_baseline']
        assert options['limits']['memory_mb'] == 2048
        assert options['capture_output'] is False
        assert options['limits']['max_file_mb'] == 16
        assert options['stdout'].fileno() != options['stderr'].fileno()
        assert options['start_new_session']
        for key in ('AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'PYTHONPATH', '_RAPTOR_TRUSTED', 'RAPTOR_DIR', 'BOGUS_SECRET'):
            assert key not in options['env']
        assert json.loads(options['input']) == {'target_path': str(tmp_path)}
        if mode == 'floor':
            raise SandboxFloorError('owned refusal', achievable=ContainmentTier.BARE, floor=ContainmentTier.MOUNT_NS)
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(command, 10)
        options['stdout'].write(b'bad' if mode == 'bad' else b'{"owned":true}')
        return subprocess.CompletedProcess(command, int(mode == 'nonzero'))
    monkeypatch.setattr(broker, '_sandbox_run', run)
    env = dict(RaptorConfig.get_safe_env(), AWS_SECRET_ACCESS_KEY='owned', OPENAI_API_KEY='owned',
               PYTHONPATH=str(tmp_path), _RAPTOR_TRUSTED='1', RAPTOR_DIR=str(tmp_path), BOGUS_SECRET='owned')
    if mode == 'floor':
        with pytest.raises(SandboxFloorError):
            broker.run_json_child(ENTRY, {'target_path': str(tmp_path)}, env=env)
    else:
        result = broker.run_json_child(ENTRY, {'target_path': str(tmp_path)}, env=env)
        assert result == ({'owned': True} if mode == 'ok' else None)
    assert len(seen) == 1 and not Path(seen[0]['output']).exists()


def test_parent_rejects_entry_and_request_before_spawn(monkeypatch):
    monkeypatch.setattr(broker, '_sandbox_run', lambda *a, **k: pytest.fail('spawned rejected request'))
    assert broker.run_json_child('time:sleep', {}, env={}) is None
    assert broker.run_json_child(ENTRY, 'x' * MAX_REQUEST_BYTES, env={}) is None


def test_vocabulary_transfers_without_target_read_authority(tmp_path, monkeypatch):
    from core.audit import sweep
    from core.audit.condition_smt import DomainVocabulary
    monkeypatch.setattr(sweep, '_verb_vocab', lambda target: DomainVocabulary(lock_pairs=frozenset({('get_owned', 'put_owned')})))
    def run(entry, request, **options):
        assert request['target_path'] is None
        assert request['vocabulary']['lock_pairs'] == [('get_owned', 'put_owned')]
        from core.audit import condition_smt
        def inner(**kwargs):
            assert kwargs['target_path'] is None
            assert kwargs['vocab'].lock_pairs == frozenset({('get_owned', 'put_owned')})
            return sweep.SweepResult(tool='smt', file_path='f.c', function_name='f', outcome='inconclusive')
        monkeypatch.setattr(sweep, '_run_smt_verb_inner', inner)
        monkeypatch.setattr(condition_smt.DomainVocabulary, 'from_domain_model', lambda *a, **k: pytest.fail('child read target'))
        return sweep._run_smt_verb_inner_json(json.loads(json.dumps(request)))
    monkeypatch.setattr(broker, 'run_json_child', run)
    result = sweep._smt_verb_in_subprocess(file_path='f.c', function_name='f', verb='check-null-deref', source='int x;', hypothesis='owned', target_path=str(tmp_path))
    assert result.outcome == 'inconclusive'


def test_user_site_hooks_never_run_in_parent(tmp_path, monkeypatch):
    packages = tmp_path / 'installed-packages'
    packages.mkdir()
    marker = tmp_path / 'parent-hook-ran'
    (packages / 'owned.pth').write_text('import pathlib; pathlib.Path(' + repr(str(marker)) + ').write_text("owned")\n')
    monkeypatch.setattr(broker.site, 'getusersitepackages', lambda: str(packages))
    def run(command, **options):
        assert str(packages) in command and str(packages) in options['tool_paths']
        options['stdout'].write(b'{"owned":true}')
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(broker, '_sandbox_run', run)
    assert broker.run_json_child(ENTRY, {}, env={}) == {'owned': True}
    assert not marker.exists()
