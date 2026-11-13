"""Known observation loss must not become a reusable calibration cache."""
import itertools
import subprocess
import tempfile

import pytest

from core import sandbox
from core.sandbox import calibrate as cal, observe_profile as observe, proxy
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize('quality', ['clean', 'untrusted', 'capture-loss', 'budget-loss',
                                     'proxy-loss', 'proxy-reserve'])
def test_observation_quality_controls_cache_publication(tmp_path, monkeypatch, quality):
    binary = tmp_path / 'tool'
    binary.write_bytes(b'owned binary; never executed')
    cache = tmp_path / 'cache'
    monkeypatch.setattr(cal, '_CACHE_DIR', cache)
    temporary = tempfile.TemporaryDirectory
    patch_module_attribute(monkeypatch, cal, 'tempfile', 'TemporaryDirectory',
                           lambda **kwargs: temporary(dir=tmp_path, **kwargs))
    observed = observe.ObserveProfile(
        paths_read=['/opt/owned/runtime'], nonce_trusted=quality != 'untrusted',
        capture_incomplete=quality == 'capture-loss', budget_truncated=quality == 'budget-loss',
    )
    events = []
    if quality.startswith('proxy-'):
        # Exercise the actual bounded-buffer producer without constructing
        # a proxy, starting its thread, or opening any sockets.
        monkeypatch.setattr(proxy, '_SANDBOX_BUFFER_MAX_EVENTS', 1)
        producer = object.__new__(proxy.EgressProxy)
        producer._sandbox_buffer_overflow = {}
        producer._event_seq = itertools.count()
        producer._stats_events = {'buffer_overflow': 0}
        events.append({'host': 'kept.example', 'result': 'allowed'})
        result_kind = 'allowed' if quality == 'proxy-loss' else 'denied_host'
        producer._append_bounded_locked(
            1, events, {'host': 'later.example', 'result': result_kind})
        marker = next(e for e in events if e['result'] == 'buffer_overflow')
        assert marker['dropped'] == (1 if quality == 'proxy-loss' else 0)
    runs, parses = [], []

    def run(command, **kwargs):
        runs.append(command)
        assert command == [str(binary), '--version']
        assert kwargs['observe'] and kwargs['target'] == kwargs['output']
        assert kwargs['timeout'] == 1
        result = subprocess.CompletedProcess(command, 0, '', '')
        result.sandbox_info = {'observe_nonce': 'owned-nonce', 'proxy_events': events}
        return result

    def parse(directory, **kwargs):
        parses.append(directory)
        assert kwargs['expected_nonce'] == 'owned-nonce' and kwargs['current_run']
        return observed

    original_run, original_parse = sandbox.run, observe.parse_observe_log
    with scoped_function_imports(cal, ('_spawn_probe',), {
            'core.sandbox': sandbox, 'core.sandbox.observe_profile': observe}) as imports:
        getattr(imports, 'core.sandbox').run = run
        getattr(imports, 'core.sandbox.observe_profile').parse_observe_log = parse
        error = None
        try:
            result = cal.calibrate_binary(binary, timeout=1)
        except RuntimeError as exc:
            error = exc
    assert sandbox.run is original_run and observe.parse_observe_log is original_parse
    assert len(runs) == len(parses) == 1
    files = list(cache.glob('*.json'))
    if quality in {'clean', 'proxy-reserve'}:
        assert error is None and len(files) == 1
        assert result.paths_read == observed.paths_read
        assert result.proxy_hosts == (['kept.example', 'later.example']
                                      if quality == 'proxy-reserve' else [])
        assert cal.SandboxProfile.from_json(files[0].read_text()).paths_read == observed.paths_read
        loaded = cal._load_matching_cache(result.binary_sha256, result.env_signature, result.probe_args)
        assert loaded is not None and loaded.cache_version == cal._CACHE_VERSION
    else:
        assert files == [], 'unqualified observation was persisted as a reusable profile'
        assert isinstance(error, RuntimeError) and 'observation' in str(error)


@pytest.mark.parametrize('version', [1, 2])
def test_pre_quality_cache_is_a_miss(tmp_path, monkeypatch, version):
    monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path / 'cache')
    profile = cal.SandboxProfile(
        binary_path='/owned/tool', binary_sha256='1' * 64,
        env_signature='2' * 64, captured_at='2026-01-01T00:00:00Z',
        probe_args=['--version'], paths_read=['/opt/runtime'], cache_version=version,
    )
    fingerprint = cal._fingerprint(profile.binary_sha256, profile.env_signature, profile.probe_args)
    cal._save_to_cache(fingerprint, profile)
    assert list((tmp_path / 'cache').glob('*.json'))
    assert cal._load_matching_cache(profile.binary_sha256, profile.env_signature,
                                    profile.probe_args) is None


def test_missing_version_remains_legacy(tmp_path, monkeypatch):
    import json

    profile = cal.SandboxProfile(
        binary_path='/owned/tool', binary_sha256='1' * 64,
        env_signature='2' * 64, captured_at='2026-01-01T00:00:00Z',
    )
    raw = json.loads(profile.to_json())
    del raw['cache_version']
    assert cal.SandboxProfile.from_json(json.dumps(raw)).cache_version == 1
    monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path)
    fingerprint = cal._fingerprint(profile.binary_sha256, profile.env_signature, profile.probe_args)
    cal._cache_path_for(fingerprint).write_text(json.dumps(raw))
    assert cal._load_matching_cache(profile.binary_sha256, profile.env_signature,
                                    profile.probe_args) is None
