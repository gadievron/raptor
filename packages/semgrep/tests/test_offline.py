"""Offline registry resolution must preserve requested coverage without egress."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from core.config import RaptorConfig
from packages.semgrep import runner


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_SEMGREP_OFFLINE', '1')
    monkeypatch.setattr(RaptorConfig, 'SEMGREP_REGISTRY_CACHE_DIR', tmp_path)
    return tmp_path


def test_missing_pack_refused_before_probe_or_invocation(cache, monkeypatch):
    probe = Mock(side_effect=AssertionError('must not probe'))
    monkeypatch.setattr(runner, 'is_available', probe)
    result = runner.run_rule(cache, 'p/security-audit')
    assert result.returncode == -1
    assert 'unavailable' in result.errors[0]
    probe.assert_not_called()


def test_cached_pack_used_in_argv_and_network_policy(cache, monkeypatch):
    path = cache / 'c.p.security-audit.json'
    path.write_text(json.dumps({'rules': [{'id': 'test'}]}))
    cmd = runner.build_cmd(cache, 'p/security-audit')
    assert cmd[cmd.index('--config') + 1] == str(path)
    assert '--strict' in cmd
    from core.sandbox import context
    run = Mock(return_value=(0, '', ''))
    monkeypatch.setattr(context, 'run', run)
    sandbox = runner._default_sandbox_runner(cache, str(path))
    sandbox(cmd)
    assert run.call_args.kwargs['block_network'] is True
    assert 'use_egress_proxy' not in run.call_args.kwargs


@pytest.mark.parametrize('data', ['{}', '{"rules": []}', '{"rules": null}', 'bad JSON'])
def test_invalid_cache_refused(cache, data):
    (cache / 'c.p.secrets.json').write_text(data)
    with pytest.raises(ValueError, match='invalid'):
        RaptorConfig.get_semgrep_config('p/secrets')


def test_symlink_cache_refused(cache):
    dest = cache / 'other.json'
    dest.write_text('{"rules":[{"id":"r"}]}')
    (cache / 'c.p.secrets.json').symlink_to(dest)
    with pytest.raises(ValueError, match='invalid'):
        RaptorConfig.get_semgrep_config('p/secrets')


@pytest.mark.parametrize('config', ['auto', 'https://semgrep.dev/p/secrets', 'r/user.rule', 'p/../../other'])
def test_remote_or_invalid_config_refused(cache, config):
    with pytest.raises(ValueError):
        runner.build_cmd(cache, config)


def test_offline_survives_safe_environment(cache):
    assert RaptorConfig.get_safe_env()['RAPTOR_SEMGREP_OFFLINE'] == '1'


def test_scanner_never_probes_or_drops_missing_packs(cache, monkeypatch):
    source = Path(__file__).resolve().parents[2] / 'static-analysis/scanner.py'
    spec = importlib.util.spec_from_file_location('semgrep_offline_scanner', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import socket
    probe = Mock(side_effect=AssertionError('must not probe'))
    monkeypatch.setattr(socket, 'create_connection', probe)
    with pytest.raises(ValueError, match='unavailable'):
        module._drop_unreachable_registry_packs([('baseline', 'p/security-audit')])
    probe.assert_not_called()


@pytest.mark.parametrize('args', [['--config', 'p/secrets'], ['--config=p/secrets'],
                                  ['--metrics=on'], ['--enable-version-check'], ['--pro']])
def test_offline_extra_arguments_cannot_enable_network(cache, args):
    rules = cache / 'local.yaml'
    rules.write_text('rules: []')
    with pytest.raises(ValueError, match='overrides'):
        runner.build_cmd(cache, str(rules), extra_args=args)
