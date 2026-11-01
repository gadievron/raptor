"""Offline kit integrity, selection, and refusal before network or unsafe writes."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.codeql import offline


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    pack = root / 'packages/llm_analysis/codeql_packs/python-queries'
    pack.mkdir(parents=True)
    (pack / 'qlpack.yml').write_text('name: raptor/python-queries\nversion: 0.0.1\ndependencies:\n  codeql/python-all: "*"\n')
    (pack / 'example.ql').write_text('import python\nfrom int x select x\n')
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.delenv('RAPTOR_CODEQL_OFFLINE', raising=False)
    monkeypatch.setattr(offline, 'ROOT', root)
    cli = tmp_path / 'tool/codeql'
    cli.parent.mkdir()
    cli.write_text('fake')
    calls = []

    def download(path, name, digest, size):
        calls.append(('download',))
        path.write_bytes(b'bundle')

    def ensure(**kwargs):
        calls.append(('ensure', kwargs))
        if 'local_archive' in kwargs:
            assert Path(kwargs['local_archive']).read_bytes() == b'bundle'
        return cli

    boot = {'VERSION': '2.27.3', '_asset': lambda: ('bundle.tar.gz', hashlib.sha256(b'bundle').hexdigest(), 6),
            '_download': download, 'ensure_installed': ensure}
    monkeypatch.setattr(offline, '_bootstrap', lambda: boot)

    def run(binary, args, *, network, paths=()):
        calls.append(('command', network, list(map(str, args))))
        if args[:2] == ['pack', 'install']:
            assert network
            cache = Path(next(str(a).split('=', 1)[1] for a in args if str(a).startswith('--common-caches=')))
            dep = cache / 'packages/codeql/python-all/1.0.0'
            dep.mkdir(parents=True)
            (dep / 'qlpack.yml').write_text('name: codeql/python-all\nversion: 1.0.0\n')
            (Path(args[-1]) / offline.LOCK).write_text('dependencies:\n  codeql/python-all:\n    version: 1.0.0\n')
        elif args[:2] == ['resolve', 'packs']:
            return json.dumps({'steps': [{'scans': [{'found': {'codeql/python-all': {}, 'codeql/python-queries': {}}}]}]})
        else:
            assert not network
        return ''

    monkeypatch.setattr(offline, '_run', run)
    return root, pack, home, calls


def prepared(tmp_path):
    kit = tmp_path / 'kit'
    digest = offline.prepare(kit, ['python'], ['standard', 'iris'])
    return kit, digest


def test_prepare_import_and_offline_check(setup, tmp_path, monkeypatch):
    root, pack, home, calls = setup
    source = offline._tree(pack, source=True)
    kit, digest = prepared(tmp_path)
    assert offline._tree(pack, source=True) == source
    assert not (pack / offline.LOCK).exists(), 'prepare modified checkout'
    calls.clear()
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')
    offline.import_kit(kit, digest)
    assert (home / '.codeql/packages/codeql/python-all/1.0.0/qlpack.yml').is_file()
    assert (pack / offline.LOCK).is_file()
    assert not any(c[0] == 'download' or (c[0] == 'command' and c[1]) for c in calls)
    offline.import_kit(kit, digest)  # repeat import preserves matching cache


@pytest.mark.parametrize('change', ['manifest', 'bundle', 'query', 'lock', 'extra_file', 'symlink'])
def test_import_refuses_changed_or_unexpected_data_before_install(setup, tmp_path, change):
    _, pack, home, calls = setup
    kit, digest = prepared(tmp_path)
    if change == 'manifest':
        (kit / 'manifest.json').write_text('{}')
    elif change == 'bundle':
        (kit / 'bundle.tar.gz').write_bytes(b'broken')
    elif change == 'query':
        (pack / 'example.ql').write_text('changed')
    elif change == 'lock':
        (pack / offline.LOCK).write_text('different operator lock')
    elif change == 'extra_file':
        (kit / 'credentials.txt').write_text('must not import')
    else:
        (kit / 'outside').symlink_to(pack, target_is_directory=True)
    calls.clear()
    with pytest.raises((ValueError, OSError)):
        offline.import_kit(kit, digest)
    assert not calls and not (home / '.codeql').exists()


def test_cache_parent_symlink_cannot_redirect_import(setup, tmp_path):
    _, _, home, _ = setup
    kit, digest = prepared(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    cache = home / '.codeql'
    cache.mkdir(mode=0o700)
    (cache / 'packages').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='cache directory'):
        offline.import_kit(kit, digest)
    assert not list(outside.iterdir())
    assert not (cache / 'raptor-offline.json').exists()


def test_different_cached_version_is_not_overwritten(setup, tmp_path):
    _, _, home, _ = setup
    kit, digest = prepared(tmp_path)
    cached = home / '.codeql/packages/codeql/python-all/1.0.0'
    cached.mkdir(parents=True)
    for directory in [cached, *list(cached.parents)[:4]]:
        directory.chmod(0o700)
    (cached / 'qlpack.yml').write_text('different existing cache')
    with pytest.raises(ValueError, match='existing cached pack differs'):
        offline.import_kit(kit, digest)
    assert (cached / 'qlpack.yml').read_text() == 'different existing cache'


def test_failed_check_does_not_report_success(setup, tmp_path, monkeypatch, capsys):
    _, _, home, _ = setup
    kit, digest = prepared(tmp_path)
    monkeypatch.setattr(offline, '_check', lambda *args: (_ for _ in ()).throw(RuntimeError('missing library')))
    with pytest.raises(RuntimeError, match='missing library'):
        offline.import_kit(kit, digest)
    assert 'Imported and verified' not in capsys.readouterr().out


def test_prepare_refuses_offline_and_existing_output(setup, tmp_path, monkeypatch):
    _, _, _, calls = setup
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')
    with pytest.raises(RuntimeError, match='connected machine'):
        offline.prepare(tmp_path / 'kit', ['python'], ['standard'])
    assert not calls
    monkeypatch.delenv('RAPTOR_CODEQL_OFFLINE')
    existing = tmp_path / 'kit'
    existing.mkdir()
    with pytest.raises(ValueError, match='already exists'):
        offline.prepare(existing, ['python'], ['standard'])


def test_runtime_offline_never_installs_local_pack_dependencies(tmp_path, monkeypatch):
    from packages.codeql.query_runner import QueryRunner
    runner = QueryRunner.__new__(QueryRunner)
    runner.codeql_cli = '/fake/codeql'
    commands = []
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')

    def sandbox(cmd, **kwargs):
        commands.append(cmd)
        assert kwargs.get('block_network', True)
        return SimpleNamespace(returncode=1, stdout='', stderr='missing dependency codeql/python-all')

    monkeypatch.setattr('core.sandbox.run', sandbox)
    result = runner._run_local_pack('python', tmp_path / 'db', tmp_path / 'pack', tmp_path / 'out',
                                    suite_name='local', sarif_name='out.sarif', label='offline')
    assert not result.success
    assert len(commands) == 1 and commands[0][1:3] == ['database', 'analyze']


def test_forged_bundle_metadata_cannot_override_repository_pin(setup, tmp_path):
    _, _, home, calls = setup
    kit, _ = prepared(tmp_path)
    (kit / 'bundle.tar.gz').write_bytes(b'forged')
    metadata = json.loads((kit / 'manifest.json').read_text())
    metadata['files']['bundle.tar.gz'] = offline._record(kit / 'bundle.tar.gz')
    manifest = json.dumps(metadata).encode()
    (kit / 'manifest.json').write_bytes(manifest)
    calls.clear()
    with pytest.raises(ValueError, match='pinned archive'):
        offline.import_kit(kit, hashlib.sha256(manifest).hexdigest())
    assert not calls and not (home / '.codeql').exists()


def test_inventory_traversal_is_rejected_even_with_matching_manifest_hash(setup, tmp_path):
    _, _, home, calls = setup
    kit, _ = prepared(tmp_path)
    metadata = json.loads((kit / 'manifest.json').read_text())
    metadata['files']['../../outside'] = metadata['files']['bundle.tar.gz']
    manifest = json.dumps(metadata).encode()
    (kit / 'manifest.json').write_bytes(manifest)
    calls.clear()
    with pytest.raises(ValueError, match='unsafe offline inventory path'):
        offline.import_kit(kit, hashlib.sha256(manifest).hexdigest())
    assert not calls and not (home / '.codeql').exists()


def test_source_change_during_import_is_not_overwritten(setup, tmp_path, monkeypatch):
    _, pack, _, _ = setup
    kit, digest = prepared(tmp_path)
    boot = offline._bootstrap()
    ensure = boot['ensure_installed']

    def change_source(**kwargs):
        (pack / 'example.ql').write_text('operator changed source during import')
        return ensure(**kwargs)

    boot['ensure_installed'] = change_source
    with pytest.raises(ValueError, match='sources changed during import'):
        offline.import_kit(kit, digest)
    assert not (pack / offline.LOCK).exists()


def test_hypothesis_adapter_does_not_fetch_pack_dependencies_offline(tmp_path, monkeypatch):
    from packages.hypothesis_validation.adapters.codeql import _ensure_pack_installed
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')
    (tmp_path / 'qlpack.yml').write_text('name: example/test\n')
    query = tmp_path / 'query.ql'
    query.write_text('select 1')
    _ensure_pack_installed(query, '/fake/codeql', lambda *a, **k: pytest.fail('unexpected pack install'), {})


def test_standard_suite_does_not_retry_downloads_offline(tmp_path, monkeypatch):
    from packages.codeql.query_runner import QueryRunner
    runner = QueryRunner.__new__(QueryRunner)
    runner.codeql_cli = '/fake/codeql'
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')
    monkeypatch.delenv('CODEQL_QUERIES', raising=False)
    monkeypatch.setattr(runner, '_threat_model_args', lambda: [])
    monkeypatch.setattr(runner, '_model_pack_args', lambda *args: [])
    calls = []

    def sandbox(cmd, **kwargs):
        calls.append(cmd)
        assert kwargs.get('block_network', True)
        return SimpleNamespace(returncode=1, stdout='', stderr='Query pack codeql/python-queries cannot be found.')

    monkeypatch.setattr('core.sandbox.run', sandbox)
    result = runner.run_suite(tmp_path / 'db', 'python', tmp_path / 'out')
    assert not result.success
    assert not any('download' in cmd for cmd in calls)
    assert any('Offline CodeQL' in err for err in result.errors)


def test_offline_preferences_and_imported_cli_survive_child_environment(monkeypatch):
    from core.config import RaptorConfig
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')
    monkeypatch.setenv('CODEQL_CLI', '/operator/cache/codeql/codeql')
    for build in (RaptorConfig.get_safe_env, RaptorConfig.get_llm_env):
        env = build()
        assert env['RAPTOR_CODEQL_OFFLINE'] == '1'
        assert env['CODEQL_CLI'] == '/operator/cache/codeql/codeql'


def test_network_denied_checks_keep_compiler_cache_writable(tmp_path, monkeypatch):
    cache = tmp_path / 'cache'
    pack = tmp_path / 'queries'
    seen = {}

    def sandbox(cmd, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(returncode=0, stdout='ok', stderr='')

    monkeypatch.setattr('core.sandbox.run', sandbox)
    assert offline._run(tmp_path / 'codeql/codeql', ['resolve', 'packs', f'--common-caches={cache}'],
                        network=False, paths=[cache, pack]) == 'ok'
    assert seen['block_network'] and seen['output'] == str(cache)
    assert str(cache) not in seen['tool_paths']
    assert str(pack) in seen['tool_paths']


def test_import_prints_working_bare_host_exports(setup, tmp_path, capsys):
    import os
    import subprocess
    _, _, _, _ = setup
    kit, digest = prepared(tmp_path)
    cli = offline._bootstrap()['ensure_installed'](install=False)
    cli.chmod(0o755)
    capsys.readouterr()
    offline.import_kit(kit, digest)
    exports = [line for line in capsys.readouterr().out.splitlines() if line.startswith('export ')]
    assert len(exports) == 3
    result = subprocess.run(['/bin/sh', '-c', '\n'.join(exports) + '\ncommand -v codeql'],
                            capture_output=True, text=True, check=True, env={**os.environ, 'PATH': '/usr/bin:/bin'})
    assert result.stdout.strip() == str(cli)


@pytest.mark.parametrize('offline_mode,failed_extra,failed_db,expected', [
    (False, True, False, True),
    (True, True, False, False),
    (True, False, True, False),
    (True, False, False, True),
])
def test_offline_workflow_rejects_partial_coverage(monkeypatch, offline_mode, failed_extra, failed_db, expected):
    from packages.codeql.agent import _workflow_success
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1' if offline_mode else '0')
    assert _workflow_success({'python': SimpleNamespace(success=True)},
                              additional_results=({'python': SimpleNamespace(success=not failed_extra)},),
                              database_results={'python': SimpleNamespace(success=not failed_db)}) is expected


def test_agent_reports_missing_iris_coverage_as_offline_failure(tmp_path, monkeypatch):
    import time
    from unittest.mock import MagicMock
    from packages.codeql.agent import CodeQLAgent
    agent = CodeQLAgent.__new__(CodeQLAgent)
    agent.repo_path = tmp_path / 'repo'
    agent.repo_path.mkdir()
    agent.out_dir = tmp_path / 'out'
    agent.out_dir.mkdir()
    agent.start_time = time.time()
    agent.language_detector = MagicMock()
    agent.build_detector = MagicMock()
    agent.database_manager = MagicMock()
    agent.query_runner = MagicMock()
    agent.database_manager.create_databases_parallel.return_value = {
        'python': SimpleNamespace(success=True, database_path=tmp_path / 'db', errors=[], cached=False)}
    agent.query_runner.analyze_all_databases.return_value = {
        'python': SimpleNamespace(success=True, sarif_path=agent.out_dir / 'standard.sarif', findings_count=0)}
    agent.query_runner.analyze_iris_packs.return_value = {
        'python': SimpleNamespace(success=False, sarif_path=None, errors=['missing codeql/python-all'])}
    agent.query_runner.analyze_curated_packs.return_value = {}
    for name in ('_run_source_summaries_pass', '_run_taint_pack_models_pass', '_run_learned_models_pass'):
        monkeypatch.setattr(agent, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(agent, '_save_report', lambda *args: None)
    monkeypatch.setattr('core.sage.hooks.recall_context_for_codeql_build', lambda *args, **kwargs: [])
    monkeypatch.setenv('RAPTOR_CODEQL_OFFLINE', '1')
    result = agent.run_autonomous_analysis(languages=['python'])
    assert result.success is False
    assert any('Offline IRIS analysis failed for python' in error for error in result.errors)
    assert 'missing codeql/python-all' in result.errors


def test_operator_entry_point_works_outside_checkout_without_ambient_root(tmp_path):
    import os
    import subprocess
    import sys
    entry = Path(__file__).resolve().parents[3] / 'engine/codeql/tools/offline.py'
    env = {k: v for k, v in os.environ.items() if k != 'RAPTOR_DIR'}
    result = subprocess.run([sys.executable, str(entry), '--help'], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=15, check=True)
    assert 'prepare' in result.stdout and 'import' in result.stdout and 'check' in result.stdout
