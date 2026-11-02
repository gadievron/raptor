"""Every query-analysis path must confine writes and scope reads."""
import json
from pathlib import Path
import subprocess

import pytest

from core.config import RaptorConfig
from packages.codeql.query_runner import QueryRunner


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path/'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.delenv('CODEQL_QUERIES', raising=False)
    monkeypatch.setattr(RaptorConfig, 'CODEQL_OFFLINE', False)
    runner = QueryRunner.__new__(QueryRunner)
    runner.codeql_cli = '/usr/bin/true'
    runner._version_probe = '2.23.8'
    runner._threat_model_gate = True
    runner.additional_model_packs = None
    database, output, pack = (tmp_path/name for name in ('db', 'out', 'pack'))
    for folder in (database, output, pack):
        folder.mkdir()
    (pack/'qlpack.yml').write_text('name: test/query\nversion: 0.0.1\n')
    (pack/'query.ql').write_text('select 1\n')
    return runner, home, database, output, pack


@pytest.mark.parametrize('relative', [False, True])
@pytest.mark.parametrize('consumer', ['standard', 'retry', 'custom', 'local', 'install'])
def test_real_consumers_declare_filesystem_scope(setup, monkeypatch, consumer, relative):
    import core.sandbox
    import packages.codeql.query_runner as module
    import packages.codeql.codeql_proxy_hosts as hosts
    runner, home, db, out, pack = setup
    calls = []
    monkeypatch.setattr(hosts, 'proxy_hosts_for_codeql', lambda *args: ['ghcr.io'])
    monkeypatch.setattr(module, '_iris_pack_deps_already_resolved', lambda *args: False)
    def dispatch(cmd, **kwargs):
        calls.append((list(cmd), kwargs))
        if consumer == 'retry' and len(calls) == 1:
            return subprocess.CompletedProcess(cmd, 1, '', 'Query pack codeql/cpp-queries cannot be found')
        for arg in cmd:
            if str(arg).startswith('--output='):
                Path(str(arg).split('=', 1)[1]).write_text(json.dumps({'version':'2.1.0', 'runs':[{'results':[]}]}))
        return subprocess.CompletedProcess(cmd, 0, '', '')
    monkeypatch.setattr(core.sandbox, 'run', dispatch)
    expected_db, expected_out, expected_pack = db, out, pack
    if relative:
        monkeypatch.chdir(out.parent)
        db, out, pack = map(lambda p: Path(p.name), (db, out, pack))
    if consumer in ('standard', 'retry'):
        result = runner.run_suite(db, 'cpp', out)
    elif consumer == 'custom':
        result = runner.run_custom_queries(db, pack/'query.ql', out, 'cpp')
    else:
        result = runner._run_local_pack('cpp', db, pack, out, suite_name='test',
            sarif_name='local.sarif', label='fixture', skip_install=consumer != 'install')
    db, out, pack = expected_db, expected_out, expected_pack
    assert result.success, result.errors
    assert len(calls) == (3 if consumer == 'retry' else 2 if consumer == 'install' else 1)
    for cmd, kwargs in calls:
        assert kwargs['restrict_reads'] is True
        assert kwargs['output'] in (str(out), str(home/'.codeql'))
        assert kwargs.get('target') in (None, str(home/'.codeql'))
        assert str(home) not in kwargs.get('writable_paths', [])
        assert str(home) not in (kwargs.get('readable_paths') or [])
        if 'analyze' in cmd:
            assert kwargs['block_network'] is True
            assert str(db) in kwargs['writable_paths']
            assert str(home/'.codeql') in kwargs['writable_paths']
        elif 'download' in cmd:
            assert kwargs['require_proxy_netns'] is True
            assert kwargs['use_egress_proxy'] is True
        elif 'install' in cmd:
            assert kwargs['use_egress_proxy'] is True
            assert str(pack) in kwargs['writable_paths']
            assert str(pack) not in (kwargs.get('readable_paths') or [])


def test_suite_and_model_roots_are_read_only_grants(setup):
    runner, home, db, out, pack = setup
    (pack/'suites').mkdir()
    suite = pack/'suites'/'test.qls'
    suite.write_text('- description: fixture\n')
    models = out.parent/'models'
    models.mkdir()
    scope = runner._analysis_scope(['codeql', '--additional-packs', str(models)], db, out, suite)
    assert str(pack) in scope['readable_paths']
    assert str(models) in scope['readable_paths']
    assert str(pack) not in scope['writable_paths']
    assert str(models) not in scope['writable_paths']


@pytest.mark.parametrize('which', ['output', 'database', 'cache-alias', 'query'])
def test_home_root_grants_are_refused(setup, which):
    runner, home, db, out, pack = setup
    if which == 'output':
        out = home
    elif which == 'database':
        db = home
    elif which == 'cache-alias':
        (home/'.codeql').symlink_to(home, target_is_directory=True)
    else:
        pack = home
    with pytest.raises(ValueError, match='dedicated directories'):
        runner._analysis_scope([], db, out, pack)


def test_sibling_source_suite_resolves_without_parent_directory_access(setup, monkeypatch):
    import core.sandbox
    runner, home, db, out, pack = setup
    install = out.parent/'distribution'/'codeql'
    install.mkdir(parents=True)
    runner.codeql_cli = str(install/'codeql')
    queries = install.parent/'codeql-queries'
    suite = queries/'cpp'/'ql'/'src'/'codeql-suites'/'cpp-security-and-quality.qls'
    suite.parent.mkdir(parents=True)
    suite.write_text('- description: fixture\n')
    def dispatch(command, **kwargs):
        assert str(suite) in command
        assert str(queries) in kwargs['readable_paths']
        assert str(install.parent) not in kwargs['readable_paths']
        for arg in command:
            if str(arg).startswith('--output='):
                Path(str(arg).split('=', 1)[1]).write_text(json.dumps({'runs': [{'results': []}]}))
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(core.sandbox, 'run', dispatch)
    assert runner.run_suite(db, 'cpp', out).success
