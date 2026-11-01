"""Installed CLI aliases must not hide CodeQL or expose all of HOME."""
import pytest


def test_cli_alias_is_resolved_consistently_for_argv_and_tool_paths(tmp_path, monkeypatch):
    from packages.codeql import _resolve_cli
    from packages.codeql.database_manager import DatabaseManager
    from packages.codeql.query_runner import QueryRunner
    distribution = tmp_path / 'distribution'
    distribution.mkdir()
    executable = distribution / 'codeql'
    executable.write_text('not executed')
    executable.chmod(0o755)
    alias = tmp_path / 'bin/codeql'
    alias.parent.mkdir()
    alias.symlink_to(executable)
    monkeypatch.setenv('CODEQL_CLI', str(alias))
    assert _resolve_cli() == str(executable)
    database = DatabaseManager.__new__(DatabaseManager)
    assert database._detect_codeql_cli() == str(executable)
    database.codeql_cli = _resolve_cli()
    query = QueryRunner.__new__(QueryRunner)
    query.codeql_cli = _resolve_cli()
    assert database._sandbox_tool_paths() == [str(distribution)]
    assert query._sandbox_tool_paths() == [str(distribution)]


@pytest.mark.parametrize('location', ['home', 'ancestor'])
def test_codeql_refuses_overbroad_installation_root(tmp_path, monkeypatch, location):
    from packages.codeql.tool_paths import codeql_tool_paths
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    directory = home if location == 'home' else tmp_path
    with pytest.raises(ValueError, match='dedicated installation directory'):
        codeql_tool_paths(str(directory / 'codeql'))


def test_default_database_directory_works_without_protection_configuration(tmp_path, monkeypatch):
    from core.config import RaptorConfig
    from packages.codeql.database_manager import DatabaseManager
    directory = tmp_path / 'databases'
    monkeypatch.setattr(RaptorConfig, 'CODEQL_DB_DIR', directory)
    monkeypatch.setattr(RaptorConfig, 'CODEQL_DB_AUTO_CLEANUP', False)
    manager = DatabaseManager(codeql_cli='/usr/bin/true')
    assert manager.db_root == directory
    assert directory.is_dir()
