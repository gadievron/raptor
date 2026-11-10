"""CVEfixes database arguments remain literal native filesystem paths."""

import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_loader


def seed(path):
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            'CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);'
            'CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);'
            'CREATE TABLE commits(hash TEXT, repo_url TEXT, parents TEXT);'
            'CREATE TABLE repository(repo_url TEXT, repo_language TEXT);'
        )
        connection.execute('INSERT INTO cwe_classification VALUES (?,?)', ('CVE-LOCAL', 'CWE-89'))
        connection.execute('INSERT INTO fixes VALUES (?,?,?)', ('CVE-LOCAL', 'fix', 'https://github.com/example/local'))
        connection.execute('INSERT INTO commits VALUES (?,?,?)', ('fix', 'https://github.com/example/local', "['parent']"))
        connection.execute('INSERT INTO repository VALUES (?,?)', ('https://github.com/example/local', 'Python'))
        connection.commit()


@pytest.mark.parametrize('name', [
    pytest.param('ordinary.sqlite', id='ordinary'),
    pytest.param('metadata?.sqlite', id='question'),
    pytest.param('metadata#.sqlite', id='fragment'),
    pytest.param('metadata%20.sqlite', id='percent'),
    pytest.param('métadonnées.sqlite', id='unicode'),
])
def test_native_literal_path_retains_read_only_access(tmp_path, monkeypatch, name):
    directory = tmp_path / 'owned data'
    directory.mkdir()
    path = directory / name
    seed(path)
    before = path.read_bytes()
    captured = []

    def connect(*args, **kwargs):
        connection = sqlite3.connect(*args, **kwargs)
        captured.append(connection)
        try:
            with pytest.raises(sqlite3.OperationalError, match='readonly'):
                connection.execute('CREATE TABLE forbidden_write(value TEXT)')
        except BaseException:
            connection.close()
            raise
        return connection

    monkeypatch.setattr(cvefix_loader, 'sqlite3', SimpleNamespace(connect=connect))
    try:
        pairs = cvefix_loader.load_pairs(path)
        assert len(pairs) == 1
        assert pairs[0].cve_id == 'CVE-LOCAL'
        assert pairs[0].fix_hash == 'fix'
        assert pairs[0].parent_hash == 'parent'
        assert path.read_bytes() == before
        assert sorted(item.name for item in directory.iterdir()) == [name]
        with pytest.raises(sqlite3.ProgrammingError, match='closed'):
            captured[0].execute('SELECT 1')
    finally:
        for connection in captured:
            connection.close()


def test_relative_literal_path_is_resolved_from_current_directory(tmp_path, monkeypatch):
    path = tmp_path / 'relative #?.sqlite'
    seed(path)
    monkeypatch.chdir(tmp_path)
    assert cvefix_loader.load_pairs(Path(path.name))[0].cve_id == 'CVE-LOCAL'


def test_missing_literal_path_is_not_created(tmp_path):
    path = tmp_path / 'missing #?.sqlite'
    with pytest.raises(sqlite3.OperationalError):
        cvefix_loader.load_pairs(path)
    assert list(tmp_path.iterdir()) == []
