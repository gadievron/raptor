"""Bridge input databases are literal read-only paths; empty work stays local."""

import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_bridge


def seed(path):
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            'CREATE TABLE walk_results(fix_hash TEXT, cve_id TEXT, cwe TEXT, '
            'repo_language TEXT, repo_url TEXT, parent_hash TEXT, status TEXT, after_count INTEGER)'
        )
        connection.execute('INSERT INTO walk_results VALUES (?,?,?,?,?,?,?,?)',
                           ('fix', 'CVE-LOCAL', 'CWE-89', 'Python', 'local-unused', 'parent', 'ok', 0))
        connection.commit()


def refuse_proposal(*args, **kwargs):
    pytest.fail('an empty candidate set must not invoke a proposer')


def run_empty(source, tmp_path):
    return cvefix_bridge.synthesize_from_results(
        source, synth_db=tmp_path / 'output.sqlite', work_dir=tmp_path / 'work',
        proposer=refuse_proposal, search_path=str(tmp_path / 'unused-search'),
        log=lambda *args: None,
    )


@pytest.mark.parametrize('name', [
    pytest.param('results.sqlite', id='ordinary'),
    pytest.param('results?.sqlite', id='question'),
    pytest.param('results#.sqlite', id='fragment'),
    pytest.param('results%20.sqlite', id='percent'),
    pytest.param('résultats.sqlite', id='unicode'),
])
def test_native_literal_source_stays_read_only_without_proposals(tmp_path, monkeypatch, name):
    source_dir = tmp_path / 'owned input'
    source_dir.mkdir()
    source = source_dir / name
    seed(source)
    before = source.read_bytes()
    captured = []

    def connect(*args, **kwargs):
        connection = sqlite3.connect(*args, **kwargs)
        captured.append(connection)
        if kwargs.get('uri'):
            try:
                with pytest.raises(sqlite3.OperationalError, match='readonly'):
                    connection.execute('CREATE TABLE forbidden_write(value TEXT)')
            except BaseException:
                connection.close()
                raise
        return connection

    monkeypatch.setattr(cvefix_bridge, 'sqlite3', SimpleNamespace(connect=connect))
    try:
        report = run_empty(source, tmp_path)
        assert (report.total, report.sound, report.not_sound, report.no_barrier) == (0, 0, 0, 0)
        assert report.per_finding == ()
        assert source.read_bytes() == before
        assert sorted(path.name for path in source_dir.iterdir()) == [name]
        assert len(captured) == 2
        for connection in captured:
            with pytest.raises(sqlite3.ProgrammingError, match='closed'):
                connection.execute('SELECT 1')
        with closing(sqlite3.connect(tmp_path / 'output.sqlite')) as output:
            assert output.execute('SELECT count(*) FROM synth_results').fetchone()[0] == 0
    finally:
        for connection in captured:
            connection.close()


def test_relative_literal_results_path(tmp_path, monkeypatch):
    source = tmp_path / 'relative #?.sqlite'
    seed(source)
    monkeypatch.chdir(tmp_path)
    assert run_empty(Path(source.name), tmp_path).total == 0


def test_missing_literal_results_source_creates_no_database(tmp_path):
    with pytest.raises(sqlite3.OperationalError):
        run_empty(tmp_path / 'missing #?.sqlite', tmp_path)
    assert list(tmp_path.iterdir()) == []
