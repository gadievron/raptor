"""Source cache bounds include empty and unavailable member results."""

import zipfile

import pytest

from packages.llm_analysis import dataflow_validation as dv
from packages.llm_analysis.tests.test_dataflow_validation import (
    _owned_database_memos as _owned_database_memos,
)


def _database(tmp_path, members):
    db = tmp_path / "db"
    db.mkdir()
    with zipfile.ZipFile(db / "src.zip", "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text, compress_type=zipfile.ZIP_STORED)
    return db


@pytest.mark.parametrize("missing", [False, True], ids=["empty", "missing"])
def test_zero_character_results_have_entry_bound(tmp_path, monkeypatch, missing):
    monkeypatch.setattr(dv, "_DB_SOURCE_CACHE_MAX_ENTRIES", 3, raising=False)
    names = [f"repo/f{i}.py" for i in range(8)]
    db = _database(tmp_path, {} if missing else dict.fromkeys(names, ""))
    expected = None if missing else ""
    for name in names:
        assert dv._read_db_source(db, name) == expected
        assert len(dv._db_source_cache) <= 3
        assert dv._db_source_cache_chars == 0
    assert (str(db), names[0]) not in dv._db_source_cache
    assert (str(db), names[-1]) in dv._db_source_cache
    assert dv._read_db_source(db, names[0]) == expected
    assert len(dv._db_source_cache) == 3


def test_entry_eviction_keeps_character_accounting_exact(tmp_path, monkeypatch):
    monkeypatch.setattr(dv, "_DB_SOURCE_CACHE_MAX_ENTRIES", 2, raising=False)
    monkeypatch.setattr(dv, "_DB_SOURCE_CACHE_BUDGET", 100)
    db = _database(tmp_path, {"repo/a.py": "abc", "repo/empty.py": ""})
    assert dv._read_db_source(db, "repo/a.py") == "abc"
    assert dv._read_db_source(db, "repo/empty.py") == ""
    assert dv._read_db_source(db, "repo/missing.py") is None
    assert (str(db), "repo/a.py") not in dv._db_source_cache
    assert dv._db_source_cache_chars == 0
    assert dv._read_db_source(db, "repo/a.py") == "abc"
    assert dv._db_source_cache_chars == 3
    dv._read_db_source.cache_clear()
    assert dv._db_source_cache == {} and dv._db_source_cache_chars == 0


def test_newest_entry_survives_character_budget_eviction(tmp_path, monkeypatch):
    monkeypatch.setattr(dv, "_DB_SOURCE_CACHE_MAX_ENTRIES", 3, raising=False)
    monkeypatch.setattr(dv, "_DB_SOURCE_CACHE_BUDGET", 2)
    db = _database(tmp_path, {"repo/a.py": "a", "repo/b.py": "1234"})
    assert dv._read_db_source(db, "repo/a.py") == "a"
    assert dv._read_db_source(db, "repo/b.py") == "1234"
    assert list(dv._db_source_cache) == [(str(db), "repo/b.py")]
    assert dv._db_source_cache_chars == 4


def test_entry_limit_boundary_reuses_cached_source(tmp_path, monkeypatch):
    monkeypatch.setattr(dv, "_DB_SOURCE_CACHE_MAX_ENTRIES", 2, raising=False)
    db = _database(tmp_path, {"repo/a.py": "a", "repo/b.py": "b"})
    calls = []
    original = dv._read_db_source_uncached

    def observed(database, member):
        calls.append(member)
        return original(database, member)

    monkeypatch.setattr(dv, "_read_db_source_uncached", observed)
    for member, expected in (("repo/a.py", "a"), ("repo/b.py", "b"), ("repo/a.py", "a")):
        assert dv._read_db_source(db, member) == expected
    assert calls == ["repo/a.py", "repo/b.py"]
    assert len(dv._db_source_cache) == 2
