"""Pair limits apply before metadata access, using inert reader seams."""

from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_loader as loader


@pytest.fixture(params=["metadata", "run"])
def owned_reader(request, tmp_path, monkeypatch):
    reads = []
    closes = []
    if request.param == "metadata":
        rows = [
            (f"CVE-OWN-{i}", "CWE-89", "https://github.com/owned/inert",
             "Python", f"fix{i}", "['parent']")
            for i in range(2)
        ]
        rows.insert(0, ("CVE-MERGE", "CWE-89", "https://github.com/owned/inert",
                        "Python", "merge", "['parent1', 'parent2']"))

        def execute(sql, parameters):
            assert "SELECT DISTINCT" in sql
            assert "CWE-89" in parameters
            return SimpleNamespace(fetchall=lambda: rows)

        def connect(database_uri, **kwargs):
            assert database_uri.endswith("?mode=ro")
            assert kwargs == {"uri": True}
            reads.append(database_uri)
            return SimpleNamespace(execute=execute, close=lambda: closes.append(True))

        # Replace only this consumer's module binding, never sqlite3 globally.
        monkeypatch.setattr(loader, "sqlite3", SimpleNamespace(connect=connect))

        def load(limit):
            result = loader.load_pairs(tmp_path / "unopened.db", limit=limit)
            assert len(closes) == len(reads)
            return result
    else:
        records = [
            SimpleNamespace(
                cve_id=f"CVE-OWN-{i}", cwe="CWE-89", parent_commit="parent",
                repository_url="https://github.com/owned/inert", fix_commit=f"fix{i}",
                files=[SimpleNamespace(path="inert.py", is_test=False)],
            )
            for i in range(2)
        ]
        paths = [tmp_path / f"unopened-run-{i}" for i in range(2)]
        records.insert(0, SimpleNamespace(
            cve_id="CVE-OTHER", cwe="CWE-476", parent_commit="parent",
            repository_url="https://github.com/owned/inert", fix_commit="other",
            files=[SimpleNamespace(path="inert.py", is_test=False)],
        ))
        paths.insert(0, tmp_path / "unopened-rejected-run")

        def read(path):
            reads.append(path)
            return records[paths.index(path)]

        monkeypatch.setattr("packages.checker_synthesis.cve_bridge.load_cve_run", read)

        def load(limit):
            return loader.load_pairs_from_cve_diff_runs(paths, limit=limit)

    return load, reads


def test_zero_limit_skips_metadata(owned_reader):
    load, reads = owned_reader
    assert load(0) == []
    assert reads == []


@pytest.mark.parametrize("limit,expected", [(None, 2), (1, 1), (2, 2)])
def test_positive_and_unlimited_pairs_are_retained(owned_reader, limit, expected):
    load, reads = owned_reader
    pairs = load(limit)
    assert [pair.cve_id for pair in pairs] == [f"CVE-OWN-{i}" for i in range(expected)]
    assert reads


@pytest.mark.parametrize("limit", [-1, True, False, 1.5, "1"])
def test_invalid_limit_refuses_before_metadata(owned_reader, limit):
    load, reads = owned_reader
    with pytest.raises(ValueError, match="limit"):
        load(limit)
    assert reads == []
