"""Metadata filters must be collections of values rather than text fragments."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_loader as loader


def _sqlite_stub(monkeypatch):
    calls = []
    class Connection:
        def execute(self, sql, values):
            calls.append(("query", values))
            return SimpleNamespace(fetchall=lambda: [])
        def close(self):
            calls.append(("close",))
    def connect(*args, **kwargs):
        calls.append(("connect",))
        return Connection()
    monkeypatch.setattr(loader, "sqlite3", SimpleNamespace(connect=connect))
    return calls


@pytest.mark.parametrize("field,value", [
    ("cwes", "CWE-22"), ("languages", "Python"),
    ("cwes", b"CWE-22"), ("languages", {"Python": True}),
    ("cwes", [22]), ("languages", [""]),
], ids=["cwe-text", "language-text", "bytes", "mapping", "nontext-member", "empty-member"])
def test_invalid_filter_refused_before_sqlite(monkeypatch, field, value):
    calls = _sqlite_stub(monkeypatch)
    with pytest.raises(ValueError, match=field):
        loader.load_pairs(Path("owned-inert.db"), **{field: value})
    assert calls == []


def test_explicit_filter_values_reach_query_unchanged(monkeypatch):
    calls = _sqlite_stub(monkeypatch)
    assert loader.load_pairs(Path("owned-inert.db"), cwes=["CWE-22"], languages=("Python",)) == []
    assert calls == [("connect",), ("query", ("CWE-22", "Python")), ("close",)]
