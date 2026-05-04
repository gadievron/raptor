"""Tests for Coccinelle data models."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.coccinelle.models import SpatchMatch, SpatchResult


class TestSpatchMatch:
    def test_from_dict_full(self):
        d = {
            "file": "/tmp/a.c",
            "line": 10,
            "col": 5,
            "line_end": 10,
            "col_end": 15,
            "rule": "test_rule",
            "message": "found it",
        }
        m = SpatchMatch.from_dict(d)
        assert m.file == "/tmp/a.c"
        assert m.line == 10
        assert m.column == 5
        assert m.line_end == 10
        assert m.column_end == 15
        assert m.rule == "test_rule"
        assert m.message == "found it"

    def test_from_dict_minimal(self):
        m = SpatchMatch.from_dict({"file": "x.c", "line": 1})
        assert m.file == "x.c"
        assert m.line == 1
        assert m.column == 0

    def test_from_dict_empty(self):
        m = SpatchMatch.from_dict({})
        assert m.file == ""
        assert m.line == 0

    def test_from_dict_none(self):
        m = SpatchMatch.from_dict(None)
        assert m.file == ""

    def test_roundtrip(self):
        m = SpatchMatch(file="a.c", line=5, column=3, rule="r1", message="msg")
        d = m.to_dict()
        m2 = SpatchMatch.from_dict(d)
        assert m2.file == m.file
        assert m2.line == m.line
        assert m2.rule == m.rule


class TestSpatchResult:
    def test_ok_true(self):
        r = SpatchResult(rule="test", returncode=0)
        assert r.ok

    def test_ok_false_on_error(self):
        r = SpatchResult(rule="test", returncode=0, errors=["parse error"])
        assert not r.ok

    def test_ok_false_on_returncode(self):
        r = SpatchResult(rule="test", returncode=1)
        assert not r.ok

    def test_match_count(self):
        matches = [
            SpatchMatch(file="a.c", line=1),
            SpatchMatch(file="b.c", line=2),
        ]
        r = SpatchResult(rule="test", matches=matches)
        assert r.match_count == 2

    def test_to_dict(self):
        r = SpatchResult(
            rule="test",
            rule_path="/tmp/test.cocci",
            matches=[SpatchMatch(file="a.c", line=1)],
            files_examined=["a.c"],
            elapsed_ms=100,
        )
        d = r.to_dict()
        assert d["rule"] == "test"
        assert len(d["matches"]) == 1
        assert d["matches"][0]["file"] == "a.c"
        assert d["elapsed_ms"] == 100
