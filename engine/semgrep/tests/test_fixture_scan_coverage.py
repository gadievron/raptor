"""A silent fixture needs a complete native scan receipt before caching."""

import json
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

from engine.semgrep.tests import test_rule_fixtures as fixtures

_RULE = "crypto/weak-hash.yaml"


def _owned_finder(monkeypatch, tmp_path, fault=None):
    positive = tmp_path / "positive.java"
    negative = tmp_path / "negative.java"
    positive.write_text("class OwnedPositive {}\n")
    negative.write_text("class OwnedNegative {}\n")
    complete = {
        "results": [{"path": str(positive), "check_id": "owned", "start": {"line": 1}}],
        "errors": [],
        "paths": {"scanned": [str(positive), str(negative)]},
    }
    first = json.loads(json.dumps(complete))
    if fault == "missing-negative":
        first["paths"]["scanned"].remove(str(negative))
    elif fault == "missing-paths":
        del first["paths"]
    elif fault == "extra-target":
        first["paths"]["scanned"].append(str(tmp_path / "unrequested.java"))
    replies = iter([first, complete])
    calls = []

    def run(argv, **kwargs):
        calls.append(tuple(argv))
        return CompletedProcess(argv, 0, json.dumps(next(replies)), "")

    monkeypatch.setattr(fixtures, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(fixtures, "_FIXTURES", tmp_path)
    monkeypatch.setattr(fixtures, "_CASES", {_RULE: ([positive.name], [negative.name])})
    return fixtures.fixture_findings.__wrapped__(), positive, negative, calls


def test_complete_pair_shares_one_scan(monkeypatch, tmp_path):
    findings, positive, negative, calls = _owned_finder(monkeypatch, tmp_path)
    assert findings(_RULE, [negative.name]) == []
    assert [row["path"] for row in findings(_RULE, [positive.name])] == [str(positive)]
    assert findings(_RULE, [negative.name]) == []
    assert len(calls) == 1


@pytest.mark.parametrize("fault", ["missing-negative", "missing-paths", "extra-target"])
def test_incomplete_pair_is_rejected_without_caching(monkeypatch, tmp_path, fault):
    findings, positive, negative, calls = _owned_finder(monkeypatch, tmp_path, fault)
    with pytest.raises(AssertionError, match="fixture scan coverage mismatch"):
        findings(_RULE, [negative.name])
    assert findings(_RULE, [negative.name]) == []
    assert [row["path"] for row in findings(_RULE, [positive.name])] == [str(positive)]
    assert len(calls) == 2
