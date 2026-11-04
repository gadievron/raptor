"""Owned scoping preserves results while memo backing objects stay isolated."""

import copy
from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit.sweep_memo import SweepMemo


@pytest.mark.parametrize("outcome", ["confirmed", "refuted", "error", "skipped", "inconclusive", "novel"])
@pytest.mark.parametrize("bounds", [(None, None), (1, 10), (70, None)])
def test_owned_and_default_scoping_have_identical_values(tmp_path, monkeypatch, outcome, bounds):
    monkeypatch.setattr(sweep, "file_substrate_coverage", lambda *a, **kw: None)
    original = sweep.SweepResult(
        tool="coccinelle", file_path="a.c", function_name="", outcome=outcome,
        matches=[{"line": 2, "metadata": {"names": ["first"]}}, {"line": 80}],
        errors=["diagnostic"], details={"nested": {"values": [1]}},
    )
    owned = copy.deepcopy(original)
    options = dict(target_path=tmp_path, function_name="f", line_start=bounds[0], line_end=bounds[1])
    normal = sweep.scope_coccinelle_result(original, **options)
    consumed = sweep.scope_coccinelle_result(owned, copy_result=False, **options)
    assert consumed is owned
    assert normal is not original
    assert asdict(consumed) == asdict(normal)
    consumed.details["nested"]["values"].append(2)
    assert original.details["nested"]["values"] == [1]


def test_owned_memo_hit_cannot_mutate_backing_or_other_consumers(tmp_path, monkeypatch):
    monkeypatch.setattr(sweep, "file_substrate_coverage", lambda *a, **kw: None)
    memo = SweepMemo()
    key = SweepMemo.make_key("coccinelle", {"file": "hash", "rule": "hash"})
    original = sweep.SweepResult(
        tool="coccinelle", file_path="a.c", function_name="", outcome="confirmed",
        matches=[{"line": 2, "nested": ["original"]}, {"line": 80}],
        details={"metadata": ["original"]},
    )
    # Preserve aliases within each independently owned result too.
    original.details["all_matches"] = original.matches
    memo.put(key, original)
    first, second = memo.get(key), memo.get(key)
    scoped = sweep.scope_coccinelle_result(
        first, target_path=tmp_path, function_name="f", line_start=1, line_end=10,
        copy_result=False,
    )
    assert len(scoped.matches) == 1
    assert len(scoped.details["all_matches"]) == 2
    assert scoped.matches[0] is scoped.details["all_matches"][0]
    scoped.matches[0]["nested"].append("changed")
    scoped.details["metadata"].append("changed")
    for result in (original, second, memo.get(key)):
        assert result.function_name == ""
        assert len(result.matches) == 2
        assert result.matches[0]["nested"] == ["original"]
        assert result.details["metadata"] == ["original"]
