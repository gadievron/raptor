"""Span-only callback reports cannot supply claim attribution."""

from dataclasses import asdict
from pathlib import Path
import sys

import pytest

from core.audit.lock_region import LockRegionEvidence, cocci_corroboration
from packages.coccinelle.models import SpatchMatch, SpatchResult


@pytest.mark.parametrize("supplied", [
    pytest.param(SpatchResult(rule="callback_under_lock", matches=[
        SpatchMatch(file="owned.c", line=3, column=8, line_end=3, column_end=10,
                    rule="callback_under_lock", message="candidate"),
    ]), id="complete-looking-span-no-identity"),
    pytest.param(SpatchResult(rule="callback_under_lock", matches=[
        SpatchMatch(file="owned.c", line=30, column=8, line_end=30, column_end=10,
                    rule="callback_under_lock", message="candidate"),
    ]), id="outside-region"),
    pytest.param(SpatchResult(rule="callback_under_lock", matches=[
        SpatchMatch(file="owned.c", line=3, rule="callback_under_lock"),
    ]), id="missing-span"),
    pytest.param(SpatchResult(rule="callback_under_lock", matches=[
        SpatchMatch(file="owned.c", line=3, column=8, line_end=3, column_end=10,
                    rule="different_rule", message="candidate"),
    ]), id="wrong-rule"),
    pytest.param(SpatchResult(rule="callback_under_lock", matches=[
        SpatchMatch(file="owned.c", line=3, column=8, line_end=3, column_end=10,
                    rule="callback_under_lock", message="candidate"),
    ], errors=["partial run"], returncode=1), id="partial-span-report"),
    pytest.param(SpatchResult(rule="callback_under_lock"), id="no-matches"),
])
def test_span_only_producer_is_not_queried_or_attributed(monkeypatch, tmp_path, supplied):
    import packages.coccinelle.runner as runner

    result = LockRegionEvidence(
        outcome="confirmed", reason="owned channel confirmation",
        lock={"acquire": "my_lock", "release": "my_unlock", "variable": "lock"},
        region={"file": "owned.c", "span": [1, 5]},
        callback={"shape": "indirect_field", "expr": "p->cb", "line": 3,
                  "code": "p->cb(1);"},
    )
    before = asdict(result), asdict(supplied)
    availability_calls = []
    runner_calls = []

    def available():
        availability_calls.append(True)
        return True

    def run(*args, **kwargs):
        runner_calls.append((args, kwargs))
        return supplied

    monkeypatch.setattr(runner, "is_available", available)
    monkeypatch.setattr(runner, "run_rule", run)
    assert cocci_corroboration(tmp_path, result) is None
    assert availability_calls == []
    assert runner_calls == []
    assert (asdict(result), asdict(supplied)) == before


@pytest.mark.parametrize("outcome,lock", [
    ("refuted", {"acquire": "my_lock", "release": "my_unlock"}),
    ("inconclusive", {"acquire": "my_lock", "release": "my_unlock"}),
    ("confirmed", None),
    ("confirmed", {"acquire": "not an identifier", "release": "my_unlock"}),
], ids=["refuted", "inconclusive", "missing-lock", "invalid-name"])
def test_unadmitted_claim_does_not_discover_or_run_coccinelle(monkeypatch, tmp_path,
                                                            outcome, lock):
    import packages.coccinelle.runner as runner

    def unexpected(*args, **kwargs):
        pytest.fail("Withheld corroboration must not invoke a native runner")

    monkeypatch.setattr(runner, "is_available", unexpected)
    monkeypatch.setattr(runner, "run_rule", unexpected)
    result = LockRegionEvidence(outcome=outcome, reason="owned control", lock=lock)
    assert cocci_corroboration(tmp_path, result) is None


def test_contract_imports_resolve_to_owned_helper_and_models():
    import packages.coccinelle.runner as runner

    root = Path(__file__).resolve().parents[3]
    helper_module = sys.modules[LockRegionEvidence.__module__]
    models_module = sys.modules[SpatchResult.__module__]
    assert Path(helper_module.__file__).resolve() == root / "core/audit/lock_region.py"
    assert Path(models_module.__file__).resolve() == root / "packages/coccinelle/models.py"
    assert Path(runner.__file__).resolve() == root / "packages/coccinelle/runner.py"
