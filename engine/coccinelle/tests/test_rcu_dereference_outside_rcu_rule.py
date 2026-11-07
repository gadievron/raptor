"""Fixture tests for the rcu_dereference_outside_rcu rule.

Detection-role rule: missing local RCU protection needs caller and lifetime
review. Native cases check each dereference independently.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "rcu_dereference_outside_rcu.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_dereference_without_lock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *peek(struct table *t)
            {
                void *entry = rcu_dereference(t->head);
                return entry;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "rcu_dereference_outside_rcu"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_dereference_inside_lock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *peek(struct table *t)
            {
                void *entry;
                rcu_read_lock();
                entry = rcu_dereference(t->head);
                rcu_read_unlock();
                return entry;
            }
        """)
        assert results == []


@pytest.mark.parametrize("rule_name,api,lock,unlock", [
    ("rcu_dereference_outside_rcu", "rcu_dereference", "rcu_read_lock", "rcu_read_unlock"),
    ("rcu_dereference_outside_rcu", "rcu_dereference_bh", "rcu_read_lock_bh", "rcu_read_unlock_bh"),
    ("rcu_no_lock", "rcu_dereference", "rcu_read_lock", "rcu_read_unlock"),
], ids=["plain", "bh", "assignment"])
def test_local_read_sections_are_correlated_with_each_dereference(tmp_path, rule_name, api, lock, unlock):
    cases = [
        ("", "", True),
        (f"{lock}();", f"{unlock}();", False),
        (f"{lock}();", "", False),
        (f"{lock}(); {unlock}();", "", True),
        (f"if (stop) {lock}();", "", True),
        (f"{lock}(); if (stop) {unlock}();", "", True),
        (f"{lock}(); {lock}(); {unlock}();", f"{unlock}();", False),
        (f"{lock}(); {lock}(); if (stop) {unlock}();", f"{unlock}();", False),
        (f"if (stop) return 0; {lock}();", f"{unlock}();", False),
        (f"{lock}(); if (stop) {lock}(); {unlock}();", "", True),
        (f"{lock}(); {lock}(); {unlock}(); {unlock}();", "", True),
    ]
    lines, expected = [], set()
    for index, (before, after, reports) in enumerate(cases):
        lines += [f"void *case_{index}(void *head, int stop) {{", "void *ptr;", before,
                  f"ptr = {api}(head);", after, "return ptr;", "}"]
        if reports:
            expected.add(len(lines)-3)
    # One protected call must not hide an earlier or later unprotected call
    # that uses the same expression in the same function.
    lines += ["void mixed(void *head) {", "void *ptr;", f"ptr = {api}(head);"]
    expected.add(len(lines))
    lines += [f"{lock}();", f"ptr = {api}(head);", f"{unlock}();", f"ptr = {api}(head);", "}"]
    expected.add(len(lines)-1)
    # A conditional use is still protected by an unconditional acquisition.
    lines += ["void conditional_use(void *head, int stop) {", f"{lock}();", f"if (stop) consume({api}(head));", f"{unlock}();", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines)+"\n", rule=_RULE.with_name(rule_name + ".cocci"))
    actual={row["line"] for row in rows}
    assert actual == expected, {"missing": expected-actual, "unexpected": actual-expected}
    assert len(rows)==len(expected)


def test_explicit_protection_contracts_are_outside_the_local_lock_check(tmp_path):
    rows = _run_rule(tmp_path, """        void *f(void *head) {
            void *p;
            p = rcu_dereference_check(head, lockdep_is_held(&lock));
            p = rcu_dereference_protected(head, 1);
            return p;
        }
    """)
    assert rows == []


@pytest.mark.integration
def test_rcu_candidates_share_production_invocation(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'void *bare(void *head) { void *p; p = rcu_dereference(head); return p; }\n'
        'void *held(void *head) { void *p; rcu_read_lock(); p = rcu_dereference(head); rcu_read_unlock(); return p; }\n'
        'void *released(void *head) { void *p; rcu_read_lock(); rcu_read_unlock(); p = rcu_dereference(head); return p; }\n'
        'void *checked(void *head) { void *p; p = rcu_dereference_check(head, lockdep_is_held(&lock)); return p; }\n'
        'void *bh_bare(void *head) { void *p; p = rcu_dereference_bh(head); return p; }\n',
    )
    original = runner._confined_default_runner
    invocations = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            invocations.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("rcu_no_lock.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"rcu_dereference_outside_rcu", "rcu_no_lock"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["rcu_no_lock"].matches) == 2
    assert len(results["rcu_dereference_outside_rcu"].matches) == 3
    assert len(invocations) == 1, invocations
