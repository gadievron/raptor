"""Native selected publication/free expression and exclusion contracts.

Matches require object-identity and lifetime review. Exclusion by a wait
or callback spelling alone is not complete grace-period evidence.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "kfree_not_rcu.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE, include_stderr=False)


class TestPositives:
    def test_publish_then_free_same_pointer_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                kfree(newc);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "kfree_not_rcu"

    def test_hlist_add_then_free_same_object_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct obj *o, struct hlist_head *h)
            {
                hlist_add_head_rcu(&o->node, h);
                kfree(o);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_free_of_unrelated_pointer_does_not_fire(self, tmp_path):
        # The original rule fired on ANY free after ANY publish in the
        # same function — false CWE-416 confirmations.
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc, struct other *tmp)
            {
                rcu_assign_pointer(*head, newc);
                kfree(tmp);
            }
        """)
        assert results == []

    def test_grace_period_then_free_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                synchronize_rcu();
                kfree(newc);
            }
        """)
        assert results == []

    def test_swap_and_free_old_after_sync_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                struct cfg *old = *head;
                rcu_assign_pointer(*head, newc);
                synchronize_rcu();
                kfree(old);
            }
        """)
        assert results == []

    def test_kfree_rcu_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                kfree_rcu(newc, rcu);
            }
        """)
        assert results == []

    def test_synchronize_net_grace_period_does_not_fire(self, tmp_path):
        # synchronize_net is a documented RCU grace-period equivalent;
        # a safe teardown also requires unpublication and matching readers.
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                synchronize_net();
                kfree(newc);
            }
        """)
        assert results == []

    def test_synchronize_srcu_grace_period_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct srcu_struct *ss, struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                synchronize_srcu(ss);
                kfree(newc);
            }
        """)
        assert results == []

    def test_rcu_barrier_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                rcu_barrier();
                kfree(newc);
            }
        """)
        assert results == []

    def test_call_rcu_handoff_does_not_fire(self, tmp_path):
        # Current callback exclusion suppresses even a later plain free;
        # queueing alone is not proof that this immediate free is safe.
        results = _run_rule(tmp_path, """\
            void ok(struct cfg **head, struct cfg *newc)
            {
                rcu_assign_pointer(*head, newc);
                call_rcu(&newc->rcu, cfg_free_cb);
                kfree(newc);
            }
        """)
        assert results == []


@pytest.mark.slow
@pytest.mark.parametrize('variant,expected', [('direct', 1), ('rebound', 1), ('barrier', 0), ('srcu', 0), ('retire_wait', 0)])
def test_publication_expression_requires_lifetime_evidence(tmp_path, monkeypatch, variant, expected):
    from core.audit.sweep import (
        is_confirm_only_coccinelle_rule, run_coccinelle_file_sweep, scope_coccinelle_result,
    )
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.coccinelle import runner
    from packages.coccinelle.models import SpatchMatch, SpatchResult
    rule = _RULE
    tails = {
        'direct': 'kfree(p);',
        'rebound': 'p = spare; kfree(p);',
        'barrier': 'rcu_barrier(); kfree(p);',
        'srcu': 'synchronize_srcu(ss); kfree(p);',
        'retire_wait': 'rcu_assign_pointer(*head, 0); synchronize_rcu(); kfree(p);',
    }
    source = ('struct cfg { int value; };\n'
              'void candidate(struct cfg **head, struct cfg *p, struct cfg *spare, struct srcu_struct *ss) {\n'
              ' if (p == spare) return;\n rcu_assign_pointer(*head, p);\n '+tails[variant]+'\n}\nvoid untouched(void) {}\n')
    target = tmp_path / 'owned.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(rule), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned RCU publication and lifetime syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert len(rows) == expected
    assert all(row['rule'] == 'kfree_not_rcu' and 'review object identity' in row['message'] for row in rows)
    native = SpatchResult(rule=rule.stem, rule_path=str(rule),
        matches=[SpatchMatch.from_dict(row) for row in rows], files_examined=[str(target)])
    calls = []
    def replay(file_path, rule_path, **kwargs):
        assert file_path == target and rule_path == rule
        calls.append((str(file_path), str(rule_path)))
        return native
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'run_rule', replay)
    result = run_coccinelle_file_sweep(target_path=tmp_path, file_path=target.name,
        cocci_rule=str(rule), language='c')
    assert len(calls) == 1
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert result.details['confirm_only']
    assert result.outcome == ('confirmed' if expected else 'inconclusive')
    last = len(source.splitlines())
    scoped = scope_coccinelle_result(result, target_path=tmp_path, function_name='untouched',
        line_start=last, line_end=last, language='c')
    assert scoped.matches == [] and scoped.outcome == 'inconclusive'
    assert scoped.details['confirm_only']
    assert len(result.matches) == expected
