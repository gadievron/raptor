"""Lock-order candidates need object-identity and concurrency review.

An intervening release of B still excludes the reversed nesting shape.
A retained syntactic match alone does not establish an ABBA deadlock.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "lock_order_violation.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_spin_abba_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void path_a(void)
            {
                spin_lock(&a);
                spin_lock(&b);
                do_work();
                spin_unlock(&b);
                spin_unlock(&a);
                spin_lock(&b);
                spin_lock(&a);
                do_other();
                spin_unlock(&a);
                spin_unlock(&b);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "lock_order_violation"

    def test_mutex_abba_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void path_m(void)
            {
                mutex_lock(&a);
                mutex_lock(&b);
                do_work();
                mutex_unlock(&b);
                mutex_unlock(&a);
                mutex_lock(&b);
                mutex_lock(&a);
                do_other();
                mutex_unlock(&a);
                mutex_unlock(&b);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_sequential_nonoverlapping_does_not_fire(self, tmp_path):
        # B is released before A is taken — no reversed nesting.
        results = _run_rule(tmp_path, """\
            void sequential(void)
            {
                spin_lock(&a);
                spin_lock(&b);
                do_work();
                spin_unlock(&b);
                spin_unlock(&a);
                spin_lock(&b);
                do_b_only();
                spin_unlock(&b);
                spin_lock(&a);
                do_a_only();
                spin_unlock(&a);
            }
        """)
        assert results == []

    def test_mutex_sequential_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void sequential(void)
            {
                mutex_lock(&a);
                mutex_lock(&b);
                do_work();
                mutex_unlock(&b);
                mutex_unlock(&a);
                mutex_lock(&b);
                do_b_only();
                mutex_unlock(&b);
                mutex_lock(&a);
                do_a_only();
                mutex_unlock(&a);
            }
        """)
        assert results == []


@pytest.mark.slow
def test_receiver_changes_require_lock_identity_review(tmp_path):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    lines = ['struct lock { int value; };',
             'struct pair { struct lock a, b; };']
    expected = set()
    for family in ['spin', 'mutex']:
        for variant in ['stable', 'rebound', 'released']:
            acquire, release = family + '_lock', family + '_unlock'
            lines += [f'void {family}_{variant}(struct pair *left, struct pair *right) {{',
                      'if (left == right) return;', 'struct pair *ctx = left;',
                      f'{acquire}(&ctx->a);', f'{acquire}(&ctx->b);',
                      f'{release}(&ctx->b);', f'{release}(&ctx->a);']
            if variant == 'rebound':
                lines += ['ctx = right;']
            lines += [f'{acquire}(&ctx->b);']
            second_b = len(lines)
            if variant == 'released':
                lines += [f'{release}(&ctx->b);']
            lines += [f'{acquire}(&ctx->a);', f'{release}(&ctx->a);']
            if variant != 'released':
                lines += [f'{release}(&ctx->b);']
                expected.add(second_b)
            lines += ['}']
    target = tmp_path / 'owned.c'
    target.write_text('\n'.join(lines) + '\n')
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned lock receiver identity syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert {row['line'] for row in rows} == expected
    assert len(rows) == len(expected) == 4
    assert {row['rule'] for row in rows} == {'lock_order_violation'}
    assert all(row['message'].startswith('Candidate:')
               and 'lock-object identity' in row['message']
               and 'concurrent reachability' in row['message'] for row in rows)
