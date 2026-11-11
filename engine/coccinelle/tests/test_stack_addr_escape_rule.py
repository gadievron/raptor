"""Fixture tests for the stack_addr_escape rule.

The safe set must be declaration-order independent: C89 style puts
every local at the top of the function, often declaring the pointer
BEFORE the variable whose address it takes. A safe set that requires
LOCAL-before-pointer order reports the C89 shape as an escape.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "stack_addr_escape.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_assign_to_global_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int *gp;

            void bug(void)
            {
                int x;
                gp = &x;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "stack_addr_escape"

    def test_write_to_outparam_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int **out)
            {
                int x;
                *out = &x;
                return 0;
            }
        """)
        assert any(r["rule"] == "stack_addr_escape_outparam" for r in results)


class TestNegatives:
    def test_local_pointer_c99_order_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(void)
            {
                int x;
                int *p;
                p = &x;
                *p = 1;
            }
        """)
        assert results == []

    def test_local_pointer_c89_order_does_not_fire(self, tmp_path):
        # Pointer declared BEFORE the target variable — same lifetime,
        # same scope, no escape.
        results = _run_rule(tmp_path, """\
            void ok(void)
            {
                int *p;
                int x;
                p = &x;
                *p = 1;
            }
        """)
        assert results == []

    def test_local_struct_member_either_order_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct holder { int *m; };

            void ok_c89(void)
            {
                struct holder h;
                int x;
                h.m = &x;
            }

            void ok_c99(void)
            {
                int x;
                struct holder h;
                h.m = &x;
            }
        """)
        assert results == []


@pytest.mark.slow
@pytest.mark.parametrize('variant', ['global_plain', 'global_clear', 'out_clear', 'static', 'aggregate_copy'])
def test_address_assignments_require_lifetime_evidence(tmp_path, monkeypatch, variant):
    from core.audit.sweep import (
        is_confirm_only_coccinelle_rule, run_coccinelle_file_sweep, scope_coccinelle_result,
    )
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.coccinelle import runner
    from packages.coccinelle.models import SpatchMatch, SpatchResult
    rule = _RULE
    bodies = {
        'global_plain': 'int x; gp = &x;',
        'global_clear': 'int x; gp = &x; gp = 0;',
        'out_clear': 'int x; *out = &x; *out = 0;',
        'static': 'static int x; gp = &x;',
        'aggregate_copy': 'int x; struct holder h; h.m = &x; *copy = h;',
    }
    source = ('struct holder { int *m; }; static int *gp;\n'
              'void candidate(int **out, struct holder *copy) {\n '+bodies[variant]+'\n}\nvoid untouched(void) {}\n')
    target = tmp_path / 'owned.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(rule), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned stack address lifetime syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    ids = {row['rule'] for row in rows}
    assert ids <= {'stack_addr_escape', 'stack_addr_escape_outparam'}
    assert len(rows) == {'global_plain':1, 'global_clear':1, 'out_clear':2, 'static':1, 'aggregate_copy':0}[variant]
    assert all('review storage duration' in row['message'] for row in rows)
    if variant in ('global_plain', 'global_clear'):
        assert ids == {'stack_addr_escape'} and len(rows) == 1
    if variant == 'out_clear':
        assert 'stack_addr_escape_outparam' in ids
    if variant == 'aggregate_copy':
        assert rows == []
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
    assert result.outcome == ('confirmed' if rows else 'inconclusive')
    last = len(source.splitlines())
    scoped = scope_coccinelle_result(result, target_path=tmp_path, function_name='untouched',
        line_start=last, line_end=last, language='c')
    assert scoped.matches == [] and scoped.outcome == 'inconclusive'
    assert scoped.details['confirm_only']
    assert len(result.matches) == len(rows)
