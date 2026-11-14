"""Inert confirm-only policy controls at the prewarm memo boundary."""

from pathlib import Path

import pytest

from core.audit import cocci_prewarm as prewarm
from core.audit import sweep
from core.audit.sweep_memo import SweepMemo, hash_file
from packages.coccinelle.models import SpatchMatch, SpatchResult


@pytest.mark.parametrize('confirm_only', [False, True])
@pytest.mark.parametrize('match_line', [None, 5, 100])
def test_prewarm_preserves_rule_role_through_memo_and_function_scope(tmp_path, monkeypatch, confirm_only, match_line):
    root = tmp_path / 'owned-target'
    root.mkdir()
    (root / 'owned.c').write_text('/* inert owned source, never parsed or executed */\n')
    rule = Path(__file__).resolve().parents[3] / 'engine/coccinelle/rules/negative_errno_unsigned_return.cocci'
    if not confirm_only:
        rule = tmp_path / 'owned.cocci'
        rule.write_text('// inert custom rule\n')
    matches = [] if match_line is None else [SpatchMatch(file='owned.c', line=match_line, rule=rule.stem)]
    memo = SweepMemo()
    state = prewarm._RuleState()
    pinned = prewarm._pin_chunk(
        memo, state, {'owned.c': SpatchResult(rule=rule.stem, matches=matches)},
        ['owned.c'], root, str(rule), 'owned-rule-hash',
    )
    key = SweepMemo.make_key('coccinelle', {
        'rule': 'owned-rule-hash', 'file': hash_file(root / 'owned.c'),
        'path': 'owned.c', 'defines': '',
    })
    file_result = memo.get(key)
    assert pinned == 1
    expected_file = 'confirmed' if matches else ('inconclusive' if confirm_only else 'refuted')
    assert file_result.outcome == expected_file
    assert bool((file_result.details or {}).get('confirm_only')) is confirm_only
    monkeypatch.setattr(sweep, 'file_substrate_coverage', lambda *args, **kwargs: None)
    scoped = sweep.scope_coccinelle_result(
        file_result, target_path=root, function_name='owned_function',
        line_start=1, line_end=10, copy_result=False,
    )
    assert scoped.outcome == ('confirmed' if match_line == 5 else ('inconclusive' if confirm_only else 'refuted'))
