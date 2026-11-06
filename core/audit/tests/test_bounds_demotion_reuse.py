"""Retired flat-source guard demotions cannot persist as cached verdicts."""

import pytest

from core.audit.gaps import _reuse_block_class, _reuse_ineligibility, compute_gaps
from core.audit.tests.test_verdict_reuse import _checklist, _entry, _gap_keys, _project_with, _write_target


STAMP = '[smt-infeasible: bounds conditions make overflow impossible (Z3 UNSAT)]\n'
LEAD = '[reused: verdict imported from run older; source hash unchanged]\n\n'


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant'])
@pytest.mark.parametrize('leads', [0, 1, 2])
def test_retired_demotion_requires_fresh_review(tmp_path, verdict, leads):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict=verdict, body=LEAD * leads + STAMP + 'review', clean_basis='verdict')
    reason = _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None, current_model=None)
    assert reason == 'unbound bounds demotion requires fresh review'
    assert _reuse_block_class(reason) == 'unbound_bounds_demotion'


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant'])
@pytest.mark.parametrize('long', [False, True])
def test_real_journal_fold_resurfaces_old_demotions(tmp_path, verdict, long):
    target = _write_target(tmp_path)
    body = LEAD + STAMP + ('prior review ' * 100 if long else 'review')
    project = _project_with(tmp_path, _entry(target, verdict=verdict, body=body, clean_basis='verdict'))
    sink, stats = {}, {}
    gaps = compute_gaps(_checklist(target), [], project_dir=project,
                        reuse_sink=sink, reuse_stats=stats, current_model='model-a')
    assert 'auth.c:check_pw' in _gap_keys(gaps)
    assert 'auth.c:check_pw' not in sink
    assert stats['auth.c:check_pw'] == 'unbound_bounds_demotion'


@pytest.mark.parametrize('verdict', ['clean', 'suspicious', 'dormant', 'finding'])
def test_fresh_review_or_quoted_marker_remains_reusable(tmp_path, verdict):
    target = _write_target(tmp_path)
    for body in ('new reviewed verdict', 'The old ' + STAMP + 'was rejected.'):
        entry = _entry(target, verdict=verdict, body=body, clean_basis='verdict')
        assert _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None, current_model=None) is None


def test_positive_finding_is_not_retired_as_a_negative_demotion(tmp_path):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict='finding', body=STAMP + 'now corroborated')
    assert _reuse_ineligibility(entry, 'auth.c:check_pw', current_strategies_fn=None, current_model=None) is None
