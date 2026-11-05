"""Ordered callback queries retain strict boundaries and first diagnostics."""

import pytest

from core.audit import callback_lifetime as cb


@pytest.mark.parametrize(('source', 'safe', 'reason'), [
    pytest.param('kfree(a);\ndel_timer(&d->timer);\nkfree(b);', False,
                 'async cancel at line 2 precedes a free at line 3', id='first-later-free'),
    pytest.param('cancel_work_sync(&d->work); kfree(d);', True,
                 'waiting teardown', id='same-line-wait-before-free'),
    pytest.param('kfree(d); cancel_work_sync(&d->work);', False,
                 'free at line 1 precedes', id='same-line-free-before-wait'),
    pytest.param('kfree_rcu(old, rcu); kfree(d); cancel_work_sync(&w);', True,
                 'waiting teardown', id='mixed-barriers-not-in-column-order'),
    pytest.param('cancel_work_sync(&w);\nkfree(d);\ndel_timer(&d->timer);', True,
                 'waiting teardown', id='all-frees-before-async'),
    pytest.param('del_timer_sync(&d->timer); del_timer(&e->timer); kfree(d);', False,
                 'async cancel at line 1 precedes a free at line 1', id='async-priority'),
    pytest.param('kfree(d);\ncancel_work_sync(&w);\nkfree(e);', False,
                 'free at line 1 precedes', id='first-free-unprotected'),
    pytest.param('kfree_rcu(d, rcu);', True,
                 'RCU-deferred reclamation', id='rcu-is-its-own-barrier'),
    pytest.param('d = container_of(w, struct dev, work);\ndel_timer(&d->timer);\nkfree(d);',
                 True, 'self-handler teardown', id='self-handler-priority'),
])
def test_safe_teardown_keeps_flags_and_first_reason(source, safe, reason):
    result = cb.check_safe_teardown(source)
    assert result.safe is safe
    assert result.reason.startswith(reason)


@pytest.mark.parametrize('source', [
    pytest.param('timer_setup(&d->timer, cb, 0); cancel_work_sync(&d->work);\nkfree(d);',
                 id='cancel-at-registration-line'),
    pytest.param('timer_setup(&d->timer, cb, 0);\ncancel_work_sync(&d->work); kfree(d);',
                 id='cancel-at-free-line'),
])
def test_local_cancellation_keeps_strict_line_boundaries(source):
    result = cb.check_callback_lifetime_local(source)
    assert result.violation_found and result.cancel_missing
    assert (result.register_line, result.free_line) == (1, 2)


def test_later_registration_can_fail_after_earlier_safe_pair():
    source = ('timer_setup(&a->timer, cb, 0);\ndel_timer_sync(&a->timer);\nkfree(a);\n'
              'timer_setup(&b->timer, cb, 0);\nkfree(b);')
    result = cb.check_callback_lifetime_local(source)
    assert result.violation_found and result.cancel_missing
    assert (result.register_line, result.free_line) == (4, 5)


def test_rcu_detection_still_runs_without_registrations():
    result = cb.check_callback_lifetime_local('p = rcu_dereference(head);\nkfree(p);')
    assert result.violation_found and result.rcu_kfree_mismatch
    assert (result.register_line, result.free_line) == (1, 2)


def test_absent_rcu_prefix_skips_rcu_walk(monkeypatch):
    def unexpected(lines):
        pytest.fail('RCU walk ran without its required prefix')

    monkeypatch.setattr(cb, '_check_rcu_kfree', unexpected)
    assert not cb.check_callback_lifetime_local('ordinary(x);').violation_found


def test_custom_split_keeps_original_rcu_walk():
    class Source(str):
        def split(self, separator):
            return ['p = rcu_dereference(head);', 'kfree(p);']

    assert cb.check_callback_lifetime_local(Source('custom view')).rcu_kfree_mismatch


@pytest.mark.parametrize('source', ['kfree(d);', 'del_timer(&d->timer);'],
                         ids=['free-only', 'async-only'])
def test_self_handler_walk_requires_both_event_types(monkeypatch, source):
    class UnexpectedSearch:
        def search(self, line):
            pytest.fail('Self-handler walk cannot affect this result')

    monkeypatch.setattr(cb, '_SELF_HANDLER_RE', UnexpectedSearch())
    cb.check_safe_teardown(source)


def test_call_free_lines_skip_call_patterns(monkeypatch):
    class UnexpectedScan:
        def search(self, line):
            pytest.fail('Call search ran without a call opener')

        def finditer(self, line):
            pytest.fail('Call iteration ran without a call opener')

    monkeypatch.setattr(cb, '_call_re', lambda names: UnexpectedScan())
    assert not cb.check_callback_lifetime_local('alpha = beta;').violation_found
    assert cb.check_safe_teardown('alpha = beta;').no_dealloc
