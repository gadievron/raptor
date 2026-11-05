"""Multiple accepted audit tails cannot erase earlier budget losses."""
import json

import pytest

from core.sandbox import observe_profile as observe


def parse(tmp_path, summaries, nonce=None):
    (tmp_path / observe.OBSERVE_FILENAME).write_text(''.join(
        json.dumps({'type': 'audit_summary', **summary}) + '\n' for summary in summaries))
    return observe.parse_observe_log(tmp_path, expected_nonce=nonce)


def test_drop_counts_accumulate_across_summary_records(tmp_path):
    profile = parse(tmp_path, [
        {'dropped_by_category': {'read': 2, 'write': 1}},
        {'dropped_by_category': {'read': 3, 'connect': 4}},
    ])
    assert profile.budget_truncated is True
    assert profile.dropped_by_category == {'read': 5, 'write': 1, 'connect': 4}


@pytest.mark.parametrize('later', [{}, {'read': 0}, {'read': False},
                                   {'read': -1}, {'read': 'invalid'}, {'read': None}])
def test_later_summary_does_not_erase_losses(tmp_path, later):
    profile = parse(tmp_path, [{'dropped_by_category': {'read': 2}},
                               {'dropped_by_category': later}])
    assert profile.budget_truncated is True
    assert profile.dropped_by_category == {'read': 2}


def test_unmatched_nonce_cannot_add_drop_counts(tmp_path):
    profile = parse(tmp_path, [
        {'nonce': 'trusted', 'dropped_by_category': {'read': 2}},
        {'nonce': 'wrong', 'dropped_by_category': {'read': 100}},
        {'nonce': 'trusted', 'dropped_by_category': {'write': 3}},
    ], nonce='trusted')
    assert profile.dropped_by_category == {'read': 2, 'write': 3}


def test_zero_only_summaries_remain_untruncated(tmp_path):
    profile = parse(tmp_path, [{'dropped_by_category': {'read': 0}},
                               {'dropped_by_category': {'write': 0}}])
    assert profile.budget_truncated is False
    assert profile.dropped_by_category == {'read': 0, 'write': 0}
