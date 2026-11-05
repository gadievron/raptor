"""Context-map augmentation preserves observation trust and completeness."""
import pytest

from core.sandbox.observe_context_merge import merge_observation_into_context_map
from core.sandbox.observe_profile import ObserveProfile


@pytest.mark.parametrize('trusted,truncated,incomplete', [
    (True, False, False), (False, False, False), (True, True, False),
    (True, False, True), (False, True, True)])
def test_profile_state_survives_context_merge(trusted, truncated, incomplete):
    profile = ObserveProfile(nonce_trusted=trusted, budget_truncated=truncated,
                             capture_incomplete=incomplete,
                             dropped_by_category={'read': 3} if truncated else {})
    result = merge_observation_into_context_map({'meta': {'target': '/repo'}}, profile)
    observation = result['runtime_observation']
    assert observation['nonce_trusted'] is trusted
    assert observation['budget_truncated'] is truncated
    assert observation['capture_incomplete'] is incomplete
    assert observation['dropped_by_category'] == profile.dropped_by_category


def test_drop_counts_are_detached_in_both_directions():
    profile = ObserveProfile(budget_truncated=True, dropped_by_category={'read': 3})
    result = merge_observation_into_context_map({}, profile)
    counts = result['runtime_observation']['dropped_by_category']
    profile.dropped_by_category['read'] = 9
    assert counts == {'read': 3}
    counts['write'] = 5
    assert profile.dropped_by_category == {'read': 9}


def test_original_context_map_is_unchanged():
    context = {'runtime_observation': {'nonce_trusted': True}, 'entry_points': []}
    profile = ObserveProfile(nonce_trusted=False, capture_incomplete=True)
    result = merge_observation_into_context_map(context, profile)
    assert context == {'runtime_observation': {'nonce_trusted': True}, 'entry_points': []}
    assert result['runtime_observation']['nonce_trusted'] is False
    assert result['runtime_observation']['capture_incomplete'] is True
