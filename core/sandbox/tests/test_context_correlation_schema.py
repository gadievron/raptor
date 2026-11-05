"""Malformed context rows cannot hide valid runtime correlations."""
import pytest

from core.sandbox import observe_context_merge as merge
from core.sandbox.observe_profile import ObserveProfile


@pytest.mark.parametrize('target_dir', [None, '/repo'])
def test_malformed_rows_and_paths_do_not_abort_merge(target_dir):
    bad = [None, 'row', 7, [], {'id': 'bad-list', 'file': ['src/file.py']},
           {'id': 'bad-object', 'file': {'path': 'src/file.py'}}]
    context = {'entry_points': bad + [{'id': 'EP-valid', 'file': 'src/file.py'}],
               'sink_details': bad + [{'id': 'SINK-valid', 'location': 'src/file.py'}]}
    profile = ObserveProfile(paths_read=['/repo/src/file.py'], paths_written=['/repo/src/file.py'])
    result = merge.merge_observation_into_context_map(context, profile, target_dir=target_dir)
    correlations = result['runtime_observation']['correlations']
    assert correlations['entry_points_runtime_confirmed'] == ['EP-valid']
    assert correlations['sinks_runtime_confirmed'] == ['SINK-valid']
    assert context['entry_points'][0] is None


@pytest.mark.parametrize('collection', [None, 42, True, 'invalid', {'unexpected': 'object'}])
def test_malformed_collections_produce_no_correlations(collection):
    profile = ObserveProfile(paths_read=['/repo/file'], paths_written=['/repo/file'])
    assert merge._correlate_entry_points(profile, collection) == []
    assert merge._correlate_sinks(profile, collection) == []


def test_generators_remain_supported():
    profile = ObserveProfile(paths_read=['/repo/file'], paths_written=['/repo/file'])
    entries = ({'id': 'EP', 'file': 'file'} for _ in range(1))
    sinks = ({'id': 'SINK', 'file': 'file'} for _ in range(1))
    assert merge._correlate_entry_points(profile, entries) == ['EP']
    assert merge._correlate_sinks(profile, sinks) == ['SINK']


def test_nonstring_observed_path_does_not_hide_following_valid_path():
    profile = ObserveProfile(paths_read=[None, '/repo/file'], paths_written=[{}, '/repo/file'])
    row = {'id': 'valid', 'file': 'file'}
    assert merge._correlate_entry_points(profile, [row], '/repo') == ['valid']
    assert merge._correlate_sinks(profile, [row], '/repo') == ['valid']
