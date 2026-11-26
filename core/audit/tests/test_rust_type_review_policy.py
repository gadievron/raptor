"""Rust layout review defaults agree across scheduling, site binding and UI."""

import pytest

from core.audit.gaps import _resolve_reviewable_kinds, compute_gaps, gap_for_site
from core.audit.orchestrator import _reviewable_item_count
from core.coverage.store import CoverageStore
from core.coverage.store_summary import store_view


@pytest.mark.parametrize('path,language,enabled', [
    ('ffi.rs', 'rust', True),
    ('ffi.rs', '', True),  # Old checklists predate the language stamp.
    ('ffi.rs', 'Rust', True),
    ('ffi.c', 'c', False),
    ('ffi.h', '', False),
    ('ffi.cpp', 'cpp', False),
    ('Api.cs', 'csharp', False),
    ('api.py', 'python', False),
    ('unknown', '', False),
])
def test_language_defaults_match_dispatch_count_and_coverage(tmp_path, path, language, enabled):
    checklist = {'files': [{'path': path, 'language': language, 'items': [
        {'name': 'S', 'kind': 'class', 'line_start': 1, 'line_end': 3},
    ]}]}
    assert bool(compute_gaps(checklist, [])) is enabled
    assert _reviewable_item_count(checklist) == int(enabled)
    assert (gap_for_site(checklist, path, 2) is not None) is enabled
    store = CoverageStore(tmp_path / 'coverage.json')
    view = store_view(store, checklist)
    assert view['llm_reviewable'] == int(enabled)
    assert bool(view['llm_gap_functions']) is enabled
    # All other languages remain explicitly opt-in; Rust can opt back out.
    assert _reviewable_item_count(checklist, {'class'}) == 1
    assert len(compute_gaps(checklist, [], include_kinds={'class'})) == 1
    assert _reviewable_item_count(checklist, {'-class'}) == 0
    assert compute_gaps(checklist, [], include_kinds={'-class'}) == []
    assert compute_gaps(checklist, [], include_kinds={'none'}) == []


def test_rust_positive_kind_override_does_not_reenable_classes():
    assert 'class' in _resolve_reviewable_kinds(None, language='rust')
    assert 'class' in _resolve_reviewable_kinds({'-macro'}, language='rust')
    assert 'class' not in _resolve_reviewable_kinds({'top_level'}, language='rust')
    assert 'class' not in _resolve_reviewable_kinds({'none'}, language='rust')
    assert 'class' not in _resolve_reviewable_kinds({'-class'}, language='rust')
